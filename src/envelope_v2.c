#define _GNU_SOURCE
#include "envelope.h"
#include "secure_mem.h"
#include "tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#define CRED_ENV_V2_KDF_INFO "CRED_ENV_v2_AES256GCM"

int derive_hkdf_aes_key(const uint8_t *eph_secret, size_t secret_len,
                        const uint8_t *salt, size_t salt_len,
                        const char *info,
                        uint8_t aes_key_out[32]) {
    if (!eph_secret || secret_len == 0 || !salt || salt_len == 0 || !info || !aes_key_out) {
        return -EINVAL;
    }

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        return -EIO;
    }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return -ENOMEM;
    }

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)eph_secret, secret_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
    params[4] = OSSL_PARAM_construct_end();

    int ret = (EVP_KDF_derive(kctx, aes_key_out, 32, params) == 1) ? 0 : -EIO;
    EVP_KDF_CTX_free(kctx);
    return ret;
}

int format_credential_aad_v2(uint8_t *buf, size_t buf_sz, size_t *aad_len_out,
                             uint16_t rsa_ct_len, uint32_t ciphertext_len,
                             const uint8_t iv[12],
                             const char *rel_path, mode_t mode) {
    if (!buf || buf_sz == 0 || !iv || !rel_path || !aad_len_out) {
        return -EINVAL;
    }

    const char *clean_path = NULL;
    int r = validate_relative_path(rel_path, &clean_path);
    if (r < 0) {
        return r;
    }

    char path_buf[PATH_MAX + 16];
    int ret = snprintf(path_buf, sizeof(path_buf), "%s:%04o", clean_path, (unsigned int)(mode & 07777));
    if (ret < 0 || (size_t)ret >= sizeof(path_buf)) {
        return -ENAMETOOLONG;
    }

    size_t path_len = strlen(path_buf);
    size_t total_len = 8 + 8 + 2 + 4 + 12 + path_len;
    if (total_len > buf_sz) {
        return -ENAMETOOLONG;
    }

    uint64_t ver_be = htobe64(CRED_ENV_VERSION_2);
    uint16_t rsa_len_be = htobe16(rsa_ct_len);
    uint32_t ct_len_be = htobe32(ciphertext_len);

    uint8_t *p = buf;
    memcpy(p, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN); p += CRED_ENV_MAGIC_LEN;
    memcpy(p, &ver_be, sizeof(ver_be)); p += sizeof(ver_be);
    memcpy(p, &rsa_len_be, sizeof(rsa_len_be)); p += sizeof(rsa_len_be);
    memcpy(p, &ct_len_be, sizeof(ct_len_be)); p += sizeof(ct_len_be);
    memcpy(p, iv, 12); p += 12;
    memcpy(p, path_buf, path_len); p += path_len;

    *aad_len_out = total_len;
    return 0;
}

int compute_oaep_label_v2(const uint8_t *aad, size_t aad_len, uint8_t label_buf[33]) {
    if (!aad || aad_len == 0 || !label_buf) {
        return -EINVAL;
    }

    uint8_t digest[32];
    unsigned int digest_len = 0;
    if (EVP_Digest(aad, aad_len, digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != 32) {
        return -EIO;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) {
        label_buf[i * 2] = (uint8_t)hex_chars[(digest[i] >> 4) & 0x0f];
        label_buf[i * 2 + 1] = (uint8_t)hex_chars[digest[i] & 0x0f];
    }
    label_buf[32] = '\0';

    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

#define CRED_ENV_V2_MIN_HDR_SIZE (sizeof(struct cred_env_commonhdr) + sizeof(uint16_t))

ssize_t inspect_envelope_v2(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out) {
    if (!hdr || hdr_len < CRED_ENV_V2_MIN_HDR_SIZE || raw_size < 0) {
        return -EINVAL;
    }

    if (memcmp(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
        return -EBADMSG;
    }

    if (be64toh(hdr->common.version) != CRED_ENV_VERSION_2) {
        return -EPROTONOSUPPORT;
    }

    ssize_t ret = inspect_envelope_v1_layout(hdr, hdr_len, raw_size, max_size, out);
    if (ret >= 0 && out) {
        out->version = CRED_ENV_VERSION_2;
    }
    return ret;
}

int decrypt_envelope_v2(const uint8_t *enc_data, size_t enc_len,
                        const char *rel_path, mode_t mode,
                        struct decrypted_node *out) {
    if (!enc_data || !rel_path || !out) {
        return -EINVAL;
    }

    const struct cred_env_hdr *hdr = (const struct cred_env_hdr *)enc_data;
    struct env_data ed = {0};
    ssize_t pt_size = inspect_envelope_v2(hdr, enc_len, (off_t)enc_len, 0, &ed);
    if (pt_size < 0) {
        return (int)pt_size;
    }

    uint8_t aad[PATH_MAX + 64];
    size_t aad_len = 0;
    int r = format_credential_aad_v2(aad, sizeof(aad), &aad_len,
                                     ed.v2.rsa_ct_len, (uint32_t)ed.v2.plaintext_len,
                                     ed.v2.iv, rel_path, mode);
    if (r < 0) {
        return r;
    }

    uint8_t label[33];
    r = compute_oaep_label_v2(aad, aad_len, label);
    if (r < 0) {
        OPENSSL_cleanse(aad, sizeof(aad));
        return r;
    }

    struct decrypted_node eph_secret = { 0 };
    r = tpm_unwrap(ed.v2.rsa_ct, ed.v2.rsa_ct_len, label, &eph_secret);
    OPENSSL_cleanse(label, sizeof(label));
    if (r < 0) {
        clean_decrypted_node(&eph_secret);
        OPENSSL_cleanse(aad, sizeof(aad));
        return r;
    }

    if (eph_secret.len != 32) {
        clean_decrypted_node(&eph_secret);
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EBADMSG;
    }

    uint8_t aes_key_bytes[32];
    r = derive_hkdf_aes_key(eph_secret.buf, eph_secret.len,
                            ed.v2.iv, 12,
                            CRED_ENV_V2_KDF_INFO,
                            aes_key_bytes);
    clean_decrypted_node(&eph_secret);
    if (r < 0) {
        OPENSSL_cleanse(aad, sizeof(aad));
        return r;
    }

    struct decrypted_node aes_key_node = {
        .buf = aes_key_bytes,
        .len = sizeof(aes_key_bytes),
        .allocated_size = sizeof(aes_key_bytes),
        .uid_slot = 0
    };

    r = do_aes_decrypt(ed.v2.iv, ed.v2.tag, ed.v2.ciphertext, ed.v2.plaintext_len,
                       aad, aad_len,
                       &aes_key_node, out);

    OPENSSL_cleanse(aes_key_bytes, sizeof(aes_key_bytes));
    OPENSSL_cleanse(aad, sizeof(aad));
    return r;
}

int encrypt_envelope_v2(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t **out_buf, size_t *out_len) {
    if (!pkey || !rel_path || !plaintext || pt_len == 0 || !out_buf || !out_len) {
        return -EINVAL;
    }

    size_t rsa_mod_bytes = (size_t)EVP_PKEY_get_size(pkey);
    if (rsa_mod_bytes != TPM2_RSA2048_KEY_BYTES && rsa_mod_bytes != TPM2_RSA4096_KEY_BYTES) {
        return -EINVAL;
    }
    uint16_t rsa_ct_len = (uint16_t)rsa_mod_bytes;

    uint8_t eph_secret[32];
    uint8_t aes_key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t rsa_ct[TPM2_RSA4096_KEY_BYTES];
    uint8_t aad[PATH_MAX + 64];
    size_t aad_len = 0;
    uint8_t oaep_label[33];

    if (RAND_bytes(eph_secret, sizeof(eph_secret)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        return -EIO;
    }

    if (format_credential_aad_v2(aad, sizeof(aad), &aad_len, rsa_ct_len, (uint32_t)pt_len, iv, rel_path, mode) < 0) {
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        return -EINVAL;
    }

    if (compute_oaep_label_v2(aad, aad_len, oaep_label) < 0) {
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }

    uint8_t *label_copy = OPENSSL_malloc(sizeof(oaep_label));
    if (!label_copy) {
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -ENOMEM;
    }
    memcpy(label_copy, oaep_label, sizeof(oaep_label));
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label_copy, (int)sizeof(oaep_label)) <= 0) {
        OPENSSL_free(label_copy);
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }

    size_t rsa_encrypted_len = sizeof(rsa_ct);
    if (EVP_PKEY_encrypt(pctx, rsa_ct, &rsa_encrypted_len, eph_secret, sizeof(eph_secret)) <= 0 ||
        rsa_encrypted_len != rsa_ct_len) {
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(oaep_label, sizeof(oaep_label));

    if (derive_hkdf_aes_key(eph_secret, sizeof(eph_secret), iv, sizeof(iv), CRED_ENV_V2_KDF_INFO, aes_key) < 0) {
        OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }
    OPENSSL_cleanse(eph_secret, sizeof(eph_secret));

    uint8_t *ct_buf = malloc(pt_len);
    if (!ct_buf) {
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -ENOMEM;
    }

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, aes_key, iv) != 1) {
        if (cctx) EVP_CIPHER_CTX_free(cctx);
        free(ct_buf);
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cctx, NULL, &outlen, aad, (int)aad_len) != 1 ||
        EVP_EncryptUpdate(cctx, ct_buf, &outlen, plaintext, (int)pt_len) != 1 ||
        EVP_EncryptFinal_ex(cctx, ct_buf + outlen, &outlen) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        free(ct_buf);
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EIO;
    }
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(aad, sizeof(aad));

    size_t payload_meta_sz = (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) ?
                             sizeof(struct cred_env_v1_rsa2048) :
                             sizeof(struct cred_env_v1_rsa4096);
    size_t header_len = sizeof(struct cred_env_commonhdr) + sizeof(uint16_t) + payload_meta_sz;
    if (pt_len > SIZE_MAX - header_len) {
        free(ct_buf);
        return -EFBIG;
    }
    size_t total_len = header_len + pt_len;
    uint8_t *envelope = malloc(total_len);
    if (!envelope) {
        free(ct_buf);
        return -ENOMEM;
    }

    struct cred_env_hdr *hdr = (struct cred_env_hdr *)envelope;
    memcpy(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN);
    hdr->common.version = htobe64(CRED_ENV_VERSION_2);
    hdr->v2.rsa_ct_len = htobe16(rsa_ct_len);

    if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
        memcpy(hdr->v2.rsa2048.rsa_ct, rsa_ct, TPM2_RSA2048_KEY_BYTES);
        memcpy(hdr->v2.rsa2048.iv, iv, sizeof(iv));
        memcpy(hdr->v2.rsa2048.tag, tag, sizeof(tag));
    } else {
        memcpy(hdr->v2.rsa4096.rsa_ct, rsa_ct, TPM2_RSA4096_KEY_BYTES);
        memcpy(hdr->v2.rsa4096.iv, iv, sizeof(iv));
        memcpy(hdr->v2.rsa4096.tag, tag, sizeof(tag));
    }
    memcpy(envelope + header_len, ct_buf, pt_len);
    free(ct_buf);

    *out_buf = envelope;
    *out_len = total_len;
    return 0;
}
