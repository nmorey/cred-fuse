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

static int derive_hkdf_aes_key(const uint8_t *eph_secret, size_t secret_len,
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

static int format_credential_aad_v2(uint8_t *buf, size_t buf_sz, size_t *aad_len_out,
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

ssize_t inspect_envelope_v2(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out) {
    return inspect_envelope_common_v1_v2(hdr, hdr_len, raw_size, max_size, CRED_ENV_VERSION_2, out);
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
    r = compute_oaep_label(aad, aad_len, label);
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

    size_t payload_meta_sz = (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) ?
                             sizeof(struct cred_env_v1_rsa2048) :
                             sizeof(struct cred_env_v1_rsa4096);
    size_t header_len = sizeof(struct cred_env_commonhdr) + sizeof(uint16_t) + payload_meta_sz;
    if (pt_len > SIZE_MAX - header_len) {
        return -EFBIG;
    }

    size_t total_len = header_len + pt_len;
    uint8_t *envelope = malloc(total_len);
    if (!envelope) {
        return -ENOMEM;
    }

    struct cred_env_hdr *hdr = (struct cred_env_hdr *)envelope;
    memcpy(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN);
    hdr->common.version = htobe64(CRED_ENV_VERSION_2);
    hdr->v2.rsa_ct_len = htobe16(rsa_ct_len);

    uint8_t *rsa_ct, *iv, *tag;
    if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
        rsa_ct = hdr->v2.rsa2048.rsa_ct;
        iv = hdr->v2.rsa2048.iv;
        tag = hdr->v2.rsa2048.tag;
    } else {
        rsa_ct = hdr->v2.rsa4096.rsa_ct;
        iv = hdr->v2.rsa4096.iv;
        tag = hdr->v2.rsa4096.tag;
    }
    uint8_t *ciphertext = envelope + header_len;

    uint8_t eph_secret[32];
    uint8_t aes_key[32];
    uint8_t aad[PATH_MAX + 64];
    size_t aad_len = 0;
    uint8_t oaep_label[33];

    EVP_PKEY_CTX *pctx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    uint8_t *label_copy = NULL;
    int ret = -EIO;

    if (RAND_bytes(eph_secret, sizeof(eph_secret)) != 1 || RAND_bytes(iv, CRED_ENV_IV_LEN) != 1) {
        ret = -EIO;
        goto out;
    }

    if (format_credential_aad_v2(aad, sizeof(aad), &aad_len, rsa_ct_len, (uint32_t)pt_len, iv, rel_path, mode) < 0) {
        ret = -EINVAL;
        goto out;
    }

    if (compute_oaep_label(aad, aad_len, oaep_label) < 0) {
        ret = -EIO;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        ret = -EIO;
        goto out;
    }

    label_copy = OPENSSL_malloc(sizeof(oaep_label));
    if (!label_copy) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(label_copy, oaep_label, sizeof(oaep_label));
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label_copy, (int)sizeof(oaep_label)) <= 0) {
        OPENSSL_free(label_copy);
        label_copy = NULL;
        ret = -EIO;
        goto out;
    }
    label_copy = NULL;

    size_t rsa_encrypted_len = rsa_ct_len;
    if (EVP_PKEY_encrypt(pctx, rsa_ct, &rsa_encrypted_len, eph_secret, sizeof(eph_secret)) <= 0 ||
        rsa_encrypted_len != rsa_ct_len) {
        ret = -EIO;
        goto out;
    }

    if (derive_hkdf_aes_key(eph_secret, sizeof(eph_secret), iv, CRED_ENV_IV_LEN, CRED_ENV_V2_KDF_INFO, aes_key) < 0) {
        ret = -EIO;
        goto out;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, CRED_ENV_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, aes_key, iv) != 1) {
        ret = -EIO;
        goto out;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cctx, NULL, &outlen, aad, (int)aad_len) != 1 ||
        EVP_EncryptUpdate(cctx, ciphertext, &outlen, plaintext, (int)pt_len) != 1 ||
        EVP_EncryptFinal_ex(cctx, ciphertext + outlen, &outlen) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, CRED_ENV_TAG_LEN, tag) != 1) {
        ret = -EIO;
        goto out;
    }

    *out_buf = envelope;
    *out_len = total_len;
    envelope = NULL;
    ret = 0;

out:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (cctx) EVP_CIPHER_CTX_free(cctx);
    if (label_copy) OPENSSL_free(label_copy);
    if (envelope) free(envelope);
    OPENSSL_cleanse(eph_secret, sizeof(eph_secret));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
    OPENSSL_cleanse(aad, sizeof(aad));
    return ret;
}
