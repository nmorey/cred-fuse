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
#include <openssl/crypto.h>

static int format_credential_aad_v1(char *buf, size_t buf_sz, const char *rel_path, mode_t mode) {
    if (!buf || buf_sz == 0 || !rel_path) {
        return -EINVAL;
    }

    const char *clean_path = NULL;
    int r = validate_relative_path(rel_path, &clean_path);
    if (r < 0) {
        return r;
    }

    int ret = snprintf(buf, buf_sz, "%s:%04o", clean_path, (unsigned int)(mode & 07777));
    if (ret < 0 || (size_t)ret >= buf_sz) {
        return -ENAMETOOLONG;
    }
    return 0;
}

ssize_t inspect_envelope_v1(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out) {
    return inspect_envelope_common_v1_v2(hdr, hdr_len, raw_size, max_size, CRED_ENV_VERSION_1, out);
}

int decrypt_envelope_v1(const uint8_t *enc_data, size_t enc_len,
                        const char *rel_path, mode_t mode,
                        struct decrypted_node *out) {
    if (!enc_data || !rel_path || !out) {
        return -EINVAL;
    }

    const struct cred_env_hdr *hdr = (const struct cred_env_hdr *)enc_data;
    struct env_data ed = {0};
    ssize_t pt_size = inspect_envelope_v1(hdr, enc_len, (off_t)enc_len, 0, &ed);
    if (pt_size < 0) {
        return (int)pt_size;
    }

    char aad[PATH_MAX + 16];
    int r = format_credential_aad_v1(aad, sizeof(aad), rel_path, mode);
    if (r < 0) {
        return r;
    }

    uint8_t label[33];
    r = compute_oaep_label(aad, strlen(aad), label);
    if (r < 0) {
        OPENSSL_cleanse(aad, sizeof(aad));
        return r;
    }

    struct decrypted_node eph_key = { 0 };
    r = tpm_unwrap(ed.v1.rsa_ct, ed.v1.rsa_ct_len, label, &eph_key);
    OPENSSL_cleanse(label, sizeof(label));
    if (r < 0) {
        clean_decrypted_node(&eph_key);
        OPENSSL_cleanse(aad, sizeof(aad));
        return r;
    }

    if (eph_key.len != 32) {
        clean_decrypted_node(&eph_key);
        OPENSSL_cleanse(aad, sizeof(aad));
        return -EBADMSG;
    }

    r = do_aes_decrypt(ed.v1.iv, ed.v1.tag, ed.v1.ciphertext, ed.v1.plaintext_len,
                       (const uint8_t *)aad, strlen(aad),
                       &eph_key, out);
    clean_decrypted_node(&eph_key);
    OPENSSL_cleanse(aad, sizeof(aad));
    return r;
}

#ifdef CRED_FUSE_TESTING
#include <openssl/rand.h>
#include <openssl/rsa.h>

int encrypt_envelope_v1(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
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
    hdr->common.version = htobe64(CRED_ENV_VERSION_1);
    hdr->v1.rsa_ct_len = htobe16(rsa_ct_len);

    uint8_t *rsa_ct, *iv, *tag;
    if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
        rsa_ct = hdr->v1.rsa2048.rsa_ct;
        iv = hdr->v1.rsa2048.iv;
        tag = hdr->v1.rsa2048.tag;
    } else {
        rsa_ct = hdr->v1.rsa4096.rsa_ct;
        iv = hdr->v1.rsa4096.iv;
        tag = hdr->v1.rsa4096.tag;
    }
    uint8_t *ciphertext = envelope + header_len;

    uint8_t eph_key[32];
    char aad[PATH_MAX + 16];
    uint8_t oaep_label[33];

    EVP_PKEY_CTX *pctx = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    uint8_t *label_copy = NULL;
    int ret = -EIO;

    ret = format_credential_aad_v1(aad, sizeof(aad), rel_path, mode);
    if (ret < 0) {
        goto out;
    }

    ret = compute_oaep_label(aad, strlen(aad), oaep_label);
    if (ret < 0) {
        goto out;
    }

    if (RAND_bytes(eph_key, sizeof(eph_key)) != 1 || RAND_bytes(iv, CRED_ENV_IV_LEN) != 1) {
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
    if (EVP_PKEY_encrypt(pctx, rsa_ct, &rsa_encrypted_len, eph_key, sizeof(eph_key)) <= 0 ||
        rsa_encrypted_len != rsa_ct_len) {
        ret = -EIO;
        goto out;
    }

    cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, CRED_ENV_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, eph_key, iv) != 1) {
        ret = -EIO;
        goto out;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cctx, NULL, &outlen, (const uint8_t *)aad, (int)strlen(aad)) != 1 ||
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
    OPENSSL_cleanse(eph_key, sizeof(eph_key));
    OPENSSL_cleanse(oaep_label, sizeof(oaep_label));
    OPENSSL_cleanse(aad, sizeof(aad));
    return ret;
}
#endif
