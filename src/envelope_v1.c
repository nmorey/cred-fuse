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

int validate_relative_path(const char *rel_path, const char **clean_path_out) {
    if (!rel_path) {
        return -EINVAL;
    }
    while (*rel_path == '/') {
        rel_path++;
    }
    if (*rel_path == '\0') {
        return -EINVAL;
    }

    const char *p = rel_path;
    while (*p) {
        if (*p == '/') {
            return -EINVAL;
        }
        const char *end = p;
        while (*end && *end != '/') {
            end++;
        }
        size_t comp_len = (size_t)(end - p);
        if ((comp_len == 1 && p[0] == '.') ||
            (comp_len == 2 && p[0] == '.' && p[1] == '.')) {
            return -EINVAL;
        }
        for (size_t i = 0; i < comp_len; i++) {
            char c = p[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-')) {
                return -EINVAL;
            }
        }
        if (*end == '/') {
            if (*(end + 1) == '\0') {
                return -EINVAL;
            }
            p = end + 1;
        } else {
            p = end;
        }
    }

    if (clean_path_out) {
        *clean_path_out = rel_path;
    }
    return 0;
}

int format_credential_aad_v1(char *buf, size_t buf_sz, const char *rel_path, mode_t mode) {
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

int compute_oaep_label_v1(const char *aad, uint8_t label_buf[33]) {
    if (!aad || aad[0] == '\0' || !label_buf) {
        return -EINVAL;
    }

    uint8_t digest[32];
    unsigned int digest_len = 0;
    if (EVP_Digest(aad, strlen(aad), digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != 32) {
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

#define CRED_ENV_V1_MIN_HDR_SIZE (sizeof(struct cred_env_commonhdr) + sizeof(uint16_t))

ssize_t inspect_envelope_v1_layout(const struct cred_env_hdr *hdr, size_t hdr_len,
                                   off_t raw_size, size_t max_size,
                                   struct env_data *out) {
    uint16_t rsa_ct_len = be16toh(hdr->v1.rsa_ct_len);
    size_t payload_meta_sz;
    if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
        payload_meta_sz = sizeof(struct cred_env_v1_rsa2048);
    } else if (rsa_ct_len == TPM2_RSA4096_KEY_BYTES) {
        payload_meta_sz = sizeof(struct cred_env_v1_rsa4096);
    } else {
        return -EBADMSG;
    }

    off_t overhead = (off_t)(sizeof(struct cred_env_commonhdr) + sizeof(uint16_t) + payload_meta_sz);
    if (raw_size <= overhead) {
        return -EBADMSG;
    }

    off_t plaintext_size = raw_size - overhead;
    if (plaintext_size > (off_t)SSIZE_MAX) {
        return -EFBIG;
    }
    if (max_size > 0 && (size_t)plaintext_size > max_size) {
        return -EFBIG;
    }

    if (out) {
        out->plaintext_len = (size_t)plaintext_size;
        out->v1.rsa_ct_len = rsa_ct_len;
        out->v1.overhead = (size_t)overhead;
        out->v1.plaintext_len = (size_t)plaintext_size;

        if (hdr_len >= (size_t)overhead) {
            if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
                out->v1.rsa_ct = hdr->v1.rsa2048.rsa_ct;
                out->v1.iv = hdr->v1.rsa2048.iv;
                out->v1.tag = hdr->v1.rsa2048.tag;
            } else {
                out->v1.rsa_ct = hdr->v1.rsa4096.rsa_ct;
                out->v1.iv = hdr->v1.rsa4096.iv;
                out->v1.tag = hdr->v1.rsa4096.tag;
            }
            out->v1.ciphertext = ((const uint8_t *)hdr) + overhead;
        } else {
            out->v1.rsa_ct = NULL;
            out->v1.iv = NULL;
            out->v1.tag = NULL;
            out->v1.ciphertext = NULL;
        }
    }

    return (ssize_t)plaintext_size;
}

ssize_t inspect_envelope_v1(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out) {
    if (!hdr || hdr_len < CRED_ENV_V1_MIN_HDR_SIZE || raw_size < 0) {
        return -EINVAL;
    }

    if (memcmp(hdr->common.magic, CRED_ENV_MAGIC, CRED_ENV_MAGIC_LEN) != 0) {
        return -EBADMSG;
    }

    if (be64toh(hdr->common.version) != CRED_ENV_VERSION_1) {
        return -EPROTONOSUPPORT;
    }

    ssize_t ret = inspect_envelope_v1_layout(hdr, hdr_len, raw_size, max_size, out);
    if (ret >= 0 && out) {
        out->version = CRED_ENV_VERSION_1;
    }
    return ret;
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
    r = compute_oaep_label_v1(aad, label);
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

    char aad[PATH_MAX + 16];
    int r = format_credential_aad_v1(aad, sizeof(aad), rel_path, mode);
    if (r < 0) {
        return r;
    }

    uint8_t oaep_label[33];
    r = compute_oaep_label_v1(aad, oaep_label);
    if (r < 0) {
        return r;
    }

    uint8_t eph_key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t rsa_ct[TPM2_RSA4096_KEY_BYTES];
    if (RAND_bytes(eph_key, sizeof(eph_key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        return -EIO;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -EIO;
    }

    uint8_t *label_copy = OPENSSL_malloc(sizeof(oaep_label));
    if (!label_copy) {
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -ENOMEM;
    }
    memcpy(label_copy, oaep_label, sizeof(oaep_label));
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label_copy, (int)sizeof(oaep_label)) <= 0) {
        OPENSSL_free(label_copy);
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -EIO;
    }

    size_t rsa_encrypted_len = sizeof(rsa_ct);
    if (EVP_PKEY_encrypt(pctx, rsa_ct, &rsa_encrypted_len, eph_key, sizeof(eph_key)) <= 0 ||
        rsa_encrypted_len != rsa_ct_len) {
        EVP_PKEY_CTX_free(pctx);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -EIO;
    }
    EVP_PKEY_CTX_free(pctx);

    uint8_t *ct_buf = malloc(pt_len);
    if (!ct_buf) {
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -ENOMEM;
    }

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx ||
        EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(cctx, NULL, NULL, eph_key, iv) != 1) {
        if (cctx) EVP_CIPHER_CTX_free(cctx);
        free(ct_buf);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -EIO;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(cctx, NULL, &outlen, (const uint8_t *)aad, (int)strlen(aad)) != 1 ||
        EVP_EncryptUpdate(cctx, ct_buf, &outlen, plaintext, (int)pt_len) != 1 ||
        EVP_EncryptFinal_ex(cctx, ct_buf + outlen, &outlen) != 1 ||
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(cctx);
        free(ct_buf);
        OPENSSL_cleanse(eph_key, sizeof(eph_key));
        return -EIO;
    }
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_cleanse(eph_key, sizeof(eph_key));

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
    hdr->common.version = htobe64(CRED_ENV_VERSION_1);
    hdr->v1.rsa_ct_len = htobe16(rsa_ct_len);

    if (rsa_ct_len == TPM2_RSA2048_KEY_BYTES) {
        memcpy(hdr->v1.rsa2048.rsa_ct, rsa_ct, TPM2_RSA2048_KEY_BYTES);
        memcpy(hdr->v1.rsa2048.iv, iv, sizeof(iv));
        memcpy(hdr->v1.rsa2048.tag, tag, sizeof(tag));
    } else {
        memcpy(hdr->v1.rsa4096.rsa_ct, rsa_ct, TPM2_RSA4096_KEY_BYTES);
        memcpy(hdr->v1.rsa4096.iv, iv, sizeof(iv));
        memcpy(hdr->v1.rsa4096.tag, tag, sizeof(tag));
    }
    memcpy(envelope + header_len, ct_buf, pt_len);
    free(ct_buf);

    *out_buf = envelope;
    *out_len = total_len;
    return 0;
}
#endif
