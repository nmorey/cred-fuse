#ifndef CRED_FUSE_ENVELOPE_H
#define CRED_FUSE_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "decryption.h"

typedef int (*decrypt_envelope_fn)(const uint8_t *enc_data, size_t enc_len,
                                   const char *rel_path, mode_t mode,
                                   struct decrypted_node *out);

typedef int (*encrypt_envelope_fn)(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t **out_buf, size_t *out_len);

extern const decrypt_envelope_fn envelope_decryptors[_CRED_ENV_VERSION_MAX];
extern const encrypt_envelope_fn envelope_encryptors[_CRED_ENV_VERSION_MAX];

/* Common path validation helper: ensures non-empty, no leading slashes, no '..' traversal */
int validate_relative_path(const char *rel_path, const char **clean_path_out);

/* Shared low-level AES-256-GCM decryptor */
int do_aes_decrypt(const uint8_t *iv,
                   const uint8_t *tag,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const struct decrypted_node *aes_key,
                   struct decrypted_node *out);

/* Shared low-level TPM RSA-OAEP decryptor */
int tpm2_rsa_decrypt(const uint8_t *in_data, size_t in_len,
                     const uint8_t oaep_label[33],
                     struct decrypted_node *out);

/* Version 1 Envelope Handlers */
int format_credential_aad_v1(char *buf, size_t buf_sz, const char *rel_path, mode_t mode);
int compute_oaep_label_v1(const char *aad, uint8_t label_buf[33]);
int decrypt_envelope_v1(const uint8_t *enc_data, size_t enc_len,
                        const char *rel_path, mode_t mode,
                        struct decrypted_node *out);

#ifdef CRED_FUSE_TESTING
int encrypt_envelope_v1(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t **out_buf, size_t *out_len);
#endif

/* Version 2 Envelope Handlers */
int derive_hkdf_aes_key(const uint8_t *eph_secret, size_t secret_len,
                        const uint8_t *salt, size_t salt_len,
                        const char *info,
                        uint8_t aes_key_out[32]);
int format_credential_aad_v2(uint8_t *buf, size_t buf_sz, size_t *aad_len_out,
                             uint16_t rsa_ct_len, uint32_t ciphertext_len,
                             const uint8_t iv[12],
                             const char *rel_path, mode_t mode);
int compute_oaep_label_v2(const uint8_t *aad, size_t aad_len, uint8_t label_buf[33]);
int decrypt_envelope_v2(const uint8_t *enc_data, size_t enc_len,
                        const char *rel_path, mode_t mode,
                        struct decrypted_node *out);
int encrypt_envelope_v2(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t **out_buf, size_t *out_len);

#endif /* CRED_FUSE_ENVELOPE_H */
