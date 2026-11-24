#ifndef CRED_FUSE_ENVELOPE_H
#define CRED_FUSE_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "secure_mem.h"
#include "pubkey.h"

#define CRED_ENV_MAGIC "CRED_ENV"
#define CRED_ENV_MAGIC_LEN 8

enum cred_env_version {
    CRED_ENV_VERSION_INVALID = 0,
    CRED_ENV_VERSION_1       = 1,
    CRED_ENV_VERSION_2       = 2,
    _CRED_ENV_VERSION_MAX,
};

#define CRED_ENV_CUR_VERSION CRED_ENV_VERSION_2

#define CRED_ENV_IV_LEN 12
#define CRED_ENV_TAG_LEN 16

/* 1. Common 16-byte fixed prefix across all envelope versions */
struct cred_env_commonhdr {
    char magic[CRED_ENV_MAGIC_LEN]; /* "CRED_ENV" */
    uint64_t version;               /* big-endian format version */
} __attribute__((packed));
_Static_assert(sizeof(struct cred_env_commonhdr) == 16, "Common header size must be 16 bytes");

/* 2. Version 1 & 2 binary layout variants */
struct cred_env_v1_rsa2048 {
    uint8_t rsa_ct[TPM2_RSA2048_KEY_BYTES];
    uint8_t iv[CRED_ENV_IV_LEN];
    uint8_t tag[CRED_ENV_TAG_LEN];
} __attribute__((packed));
_Static_assert(sizeof(struct cred_env_v1_rsa2048) == 284, "RSA-2048 block must be 284 bytes");

struct cred_env_v1_rsa4096 {
    uint8_t rsa_ct[TPM2_RSA4096_KEY_BYTES];
    uint8_t iv[CRED_ENV_IV_LEN];
    uint8_t tag[CRED_ENV_TAG_LEN];
} __attribute__((packed));
_Static_assert(sizeof(struct cred_env_v1_rsa4096) == 540, "RSA-4096 block must be 540 bytes");

typedef struct cred_env_v1_hdr {
    uint16_t rsa_ct_len;            /* big-endian: 256 or 512 */
    union {
        struct cred_env_v1_rsa2048 rsa2048;
        struct cred_env_v1_rsa4096 rsa4096;
    };
} cred_env_v1_hdr;

typedef cred_env_v1_hdr cred_env_v2_hdr;

/* 3. Combined envelope header with tagged union */
struct cred_env_hdr {
    struct cred_env_commonhdr common;
    union {
        cred_env_v1_hdr v1;
        cred_env_v2_hdr v2;
        /* Future: cred_env_v3_hdr v3; */
    };
} __attribute__((packed));

/* 4. In-memory parsed envelope representations */
typedef struct env_data_v1 {
    uint16_t rsa_ct_len;
    size_t overhead;
    size_t plaintext_len;
    const uint8_t *rsa_ct;
    const uint8_t *iv;
    const uint8_t *tag;
    const uint8_t *ciphertext;
} env_data_v1;

typedef env_data_v1 env_data_v2;

struct env_data {
    uint64_t version;
    size_t plaintext_len;
    union {
        env_data_v1 v1;
        env_data_v2 v2;
        /* Future: env_data_v3 v3; */
    };
};

typedef int (*decrypt_envelope_fn)(const uint8_t *enc_data, size_t enc_len,
                                   const char *rel_path, mode_t mode,
                                   struct decrypted_node *out);

typedef int (*encrypt_envelope_fn)(EVP_PKEY *pkey, const char *rel_path, mode_t mode,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t **out_buf, size_t *out_len);

typedef ssize_t (*inspect_envelope_fn)(const struct cred_env_hdr *hdr, size_t hdr_len,
                                       off_t raw_size, size_t max_size,
                                       struct env_data *out);

extern const decrypt_envelope_fn envelope_decryptors[_CRED_ENV_VERSION_MAX];
extern const encrypt_envelope_fn envelope_encryptors[_CRED_ENV_VERSION_MAX];
extern const inspect_envelope_fn envelope_inspectors[_CRED_ENV_VERSION_MAX];

/* Common inspection interfaces */
ssize_t envelope_inspect_header_version(const struct cred_env_hdr *hdr, size_t hdr_len,
                                        off_t raw_size, size_t max_size,
                                        uint64_t min_version,
                                        struct env_data *out);

ssize_t envelope_inspect_file_version(int fd, off_t raw_size, size_t max_size,
                                      uint64_t min_version,
                                      struct env_data *out);

ssize_t envelope_inspect_header(const struct cred_env_hdr *hdr, size_t hdr_len,
                                off_t raw_size, size_t max_size);

ssize_t envelope_inspect_file(int fd, off_t raw_size, size_t max_size);

/* Common path validation helper: ensures non-empty, no leading slashes, no '..' traversal */
int validate_relative_path(const char *rel_path, const char **clean_path_out);

/* Mode parser helper */
int parse_octal_mode(const char *mode_str, mode_t *mode_out);

/* Shared low-level AES-256-GCM decryptor */
int do_aes_decrypt(const uint8_t *iv,
                   const uint8_t *tag,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   const struct decrypted_node *aes_key,
                   struct decrypted_node *out);

/* Top-level envelope decryption dispatch */
int decrypt_envelope(const uint8_t *enc_data, size_t enc_len,
                     const char *rel_path, mode_t mode,
                     struct decrypted_node *out);

int decrypt_envelope_version(const uint8_t *enc_data, size_t enc_len,
                             const char *rel_path, mode_t mode,
                             struct decrypted_node *out,
                             uint64_t *version_out);

int decrypt_credential(int fd, const char *rel_path, struct decrypted_node *out);

/* Version 1 Envelope Handlers */
ssize_t inspect_envelope_v1_layout(const struct cred_env_hdr *hdr, size_t hdr_len,
                                   off_t raw_size, size_t max_size,
                                   struct env_data *out);
ssize_t inspect_envelope_v1(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out);
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
ssize_t inspect_envelope_v2(const struct cred_env_hdr *hdr, size_t hdr_len,
                            off_t raw_size, size_t max_size,
                            struct env_data *out);
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
