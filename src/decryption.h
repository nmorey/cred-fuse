#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/evp.h>

#define CRED_ENV_MAGIC "CRED_ENV"
#define CRED_ENV_MAGIC_LEN 8

enum cred_env_version {
    CRED_ENV_VERSION_INVALID = 0,
    CRED_ENV_VERSION_1       = 1,
    CRED_ENV_VERSION_2       = 2,
    _CRED_ENV_VERSION_MAX,
};

#define CRED_ENV_CUR_VERSION CRED_ENV_VERSION_2
#define TPM2_RSA2048_KEY_BYTES 256
#define TPM2_RSA4096_KEY_BYTES 512
#define MAX_ALLOWED_FILE_SIZE 65536

struct cred_fuse_opts {
    char *source_dir;
    size_t source_dir_len;
    int source_dir_fd;
    char *mountpoint;
    char *tpm_handle_str;
    uint32_t tpm_handle;
    char *tpm_pubkey;
    char *tcti;
    int max_open_files;
    int max_file_size;
    int max_threads;
};

struct decrypted_node {
    uint8_t *buf;
    size_t len;
    size_t allocated_size;
    uint16_t uid_slot;
};

extern struct cred_fuse_opts global_opts;
extern int mlockall_active;

void *malloc_mlock(size_t size);
void free_munlock(void *ptr, size_t size);

/*
 * Cleanse, munlock and free the buffer attached to a decrypted_node
 */
void clean_decrypted_node(struct decrypted_node *node);

/*
 * Validate TCTI configuration string against allowed schemes and options.
 * Returns 1 if valid, 0 if invalid.
 */
int validate_tcti(const char *tcti);

/*
 * Parse an octal permission mode string (e.g. "0600", "640") into mode_t (0..07777).
 * Returns 0 on success, < 0 on error.
 */
int parse_octal_mode(const char *mode_str, mode_t *mode_out);

/*
 * Format the canonical AAD string "<rel_path>:<04o mode>" into buf (v1 format).
 * Strips leading slashes and rejects empty paths or ".." traversal components.
 * Returns 0 on success, < 0 on error.
 */
int format_credential_aad(char *buf, size_t buf_sz, const char *rel_path, mode_t mode);

/*
 * Format binary AAD for v2 format:
 * magic[8] || version[8] || rsa_ct_len[2] || ciphertext_len[4] || iv[12] || "<rel_path>:<04o mode>"
 * Returns 0 on success, < 0 on error.
 */
int format_credential_aad_v2(uint8_t *buf, size_t buf_sz, size_t *aad_len_out,
                             uint16_t rsa_ct_len, uint32_t ciphertext_len,
                             const uint8_t iv[12],
                             const char *rel_path, mode_t mode);

/*
 * Compute the 33-byte null-terminated RSA-OAEP label from the canonical AAD string
 * (first 32 lowercase hex characters of SHA-256(aad) plus trailing '\0').
 * Returns 0 on success, < 0 on error.
 */
int compute_oaep_label(const char *aad, uint8_t label_buf[33]);

/*
 * Compute the 33-byte null-terminated RSA-OAEP label from a binary AAD buffer.
 * Returns 0 on success, < 0 on error.
 */
int compute_oaep_label_bin(const uint8_t *aad, size_t aad_len, uint8_t label_buf[33]);

/*
 * Derives a 32-byte AES key from an ephemeral secret using HKDF-SHA256.
 * Returns 0 on success, < 0 on error.
 */
int derive_hkdf_aes_key(const uint8_t *eph_secret, size_t secret_len,
                        const uint8_t *salt, size_t salt_len,
                        const char *info,
                        uint8_t aes_key_out[32]);

/*
 * Load a 2048-bit or 4096-bit RSA public key from a PEM or TSS2 TPM2B_PUBLIC file.
 * If require_secure_perms is non-zero, enforces root/euid ownership and no group/other write bits.
 * Optionally outputs the big-endian modulus bytes.
 * Returns an EVP_PKEY* on success (caller must EVP_PKEY_free), or NULL on error.
 */
EVP_PKEY *load_rsa_pubkey_evp(const char *path, int require_secure_perms,
                              size_t *modulus_len_out, uint8_t modulus_out[TPM2_RSA4096_KEY_BYTES]);

/* Initializes decryption module (page size and optional pinned TPM public key).
 * Returns 0 on success, < 0 on error.
 */
int init_decryption(void);

/* Checks if the TPM is in dictionary attack lockout mode and pins the TPM handle's public key.
 * Returns 0 if not locked out, < 0 on error or if locked out.
 */
int check_tpm_lockout(void);

/*
 * Decrypts an in-memory CRED_ENV envelope bound to (rel_path, mode).
 * Uses envelope_decryptors[CRED_ENV_CUR_VERSION] (strict v2).
 * Returns 0 on success, < 0 on error.
 */
int decrypt_envelope(const uint8_t *enc_data, size_t enc_len,
                     const char *rel_path, mode_t mode,
                     struct decrypted_node *out);

/*
 * Decrypts an in-memory CRED_ENV envelope supporting legacy versions <= CRED_ENV_CUR_VERSION.
 * Stores the detected version in *version_out if non-NULL.
 * Returns 0 on success, < 0 on error.
 */
int decrypt_envelope_version(const uint8_t *enc_data, size_t enc_len,
                             const char *rel_path, mode_t mode,
                             struct decrypted_node *out,
                             uint64_t *version_out);

/*
 * Reads an encrypted file descriptor, extracts its permission bits, and decrypts
 * the CRED_ENV v1 envelope into *out.
 * Returns 0 on success, < 0 on error.
 */
int decrypt_credential(int fd,
		       const char *rel_path,
		       struct decrypted_node *out);

#endif /* DECRYPTION_H */
