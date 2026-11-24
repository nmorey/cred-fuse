#ifndef CRED_FUSE_TPM_H
#define CRED_FUSE_TPM_H

#include <stddef.h>
#include <stdint.h>
#include "secure_mem.h"

/*
 * Initialize the TPM subsystem: validate TCTI, connect, pin the public key and object Name.
 * If pubkey_path is non-NULL, verifies against the pinned public key on disk.
 * Returns 0 on success, or negative errno on failure.
 */
int tpm_init(const char *tcti, uint32_t handle, const char *pubkey_path);

/*
 * Checks if the TPM is in dictionary attack lockout mode and verifies the key Name.
 * Returns 0 on success, or negative errno on failure (e.g. -EKEYREJECTED if locked out).
 */
int tpm_check_health(void);

/*
 * Unwraps an RSA-OAEP encrypted secret inside the hardware TPM using the pinned persistent key.
 * Parameter encryption dynamically negotiates AES-256-CFB with AES-128-CFB fallback.
 * Decrypted output is placed in a locked memory buffer in *out.
 * Returns 0 on success, or negative errno on failure.
 */
int tpm_unwrap(const uint8_t *in_data, size_t in_len,
               const uint8_t oaep_label[33],
               struct decrypted_node *out);

/*
 * Validates a TCTI configuration string against allowed schemes and paths.
 * Returns 1 if valid, 0 if invalid.
 */
int validate_tcti(const char *tcti);

/*
 * Cleanup any cached TPM state, locks, or sessions.
 */
void tpm_cleanup(void);

#endif /* CRED_FUSE_TPM_H */
