#ifndef CRED_FUSE_PUBKEY_H
#define CRED_FUSE_PUBKEY_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define TPM2_RSA2048_KEY_BYTES 256
#define TPM2_RSA4096_KEY_BYTES 512

/*
 * Load a 2048-bit or 4096-bit RSA public key from a PEM or TSS2 TPM2B_PUBLIC file.
 * If require_secure_perms is non-zero, enforces root/euid ownership and no group/other write bits.
 * Optionally outputs the big-endian modulus bytes.
 * Returns an EVP_PKEY* on success (caller must EVP_PKEY_free), or NULL on error.
 */
EVP_PKEY *load_rsa_pubkey_evp(const char *path, int require_secure_perms,
                              size_t *modulus_len_out, uint8_t modulus_out[TPM2_RSA4096_KEY_BYTES]);

#endif /* CRED_FUSE_PUBKEY_H */
