# 2. TPM Hardware Adapter and Cryptographic Module Isolation

Date: 2026-11-24

## Context

Previously, `src/decryption.c` acted as a monolithic god module conflating TPM 2.0 hardware session management, dictionary attack lockout checking, public key parsing, secure memory management (`mlock`), and symmetric cipher execution. Because of this coupling, offline tools like `cred-encrypt` (which only needs OpenSSL to encrypt with a public key) and unit tests were forced to link all TSS2 hardware libraries (`libtss2-esys`, `libtss2-tctildr`, `libtss2-rc`).

## Decision

1. **Dedicated Hardware TPM Adapter (`src/tpm.h` & `src/tpm_esys.c`)**:
   - Isolate all TSS2 hardware communication behind a clean seam: `tpm_init`, `tpm_check_health`, `tpm_unwrap`, `validate_tcti`, and `tpm_cleanup`.
   - Encapsulate ESYS session parameter encryption, dynamic AES-256/128 negotiation, retry handling (`TPM2_RC_RETRY`), object Name verification, and lockout queries as private static details inside `src/tpm_esys.c`.
   - Only link TSS2 hardware libraries into binaries that actually talk to hardware (`mount.cred-fuse` and `cred-decrypt`).

2. **Dedicated Secure Memory Module (`src/secure_mem.h` & `src/secure_mem.c`)**:
   - Extract `struct decrypted_node`, `malloc_mlock`, `free_munlock`, and `clean_decrypted_node` into a focused secure memory module.

3. **Dedicated Public Key Module (`src/pubkey.h` & `src/pubkey.c`)**:
   - Extract `load_rsa_pubkey_evp` (PEM and TSS2 `TPM2B_PUBLIC` unmarshaling) so public key parsing requires only `OpenSSL::Crypto` and `libtss2-mu`.

4. **Decouple `cred-encrypt`**:
   - Completely remove `libtss2-esys`, `libtss2-tctildr`, and `libtss2-rc` from `cred-encrypt`.

5. **Consolidate Envelope Cryptography (`src/envelope.h` & `src/envelope.c`)**:
   - Move envelope decryption dispatchers (`envelope_decryptors[]`, `decrypt_envelope`), `do_aes_decrypt`, and `parse_octal_mode` into the envelope module.
   - Delete `src/decryption.c` and `src/decryption.h`.

## Consequences

- Hardware TPM dependencies are strictly confined to `src/tpm_esys.c`.
- `cred-encrypt` operates completely offline without linking TPM hardware libraries.
- The god module `decryption.c` is eliminated in favor of single-responsibility, deep modules with clean seams.
