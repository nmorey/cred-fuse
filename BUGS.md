# Security Audit Findings & Vulnerabilities: cred-fuse

**Date:** 2026-11-24  
**Audit Scope:** Full repository review (`mount.cred-fuse`, `cred-encrypt`, `cred-decrypt`, `src/`)  
**Auditor:** Principal Security Engineer & Low-Level Systems Security Auditor  
**Status:** All findings resolved.

---

## Executive Summary

An adversarial source code security review was performed across the `cred-fuse` codebase, evaluating Linux kernel interfaces, FUSE filesystem operations, TPM 2.0 communication channels (`libtss2`), cryptographic envelope handling (`CRED_ENV`), privilege boundaries, and process lifecycle management.

All identified vulnerabilities, race conditions, and hygiene findings have been remediated and verified:
- **TOCTOU in `cred-encrypt` atomic creation**: Resolved using `renameat2` with `RENAME_NOREPLACE`.
- **Plaintext secret retention on `cred-decrypt` failure**: Resolved by unlinking partial output files and zeroizing ciphertext buffers.
- **Data race on `pinned_key.session_aes_bits`**: Resolved using C11 atomic operations (`__atomic_load_n` / `__atomic_store_n`).
- **Memory cleansing of pinned TPM key on cleanup**: Resolved using `OPENSSL_cleanse`.

Architectural decisions evaluated and confirmed as by-design:
- *Foreground health check re-exec environment variable `_CREDFUSE_LOCKOUT_CHECKED` documented in `docs/adr/0003-foreground-tpm-health-check-and-reexec-design.md`.*
- *Backing store inode identity updates on re-lookup documented in `docs/adr/0004-inode-identity-binding-and-administrative-file-rotation.md`.*
