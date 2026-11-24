# Security Audit Findings & Vulnerabilities: cred-fuse

**Date:** 2026-11-24  
**Audit Scope:** Full repository review (`mount.cred-fuse`, `cred-encrypt`, `cred-decrypt`, `src/`)  
**Auditor:** Principal Security Engineer & Low-Level Systems Security Auditor  

---

## Executive Summary

An adversarial source code security review was performed across the `cred-fuse` codebase, evaluating Linux kernel interfaces, FUSE filesystem operations, TPM 2.0 communication channels (`libtss2`), cryptographic envelope handling (`CRED_ENV`), privilege boundaries, and process lifecycle management.

A total of **1 informational finding** is tracked for defense-in-depth zeroization hygiene:
- **Informational:** 1

*(Notes on evaluated items rejected as by-design:)*
- *The foreground health check re-exec environment variable `_CREDFUSE_LOCKOUT_CHECKED` is documented in `docs/adr/0003-foreground-tpm-health-check-and-reexec-design.md`.*
- *Updating `set_inode_identity` on `lookup`/`readdir` is intentional: the backing store directory hierarchy is strictly enforced to be root-owned with no group/world write permissions (`open_and_validate_path`), so non-root users cannot replace files. Updating identity on re-lookup allows legitimate administrative file rotations and credential updates.*

---

## Detailed Findings

### 1. Missing Memory Cleansing of Pinned TPM Modulus on Cleanup
- **Severity:** Informational / Defense-in-Depth
- **Location:** `src/tpm_esys.c`, lines 538–548
- **Vulnerability Mechanism:**  
  In `tpm_cleanup()`, `pinned_key.modulus_len` is reset to 0, but the modulus buffer (`pinned_key.modulus`) is not zeroized. While the RSA public modulus is not a secret, leaving key material in memory segments after cleanup violates defense-in-depth zeroization standards.
- **Concrete Remediation:**  
  Zeroize `pinned_key.modulus` using `OPENSSL_cleanse`.
