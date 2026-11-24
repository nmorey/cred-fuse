# Security Audit Findings & Vulnerabilities: cred-fuse

**Date:** 2026-11-24  
**Audit Scope:** Full repository review (`mount.cred-fuse`, `cred-encrypt`, `cred-decrypt`, `src/`)  
**Auditor:** Principal Security Engineer & Low-Level Systems Security Auditor  

---

## Executive Summary

An adversarial source code security review was performed across the `cred-fuse` codebase, evaluating Linux kernel interfaces, FUSE filesystem operations, TPM 2.0 communication channels (`libtss2`), cryptographic envelope handling (`CRED_ENV`), privilege boundaries, and process lifecycle management.

A total of **2 security vulnerabilities and design weaknesses** are tracked for remediation:
- **Low Severity:** 1
- **Informational:** 1

*(Note: The foreground health check re-exec environment variable `_CREDFUSE_LOCKOUT_CHECKED` was evaluated and documented as by-design in `docs/adr/0003-foreground-tpm-health-check-and-reexec-design.md`).*

---

## Detailed Findings

### 1. Inode Identity Overwrite Allows TOCTOU File Swap Laundering
- **Severity:** Low
- **Location:** `src/main.c`, lines 238 & 558; `src/inode.c`, lines 354–365
- **Vulnerability Mechanism:**  
  `set_inode_identity(ino, dev, backing_ino)` is invoked on every `lookup` and `readdir`. If an inode is already present in the active table, `set_inode_identity` unconditionally overwrites the previously recorded `(dev, backing_ino)` pair without checking if `backing_ino` was already set.
- **Threat Scenario:**  
  If a file in the backing store is replaced while an inode remains active in memory, a subsequent `lookup` request on the same path overwrites the recorded backing identity on the existing inode with the new file's identity. Any subsequent `open()` on that inode compares against the newly overwritten identity, defeating the TOCTOU file swap protection established in commit `d80266e4d43b`.
- **Concrete Remediation:**  
  In `set_inode_identity`, verify whether `backing_ino` is already set. If it is set and does not match the new identity, reject the update or mark the inode entry as stale.

---

### 2. Missing Memory Cleansing of Pinned TPM Modulus on Cleanup
- **Severity:** Informational / Defense-in-Depth
- **Location:** `src/tpm_esys.c`, lines 538–548
- **Vulnerability Mechanism:**  
  In `tpm_cleanup()`, `pinned_key.modulus_len` is reset to 0, but the modulus buffer (`pinned_key.modulus`) is not zeroized. While the RSA public modulus is not a secret, leaving key material in memory segments after cleanup violates defense-in-depth zeroization standards.
- **Concrete Remediation:**  
  Zeroize `pinned_key.modulus` using `OPENSSL_cleanse`.
