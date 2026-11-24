# Security Audit Findings & Vulnerabilities: cred-fuse

**Date:** 2026-11-24  
**Audit Scope:** Full repository review (`mount.cred-fuse`, `cred-encrypt`, `cred-decrypt`, `src/`)  
**Auditor:** Principal Security Engineer & Low-Level Systems Security Auditor  

---

## Executive Summary

An adversarial source code security review was performed across the `cred-fuse` codebase, evaluating Linux kernel interfaces, FUSE filesystem operations, TPM 2.0 communication channels (`libtss2`), cryptographic envelope handling (`CRED_ENV`), privilege boundaries, and process lifecycle management.

A total of **5 security vulnerabilities and design weaknesses** are tracked for remediation:
- **Medium Severity:** 3
- **Low Severity:** 1
- **Informational:** 1

*(Note: The foreground health check re-exec environment variable `_CREDFUSE_LOCKOUT_CHECKED` was evaluated and documented as by-design in `docs/adr/0003-foreground-tpm-health-check-and-reexec-design.md`).*

---

## Detailed Findings

### 1. TOCTOU File Clobbering in `cred-encrypt` Atomic Output Creation
- **Severity:** Medium
- **Location:** `src/cred_encrypt.c`, lines 228–274
- **Vulnerability Mechanism:**  
  `cred-encrypt` implements a security policy refusing to overwrite existing files (`stat(out_path, &check_st) == 0`). To achieve atomic creation, it writes to a temporary file `%s.tmp.<pid>` and calls `rename(tmp_out_path, out_path)`. Under POSIX and Linux semantics, standard `rename(2)` silently and atomically replaces the destination file if it exists.
- **Threat Scenario:**  
  There is a Time-of-Check to Time-of-Use (TOCTOU) race window between `stat(out_path)` and `rename(tmp_out_path, out_path)`. If an attacker or concurrent process creates a target file (or symlink) at `out_path` after `stat()` but before `rename()`, `cred-encrypt` will clobber the target file without reporting an error.
- **Concrete Remediation:**  
  Use `renameat2` with `RENAME_NOREPLACE` on Linux to ensure atomic creation fails if the destination was created during the race window.

---

### 2. Plaintext Secret Retention on Disk on `cred-decrypt` Write Failure
- **Severity:** Medium
- **Location:** `src/cred_decrypt.c`, lines 233–259
- **Vulnerability Mechanism:**  
  When writing decrypted plaintext to an output file (`-o <out_path>`), `cred-decrypt` creates the file with `open(out_path, O_WRONLY | O_CREAT | O_EXCL, 0600)` and writes the buffer using `write_all_fd`. If `write_all_fd` fails midway (e.g., due to ENOSPC, disk quota, or I/O error), execution jumps to `cleanup:`, which closes `out_fd` without unlinking `out_path`.
- **Threat Scenario:**  
  When a write fails, unencrypted partial credentials remain permanently on disk with permissions 0600. Subsequent `cred-decrypt` invocations will fail with `EEXIST` due to `O_EXCL`, leaving sensitive plaintext fragments exposed on the filesystem in an error state.
- **Concrete Remediation:**  
  Unlink `out_path` on write failure or use a temporary file with atomic rename (matching `cred-encrypt`).

---

### 3. Data Race on `pinned_key.session_aes_bits` in Multi-Threaded FUSE Daemon
- **Severity:** Medium
- **Location:** `src/tpm_esys.c`, lines 404, 460, 463
- **Vulnerability Mechanism:**  
  In `tpm_unwrap`, `pinned_key.session_aes_bits` is read at line 404 without acquiring `pinned_key.lock`. When negotiating dynamic AES-256 vs. AES-128 CFB session encryption, worker threads update `pinned_key.session_aes_bits` on lines 460 and 463 without holding `pinned_key.lock`.
- **Threat Scenario:**  
  Under concurrent file opens in a multi-threaded FUSE session (`fuse_session_loop_mt` with up to 10 threads), concurrent unsynchronized reads and writes to `pinned_key.session_aes_bits` cause data race conditions. Threads may read torn values or simultaneously initiate conflicting session negotiations, leading to transient TPM transport session failures (`TPM2_RC_VALUE 0x4c4`).
- **Concrete Remediation:**  
  Protect access to `session_aes_bits` using `pinned_key.lock` or use C11 atomic operations.

---

### 4. Inode Identity Overwrite Allows TOCTOU File Swap Laundering
- **Severity:** Low
- **Location:** `src/main.c`, lines 238 & 558; `src/inode.c`, lines 354–365
- **Vulnerability Mechanism:**  
  `set_inode_identity(ino, dev, backing_ino)` is invoked on every `lookup` and `readdir`. If an inode is already present in the active table, `set_inode_identity` unconditionally overwrites the previously recorded `(dev, backing_ino)` pair without checking if `backing_ino` was already set.
- **Threat Scenario:**  
  If a file in the backing store is replaced while an inode remains active in memory, a subsequent `lookup` request on the same path overwrites the recorded backing identity on the existing inode with the new file's identity. Any subsequent `open()` on that inode compares against the newly overwritten identity, defeating the TOCTOU file swap protection established in commit `d80266e4d43b`.
- **Concrete Remediation:**  
  In `set_inode_identity`, verify whether `backing_ino` is already set. If it is set and does not match the new identity, reject the update or mark the inode entry as stale.

---

### 5. Missing Memory Cleansing of Pinned TPM Modulus on Cleanup
- **Severity:** Informational / Defense-in-Depth
- **Location:** `src/tpm_esys.c`, lines 538–548
- **Vulnerability Mechanism:**  
  In `tpm_cleanup()`, `pinned_key.modulus_len` is reset to 0, but the modulus buffer (`pinned_key.modulus`) is not zeroized. While the RSA public modulus is not a secret, leaving key material in memory segments after cleanup violates defense-in-depth zeroization standards.
- **Concrete Remediation:**  
  Zeroize `pinned_key.modulus` using `OPENSSL_cleanse`.
