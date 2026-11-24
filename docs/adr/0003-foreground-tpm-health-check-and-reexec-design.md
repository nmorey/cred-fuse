# 3. Foreground TPM Health Check and Re-Exec Design

Date: 2026-11-24

## Context

`mount.cred-fuse` performs an early TPM health and lockout check (`tpm_check_health()`) in the foreground before mounting so that errors (such as dictionary-attack lockout or invalid persistent handles) fail fast with an informative error message on standard error, rather than failing silently after daemonizing.

However, when using the `tabrmd` TCTI backend, querying the TPM initializes GLib/GDBus worker threads and D-Bus IPC sockets. These background threads and socket file descriptors do not survive `fuse_daemonize()` (`fork()`), resulting in broken D-Bus connection state and 25-second timeouts in the background daemon.

To ensure a clean process memory space and reset all D-Bus connections before `fork()`, the binary re-execs itself via `execv("/proc/self/exe", argv)` upon a successful foreground check, using an environment variable `_CREDFUSE_LOCKOUT_CHECKED=1` as an execution phase discriminator.

## Decision

We deliberately retain the unauthenticated environment variable `_CREDFUSE_LOCKOUT_CHECKED` rather than introducing complex IPC mechanisms (e.g. inherited pipes or cryptographic tokens) across `execv`:

1. **Privilege Boundary**: `mount.cred-fuse` requires root privileges (`geteuid() == 0`). Any caller capable of passing environment variables to `mount.cred-fuse` already possesses full root access.
2. **Failure Safety**: If a caller intentionally pre-sets `_CREDFUSE_LOCKOUT_CHECKED=1`, the foreground check is skipped, but no security boundary is bypassed. The TPM hardware continues to enforce lockout, authorization, and cryptographic object Name checks on every decryption attempt in the worker daemon. If the TPM is locked out, decryptions will still fail with `-EKEYREJECTED`.
3. **Operational Scope**: The check is an operational convenience for fast foreground reporting, not a security gate.

## Consequences

- The simple environment variable discriminator is preserved without adding unnecessary IPC complexity.
- Future security audits and architectural reviews must not flag `_CREDFUSE_LOCKOUT_CHECKED` as an exploitable security bypass.
