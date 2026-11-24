# 4. Inode Identity Binding and Administrative File Rotation

Date: 2026-11-24

## Context

`mount.cred-fuse` binds the backing store's `(st_dev, st_ino)` tuple to in-memory FUSE inode entries during `lookup` and `readdir`, and checks it in `open()` (`check_inode_identity`) to detect file swaps. Questions arose during security review as to whether updating this identity on re-lookup could allow file swap laundering if an inode's backing file changed.

## Decision

We deliberately allow `set_inode_identity` to update `(st_dev, st_ino)` upon re-lookup and `readdir`:

1. **Backing Store Access Control**: All directories in the backing store must be owned by root (`uid == 0`) and strictly non-group/world-writable (`open_and_validate_path`). Unprivileged users cannot create, delete, or swap files in the backing store.
2. **Administrative Rotation**: When an administrator rotates or updates a credential file (e.g., using `cred-encrypt`), the underlying file receives a new inode number. Allowing re-lookup to update the identity ensures that legitimate administrative updates are recognized without requiring a daemon restart.
3. **Open-Time Race Protection**: `check_inode_identity` still prevents file swaps within an active `open()` request, since the open file descriptor's `fstat` identity is verified before decryption.

## Consequences

- Inode identities update naturally when files are rotated by root in the backing store.
- Future security audits must not treat re-lookup identity updates as a TOCTOU vulnerability.
