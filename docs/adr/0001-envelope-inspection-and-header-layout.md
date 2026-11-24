# 1. Envelope Inspection and Header Layout Architecture

Date: 2026-11-24

## Context

`cred-fuse` dynamically derives plaintext file sizes from encrypted envelopes on disk. Previously, filesystem path traversal (`path.c`) directly performed `pread` on raw binary headers and calculated sizes using numeric offsets (`+ 18`, `+ 46`), causing format knowledge and version policies to leak across the filesystem seam. Furthermore, `decrypt_envelope_v1` and `decrypt_envelope_v2` duplicated magic, version, and buffer bounds checks, and envelope layouts relied on manual byte arithmetic.

## Decision

1. **Separation of Common Prefix and Version Layouts**:
   - `struct cred_env_commonhdr` defines the universal 16-byte fixed prefix (`magic[8]` + `version[8]`).
   - Version-specific header structs (`cred_env_v1_hdr`, `cred_env_v2_hdr`, etc.) model the metadata layout for that generation.
   - `struct cred_env_hdr` combines them via an anonymous union. `sizeof(struct cred_env_hdr)` is automatically large enough to accommodate the largest supported header variant.
   - In-memory representations use `struct env_data` containing typed pointers to envelope sections (`rsa_ct`, `iv`, `tag`, `ciphertext`).

2. **Inspector Dispatch Table (`envelope_inspectors[]`)**:
   - An inspection dispatch table mirrors `envelope_decryptors[]` and `envelope_encryptors[]`.
   - `envelope_inspect_file` reads `sizeof(struct cred_env_hdr)` from disk (only failing early if fewer than 16 bytes can be read) and dispatches to the version inspector.
   - Each version inspector (`inspect_envelope_vX`) verifies magic and its specific version, derives exact plaintext size using `sizeof()` on concrete payload structs (eliminating hardcoded `OVERHEAD` macros), and populates `env_data`.

3. **Decryptors Call Inspector First**:
   - `decrypt_envelope_vX` invokes its respective inspector before unwrapping. Magic, version, length, and bounds validation are eliminated from decryptors, which directly consume typed pointers from `env_data`.

4. **Version Policy**:
   - FUSE mounts strictly require `CRED_ENV_CUR_VERSION`.
   - Inspection accepts a `min_version` parameter (defaulting to 0 / `CRED_ENV_VERSION_1` for CLI migration tools). Maximum supported version is always implicitly bounded by `CRED_ENV_CUR_VERSION`.

## Consequences

- Introducing future envelope formats (e.g. `v3`) requires only adding `cred_env_v3_hdr` to the union, adding an entry to `envelope_inspectors[]` and `envelope_decryptors[]`, and implementing `envelope_v3.c`. Filesystem traversal (`path.c`) and mount dispatching require zero code changes.
- Eliminating fixed overhead defines ensures payload overhead is calculated strictly from the concrete payload structs matching the active cryptographic variant.
