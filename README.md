# cred-fuse

`cred-fuse` is a specialized FUSE driver designed to dynamically decouple decrypted credentials from their underlying encrypted templates utilizing hardware TPM schemas natively.

It interacts directly with the TPM NVRAM handles without touching external CLI utilities (`tpm2_rsadecrypt` or `openssl`) ensuring a very robust, secure, and performant secret layer that safely runs on Linux systems mapping traditional `fstab` loops to applications.

## Key Features
- **In-Memory Decryption Targets**: Payloads are decrypted entirely into securely managed memory buffers (`mlock`) utilizing `tss2_esys` and `OpenSSL 3.x` block allocations without risking swap-file leaks.
- **Node Hiding Isolation**: The driver asserts FUSE visibility over credentials explicitly. Nodes missing a correct pre-computed `user.size` hexadecimal extended attribute are inherently inaccessible via `-ENOENT`.
- **Inherited Posix Mapping**: Relies directly on Kernel VFS ACL behaviors mapping underlying UID/GID permissions identically so native least-privilege constraints operate natively.

## Installation & Packaging

```bash
mkdir build && cd build
cmake ..
make
```

## Configuration (Mounting)

`cred-fuse` requires the source directory and mount point as positional arguments, and leverages parameters directly inside its mount declaration:
- `<source_dir>`: The first positional argument, mapping into the target encrypted secrets.
- `<mount_point>`: The second positional argument, where the decrypted secrets will be accessible.
- `-o tpm_handle`: The persistent configuration slot housing your TPM decryption key (e.g., `0x81010002`).
- `-o tcti`: (Optional) The TCTI context string to use for connecting to the TPM (e.g., `swtpm`, `device:/dev/tpmrm0`). Defaults to the standard TSS2 connection logic if omitted.
- `-o max_open_files`: (Optional) Maximum number of credentials that can be simultaneously opened via FUSE (Default: `1024`). Prevents memory exhaustion attacks via excessive allocations.
- `-o max_file_size`: (Optional) Maximum size in bytes a single encrypted payload can be on disk (Default: `65536` bytes / 64KB). Protects against out-of-memory allocations.

Example usage manually:
```bash
./mount.cred-fuse /etc/credstore.encrypted /credentials -o tpm_handle=0x81010002,max_open_files=500,max_file_size=32768
```

Example inside `/etc/fstab`:
```
cred-fuse#/etc/credstore.encrypted /credentials fuse rw,allow_other,default_permissions,tpm_handle=0x81010002,max_open_files=500 0 0
```

## Testing

A standalone test suite (`test_swtpm.sh`) exercises logic against virtualized bounds using Unix Sockets via `swtpm` verifying `getattr` leaks, FUSE node behaviors, and Valgrind (`USE_VALGRIND=1`). CTest targets are natively generated via `make test`.
