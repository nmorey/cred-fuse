# cred-fuse

`cred-fuse` is a read-only FUSE filesystem and CLI toolset (`mount.cred-fuse`, `cred-encrypt`, `cred-decrypt`) designed to dynamically decrypt TPM-bound credentials on demand into locked RAM (`mlock`) without exposing plaintext secrets on disk.

It communicates directly with the TPM 2.0 via `tss2-esys` and performs symmetric authenticated encryption via OpenSSL `EVP_aes_256_gcm`, preserving POSIX DAC ownership and permissions from the encrypted backing store.

## Key Features
- **Unified Hybrid Envelope Encryption (`CRED_ENV` v1)**: Every credential file is encrypted with a fresh per-file random secret wrapped solely with the target host's TPM RSA-2048/4096 public key (`RSA-OAEP-SHA256`), eliminating any shared static symmetric host keys on disk.
- **Cryptographic Metadata Binding (AAD)**: Each credential's envelope header, relative FUSE path (`rel_path`), and POSIX permission bits (`st_mode & 07777`) are bound into the AES-256-GCM Additional Authenticated Data (AAD). Moving/renaming an encrypted file or altering its permissions (`chmod`) causes GCM tag verification to fail with `-EACCES`.
- **Automatic Plaintext Size Derivation**: Because AES-256-GCM is a stream mode with zero padding, `mount.cred-fuse` computes the exact plaintext `st_size` directly from the `CRED_ENV` v1 header on disk without requiring external extended attributes (`xattr`).
- **TPM Key Pinning & Verification**: On startup, `mount.cred-fuse` validates the TPM handle's `TPMA_OBJECT` attributes (`fixedTPM`, `sensitiveDataOrigin`, `decrypt`, and not `restricted`), optionally verifies it against a pinned public key (`-o tpm_pubkey=<path>`), and verifies the TPM object's cryptographic `Name` on every decryption to prevent TPM handle substitution.
- **Locked In-Memory Buffers & Auditd Integration**: Plaintext payloads are held exclusively in `mlock`-protected buffers that are zeroized (`OPENSSL_cleanse`) on release, while `libaudit` watches the backing store and logs credential access and errors.

## Cryptographic Design (`CRED_ENV` v1)

### Binary Envelope Format
All credentials use a single binary layout regardless of size (from 1 byte up to `max_file_size`, default 64 KiB):

| Offset | Size (Bytes) | Field | Description |
| :--- | :--- | :--- | :--- |
| `0` | `8` | `magic` | ASCII `"CRED_ENV"` (`0x43 0x52 0x45 0x44 0x5F 0x45 0x4E 0x56`) |
| `8` | `8` | `version` | `uint64_t` big-endian format version (`1`) |
| `16` | `2` | `rsa_ct_len` | `uint16_t` big-endian RSA ciphertext length (`256` for RSA-2048 or `512` for RSA-4096) |
| `18` | `rsa_ct_len` | `rsa_ciphertext` | `RSA-OAEP-SHA256(TPM_PubKey, pre_key[32])` |
| `18 + rsa_ct_len` | `12` | `iv` | 96-bit random AES-GCM nonce (`RAND_bytes`) |
| `30 + rsa_ct_len` | `16` | `tag` | 128-bit AES-256-GCM authentication tag |
| `46 + rsa_ct_len` | `N` (`>= 1`) | `ciphertext` | AES-256-GCM encrypted payload (same byte length `N` as plaintext) |

Plaintext size calculation:
$$\text{Plaintext Size} = \text{st\_size} - (46 + \text{rsa\_ct\_len})$$

### Encryption (`cred-encrypt`)
Encryption requires only the target host's TPM RSA public key (PEM `SubjectPublicKeyInfo` or TSS2 `TPM2B_PUBLIC` binary format from `tpm2_readpublic`) and can run completely offline without a TPM:
1. Generate a fresh 32-byte random secret `pre_key` and a 12-byte random `iv` via `RAND_bytes()`.
2. Encrypt `pre_key` with the TPM RSA public key using `RSA-OAEP` (`SHA-256` digest and `MGF1-SHA256`).
3. Derive a per-file 256-bit AES key via `HKDF-SHA256`:
   - `IKM`: `pre_key` (32 bytes)
   - `Salt`: `iv` (12 bytes)
   - `Info`: `"CRED-FUSE-SYMKEY-v1\0" || rel_path`
4. Construct the Additional Authenticated Data (AAD):
   $$\text{AAD} = \text{magic}[8] \parallel \text{version\_be64}[8] \parallel \text{rsa\_ct\_len\_be16}[2] \parallel \text{rsa\_ciphertext}[\text{rsa\_ct\_len}] \parallel \text{mode\_be32}[4] \parallel \text{rel\_path}$$
   where `mode_be32` is `htobe32(mode & 07777)` and `rel_path` has leading `/` stripped.
5. Encrypt the plaintext with `AES-256-GCM(aes_key, iv, AAD)` and write the envelope atomically.

### Decryption (`mount.cred-fuse` & `cred-decrypt`)
1. Parse and validate the 18-byte `CRED_ENV` v1 header and verify `ciphertext_len` (`1 <= N <= max_file_size`).
2. Verify the TPM persistent handle's cryptographic `Name` via `Esys_ReadPublic` and unwrap `pre_key` inside the hardware TPM via `Esys_RSA_Decrypt` (`TPM2_ALG_OAEP`, `TPM2_ALG_SHA256`).
3. Derive `aes_key` via `HKDF-SHA256(pre_key, iv, "CRED-FUSE-SYMKEY-v1\0" || rel_path)`.
4. Reconstruct AAD using the on-disk file's `st_mode & 07777` and relative path `rel_path`, and verify + decrypt with `AES-256-GCM`.

## Building & Installation

```bash
mkdir build && cd build
cmake ..
make
```

## CLI Tools Usage

### `cred-encrypt`
Encrypts a credential using a TPM public key (PEM or TSS2 `TPM2B_PUBLIC`), binding it to its target relative path in the FUSE mount and its octal file mode:

```bash
Usage: cred-encrypt -k <pubkey> -p <rel_path> -m <octal_mode> [-i <in_file>] [-o <out_file>]

Required arguments:
  -k, --pubkey <path>     RSA-2048/4096 public key file (PEM or TSS2 TPM2B_PUBLIC)
  -p, --path <rel_path>   Relative path in the mounted FUSE filesystem
  -m, --mode <octal_mode> File permissions in octal (e.g. 0600, 0400, 0640)

Optional arguments:
  -i, --input <path>      Input plaintext file (default: stdin)
  -o, --output <path>     Output encrypted file (default: stdout)
```

Examples:
```bash
# Encrypt a file to a target path in the encrypted store (automatically sets chmod 0400 on -o file)
cred-encrypt -k /etc/credstore/tpm_pub.pem -p service/db_pass.cred -m 0400 \
    -i plain_secret.txt -o /etc/credstore.encrypted/service/db_pass.cred

# Encrypt from stdin to stdout in a pipeline
printf '%s' "super-secret" | cred-encrypt -k host_tpm.pub -p api.token -m 0600 > /etc/credstore.encrypted/api.token
chmod 0600 /etc/credstore.encrypted/api.token
```

### `cred-decrypt`
Decrypts a `CRED_ENV` v1 credential directly using the host's hardware TPM persistent handle:

```bash
Usage: cred-decrypt -c <tpm_handle> -p <rel_path> -m <octal_mode> [-k <tpm_pubkey>] [-T <tcti>] [-i <in_file>] [-o <out_file>]

Required arguments:
  -c, --handle <handle>   Persistent TPM 2.0 handle in hex (0x81000000 - 0x81FFFFFF)
  -p, --path <rel_path>   Relative path in the mounted FUSE filesystem
  -m, --mode <octal_mode> File permissions in octal (e.g. 0600, 0400, 0640)

Optional arguments:
  -k, --pubkey <path>     Pinned TPM RSA public key file (PEM or TSS2 TPM2B_PUBLIC)
  -T, --tcti <tcti>       TCTI configuration string (default: device:/dev/tpmrm0)
  -i, --input <path>      Input encrypted file (default: stdin)
  -o, --output <path>     Output plaintext file (default: stdout)
```

Example:
```bash
cred-decrypt -c 0x81010002 -k /etc/credstore/tpm_pub.pem -p service/db_pass.cred -m 0400 \
    -i /etc/credstore.encrypted/service/db_pass.cred
```

## Mounting (`mount.cred-fuse`)

`mount.cred-fuse` requires `<source_dir>` and `<mount_point>` as positional arguments:
- `<source_dir>`: Directory containing the `CRED_ENV` v1 encrypted files.
- `<mount_point>`: Target directory where decrypted credentials will be exposed.
- `-o ro,default_permissions`: Required mount flags enforcing read-only access and kernel VFS permission checks.
- `-o tpm_handle=<hex>`: Persistent TPM handle housing the RSA decryption key (e.g., `0x81010002`).
- `-o tpm_pubkey=<path>`: (Optional, recommended) Path to expected TPM public key (PEM or `TPM2B_PUBLIC`) to pin at startup.
- `-o tcti=<tcti>`: (Optional) TCTI specification (`device` / `device:/dev/tpmrm0` or `tabrmd`). Defaults to `device:/dev/tpmrm0`.
- `-o max_open_files=<N>`: (Optional) Maximum concurrently open files (Default: `1024`).
- `-o max_file_size=<bytes>`: (Optional) Maximum plaintext credential size in bytes (Default: `65536` / 64 KiB).

Manual mount example:
```bash
mount.cred-fuse /etc/credstore.encrypted /credentials \
    -o ro,default_permissions,allow_other,tpm_handle=0x81010002,tpm_pubkey=/etc/credstore/tpm_pub.pem,max_open_files=500,max_file_size=32768
```

Example `/etc/fstab` entry:
```fstab
cred-fuse#/etc/credstore.encrypted /credentials fuse ro,allow_other,default_permissions,tpm_handle=0x81010002,tpm_pubkey=/etc/credstore/tpm_pub.pem,max_open_files=500 0 0
```

## Testing

The test suite spins up an isolated software TPM (`swtpm`) over a local UNIX socket and exercises `cred-encrypt`, `cred-decrypt`, and `mount.cred-fuse` across 14 test suites:
```bash
ctest --test-dir build --output-on-failure
```
