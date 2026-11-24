# cred-fuse

A read-only FUSE filesystem and CLI toolset for decrypting TPM 2.0-bound credentials on demand into locked memory.

## Language

**Credential**:
An authenticated, encrypted secret payload stored on disk and dynamically decrypted into locked RAM on demand.
_Avoid_: Secret, token, key file

**Envelope**:
The authenticated binary container (`CRED_ENV`) encapsulating an encrypted credential alongside its TPM-wrapped ephemeral key, initialization vector, and authentication tag.
_Avoid_: Packet, wrapper, container

**Envelope Header**:
The binary header (`struct cred_env_hdr`) prefixing an envelope, comprising a 16-byte common prefix (`struct cred_env_commonhdr`) and version-specific cryptographic metadata.
_Avoid_: File header, metadata prefix

**Backing Store**:
The underlying regular filesystem directory containing encrypted credential files presented by the FUSE mount.
_Avoid_: Source directory, encrypted store

**Plaintext Size**:
The unencrypted byte length of a credential, computed by subtracting the envelope overhead from the backing store file size.
_Avoid_: Decrypted length, payload size
