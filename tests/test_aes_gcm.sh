#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create AES-256-GCM test vectors
HOSTNAME_RAW=$(hostname)
HOSTNAME="${HOSTNAME_RAW%%.*}"
python3 -c "
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = os.urandom(32)
with open('${WORKDIR}/raw_host.key', 'wb') as f:
    f.write(key)
plaintext = b'aes-gcm-secret-value'
aesgcm = AESGCM(key)
iv = os.urandom(12)
encrypted = aesgcm.encrypt(iv, plaintext, None)
tag = encrypted[-16:]
ciphertext = encrypted[:-16]
with open('${WORKDIR}/source/gcm_test.enc', 'wb') as f:
    f.write(b'Salted__')
    f.write(iv)
    f.write(tag)
    f.write(ciphertext)
tampered_ciphertext = bytearray(ciphertext)
if len(tampered_ciphertext) > 0:
    tampered_ciphertext[0] ^= 1
with open('${WORKDIR}/source/gcm_tampered.enc', 'wb') as f:
    f.write(b'Salted__')
    f.write(iv)
    f.write(tag)
    f.write(bytes(tampered_ciphertext))
"
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/${HOSTNAME}.key" "${WORKDIR}/raw_host.key" -T "swtpm"
rm -f "${WORKDIR}/raw_host.key"
setfattr -n user.size -v 14 "${WORKDIR}/source/gcm_test.enc" # 20 bytes in hex is 14
setfattr -n user.size -v 14 "${WORKDIR}/source/gcm_tampered.enc"
chmod 644 "${WORKDIR}/source/gcm_test.enc" "${WORKDIR}/source/gcm_tampered.enc"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing AES-256-GCM valid decryption..."
if [ "$(cat "${WORKDIR}/credentials/gcm_test.enc")" != "aes-gcm-secret-value" ]; then
    echo "ERROR: AES-256-GCM file decryption mismatched"
    exit 1
fi
echo "TEST: AES-256-GCM valid decryption: Success"

echo "Testing AES-256-GCM integrity failure handling..."
if cat "${WORKDIR}/credentials/gcm_tampered.enc" 2>/dev/null; then
    echo "ERROR: Tampered AES-256-GCM file was successfully decrypted (should have failed)"
    exit 1
fi
echo "TEST: AES-256-GCM integrity failure handling: Success"
