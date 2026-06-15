#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create test vector for this test
echo -n "valid-secret" > "${WORKDIR}/valid.txt"
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/valid.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc" # 'c' is 12 bytes
chmod 644 "${WORKDIR}/source/valid.enc"
rm -f "${WORKDIR}/valid.txt"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing valid file decryption..."
if [ "$(cat "${WORKDIR}/credentials/valid.enc")" != "valid-secret" ]; then
    echo "ERROR: Valid file decryption mismatched"
    exit 1
fi
echo "TEST: Valid file: Success"
