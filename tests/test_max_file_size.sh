#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create 12-byte and 200-byte test vectors
echo -n "valid-secret" > "${WORKDIR}/small.txt"
rsa_encrypt_cred "${WORKDIR}/small.txt" "${WORKDIR}/source/small.enc" 0644
rm -f "${WORKDIR}/small.txt"

head -c 200 /dev/urandom | base64 | head -c 200 > "${WORKDIR}/too_big.txt"
rsa_encrypt_cred "${WORKDIR}/too_big.txt" "${WORKDIR}/source/too_big.enc" 0644
rm -f "${WORKDIR}/too_big.txt"

# Start FUSE mount with custom max_file_size=100 (plaintext limit)
start_fuse "${FUSE_EXE}" "max_open_files=2,max_file_size=100"

echo "Testing max_file_size allows credential <= max_file_size despite envelope overhead..."
if [ "$(cat "${WORKDIR}/credentials/small.enc")" != "valid-secret" ]; then
    echo "ERROR: 12-byte credential failed to read with max_file_size=100"
    exit 1
fi

echo "Testing max_file_size rejects credential > max_file_size..."
if cat "${WORKDIR}/credentials/too_big.enc" 2>/dev/null; then
    echo "ERROR: 200-byte credential was read successfully despite max_file_size=100"
    exit 1
fi
echo "TEST: max_file_size: Success"
