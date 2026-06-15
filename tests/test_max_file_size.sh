#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create test vector
echo -n "valid-secret" > "${WORKDIR}/valid.txt"
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/valid.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc" # 'c' is 12 bytes
chmod 644 "${WORKDIR}/source/valid.enc"
rm -f "${WORKDIR}/valid.txt"

# Start FUSE mount with custom max_file_size option
start_fuse "${FUSE_EXE}" "max_open_files=2,max_file_size=100"

echo "Testing max_file_size limit..."
if cat "${WORKDIR}/credentials/valid.enc" 2>/dev/null; then
    echo "ERROR: File size limit failed, file was read successfully (max_file_size=100 < 256)"
    exit 1
fi
echo "TEST: max_file_size: Success"
