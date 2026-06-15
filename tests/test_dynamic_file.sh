#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Start standard FUSE mount (empty initially)
start_fuse "${FUSE_EXE}"

echo "Testing dynamically added file..."
echo -n "late-secret" > "${WORKDIR}/late.txt"
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/late.enc" "${WORKDIR}/late.txt" -T "swtpm"
setfattr -n user.size -v b "${WORKDIR}/source/late.enc" # 'b' is 11 bytes
rm -f "${WORKDIR}/late.txt"

if [ "$(cat "${WORKDIR}/credentials/late.enc")" != "late-secret" ]; then
    echo "ERROR: Late file decryption mismatched"
    exit 1
fi
echo "TEST: dynamic file: Success"
