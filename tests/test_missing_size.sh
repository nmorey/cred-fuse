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
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/missing.enc" "${WORKDIR}/valid.txt" -T "swtpm"
rm -f "${WORKDIR}/valid.txt"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing Missing user.size (readdir)..."
if ls "${WORKDIR}/credentials" | grep -q missing.enc; then
    echo "ERROR: File without user.size appeared in readdir (ls)"
    exit 1
fi
echo "TEST: Missing user.size (readdir): Success"

echo "Testing Missing user.size (getattr)..."
if [ -e "${WORKDIR}/credentials/missing.enc" ]; then
    echo "ERROR: File without user.size is accessible via getattr (stat)"
    exit 1
fi
echo "TEST: Missing user.size (getattr): Success"

echo "Testing Missing user.size (read)..."
if cat "${WORKDIR}/credentials/missing.enc" 2>/dev/null; then
    echo "ERROR: File without user.size is readable"
    exit 1
fi
echo "TEST: Missing user.size (read): Success"
