#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create a non-CRED_ENV file (e.g., raw data without CRED_ENV header)
head -c 256 /dev/urandom > "${WORKDIR}/source/missing.enc"
chmod 644 "${WORKDIR}/source/missing.enc"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing Missing CRED_ENV header (readdir)..."
if ls "${WORKDIR}/credentials" | grep -q missing.enc; then
    echo "ERROR: File without CRED_ENV header appeared in readdir (ls)"
    exit 1
fi
echo "TEST: Missing CRED_ENV header (readdir): Success"

echo "Testing Missing CRED_ENV header (getattr)..."
if [ -e "${WORKDIR}/credentials/missing.enc" ]; then
    echo "ERROR: File without CRED_ENV header is accessible via getattr (stat)"
    exit 1
fi
echo "TEST: Missing CRED_ENV header (getattr): Success"

echo "Testing Missing CRED_ENV header (read)..."
if cat "${WORKDIR}/credentials/missing.enc" 2>/dev/null; then
    echo "ERROR: File without CRED_ENV header is readable"
    exit 1
fi
echo "TEST: Missing CRED_ENV header (read): Success"
