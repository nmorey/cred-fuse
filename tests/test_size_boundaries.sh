#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

echo -n "valid-secret" > "${WORKDIR}/valid.txt"

# Zero size
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/zero.enc" 0644
setfattr -n user.size -v 0 "${WORKDIR}/source/zero.enc"

# Too short
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/short.enc" 0644
setfattr -n user.size -v 2 "${WORKDIR}/source/short.enc"

# Too long
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/long.enc" 0644
setfattr -n user.size -v ff "${WORKDIR}/source/long.enc"

# Garbage size
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/garbage.enc" 0644
setfattr -n user.size -v random_string "${WORKDIR}/source/garbage.enc"

rm -f "${WORKDIR}/valid.txt"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing user.size (zero)..."
if cat "${WORKDIR}/credentials/zero.enc" 2>/dev/null; then
    echo "ERROR: Zero size mismatch did not fail open"
    exit 1
fi
echo "TEST: user.size (zero): Success"

echo "Testing user.size (shorter)..."
if cat "${WORKDIR}/credentials/short.enc" 2>/dev/null; then
    echo "ERROR: Short boundary mismatch did not fail open"
    exit 1
fi
echo "TEST: user.size (shorter): Success"

echo "Testing user.size (longer)..."
if cat "${WORKDIR}/credentials/long.enc" 2>/dev/null; then
    echo "ERROR: Long boundary mismatch did not fail open"
    exit 1
fi
echo "TEST: user.size (longer): Success"

echo "Testing user.size (garbage)..."
if [ "$(cat "${WORKDIR}/credentials/garbage.enc")" != "" ]; then
    echo "ERROR: Garbage boundary mismatch"
    exit 1
fi
echo "TEST: user.size (garbage): Success"
