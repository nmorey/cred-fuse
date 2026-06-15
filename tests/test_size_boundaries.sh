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
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/zero.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v 0 "${WORKDIR}/source/zero.enc"

# Too short
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/short.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v 2 "${WORKDIR}/source/short.enc"

# Too long
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/long.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v ff "${WORKDIR}/source/long.enc"

# Garbage size
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/garbage.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v random_string "${WORKDIR}/source/garbage.enc"

rm -f "${WORKDIR}/valid.txt"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing user.size (zero)..."
if [ "$(cat "${WORKDIR}/credentials/zero.enc")" != "" ]; then
    echo "ERROR: Zero size mismatch"
    exit 1
fi
echo "TEST: user.size (zero): Success"

echo "Testing user.size (shorter)..."
if [ "$(cat "${WORKDIR}/credentials/short.enc" | wc -c)" != "2" ]; then
    echo "ERROR: Short boundary mismatch"
    exit 1
fi
echo "TEST: user.size (shorter): Success"

echo "Testing user.size (longer)..."
if [ "$(cat "${WORKDIR}/credentials/long.enc" | wc -c)" != "12" ]; then
    echo "ERROR: Long boundary exceeded decrypted footprint"
    exit 1
fi
echo "TEST: user.size (longer): Success"

echo "Testing user.size (garbage)..."
if [ "$(cat "${WORKDIR}/credentials/garbage.enc")" != "" ]; then
    echo "ERROR: Garbage boundary mismatch"
    exit 1
fi
echo "TEST: user.size (garbage): Success"
