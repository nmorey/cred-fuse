#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create test vectors
echo -n "valid-secret" > "${WORKDIR}/valid.txt"

# perms.enc: 400
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/perms.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/perms.enc"
chmod 400 "${WORKDIR}/source/perms.enc"

# valid.enc: 644
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/valid.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc"
chmod 644 "${WORKDIR}/source/valid.enc"

# write_perms.enc: 777
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/write_perms.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/write_perms.enc"
chmod 777 "${WORKDIR}/source/write_perms.enc"

rm -f "${WORKDIR}/valid.txt"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing Permission propagation..."
PERM=$(stat -c %a "${WORKDIR}/credentials/perms.enc")
if [ "$PERM" != "400" ]; then
    echo "ERROR: Permission propagation failed. Expected 400, got $PERM"
    exit 1
fi
echo "TEST: Permission: Success"

echo "Testing Write permissions stripped..."
PERM=$(stat -c %a "${WORKDIR}/credentials/valid.enc")
if [ "$PERM" != "444" ]; then
    echo "ERROR: Write permissions not stripped. Expected 444, got $PERM"
    exit 1
fi
echo "TEST: Write permissions stripped: Success"

echo "Testing All write permissions stripped (777 becomes 555)..."
PERM=$(stat -c %a "${WORKDIR}/credentials/write_perms.enc")
if [ "$PERM" != "555" ]; then
    echo "ERROR: Write permissions not completely stripped from 777. Expected 555, got $PERM"
    exit 1
fi
echo "TEST: All write permissions stripped: Success"
