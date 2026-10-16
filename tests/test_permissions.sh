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
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/perms.enc" 0400

# valid.enc: 644
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/valid.enc" 0644

# write_perms.enc: 777
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/write_perms.enc" 0777

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
