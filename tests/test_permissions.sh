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

# suid_perms.enc: 4755
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/suid_perms.enc" 04755

# subdir with 2777 permissions
mkdir -p "${WORKDIR}/source/subdir"
chmod 02777 "${WORKDIR}/source/subdir"

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

echo "Testing All write and execute permissions stripped on regular file (777 becomes 444)..."
PERM=$(stat -c %a "${WORKDIR}/credentials/write_perms.enc")
if [ "$PERM" != "444" ]; then
    echo "ERROR: Write/execute permissions not completely stripped from 777. Expected 444, got $PERM"
    exit 1
fi
echo "TEST: All write/exec permissions stripped on file: Success"

echo "Testing SUID and execute permissions stripped on regular file (4755 becomes 444)..."
PERM=$(stat -c %a "${WORKDIR}/credentials/suid_perms.enc")
if [ "$PERM" != "444" ]; then
    echo "ERROR: SUID/execute permissions not stripped from 4755. Expected 444, got $PERM"
    exit 1
fi
echo "TEST: SUID/exec permissions stripped on file: Success"

echo "Testing Write and SGID permissions stripped on directory while preserving traverse (2777 becomes 555)..."
PERM=$(stat -c %a "${WORKDIR}/credentials/subdir")
if [ "$PERM" != "555" ]; then
    echo "ERROR: Directory permissions not masked properly. Expected 555, got $PERM"
    exit 1
fi
echo "TEST: Directory permissions masked: Success"

echo "Testing rejection of POSIX ACLs in getxattr..."
if getfattr -n system.posix_acl_access "${WORKDIR}/credentials/perms.enc" 2>/dev/null; then
    echo "ERROR: POSIX ACL query succeeded, expected rejection (ENODATA)"
    exit 1
fi
echo "TEST: POSIX ACL rejection: Success"
