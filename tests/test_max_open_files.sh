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

# Create valid.enc
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/valid.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc"
chmod 644 "${WORKDIR}/source/valid.enc"

# Create perms.enc
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/perms.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/perms.enc"
chmod 400 "${WORKDIR}/source/perms.enc"

# Create late.enc
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/late.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/late.enc"
chmod 644 "${WORKDIR}/source/late.enc"

rm -f "${WORKDIR}/valid.txt"

# Start FUSE mount with custom max_open_files option
start_fuse "${FUSE_EXE}" "max_open_files=2,max_file_size=1000"

echo "Testing max_open_files limit..."
exec 3< "${WORKDIR}/credentials/valid.enc"
exec 4< "${WORKDIR}/credentials/perms.enc"

if cat "${WORKDIR}/credentials/late.enc" 2>/dev/null; then
    echo "ERROR: max_open_files limit failed, third file was opened"
    exec 3<&-
    exec 4<&-
    exit 1
fi
echo "TEST: max_open_files: Success"

exec 3<&-
exec 4<&-

if ! cat "${WORKDIR}/credentials/late.enc" >/dev/null; then
    echo "ERROR: Failed to open file after FDs were closed"
    exit 1
fi
echo "TEST: max_open_files (after closed): Success"
