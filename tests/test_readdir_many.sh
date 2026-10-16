#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create 3000 files for readdir test
echo -n "valid-secret" > "${WORKDIR}/valid.txt"
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/valid.enc" 0644
rm -f "${WORKDIR}/valid.txt"

mkdir -p "${WORKDIR}/source/many"
for i in $(seq 1 3000); do
    cp "${WORKDIR}/source/valid.enc" "${WORKDIR}/source/many/file_$i.enc"
done

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing readdir of many files..."
NUM_FILES=$(ls "${WORKDIR}/credentials/many" | wc -l)
if [ "$NUM_FILES" != "3000" ]; then
    echo "ERROR: Readdir failed to list all files, found $NUM_FILES, expected 3000"
    exit 1
fi
echo "TEST: many files: Success"
