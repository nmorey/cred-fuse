#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create many test vector
echo -n "valid-secret" > "${WORKDIR}/valid.txt"
tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/valid.enc" "${WORKDIR}/valid.txt" -T "swtpm"
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc"
chmod 644 "${WORKDIR}/source/valid.enc"
rm -f "${WORKDIR}/valid.txt"

mkdir -p "${WORKDIR}/source/many"
for i in $(seq 1 3000); do
    cp "${WORKDIR}/source/valid.enc" "${WORKDIR}/source/many/file_$i.enc"
    setfattr -n user.size -v c "${WORKDIR}/source/many/file_$i.enc"
done

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing inode eviction under pressure..."
cp -a "${WORKDIR}/source/many" "${WORKDIR}/source/many2"
cp -a "${WORKDIR}/source/many" "${WORKDIR}/source/many3"

# List many multiple times (should keep refcount at 0, no leaks/increases)
ls "${WORKDIR}/credentials/many" > /dev/null
ls "${WORKDIR}/credentials/many" > /dev/null

# List many2 multiple times (should keep refcount at 0)
ls "${WORKDIR}/credentials/many2" > /dev/null
ls "${WORKDIR}/credentials/many2" > /dev/null

# List many3 (should trigger inode eviction of many and many2 entries, and succeed)
NUM_FILES_3=$(ls "${WORKDIR}/credentials/many3" | wc -l)
if [ "$NUM_FILES_3" != "3000" ]; then
    echo "ERROR: Failed to list many3 under inode pressure, found $NUM_FILES_3, expected 3000"
    exit 1
fi
echo "TEST: inode pressure eviction (first pass): Success"

# List many again (should trigger eviction of many3, and succeed)
NUM_FILES_1=$(ls "${WORKDIR}/credentials/many" | wc -l)
if [ "$NUM_FILES_1" != "3000" ]; then
    echo "ERROR: Failed to list many after eviction, found $NUM_FILES_1, expected 3000"
    exit 1
fi
echo "TEST: inode pressure eviction (second pass): Success"

# Cleanup pressure test directories
rm -rf "${WORKDIR}/source/many2" "${WORKDIR}/source/many3"
