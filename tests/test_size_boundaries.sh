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
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/valid.enc" 0644
rm -f "${WORKDIR}/valid.txt"

python3 -c "
with open('${WORKDIR}/source/valid.enc', 'rb') as f:
    data = bytearray(f.read())

# 1. Header-only (zero payload bytes: 46 + 256 = 302 bytes)
with open('${WORKDIR}/source/zero.enc', 'wb') as f:
    f.write(data[:302])

# 2. Truncated header (< 18 bytes)
with open('${WORKDIR}/source/short_hdr.enc', 'wb') as f:
    f.write(data[:10])

# 3. Truncated envelope (< 302 bytes)
with open('${WORKDIR}/source/short_env.enc', 'wb') as f:
    f.write(data[:200])

# 4. Invalid rsa_ct_len in header (e.g. 128 instead of 256/512)
bad_len = bytearray(data)
bad_len[16] = 0
bad_len[17] = 128
with open('${WORKDIR}/source/bad_keylen.enc', 'wb') as f:
    f.write(bad_len)
"
chmod 644 "${WORKDIR}/source/zero.enc" "${WORKDIR}/source/short_hdr.enc" "${WORKDIR}/source/short_env.enc" "${WORKDIR}/source/bad_keylen.enc"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing exact st_size derivation from CRED_ENV header..."
STAT_SIZE=$(stat -c %s "${WORKDIR}/credentials/valid.enc")
if [ "$STAT_SIZE" != "12" ]; then
    echo "ERROR: Expected st_size 12 for valid.enc, got $STAT_SIZE"
    exit 1
fi
echo "TEST: exact st_size derivation: Success"

echo "Testing CRED_ENV boundary (zero payload)..."
if [ -e "${WORKDIR}/credentials/zero.enc" ] || cat "${WORKDIR}/credentials/zero.enc" 2>/dev/null; then
    echo "ERROR: Zero-payload envelope did not fail"
    exit 1
fi
echo "TEST: CRED_ENV boundary (zero payload): Success"

echo "Testing CRED_ENV boundary (truncated header)..."
if [ -e "${WORKDIR}/credentials/short_hdr.enc" ] || cat "${WORKDIR}/credentials/short_hdr.enc" 2>/dev/null; then
    echo "ERROR: Truncated header did not fail"
    exit 1
fi
echo "TEST: CRED_ENV boundary (truncated header): Success"

echo "Testing CRED_ENV boundary (truncated envelope)..."
if [ -e "${WORKDIR}/credentials/short_env.enc" ] || cat "${WORKDIR}/credentials/short_env.enc" 2>/dev/null; then
    echo "ERROR: Truncated envelope did not fail"
    exit 1
fi
echo "TEST: CRED_ENV boundary (truncated envelope): Success"

echo "Testing CRED_ENV boundary (invalid rsa_ct_len)..."
if [ -e "${WORKDIR}/credentials/bad_keylen.enc" ] || cat "${WORKDIR}/credentials/bad_keylen.enc" 2>/dev/null; then
    echo "ERROR: Invalid rsa_ct_len envelope did not fail"
    exit 1
fi
echo "TEST: CRED_ENV boundary (invalid rsa_ct_len): Success"
