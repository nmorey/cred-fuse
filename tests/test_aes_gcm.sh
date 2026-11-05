#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

CRED_ENCRYPT="${BINARY_DIR}/cred-encrypt"
CRED_DECRYPT="${BINARY_DIR}/cred-decrypt"

# 1. Create standard and large CRED_ENV v1 test vectors using cred-encrypt
echo -n "aes-gcm-secret-value" > "${WORKDIR}/plain_small.txt"
rsa_encrypt_cred "${WORKDIR}/plain_small.txt" "${WORKDIR}/source/gcm_test.enc" 0644

head -c 4096 /dev/urandom | base64 | head -c 4096 > "${WORKDIR}/plain_large.txt"
rsa_encrypt_cred "${WORKDIR}/plain_large.txt" "${WORKDIR}/source/gcm_large.enc" 0600

echo "Testing cred-decrypt CLI round-trip (small and large payloads)..."
DECRYPTED_SMALL=$("${CRED_DECRYPT}" -c 0x81010002 -p "gcm_test.enc" -m 0644 -k "${WORKDIR}/tpm_pub.pem" -T "$TCTI_ARG" -i "${WORKDIR}/source/gcm_test.enc")
if [ "$DECRYPTED_SMALL" != "aes-gcm-secret-value" ]; then
    echo "ERROR: cred-decrypt small payload mismatch"
    exit 1
fi
"${CRED_DECRYPT}" -c 0x81010002 -p "gcm_large.enc" -m 0600 -k "${WORKDIR}/tpm_pub.pem" -T "$TCTI_ARG" -i "${WORKDIR}/source/gcm_large.enc" -o "${WORKDIR}/decrypted_large.txt"
if ! cmp -s "${WORKDIR}/plain_large.txt" "${WORKDIR}/decrypted_large.txt"; then
    echo "ERROR: cred-decrypt large payload mismatch"
    exit 1
fi
rm -f "${WORKDIR}/plain_small.txt" "${WORKDIR}/decrypted_large.txt"
echo "TEST: cred-decrypt CLI round-trip: Success"

echo "Testing cred-decrypt rejection of mismatched path or mode..."
if "${CRED_DECRYPT}" -c 0x81010002 -p "wrong_path.enc" -m 0644 -T "$TCTI_ARG" -i "${WORKDIR}/source/gcm_test.enc" >/dev/null 2>&1; then
    echo "ERROR: cred-decrypt succeeded with wrong --path"
    exit 1
fi
if "${CRED_DECRYPT}" -c 0x81010002 -p "gcm_test.enc" -m 0600 -T "$TCTI_ARG" -i "${WORKDIR}/source/gcm_test.enc" >/dev/null 2>&1; then
    echo "ERROR: cred-decrypt succeeded with wrong --mode"
    exit 1
fi
echo "TEST: cred-decrypt path/mode binding verification: Success"

echo "Testing cred-encrypt atomic creation (refusal to overwrite existing file)..."
echo -n "test" > "${WORKDIR}/plain_sec02.txt"
if "${CRED_ENCRYPT}" -k "${WORKDIR}/tpm_pub.pem" -p "gcm_test.enc" -m 0644 -i "${WORKDIR}/plain_sec02.txt" -o "${WORKDIR}/source/gcm_test.enc" >/dev/null 2>&1; then
    echo "ERROR: cred-encrypt overwrote an existing file without O_EXCL rejection"
    exit 1
fi
echo "TEST: cred-encrypt refusal to overwrite existing file: Success"

echo "Testing cred-encrypt default restrictive file mode (0600)..."
"${CRED_ENCRYPT}" -k "${WORKDIR}/tpm_pub.pem" -p "default_mode.enc" -m 0644 -i "${WORKDIR}/plain_sec02.txt" -o "${WORKDIR}/source/default_mode.enc"
DEFAULT_MODE=$(stat -c "%a" "${WORKDIR}/source/default_mode.enc")
if [ "$DEFAULT_MODE" != "600" ]; then
    echo "ERROR: cred-encrypt created file with insecure mode $DEFAULT_MODE (expected 600)"
    exit 1
fi
rm -f "${WORKDIR}/source/default_mode.enc"
echo "TEST: cred-encrypt default mode 0600: Success"

echo "Testing cred-encrypt with --set-mode (-s)..."
"${CRED_ENCRYPT}" -k "${WORKDIR}/tpm_pub.pem" -p "set_mode.enc" -m 0400 -s -i "${WORKDIR}/plain_sec02.txt" -o "${WORKDIR}/source/set_mode.enc"
SET_MODE=$(stat -c "%a" "${WORKDIR}/source/set_mode.enc")
if [ "$SET_MODE" != "400" ]; then
    echo "ERROR: cred-encrypt with -s created file with mode $SET_MODE (expected 400)"
    exit 1
fi
rm -f "${WORKDIR}/source/set_mode.enc" "${WORKDIR}/plain_sec02.txt"
echo "TEST: cred-encrypt --set-mode: Success"

# 2. Create tampered and swapped envelopes
python3 -c "
with open('${WORKDIR}/source/gcm_test.enc', 'rb') as f:
    data = bytearray(f.read())

# Tamper with the last byte (AES-GCM ciphertext)
tampered_ct = bytearray(data)
tampered_ct[-1] ^= 0x01
with open('${WORKDIR}/source/gcm_tampered.enc', 'wb') as f:
    f.write(tampered_ct)

# Tamper with version field (offset 8..15 -> version 2)
bad_ver = bytearray(data)
bad_ver[15] = 2
with open('${WORKDIR}/source/gcm_bad_version.enc', 'wb') as f:
    f.write(bad_ver)
"
chmod 644 "${WORKDIR}/source/gcm_tampered.enc" "${WORKDIR}/source/gcm_bad_version.enc"

cp "${WORKDIR}/source/gcm_test.enc" "${WORKDIR}/source/gcm_swapped.enc"
chmod 644 "${WORKDIR}/source/gcm_swapped.enc"

# Start standard FUSE mount
start_fuse "${FUSE_EXE}"

echo "Testing CRED_ENV v1 valid decryption (small and large)..."
if [ "$(cat "${WORKDIR}/credentials/gcm_test.enc")" != "aes-gcm-secret-value" ]; then
    echo "ERROR: CRED_ENV small file decryption mismatched"
    exit 1
fi
if ! cmp -s "${WORKDIR}/plain_large.txt" "${WORKDIR}/credentials/gcm_large.enc"; then
    echo "ERROR: CRED_ENV large file decryption mismatched"
    exit 1
fi
rm -f "${WORKDIR}/plain_large.txt"
echo "TEST: CRED_ENV v1 valid decryption: Success"

echo "Testing CRED_ENV v1 AES-GCM integrity failure handling..."
if cat "${WORKDIR}/credentials/gcm_tampered.enc" 2>/dev/null; then
    echo "ERROR: Tampered CRED_ENV file was successfully decrypted (should have failed)"
    exit 1
fi
echo "TEST: CRED_ENV v1 integrity failure handling: Success"

echo "Testing CRED_ENV unsupported version rejection..."
if cat "${WORKDIR}/credentials/gcm_bad_version.enc" 2>/dev/null; then
    echo "ERROR: CRED_ENV file with unsupported version was decrypted"
    exit 1
fi
echo "TEST: CRED_ENV unsupported version rejection: Success"

echo "Testing CRED_ENV cross-file substitution rejection..."
if cat "${WORKDIR}/credentials/gcm_swapped.enc" 2>/dev/null; then
    echo "ERROR: Swapped CRED_ENV file was decrypted despite path mismatch"
    exit 1
fi
echo "TEST: CRED_ENV cross-file substitution rejection: Success"

echo "Testing CRED_ENV permission tampering rejection..."
chmod 600 "${WORKDIR}/source/gcm_test.enc"
if cat "${WORKDIR}/credentials/gcm_test.enc" 2>/dev/null; then
    echo "ERROR: CRED_ENV file was decrypted despite mode mismatch"
    exit 1
fi
chmod 644 "${WORKDIR}/source/gcm_test.enc"
echo "TEST: CRED_ENV permission tampering rejection: Success"
