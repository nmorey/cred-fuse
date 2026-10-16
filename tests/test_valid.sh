#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

# Clear any previous test vectors
rm -rf "${WORKDIR}/source"/*

# Create test vector for this test
echo -n "valid-secret" > "${WORKDIR}/valid.txt"
rsa_encrypt_cred "${WORKDIR}/valid.txt" "${WORKDIR}/source/valid.enc" 0644
setfattr -n user.size -v c "${WORKDIR}/source/valid.enc" # 'c' is 12 bytes
rm -f "${WORKDIR}/valid.txt"
cp "${WORKDIR}/source/valid.enc" "${WORKDIR}/source/swapped.enc"
setfattr -n user.size -v c "${WORKDIR}/source/swapped.enc"
chmod 644 "${WORKDIR}/source/swapped.enc"

# Export TPM public key in PEM format and generate a mismatched RSA public key
tpm2_readpublic -Q -c 0x81010002 -f pem -o "${WORKDIR}/tpm_pub.pem" -T "$TCTI_ARG"
chmod 644 "${WORKDIR}/tpm_pub.pem"
openssl genrsa 2048 2>/dev/null | openssl rsa -pubout -out "${WORKDIR}/wrong_pub.pem" 2>/dev/null
chmod 644 "${WORKDIR}/wrong_pub.pem"

echo "Testing rejection of mismatched tpm_pubkey..."
if "${FUSE_EXE}" -f "${WORKDIR}/source" "${WORKDIR}/credentials" -o "tpm_handle=0x81010002,tpm_pubkey=${WORKDIR}/wrong_pub.pem,tcti=${TCTI_ARG},ro,default_permissions" 2>/dev/null; then
    echo "ERROR: FUSE mounted despite mismatched tpm_pubkey"
    exit 1
fi
echo "TEST: Rejection of mismatched tpm_pubkey: Success"

# Start standard FUSE mount with valid tpm_pubkey
start_fuse "${FUSE_EXE}" "tpm_pubkey=${WORKDIR}/tpm_pub.pem"

echo "Testing valid file decryption..."
if [ "$(cat "${WORKDIR}/credentials/valid.enc")" != "valid-secret" ]; then
    echo "ERROR: Valid file decryption mismatched"
    exit 1
fi
echo "TEST: Valid file: Success"

echo "Testing RSA-OAEP label cross-file substitution rejection..."
if cat "${WORKDIR}/credentials/swapped.enc" 2>/dev/null; then
    echo "ERROR: Swapped RSA file was decrypted despite path mismatch"
    exit 1
fi
echo "TEST: RSA-OAEP label cross-file substitution rejection: Success"

echo "Testing RSA-OAEP label permission tampering rejection..."
chmod 600 "${WORKDIR}/source/valid.enc"
if cat "${WORKDIR}/credentials/valid.enc" 2>/dev/null; then
    echo "ERROR: RSA file was decrypted despite mode mismatch"
    exit 1
fi
chmod 644 "${WORKDIR}/source/valid.enc"
echo "TEST: RSA-OAEP label permission tampering rejection: Success"

