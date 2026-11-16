#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

NV_INDEX="0x1500020"

# Cleanup trap to ensure NV index is removed and lockout cleared
cleanup_nv() {
    tpm2_dictionaryattackcmd -c -T "$TCTI_ARG" >/dev/null 2>&1 || true
    tpm2_nvundefine -Q "$NV_INDEX" -C o -T "$TCTI_ARG" >/dev/null 2>&1 || true
}
trap cleanup_nv EXIT

echo "Triggering TPM dictionary attack lockout via NV index auth failures..."
tpm2_nvdefine -Q "$NV_INDEX" -C o -s 32 -a "authread|authwrite" -p realpass -T "$TCTI_ARG"

for i in 1 2 3; do
    tpm2_nvread "$NV_INDEX" -C "$NV_INDEX" -P wrongpass -T "$TCTI_ARG" >/dev/null 2>&1 || true
done

echo "Testing daemon rejection when TPM is in lockout mode..."
if "${FUSE_EXE}" -f "${WORKDIR}/source" "${WORKDIR}/credentials" \
    -o "tpm_handle=0x81010002,tpm_pubkey=${WORKDIR}/tpm_pub.pem,tcti=${TCTI_ARG},ro,default_permissions" >/dev/null 2>&1; then
    echo "ERROR: Daemon mounted despite TPM being in dictionary attack lockout mode!"
    exit 1
fi
echo "TEST: TPM lockout rejection on mount: Success"

echo "Clearing TPM lockout and testing normal mount recovery..."
cleanup_nv

start_fuse "${FUSE_EXE}"

echo "TEST: Lockout recovery: Success"
