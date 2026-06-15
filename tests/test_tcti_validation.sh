#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

echo "Testing TCTI options validation..."

# List of invalid or malicious TCTI options
bad_tctis=(
    "none"
    "mssim"
    "mssim:host=evil.com,port=2321"
    "device:../../tpm0"
    "device:/dev/tpm0;evil-command"
    "swtpm:path=relative/path.sock"
    "swtpm:path=/dev/stdout;evil"
    "tabrmd:bus_name=val;evil"
    "invalid_scheme"
    "device:"
    "swtpm:path="
)

for tcti in "${bad_tctis[@]}"; do
    echo "Checking bad TCTI: $tcti"
    # We expect this to fail, so we invert the condition
    if "$FUSE_EXE" -f "$WORKDIR/source" "$WORKDIR/credentials" -o tpm_handle=0x81010002,tcti="$tcti",ro,default_permissions >/dev/null 2>&1; then
        echo "ERROR: FUSE daemon started with invalid TCTI: $tcti"
        exit 1
    fi
done

echo "TEST: TCTI option validation: Success"
