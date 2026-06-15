#!/bin/bash
set -e
FUSE_EXE="$1"
BINARY_DIR="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

load_context "${BINARY_DIR}"

echo "Testing missing 'ro' mount option..."
if "$FUSE_EXE" -f "$WORKDIR/source" "$WORKDIR/credentials" -o tpm_handle=0x81010002,tcti="swtpm" >/dev/null 2>&1; then
    echo "ERROR: FUSE started without 'ro' option"
    exit 1
fi
echo "TEST: missing ro option: Success"
