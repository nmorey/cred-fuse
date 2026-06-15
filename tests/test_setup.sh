#!/bin/bash
set -e
BINARY_DIR="$1"

if [ -z "$BINARY_DIR" ]; then
    echo "Error: BINARY_DIR not specified to test_setup.sh" >&2
    exit 1
fi

WORKDIR=$(mktemp -d -t cred-fuse-test-XXXXXX)
echo "Working directory: $WORKDIR"

# Save the workdir immediately for cleanup if setup fails
echo "$WORKDIR" > "${BINARY_DIR}/test_workdir.txt"

cleanup_failure() {
    echo "Setup failed! Performing cleanup..."
    if [ -f "${BINARY_DIR}/swtpm.pid" ]; then
        kill $(cat "${BINARY_DIR}/swtpm.pid") 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
    rm -f "${BINARY_DIR}/test_workdir.txt" "${BINARY_DIR}/swtpm.pid"
}
trap cleanup_failure ERR

export DBUS_SESSION_BUS_ADDRESS=/dev/null
export TSS2_LOG=all+none
TCTI_ARG="swtpm"

# 1. Setup swtpm (Default TCP port 2321)
mkdir -p "${WORKDIR}/tpmstate"
swtpm socket --tpmstate dir="${WORKDIR}/tpmstate" --tpm2 \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags not-need-init,startup-clear >/dev/null 2>&1 &
SWTPM_PID=$!
echo "$SWTPM_PID" > "${BINARY_DIR}/swtpm.pid"
sleep 1

# 2. Key Generation
tpm2_startup -c -T "$TCTI_ARG"
tpm2_createprimary -Q -C o -G rsa -a 'decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth' -c "${WORKDIR}/primary.ctx" -T "$TCTI_ARG"
tpm2_evictcontrol -C o -c "${WORKDIR}/primary.ctx" 0x81010002 -T "$TCTI_ARG" || true

mkdir -p "${WORKDIR}/source" "${WORKDIR}/credentials"

echo "Setup completed successfully."
