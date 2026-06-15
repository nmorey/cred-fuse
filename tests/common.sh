#!/bin/bash

export DBUS_SESSION_BUS_ADDRESS=/dev/null
export TSS2_LOG=all+none
TCTI_ARG="swtpm"

load_context() {
    BINARY_DIR="$1"
    if [ -z "$BINARY_DIR" ]; then
        echo "Error: BINARY_DIR not specified in load_context" >&2
        exit 1
    fi
    if [ ! -f "${BINARY_DIR}/test_workdir.txt" ]; then
        echo "Error: test_workdir.txt not found in ${BINARY_DIR}. Did you run test_setup?" >&2
        exit 1
    fi
    WORKDIR=$(cat "${BINARY_DIR}/test_workdir.txt")
    if [ -z "$WORKDIR" ] || [ ! -d "$WORKDIR" ]; then
        echo "Error: WORKDIR is invalid or does not exist: $WORKDIR" >&2
        exit 1
    fi
    export WORKDIR
}

generate_aes_host_key() {
    HOSTNAME_RAW=$(hostname)
    HOSTNAME="${HOSTNAME_RAW%%.*}"
    python3 -c "
import os
key = os.urandom(32)
with open('${WORKDIR}/raw_host.key', 'wb') as f:
    f.write(key)
"
    tpm2_rsaencrypt -c 0x81010002 -s oaep -o "${WORKDIR}/source/${HOSTNAME}.key" "${WORKDIR}/raw_host.key" -T "swtpm"
    rm -f "${WORKDIR}/raw_host.key"
    setfattr -n user.size -v 20 "${WORKDIR}/source/${HOSTNAME}.key"
}

start_fuse() {
    FUSE_EXE="$1"
    EXTRA_OPTS="$2" # Optional custom options
    
    if [ -z "$FUSE_EXE" ] || [ ! -x "$FUSE_EXE" ]; then
        echo "Error: FUSE executable invalid: $FUSE_EXE" >&2
        exit 1
    fi

    # Build the full mount options
    FUSE_OPTS="tpm_handle=0x81010002,tcti=swtpm,ro,default_permissions"
    if [ -n "$EXTRA_OPTS" ]; then
        FUSE_OPTS="${FUSE_OPTS},${EXTRA_OPTS}"
    fi

    if [ "$USE_VALGRIND" = "1" ]; then
        FUSE_CMD="valgrind --leak-check=full --error-exitcode=1 $FUSE_EXE"
    else
        FUSE_CMD="$FUSE_EXE"
    fi

    # Start FUSE in the background
    $FUSE_CMD -f "$WORKDIR/source" "$WORKDIR/credentials" -o "$FUSE_OPTS" >/dev/null 2>&1 &
    FUSE_PID=$!
    export FUSE_PID
    
    # Register automatic cleanup on script exit or crash
    cleanup_local_fuse() {
        echo "Stopping local FUSE daemon (PID: $FUSE_PID)..."
        kill "$FUSE_PID" 2>/dev/null || true
        umount "$WORKDIR/credentials" 2>/dev/null || true
    }
    trap cleanup_local_fuse EXIT
    
    sleep 0.5
}
