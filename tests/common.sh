#!/bin/bash

export DBUS_SESSION_BUS_ADDRESS=/dev/null
export TSS2_LOG=all+none

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
    export TCTI_ARG="swtpm:path=${WORKDIR}/swtpm.sock"
}

rsa_encrypt_cred() {
    local src="$1"
    local dst="$2"
    local mode="${3:-0644}"
    local rel_path="${dst#${WORKDIR}/source/}"
    "${BINARY_DIR}/cred-encrypt" -k "${WORKDIR}/tpm_pub.pem" -p "$rel_path" -m "$mode" -i "$src" -o "$dst"
    chmod "$mode" "$dst"
}

start_fuse() {
    FUSE_EXE="$1"
    EXTRA_OPTS="$2" # Optional custom options
    
    if [ -z "$FUSE_EXE" ] || [ ! -x "$FUSE_EXE" ]; then
        echo "Error: FUSE executable invalid: $FUSE_EXE" >&2
        exit 1
    fi

    # Build the full mount options
    FUSE_OPTS="tpm_handle=0x81010002,tcti=${TCTI_ARG},ro,default_permissions"
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
