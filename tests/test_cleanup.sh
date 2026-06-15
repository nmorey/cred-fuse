#!/bin/bash
BINARY_DIR="$1"

if [ -z "$BINARY_DIR" ]; then
    echo "Error: BINARY_DIR not specified to test_cleanup.sh" >&2
    exit 1
fi

if [ -f "${BINARY_DIR}/swtpm.pid" ]; then
    SWTPM_PID=$(cat "${BINARY_DIR}/swtpm.pid")
    echo "Stopping background SWTPM (PID: $SWTPM_PID)..."
    kill "$SWTPM_PID" 2>/dev/null || true
    rm -f "${BINARY_DIR}/swtpm.pid"
fi

if [ -f "${BINARY_DIR}/test_workdir.txt" ]; then
    WORKDIR=$(cat "${BINARY_DIR}/test_workdir.txt")
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        echo "Cleaning up credentials mount and test directory: $WORKDIR"
        umount "${WORKDIR}/credentials" 2>/dev/null || true
        rm -rf "$WORKDIR"
    fi
    rm -f "${BINARY_DIR}/test_workdir.txt"
fi

echo "Cleanup completed successfully."
