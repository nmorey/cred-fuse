#!/bin/bash
set -e

WORKDIR=$(mktemp -d -t cred-fuse-test-XXXXXX)
cd $WORKDIR

echo "Working directory: $WORKDIR"

cleanup() {
    echo "Test cleanup..."
    kill $FUSE_PID 2>/dev/null || true
    umount $WORKDIR/credentials 2>/dev/null || true
    kill $SWTPM_PID 2>/dev/null || true
    rm -rf $WORKDIR
}
trap cleanup EXIT
export DBUS_SESSION_BUS_ADDRESS=/dev/null

# 1. Setup swtpm (Default TCP port 2321)
mkdir -p tpmstate
swtpm socket --tpmstate dir=tpmstate --tpm2 \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
sleep 1

TCTI_ARG="swtpm"
export TSS2_LOG=all+none

# 2. Key Generation
tpm2_startup -c -T "$TCTI_ARG"
tpm2_createprimary -Q -C o -G rsa -a 'decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth' -c primary.ctx -T "$TCTI_ARG"
tpm2_evictcontrol -C o -c primary.ctx 0x81010002 -T "$TCTI_ARG" || true

mkdir -p source credentials

# 3. Create varying test vectors
echo -n "valid-secret" > valid.txt
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/valid.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v c source/valid.enc # 'c' is 12 bytes
chmod 644 source/valid.enc

# Missing user.size
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/missing.enc valid.txt -T "$TCTI_ARG"

# Zero size
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/zero.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v 0 source/zero.enc

# Too short
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/short.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v 2 source/short.enc

# Too long
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/long.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v ff source/long.enc

# Garbage size
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/garbage.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v random_string source/garbage.enc

# Permissions test
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/perms.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v c source/perms.enc
chmod 400 source/perms.enc

# Write permissions stripping test
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/write_perms.enc valid.txt -T "$TCTI_ARG"
setfattr -n user.size -v c source/write_perms.enc
chmod 777 source/write_perms.enc

# Many files for readdir test
mkdir -p source/many
for i in $(seq 1 3000); do
    cp source/valid.enc source/many/file_$i.enc
    setfattr -n user.size -v c source/many/file_$i.enc
done

# 4. Start FUSE
FUSE_EXE="${1:-./mount.cred-fuse}"
if [ ! -x "$FUSE_EXE" ]; then
    echo "Error: FUSE executable not found at $FUSE_EXE"
    exit 1
fi
if [ "$USE_VALGRIND" = "1" ]; then
    FUSE_CMD="valgrind --leak-check=full --error-exitcode=1 $FUSE_EXE"
else
    FUSE_CMD="$FUSE_EXE"
fi

echo "Testing missing 'ro' mount option..."
if $FUSE_CMD -f $WORKDIR/source $WORKDIR/credentials -o tpm_handle=0x81010002,tcti="$TCTI_ARG" >/dev/null 2>&1; then
    echo "ERROR: FUSE started without 'ro' option"
    exit 1
fi
echo "TEST: missing ro option: Success"

echo "Starting FUSE..."
$FUSE_CMD -f $WORKDIR/source $WORKDIR/credentials -o tpm_handle=0x81010002,tcti="$TCTI_ARG",ro &
FUSE_PID=$!
sleep 1

# 5. Run Assertions
echo "Running assertions..."

# 5.1 Valid file
if [ "$(cat credentials/valid.enc)" != "valid-secret" ]; then
    echo "ERROR: Valid file decryption mismatched"
    exit 1
fi
echo "TEST: Valid file: Success"

# 5.2 Permissions propagation
PERM=$(stat -c %a credentials/perms.enc)
if [ "$PERM" != "400" ]; then
    echo "ERROR: Permission propagation failed. Expected 400, got $PERM"
    exit 1
fi
echo "TEST: Permission: Success"

# 5.2.1 Check read-only permissions
PERM=$(stat -c %a credentials/valid.enc)
if [ "$PERM" != "444" ]; then
    echo "ERROR: Write permissions not stripped. Expected 444, got $PERM"
    exit 1
fi
echo "TEST: Write permissions stripped: Success"

# 5.2.2 Check 777 becomes 555
PERM=$(stat -c %a credentials/write_perms.enc)
if [ "$PERM" != "555" ]; then
    echo "ERROR: Write permissions not completely stripped from 777. Expected 555, got $PERM"
    exit 1
fi
echo "TEST: All write permissions stripped: Success"

# 5.3 Missing user.size (should be transparent/invisible)
if ls credentials/ | grep -q missing.enc; then
    echo "ERROR: File without user.size appeared in readdir (ls)"
    exit 1
fi
echo "TEST: Missing user.size (readdir): Success"

if [ -e credentials/missing.enc ]; then
    echo "ERROR: File without user.size is accessible via getattr (stat)"
    exit 1
fi
echo "TEST: Missing user.size (getattr): Success"

if cat credentials/missing.enc 2>/dev/null; then
    echo "ERROR: File without user.size is readable"
    exit 1
fi
echo "TEST: Missing user.size (read): Success"

# 5.4 Zero size (should be empty read natively based on getattr size 0)
if [ "$(cat credentials/zero.enc)" != "" ]; then
    echo "ERROR: Zero size mismatch"
    exit 1
fi
echo "TEST: user.size (zero): Success"

# 5.5 Short size (bounds should limit to what getattr returned)
if [ "$(cat credentials/short.enc | wc -c)" != "2" ]; then
    echo "ERROR: Short boundary mismatch"
    exit 1
fi
echo "TEST: user.size (shorter): Success"

# 5.6 Long size (bounds should be protected by the actual decrypted memory limit in read)
if [ "$(cat credentials/long.enc | wc -c)" != "12" ]; then
    echo "ERROR: Long boundary exceeded decrypted footprint"
    exit 1
fi
echo "TEST: user.size (longer): Success"

# 5.7 Garbage size (strtol parses natively mapping to 0 for invalid hex completely, so it acts like 0 size)
if [ "$(cat credentials/garbage.enc)" != "" ]; then
    echo "ERROR: Garbage boundary mismatch"
    exit 1
fi
echo "TEST: user.size (garbage): Success"

# 5.8 Readdir test
NUM_FILES=$(ls credentials/many | wc -l)
if [ "$NUM_FILES" != "3000" ]; then
    echo "ERROR: Readdir failed to list all files, found $NUM_FILES, expected 300"
    exit 1
fi
echo "TEST: many files: Success"

# 6. Add a file after FUSE started
echo -n "late-secret" > late.txt
tpm2_rsaencrypt -c 0x81010002 -s oaep -o source/late.enc late.txt -T "$TCTI_ARG"
setfattr -n user.size -v b source/late.enc # 'b' is 11 bytes

if [ "$(cat credentials/late.enc)" != "late-secret" ]; then
    echo "ERROR: Late file decryption mismatched"
    exit 1
fi
echo "TEST: dynamic file: Success"

kill $FUSE_PID 2>/dev/null || true
umount $WORKDIR/credentials 2>/dev/null || true
sleep 1
$FUSE_CMD -f $WORKDIR/source $WORKDIR/credentials -o tpm_handle=0x81010002,tcti="$TCTI_ARG",ro,max_open_files=2,max_file_size=100 &
FUSE_PID=$!
sleep 1

if cat credentials/valid.enc 2>/dev/null; then
    echo "ERROR: File size limit failed, file was read successfully (max_file_size=100 < 256)"
    exit 1
fi
echo "TEST: max_file_size: Success"

kill $FUSE_PID 2>/dev/null || true
umount $WORKDIR/credentials 2>/dev/null || true
sleep 1
$FUSE_CMD -f $WORKDIR/source $WORKDIR/credentials -o tpm_handle=0x81010002,tcti="$TCTI_ARG",ro,max_open_files=2,max_file_size=1000 &
FUSE_PID=$!
sleep 1

exec 3< credentials/valid.enc
exec 4< credentials/perms.enc
if cat credentials/late.enc 2>/dev/null; then
    echo "ERROR: max_open_files limit failed, third file was opened"
    exit 1
fi
echo "TEST: max_open_files: Success"


exec 3<&-
exec 4<&-
if ! cat credentials/late.enc >/dev/null; then
    echo "ERROR: Failed to open file after FDs were closed"
    exit 1
fi
echo "TEST: max_open_files: Success"

echo "All tests passed successfully!"
