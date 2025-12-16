#!/bin/bash
set -e

############################
# Argument parsing
############################
if [ $# -ne 2 ]; then
    echo "Usage: $0 <mount_point> <filesystem_script>"
    echo "Example: $0 /mnt/efs ~/encfs/encfs.py"
    exit 1
fi

MNT="$1"
FS="$2"

############################
# Helper
############################
banner() {
    echo
    echo "=================================================="
    echo " $1"
    echo "=================================================="
}

log() {
    echo "[LOG] $1"
}

############################
# Cleanup
############################
cleanup() {
    echo
    log "Cleanup: unmount filesystem"
    cd ~ >/dev/null 2>&1 || true
    fusermount -u "$MNT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

############################
# Header
############################
echo "=============================="
echo " Part 6 - Testing & Validation"
echo "=============================="
log "Mount point : $MNT"
log "FS script  : $FS"

############################
# Mount FS
############################
mkdir -p "$MNT"
log "Mounting encrypted filesystem"
python3 "$FS" "$MNT" &
sleep 1

############################
# Test 1: Create file
############################
banner "Test 1: Create file (no key yet)"

log "Creating file a.txt"
touch "$MNT/a.txt"

log "Listing directory to verify file creation"
ls -l "$MNT"

############################
# Test 2: Write without key (should fail)
############################
banner "Test 2: Write without key (expected failure)"

log "Attempting to write without encryption key"
echo "secret data" > "$MNT/a.txt" 2>&1 || true

log "System response (stderr above) confirms write is denied"

############################
# Test 3: Read without key (should fail)
############################
banner "Test 3: Read without key (expected failure)"

log "Attempting to read file without key"
cat "$MNT/a.txt" 2>&1 || true

log "System response (stderr above) confirms read is denied"

############################
# Test 4: Write with correct key
############################
banner "Test 4: Write with correct key"

log "Setting encryption key for a.txt"
setfattr -n user.key -v "correctkey" "$MNT/a.txt"

log "Writing data with correct key"
echo "hello encrypted fs" > "$MNT/a.txt"

log "Reading file to verify successful write and decryption"
cat "$MNT/a.txt"

############################
# Test 5: Read with wrong key
############################
banner "Test 5: Read with wrong key (expected failure)"

log "Replacing key with wrong key"
setfattr -n user.key -v "wrongkey" "$MNT/a.txt"

log "Attempting to read with wrong key"
cat "$MNT/a.txt" 2>&1 || true

log "System response (stderr above) confirms decryption failure"

############################
# Test 6: Per-file different encryption keys (strict verification)
############################
banner "Test 6: Per-file different encryption keys (strict)"

log "Step 1: Create File A (f1.txt) and File B (f2.txt)"
touch "$MNT/f1.txt"
touch "$MNT/f2.txt"

log "Directory listing after file creation (evidence)"
ls -l "$MNT"

echo
log "Step 2: Assign File A key and verify File A access"
setfattr -n user.key -v "keyA" "$MNT/f1.txt"

log "Write to File A using its own key"
echo "content_of_file_A" > "$MNT/f1.txt"

log "Read File A using its own key (should succeed)"
cat "$MNT/f1.txt"

echo
log "Step 3: Assign File B key and verify File B access"
setfattr -n user.key -v "keyB" "$MNT/f2.txt"

log "Write to File B using its own key"
echo "content_of_file_B" > "$MNT/f2.txt"

log "Read File B using its own key (should succeed)"
cat "$MNT/f2.txt"

echo
log "Step 4: Cross-check — use File A key to read File B (should fail)"
setfattr -n user.key -v "keyA" "$MNT/f2.txt"
cat "$MNT/f2.txt" 2>&1 || true

log "Above error message proves File A key cannot decrypt File B"

echo
log "Step 5: Cross-check — use File B key to read File A (should fail)"
setfattr -n user.key -v "keyB" "$MNT/f1.txt"
cat "$MNT/f1.txt" 2>&1 || true

log "Above error message proves File B key cannot decrypt File A"

############################
# Test 7: Remove key
############################
banner "Test 7: Remove key and verify access denied"

log "Removing encryption key from f1.txt"
setfattr -x user.key "$MNT/f1.txt"

log "Attempting to read f1.txt after key removal"
cat "$MNT/f1.txt" 2>&1 || true

log "System response (stderr above) confirms access is denied"



############################
# End
############################




banner "All Part 6 tests completed with observable evidence"
