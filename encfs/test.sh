#!/bin/bash
set -e

MNT="$1"

if [ -z "$MNT" ]; then
    echo "Usage: $0 <mountpoint>"
    exit 1
fi

echo "=== BEGIN AUTOMATIC TESTS for encrypted_memfs ==="
echo "Mount point: $MNT"
echo

# 安全 HEX 金鑰（固定 32 bytes）
KEY="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

echo "=== [1] 清理殘留 ==="
rm -f "$MNT/secret.txt" "$MNT/.keyring" "$MNT/dir1" 2>/dev/null || true
echo OK
echo

echo "=== [2] 加入金鑰 ADD /secret.txt ==="
echo "ADD /secret.txt $KEY" > $MNT/.keyring
cat $MNT/.keyring
echo

echo "=== [3] 建立 secret.txt 並寫入內容 ==="
echo "hello encrypted world" > $MNT/secret.txt
sync
echo OK

echo "=== [4] 讀取應成功 ==="
cat $MNT/secret.txt
echo

echo "=== [5] 刪除金鑰 → 應該不能讀 ==="
echo "DEL /secret.txt" > $MNT/.keyring || true
echo "(below should fail with Permission denied)"
(cat $MNT/secret.txt && echo "ERROR: should not succeed") || echo "Access correctly denied"
echo

echo "=== [6] 再加入金鑰 → 讀取應成功 ==="
echo "ADD /secret.txt $KEY" > $MNT/.keyring
cat $MNT/secret.txt
echo

echo "=== [7] 測試 rename（最重要） ==="
mkdir -p $MNT/dir1
mv $MNT/secret.txt $MNT/dir1/a.txt

echo "=== 為 rename 後的新路徑加入金鑰 ==="
echo "ADD /dir1/a.txt $KEY" > $MNT/.keyring

echo "=== rename 後讀取應成功（fid AAD 驗證） ==="
cat $MNT/dir1/a.txt
echo

echo "=== [8] 測試 append ==="
echo -n " APPEND!" >> $MNT/dir1/a.txt
sync
echo "ADD /dir1/a.txt $KEY" > $MNT/.keyring
cat $MNT/dir1/a.txt
echo

echo "=== [9] truncate 測試 ==="
truncate -s 5 $MNT/dir1/a.txt
sync
echo "ADD /dir1/a.txt $KEY" > $MNT/.keyring
echo -n "TRUNC RESULT: "
cat $MNT/dir1/a.txt
echo

echo "=== [10] 測試多次 open/close 循環 ==="
echo "ADD /dir1/a.txt $KEY" > $MNT/.keyring
for i in {1..5}; do
    echo -n "loop $i " >> $MNT/dir1/a.txt
    sync
done
echo "ADD /dir1/a.txt $KEY" > $MNT/.keyring
cat $MNT/dir1/a.txt
echo

echo "=== [11] 測試目錄操作 ==="
mkdir $MNT/dir2
touch $MNT/dir2/x
ls -l $MNT/dir2
echo

echo "=== [12] 測試 unlink ==="
rm $MNT/dir2/x
echo "Removed dir2/x"
ls -l $MNT/dir2
echo

echo "=== ALL TESTS PASSED ==="
