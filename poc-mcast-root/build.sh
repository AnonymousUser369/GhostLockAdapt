#!/bin/sh
# build.sh — build poc_mcast_root standalone binary (aarch64, static).
# Combines poc-mcast UAF topology + MCAST stamp with configfs-free DirtyPipe.
set -u
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast-root
NDK=/mnt/Data/AI_Workspace/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
cd "$DIR" || exit 1

echo "[*] rm old binary"
rm -f poc_mcast_root

echo "[*] build"
$CC -O2 -static -pthread -Wall -Wextra \
    -Isrc \
    src/poc_mcast_root.c src/pipe.c src/util.c src/globals.c src/kaslr_perf.c \
    -o poc_mcast_root 2>&1 | head -60
if [ ! -x poc_mcast_root ]; then echo "[!] build failed"; exit 1; fi

echo "[*] verify"
ls -la poc_mcast_root
file poc_mcast_root 2>/dev/null | sed 's/^/    /'
echo "[*] sha256:"; sha256sum poc_mcast_root | sed 's/^/    /'
echo "[*] done. Next: ./run.sh   (push + run on device)"
echo "[*] env overrides: PROBE=1 (map stamp fields), MCAST_PROBE_INDEX=1 (WAITER_OFF gate), MCAST_DEBUG_RET=1, KASLR_OFF=<signed>"
