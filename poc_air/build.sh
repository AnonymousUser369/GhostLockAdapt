#!/bin/sh
# build.sh — build poc_air standalone binary (aarch64, static).
set -u
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc_air
NDK=/mnt/Data/AI_Workspace/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
cd "$DIR" || exit 1

echo "[*] rm old binary"
rm -f poc_air

echo "[*] build"
$CC -O2 -static -pthread -Wall -Wextra poc_air.c -o poc_air 2>&1 | head -40
if [ ! -x poc_air ]; then echo "[!] build failed"; exit 1; fi

echo "[*] verify"
ls -la poc_air
file poc_air 2>/dev/null | sed 's/^/    /'
echo "[*] sha256:"; sha256sum poc_air | sed 's/^/    /'
echo "[*] done. Next: ./run.sh [tag] [extra-env]   e.g. ./run.sh v7 'IOV_IDX=0'"
