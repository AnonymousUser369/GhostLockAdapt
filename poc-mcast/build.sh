#!/bin/sh
# build.sh — build poc_mcast + poc_mcastv2 standalone binaries (aarch64, static).
set -u
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast
NDK=/mnt/Data/AI_Workspace/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
cd "$DIR" || exit 1

echo "[*] rm old binaries"
rm -f poc_mcast poc_mcastv2

echo "[*] build poc_mcast"
$CC -O2 -static -pthread -Wall -Wextra poc_mcast.c -o poc_mcast 2>&1 | head -40
if [ ! -x poc_mcast ]; then echo "[!] poc_mcast build failed"; exit 1; fi

echo "[*] build poc_mcastv2"
$CC -O2 -static -pthread -Wall -Wextra poc_mcastv2.c -o poc_mcastv2 2>&1 | head -40
if [ ! -x poc_mcastv2 ]; then echo "[!] poc_mcastv2 build failed"; exit 1; fi

echo "[*] verify"
ls -la poc_mcast poc_mcastv2
file poc_mcast poc_mcastv2 2>/dev/null | sed 's/^/    /'
echo "[*] sha256:"; sha256sum poc_mcast poc_mcastv2 | sed 's/^/    /'
echo "[*] done. Next: ./run.sh [tag] [extra-env]   e.g. ./run.sh v1 'PROBE=1'"
