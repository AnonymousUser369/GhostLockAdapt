#!/bin/sh
# run.sh — push + run poc_mcast. Usage: run.sh [tag] [extra-env]
#   e.g.  run.sh v1
#         run.sh v1 "PROBE=1"
#         run.sh v1 "IOV_IDX=0"
set -u
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast
LOGDIR=$DIR/runlogs
NDK=/mnt/Data/AI_Workspace/android-ndk-r29
CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
TAG="${1:-run}"
ENV="${2:-}"
TS=$(date +%Y%m%d_%H%M%S)
OUT=$LOGDIR/run_${TAG}_${TS}.out
mkdir -p "$LOGDIR"
cd "$DIR" || exit 1

[ -x poc_mcast ] || { echo "[!] build first: ./build.sh"; exit 1; }

echo "[*] push -> /data/local/tmp/poc_mcast_$TAG"
adb push poc_mcast /data/local/tmp/poc_mcast_$TAG || { echo "[!] push failed"; exit 1; }
adb shell chmod 755 /data/local/tmp/poc_mcast_$TAG

echo "[*] run ($ENV)"
( eval "$ENV" ; timeout 30 adb exec-out "cd /data/local/tmp && ${ENV} ./poc_mcast_$TAG 2>&1 | tee poc_mcast_${TAG}.log; echo ENFORCE=\$(getenforce)" ) > "$OUT" 2>&1
echo "EXIT=$?" >> "$OUT"
echo "[*] saved run -> $OUT"
cat "$OUT"
echo "[*] next: ./getpanic.sh"
