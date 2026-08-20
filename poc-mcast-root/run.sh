#!/bin/sh
# run.sh — push + run poc_mcast_root on the POCO air device.
# Usage: ./run.sh [tag] [extra-env]
#   ./run.sh                 # default run
#   ./run.sh probe PROBE=1  # map stamp fields
#   ./run.sh gate MCAST_PROBE_INDEX=1   # WAITER_OFF panic gate
set -u
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast-root
SERIAL=8575859PBYFYU8SW
DEVICE=/data/local/tmp
BIN=poc_mcast_root

TAG="${1:-run}"
shift 2>/dev/null || true
EXTRA="$*"

cd "$DIR" || exit 1
[ -x "$BIN" ] || { echo "[!] $BIN not built; run ./build.sh first"; exit 1; }

echo "[*] push $BIN"
adb -s "$SERIAL" push "$BIN" "$DEVICE/$BIN" 2>&1 | tail -1
adb -s "$SERIAL" shell chmod 755 "$DEVICE/$BIN"

LOG="runlogs/run_${TAG}_$(date +%Y%m%d_%H%M%S).out"
mkdir -p runlogs
echo "[*] run (env: $EXTRA) -> $LOG"
echo "===== $(date) tag=$TAG env=[$EXTRA] =====" > "$LOG"
adb -s "$SERIAL" shell "cd $DEVICE && ./$BIN $EXTRA" 2>&1 | tee -a "$LOG"
echo "[*] done. panic: ./getpanic.sh $TAG"
