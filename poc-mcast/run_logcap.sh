#!/bin/sh
# run_logcap.sh — run poc_mcastv2 and capture THIS dying boot's logs WITHOUT root/dmesg.
#
# POCO-specific constraint (per user): the death is a silent userspace wedge / clean power-OFF
# (NOT a kernel panic — no ramoops), and `dmesg` is gated behind CAP_SYSLOG+selinux (shell can't
# read it, only mqsas after permissive). The device HARD-POWERS-OFF (manual boot needed), so
# pstore/console-ramoops and `dumpsys dropbox SYSTEM_LAST_KMSG` are POST-RESTART artifacts and
# CANNOT capture this boot — they hold the previous (or no) boot.
#
# => To capture THIS boot we must grab the LIVE buffers during the responsive window:
#    - `adb bugreport` (bugreportd, system uid + CAP_SYSLOG): live kernel log + logcat
#      (watchdog/tombstone of the wedge) + pstore. Written progressively; partial zip still has dmesg.
#    - `adb logcat -d -b all`: fast userspace log dump (the wedge signal lives here).
#    - `dumpsys dropbox SYSTEM_KERNEL_LOG`: fast live kernel-log fallback.
#
# Usage:
#   ./run_logcap.sh live    # push + run exploit, start background bugreport, poll + grab live logs
#   ./run_logcap.sh post    # (optional) after manual boot, grab last_kmsg/pstore for completeness
set -u

SERIAL=8575859PBYFYU8SW
DIR=/mnt/Data/AI_Workspace/ghostlock_repo/poc-mcast
BIN=poc_mcastv2
REMOTE=/data/local/tmp/$BIN
LOGDIR="$DIR/runlogs"
TS=$(date +%Y%m%d_%H%M%S)
LOG="$LOGDIR/logcap_${TS}.txt"
ADB="timeout 25 adb -s $SERIAL"

mkdir -p "$LOGDIR"
exec > >(tee -a "$LOG") 2>&1
echo "[*] logcap $TS  (serial $SERIAL)"

wait_device() {
  for i in $(seq 1 15); do
    if $ADB get-state 2>/dev/null | grep -q device; then return 0; fi
    echo "[*] waiting for device ($i)..."; sleep 3
  done
  echo "[!] device not found"; return 1
}

cap_dropbox() {
  # $1 = tag, $2 = outfile
  $ADB shell "dumpsys dropbox --print $1" 2>/dev/null > "$2"
}

cap_live() {
  wait_device || exit 1
  echo "[*] pushing $BIN"
  timeout 25 adb -s $SERIAL push "$DIR/$BIN" "$REMOTE" 2>&1 | tail -1
  timeout 20 adb -s $SERIAL shell "chmod 755 $REMOTE; nohup $REMOTE > /data/local/tmp/v2.log 2>&1 & echo launched"

  # Start a BACKGROUND bugreport IMMEDIATELY — it captures the LIVE kernel log + logcat
  # (watchdog/tombstone of a userspace wedge) + pstore. Zip is written progressively, so even
  # a partial one (if device dies mid-capture) still holds the dmesg section. This is the
  # ONLY method that captures THIS dying boot (SYSTEM_LAST_KMSG/pstore are post-restart only).
  echo "[*] starting background bugreport (live capture of this boot)..."
  timeout 150 adb -s $SERIAL bugreport "$LOGDIR/${TS}_bugreport.zip" >/dev/null 2>&1 &
  BUGR=$!

  echo "[*] polling responsiveness + grabbing live logcat/dropbox (Ctrl-C safe; rerun 'post' after manual boot)"
  for i in $(seq 1 60); do
    sleep 4
    ENC=$($ADB shell 'cat /sys/fs/selinux/enforce' 2>/dev/null)
    echo "[+$(($i*4))s] enforce=${ENC:-<unresponsive>}"
    if [ -z "$ENC" ]; then echo "[!] adb unresponsive — device dead/rebooting. Stopping live capture."; break; fi
    # fast live snapshots (fallback if bugreport didn't finish)
    if [ "$i" -eq 1 ]; then
      timeout 20 adb -s $SERIAL logcat -d -b all > "$LOGDIR/${TS}_live_logcat.txt" 2>/dev/null &
    fi
    cap_dropbox SYSTEM_KERNEL_LOG "$LOGDIR/${TS}_live_kernel_log_${i}.txt"
    $ADB shell 'ls -la /sys/fs/pstore /proc/last_kmsg 2>&1' 2>/dev/null > "$LOGDIR/${TS}_live_pstore_${i}.txt"
    $ADB shell 'tail -4 /data/local/tmp/v2.log' 2>/dev/null | sed 's/^/    v2.log: /'
  done
  wait $BUGR 2>/dev/null
  echo "[*] pulling v2.log"
  timeout 20 adb -s $SERIAL pull /data/local/tmp/v2.log "$LOGDIR/${TS}_v2.log" 2>&1 | tail -1
  echo "[*] LIVE done. Primary artifact: ${TS}_bugreport.zip (this boot's kernel+logcat)."
  echo "[*] After the device dies and you MANUALLY BOOT, run: ./run_logcap.sh post (for completeness)"
}

cap_post() {
  wait_device || exit 1
  echo "[*] POST-MORTEM: dying boot's last_kmsg + pstore"
  cap_dropbox SYSTEM_LAST_KMSG "$LOGDIR/${TS}_post_last_kmsg.txt"
  echo "[*] saved ${TS}_post_last_kmsg.txt ($(wc -l < "$LOGDIR/${TS}_post_last_kmsg.txt" 2>/dev/null) lines)"
  $ADB shell 'ls -la /sys/fs/pstore /proc/last_kmsg 2>&1' 2>/dev/null > "$LOGDIR/${TS}_post_pstore.txt"
  echo "[*] pstore listing:"
  cat "$LOGDIR/${TS}_post_pstore.txt"
  timeout 25 adb -s $SERIAL pull /sys/fs/pstore "$LOGDIR/${TS}_pstore" 2>&1 | tail -3
  echo "[*] POST done. Inspect ${TS}_post_last_kmsg.txt and ${TS}_pstore/ for the death cause."
}

case "${1:-live}" in
  live) cap_live ;;
  post) cap_post ;;
  *) echo "usage: $0 [live|post]"; exit 1 ;;
esac
