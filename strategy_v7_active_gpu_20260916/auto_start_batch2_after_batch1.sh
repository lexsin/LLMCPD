#!/usr/bin/env bash
set -euo pipefail

ROOT=/home/lixiao/llm-detect/TEST
[ -f "$ROOT/logs/SCAN_PIPELINES_PAUSED" ] && exit 0
FIRST_RUN=batch1_v7_343_remote237_20261008
RUN=batch2_v7_343_remote237_20261012_auto
RUNNER="$ROOT/strategy_v7_active_gpu_20260916/run_all_42_isolated_20260907.sh"
FIRST_LOG="$ROOT/logs/$FIRST_RUN"
LOG_DIR="$ROOT/logs/$RUN"
LOCK=/tmp/batch2_autostart.lock

[ -f "$FIRST_LOG/COMPLETE" ] || exit 0
mkdir -p "$LOG_DIR"
exec 9>"$LOCK"
flock -n 9 || exit 0

if [ -f "$LOG_DIR/COMPLETE" ]; then
  exit 0
fi

for env_file in /proc/[0-9]*/environ; do
  if tr '\000' '\n' < "$env_file" 2>/dev/null | grep -Fxq "RUN_ID=$RUN"; then
    exit 0
  fi
done

hour=$(date +%H)
if [ "$hour" -ge 20 ] || [ "$hour" -lt 9 ]; then
  workers=14
else
  workers=8
fi

touch "$LOG_DIR/STARTED"
nohup env PATH=/root/miniconda3/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin RUN_ID="$RUN" SOURCE_TABLE=source_ip_ranges_batch2 PORT_SCAN_WORKERS="$workers" PORT_VERIFY_WORKERS=12 FULL_PORT_SCAN=1 FULL_PORT_EXECUTOR=remote FULL_PORT_REMOTE_CONFIG="$ROOT/config/full_port_remote_237.ini" ACTIVE_GPU_RECHECK=1 bash "$RUNNER" >> "$LOG_DIR/run.log" 2>&1 < /dev/null &
printf '%s started pid=%s scan_workers=%s\n' "$(date '+%F %T')" "$!" "$workers" >> "$LOG_DIR/autostart.log"
