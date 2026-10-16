#!/usr/bin/env bash
set -euo pipefail

DESIRED=$(printf '%s' "$1" 2>/dev/null || true)
case "$DESIRED" in
  8|12|14) ;;
  *) echo  usage: worker count must be 8, 12, or 14 >&2; exit 64 ;;
esac

ROOT=/home/lixiao/llm-detect/TEST
[ -f "$ROOT/logs/SCAN_PIPELINES_PAUSED" ] && exit 0
RUN=batch1_v7_343_remote237_20261008
RUNNER="$ROOT/strategy_v7_active_gpu_20260916/run_all_42_isolated_20260907.sh"
LOG_DIR="$ROOT/logs/$RUN"
LOCK=/tmp/batch1_port_worker_switch.lock
mkdir -p "$LOG_DIR"
exec 9>"$LOCK"
flock -n 9 || exit 0

log() {
  printf '%s worker-switch desired=%s %s\n' "$(date '+%F %T')" "$DESIRED" "$*" >> "$LOG_DIR/concurrency_switch.log"
}

if [ -f "$LOG_DIR/COMPLETE" ]; then
  log "ignored: run already complete"
  exit 0
fi

current=$(ps -eo args= | awk '/scan_ports_by_source_type.py/ && /[b]atch1_v7_343_remote237_20261008/ { for (i=1; i<=NF; i++) if ($i=="--parallel-workers") { print $(i+1); exit } }')
if [ "$current" = "$DESIRED" ]; then
  log "ignored: already using requested scan workers"
  exit 0
fi

pids=""
for env_file in /proc/[0-9]*/environ; do
  pid=$(printf '%s' "$env_file" | cut -d/ -f3)
  if tr '\000' '\n' < "$env_file" 2>/dev/null | grep -Fxq "RUN_ID=$RUN"; then
    pids="$pids $pid"
  fi
done

if [ -n "$pids" ]; then
  log "stopping active run for checkpointed restart pids:$pids"
  kill -TERM $pids 2>/dev/null || true
  for n in $(seq 1 60); do
    active=0
    for env_file in /proc/[0-9]*/environ; do
      if tr '\000' '\n' < "$env_file" 2>/dev/null | grep -Fxq "RUN_ID=$RUN"; then
        active=1
        break
      fi
    done
    [ "$active" -eq 0 ] && break
    sleep 1
  done
fi

if [ -f "$LOG_DIR/COMPLETE" ]; then
  log "stopped after completion; no restart"
  exit 0
fi

if ps -eo args= | grep -q '[r]un_all_42_isolated_20260907.sh'; then
  log "not restarted: a runner still holds the pipeline lock"
  exit 1
fi

nohup env PATH=/root/miniconda3/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin RUN_ID="$RUN" SOURCE_TABLE=source_ip_ranges PORT_SCAN_WORKERS="$DESIRED" PORT_VERIFY_WORKERS=12 FULL_PORT_SCAN=1 FULL_PORT_EXECUTOR=remote FULL_PORT_REMOTE_CONFIG="$ROOT/config/full_port_remote_237.ini" ACTIVE_GPU_RECHECK=1 bash "$RUNNER" >> "$LOG_DIR/run.log" 2>&1 < /dev/null &
log "restarted pid=$! scan_workers=$DESIRED verify_workers=12"
