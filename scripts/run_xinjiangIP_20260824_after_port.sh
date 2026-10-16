#!/usr/bin/env bash
# Wait for xinjiangIP_20260824 port scan to finish, then expand -> LLM -> finalize (screenshots).
# Does not stop or restart the running ip_port_scan.py.
set -u
ROOT=/home/lixiao/llm-detect/TEST
RUN="$ROOT/data/xinjiangIP_20260824"
LOG_DIR="$ROOT/logs"
LOG="$LOG_DIR/xinjiangIP_20260824_after_port.log"
LOCK="$RUN/after_port.lock"
STATUS="$LOG_DIR/xinjiangIP_20260824_after_port.status"
STEM="xinjiangIP-8月"
RESULT="$RUN/${STEM}_result.csv"
SCAN_RESULT="$RUN/${STEM}_port_scan.csv"
SCAN_PORTS="$RUN/${STEM}_scan_ports.csv"
LLM="$RUN/${STEM}_llm.csv"
LLM_CKPT="$RUN/${STEM}_llm_checkpoint.jsonl"
FINAL="$RUN/${STEM}_llm_最终版.xlsx"

mkdir -p "$LOG_DIR" "$RUN"
cd "$ROOT" || exit 1

exec >>"$LOG" 2>&1
log() { echo "[$(date '+%F %T')] $*"; }
status() { printf '%s\n' "$*" > "$STATUS"; }

if [ -e "$LOCK" ] && kill -0 "$(cat "$LOCK" 2>/dev/null)" 2>/dev/null; then
  log "after-port watcher already running as PID $(cat "$LOCK")"
  exit 0
fi
echo "$$" > "$LOCK"
trap 'rm -f "$LOCK"' EXIT

port_running() {
  pgrep -af "ip_port_scan.py" | grep -F "xinjiangIP_20260824" | grep -v grep >/dev/null
}

wait_for_port_scan() {
  if port_running; then
    log "waiting for xinjiangIP_20260824 ip_port_scan.py to finish"
    status "phase=wait-port"
    while port_running; do
      sleep 60
    done
    sleep 20
    if port_running; then
      log "ip_port_scan.py restarted; keep waiting"
      while port_running; do
        sleep 60
      done
    fi
    log "port scan process is gone"
  else
    log "no xinjiangIP_20260824 ip_port_scan.py process; continue"
  fi
}

wait_for_port_scan

if [ -f "$RUN/AFTER_PORT_COMPLETE" ]; then
  log "already completed: $RUN/AFTER_PORT_COMPLETE"
  status "phase=already-complete"
  exit 0
fi

if [ ! -s "$SCAN_RESULT" ]; then
  log "missing port scan result: $SCAN_RESULT"
  status "phase=error missing-scan-result"
  exit 1
fi

status "phase=expand-ports"
log "expand_scan_ports.py start"
set +e
python3 "$ROOT/expand_scan_ports.py" --input "$SCAN_RESULT" --output "$SCAN_PORTS"
expand_rc=$?
set -e
if [ "$expand_rc" -ne 0 ]; then
  log "no open ports or expand failed; skip LLM/screenshot"
  touch "$RUN/AFTER_PORT_COMPLETE"
  status "phase=complete-empty"
  exit 0
fi

status "phase=llm"
log "scan_llm.py start"
llm_args=(--input "$SCAN_PORTS" --output "$LLM" --checkpoint "$LLM_CKPT" --resume)
if [ -f "$ROOT/llm_scan_rules.yaml" ]; then
  llm_args+=(--config "$ROOT/llm_scan_rules.yaml")
fi
python3 "$ROOT/scan_llm.py" "${llm_args[@]}"

status "phase=finalize-screenshot"
log "finalize_llm_results.py start (includes screenshots)"
python3 "$ROOT/finalize_llm_results.py" "$LLM" --reported-source "$RESULT" -o "$FINAL"

touch "$RUN/AFTER_PORT_COMPLETE"
status "phase=complete"
log "done: $FINAL"
