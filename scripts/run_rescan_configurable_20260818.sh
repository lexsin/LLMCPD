#!/usr/bin/env bash
set -eEuo pipefail
ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=rescan_requested_20260813
RUN_DIR="$ROOT/data/$RUN_ID"; LOG_DIR="$ROOT/logs/$RUN_ID"; BACKUP_DIR="$ROOT/backups/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"; MASTER_LOG="$LOG_DIR/master_configurable_20260818.log"
START_INDEX=6; LOW_OPEN_CONFIRM_UNTIL_INDEX=17
usage() { echo "Usage: $0 [--start-index 6..17] [--low-open-confirm-until-index 0..17]"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --start-index) START_INDEX="$2"; shift 2 ;;
    --low-open-confirm-until-index) LOW_OPEN_CONFIRM_UNTIL_INDEX="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$START_INDEX" =~ ^[0-9]+$ ]] && [ "$START_INDEX" -ge 6 ] && [ "$START_INDEX" -le 17 ] || { echo "Invalid --start-index" >&2; exit 2; }
[[ "$LOW_OPEN_CONFIRM_UNTIL_INDEX" =~ ^[0-9]+$ ]] && [ "$LOW_OPEN_CONFIRM_UNTIL_INDEX" -le 17 ] || { echo "Invalid --low-open-confirm-until-index" >&2; exit 2; }
mkdir -p "$RUN_DIR" "$LOG_DIR" "$BACKUP_DIR"; cd "$ROOT"
exec > >(tee -a "$MASTER_LOG") 2>&1
log() { echo "[$(date '+%F %T')] $*"; }
status() { printf '%s\n' "$*" > "$STATUS_FILE"; }
backup() { local s="$1" d="$BACKUP_DIR/$1"; mkdir -p "$d"; for x in .xlsx _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do [ ! -f "$ROOT/data/$s$x" ] || cp -p "$ROOT/data/$s$x" "$d/"; done; }
post() {
  local i="$1" s="$2" st="$RUN_DIR/$2"
  local r="$st/$s"_result.csv; local o="$st/$s"_scan_result.csv; local p="$st/$s"_scan_ports.csv
  local l="$st/$s"_llm.csv; local c="$st/$s"_llm_checkpoint.jsonl; local f="$st/$s"_llm_最终版.xlsx
  log "[$i/17] LLM start: $s"
  python3 expand_scan_ports.py --input "$o" --output "$p"
  python3 scan_llm.py --input "$p" --output "$l" --checkpoint "$c" --config "$ROOT/llm_scan_rules.yaml"
  python3 finalize_llm_results.py "$l" --reported-source "$r" -o "$f"
  for x in _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do cp -p "$st/$s$x" "$ROOT/data/$s$x"; done
  touch "$st/COMPLETE"; log "[$i/17] complete: $s"
}
port() {
  local i="$1" s="$2" src="$3" st="$RUN_DIR/$2"
  local r="$st/$s"_result.csv; local o="$st/$s"_scan_result.csv; local a="$st/$s"_port_cache.json; local c="$st/$s"_port_checkpoint.jsonl
  if [ ! -f "$r" ]; then
    log "[$i/17] prepare: $s source=$src"; backup "$s"; mkdir -p "$st"; cp -p "$ROOT/data/$src" "$st/$s.xlsx"
    status "phase=rescan index=$i total=17 current=$s step=expand low_open_confirm=pending"
    python3 ip_ping_check.py --data-dir "$st/$s.xlsx" --output-dir "$st" --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 --skip-ping --dedup-ip --max-expand 2048 --expand-all
  else
    log "[$i/17] resume existing stage: $s"
  fi
  local n; n=$(( $(wc -l < "$r") - 1 )); local m=pn; local confirm=off; local confirm_args=()
  if [ "$n" -gt 50000 ]; then m=host-discovery; fi
  if [ "$i" -le "$LOW_OPEN_CONFIRM_UNTIL_INDEX" ]; then confirm=on; confirm_args+=(--low-open-confirm); fi
  status "phase=rescan index=$i total=17 current=$s step=ports ip_rows=$n mode=$m workers=16 min_rate=3000 max_retries=1 host_timeout=120s low_open_confirm=$confirm"
  log "[$i/17] port scan: $s ip_rows=$n mode=$m workers=16 min_rate=3000 max_retries=1 host_timeout=120s low_open_confirm=$confirm"
  if [ "$m" = host-discovery ]; then
    python3 ip_port_scan.py --input "$r" --output "$o" --cache "$a" --checkpoint "$c" --batch-size 500 --parallel-workers 16 --verify-workers 16 --min-rate 3000 --max-retries 1 --host-timeout 120s "${confirm_args[@]}" --host-discovery --resume
  else
    python3 ip_port_scan.py --input "$r" --output "$o" --cache "$a" --checkpoint "$c" --batch-size 500 --parallel-workers 16 --verify-workers 16 --min-rate 3000 --max-retries 1 --host-timeout 120s "${confirm_args[@]}" --resume
  fi
}
declare -A STEM=([6]=3电信湖南 [7]=3联通山西 [8]=3联通天津 [9]=3联通浙江 [10]=3联通重庆 [11]=3移动河南 [12]=3移动湖南 [13]=3移动江苏 [14]=3移动青海 [15]=3移动四川 [16]=3移动云南 [17]=3移动浙江)
declare -A SRC=([6]=3电信湖南.xlsx [7]=3联通山西.xlsx [8]=3联通天津.xlsx [9]=3联通浙江.xlsx [10]=3联通重庆.xlsx [11]=3移动河南.xlsx [12]=3移动湖南.xlsx [13]=3移动江苏.xlsx [14]=3移动青海.xlsx [15]=3移动四川.xlsx [16]=3移动云南.xlsx [17]=3移动浙江.xlsx)
prev_pid=""
trap '[ -z "$prev_pid" ] || kill "$prev_pid" 2>/dev/null || true; exit 130' INT TERM
log "config: start_index=$START_INDEX low_open_confirm_until_index=$LOW_OPEN_CONFIRM_UNTIL_INDEX"
for i in 6 7 8 9 10 11 12 13 14 15 16 17; do
  [ "$i" -lt "$START_INDEX" ] && continue
  s="${STEM[$i]}"; st="$RUN_DIR/$s"
  if [ -f "$st/COMPLETE" ]; then log "[$i/17] skip complete: $s"; continue; fi
  port "$i" "$s" "${SRC[$i]}"
  if [ -n "$prev_pid" ]; then wait "$prev_pid"; fi
  post "$i" "$s" & prev_pid=$!
done
if [ -n "$prev_pid" ]; then wait "$prev_pid"; fi
status "phase=complete current=none workers=16 min_rate=3000 max_retries=1 host_timeout=120s low_open_confirm_until_index=$LOW_OPEN_CONFIRM_UNTIL_INDEX"
touch "$LOG_DIR/COMPLETE"; log "configurable requested rescan pipeline complete"
