#!/usr/bin/env bash
set -eEuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=rescan_requested_20260813
RUN_DIR="$ROOT/data/$RUN_ID"
LOG_DIR="$ROOT/logs/$RUN_ID"
BACKUP_DIR="$ROOT/backups/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"
MASTER_LOG="$LOG_DIR/master.log"
WAIT_STATUS="$ROOT/logs/refresh_telecom_gdj_20260813/status.txt"
WAIT_DONE="$ROOT/logs/refresh_telecom_gdj_20260813/COMPLETE"

mkdir -p "$RUN_DIR" "$LOG_DIR" "$BACKUP_DIR"
cd "$ROOT"
exec > >(tee -a "$MASTER_LOG") 2>&1

log() { echo "[$(date '+%F %T')] $*"; }
status() { printf '%s\n' "$*" > "$STATUS_FILE"; }

backup_existing() {
  local stem="$1"
  local dir="$BACKUP_DIR/$stem"
  mkdir -p "$dir"
  for suffix in .xlsx _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do
    local file="$ROOT/data/${stem}${suffix}"
    [ ! -f "$file" ] || cp -p "$file" "$dir/"
  done
}

run_one() {
  local index="$1"
  local total="$2"
  local stem="$3"
  local source_name="$4"
  local stage="$RUN_DIR/$stem"
  local source="$ROOT/data/$source_name"

  status "phase=rescan index=$index total=$total current=$stem step=prepare"
  log "[$index/$total] start: $stem source=$source_name"
  backup_existing "$stem"
  mkdir -p "$stage"
  cp -p "$source" "$stage/$stem.xlsx"

  status "phase=rescan index=$index total=$total current=$stem step=expand"
  python3 ip_ping_check.py \
    --data-dir "$stage/$stem.xlsx" \
    --output-dir "$stage" \
    --col-start 起始IP \
    --col-end 终止IP \
    --col-unit 使用单位信息 \
    --skip-ping \
    --dedup-ip \
    --max-expand 2048 \
    --expand-all

  local result="$stage/${stem}_result.csv"
  local scan_result="$stage/${stem}_scan_result.csv"
  local cache="$stage/${stem}_port_cache.json"
  local checkpoint="$stage/${stem}_port_checkpoint.jsonl"
  local scan_ports="$stage/${stem}_scan_ports.csv"
  local llm="$stage/${stem}_llm.csv"
  local llm_checkpoint="$stage/${stem}_llm_checkpoint.jsonl"
  local final="$stage/${stem}_llm_最终版.xlsx"
  local rows=$(( $(wc -l < "$result") - 1 ))
  local mode=pn
  local extra=()
  if [ "$rows" -gt 50000 ]; then
    mode=host-discovery
    extra+=(--host-discovery)
  fi

  status "phase=rescan index=$index total=$total current=$stem step=ports ip_rows=$rows mode=$mode"
  log "[$index/$total] port scan: $stem ip_rows=$rows mode=$mode"
  python3 ip_port_scan.py \
    --input "$result" \
    --output "$scan_result" \
    --cache "$cache" \
    --checkpoint "$checkpoint" \
    --batch-size 500 \
    --parallel-workers 8 \
    --verify-workers 16 \
    --min-rate 1500 \
    --low-open-confirm \
    "${extra[@]}" \
    --resume

  status "phase=rescan index=$index total=$total current=$stem step=llm"
  python3 expand_scan_ports.py --input "$scan_result" --output "$scan_ports"
  python3 scan_llm.py --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" --config "$ROOT/llm_scan_rules.yaml"
  python3 finalize_llm_results.py "$llm" --reported-source "$result" -o "$final"

  for suffix in _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do
    cp -p "$stage/${stem}${suffix}" "$ROOT/data/${stem}${suffix}"
  done
  touch "$stage/COMPLETE"
  log "[$index/$total] complete: $stem"
}

status "phase=waiting current=电信广东/电信甘肃 detail=waiting_for_existing_refresh"
while [ ! -f "$WAIT_DONE" ]; do
  log "Waiting for existing refresh: $(cat "$WAIT_STATUS" 2>/dev/null || echo unknown)"
  sleep 60
done

run_one 1 17 2电信湖南 2电信湖南_2048.xlsx
run_one 2 17 2电信浙江 2电信浙江_2048.xlsx
run_one 3 17 中联网络北京 中联网络北京.xlsx
run_one 4 17 2中联网络河南 2中联网络河南_2048.xlsx
run_one 5 17 2中国移动广西 2中国移动广西_2048.xlsx
run_one 6 17 3电信湖南 3电信湖南.xlsx
run_one 7 17 3联通山西 3联通山西.xlsx
run_one 8 17 3联通天津 3联通天津.xlsx
run_one 9 17 3联通浙江 3联通浙江.xlsx
run_one 10 17 3联通重庆 3联通重庆.xlsx
run_one 11 17 3移动河南 3移动河南.xlsx
run_one 12 17 3移动湖南 3移动湖南.xlsx
run_one 13 17 3移动江苏 3移动江苏.xlsx
run_one 14 17 3移动青海 3移动青海.xlsx
run_one 15 17 3移动四川 3移动四川.xlsx
run_one 16 17 3移动云南 3移动云南.xlsx
run_one 17 17 3移动浙江 3移动浙江.xlsx

status "phase=complete current=none"
touch "$LOG_DIR/COMPLETE"
log "requested rescan pipeline complete"
