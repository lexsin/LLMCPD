#!/usr/bin/env bash
set -eEuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=refresh_telecom_gdj_20260813
RUN_DIR="$ROOT/data/$RUN_ID"
LOG_DIR="$ROOT/logs/$RUN_ID"
BACKUP_DIR="$ROOT/backups/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"
MASTER_LOG="$LOG_DIR/master.log"

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
  local stem="$2"
  local source_name="$3"
  local stage="$RUN_DIR/$stem"
  local source="$ROOT/data/$source_name"

  status "phase=refresh index=$index total=3 current=$stem step=prepare"
  log "[$index/3] start: $stem source=$source_name"
  backup_existing "$stem"
  mkdir -p "$stage"
  cp -p "$source" "$stage/$stem.csv"

  status "phase=refresh index=$index total=3 current=$stem step=expand"
  python3 ip_ping_check.py \
    --data-dir "$stage/$stem.csv" \
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

  status "phase=refresh index=$index total=3 current=$stem step=ports ip_rows=$rows mode=$mode"
  log "[$index/3] port scan: $stem ip_rows=$rows mode=$mode"
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

  status "phase=refresh index=$index total=3 current=$stem step=llm"
  python3 expand_scan_ports.py --input "$scan_result" --output "$scan_ports"
  python3 scan_llm.py --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" --config "$ROOT/llm_scan_rules.yaml"
  python3 finalize_llm_results.py "$llm" --reported-source "$result" -o "$final"

  cp -p "$stage/$stem.csv" "$ROOT/data/$stem.csv"
  for suffix in _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do
    cp -p "$stage/${stem}${suffix}" "$ROOT/data/${stem}${suffix}"
  done
  touch "$stage/COMPLETE"
  log "[$index/3] complete: $stem"
}

run_one 1 电信广东 source_refresh_guangdong.csv
run_one 2 电信甘肃 source_refresh_gansu.csv
run_one 3 电信吉林 source_refresh_jilin.csv

status "phase=complete current=none"
touch "$LOG_DIR/COMPLETE"
log "refresh pipeline complete"
