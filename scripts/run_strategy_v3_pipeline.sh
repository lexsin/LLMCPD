#!/usr/bin/env bash
set -eEuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=strategy_v3_20260802
RUN_DIR="$ROOT/data/$RUN_ID"
REPROCESS_DIR="$RUN_DIR/reprocess"
PORT_DIR="$RUN_DIR/port_rescan"
LOG_DIR="$ROOT/logs/$RUN_ID"
BACKUP_DIR="$ROOT/backups/$RUN_ID"
MASTER_LOG="$LOG_DIR/master.log"
STATUS_FILE="$LOG_DIR/status.txt"

mkdir -p "$REPROCESS_DIR" "$PORT_DIR" "$LOG_DIR" \
  "$BACKUP_DIR/reprocess" "$BACKUP_DIR/port_rescan"
cd "$ROOT"

exec > >(tee -a "$MASTER_LOG") 2>&1

log() {
  echo "[$(date '+%F %T')] $*"
}

set_status() {
  printf '%s\n' "$*" > "$STATUS_FILE"
}

on_error() {
  code=$?
  log "FAILED code=$code status=$(cat "$STATUS_FILE" 2>/dev/null || true)"
  exit "$code"
}
trap on_error ERR

count_rows() {
  lines=$(wc -l < "$1")
  if [ "$lines" -gt 0 ]; then
    echo $((lines - 1))
  else
    echo 0
  fi
}

backup_file() {
  source_path="$1"
  target_dir="$2"
  if [ -f "$source_path" ]; then
    mkdir -p "$target_dir"
    target_path="$target_dir/$(basename "$source_path")"
    if [ ! -e "$target_path" ]; then
      cp -p --reflink=auto "$source_path" "$target_path"
    fi
  fi
}

log "strategy v3 pipeline started pid=$$"
set_status "phase=reprocess current=initializing"

# Preserve the current classification outputs before replacing them.
for file in data/3*_llm.csv data/3*_llm_最终版.xlsx data/3*_llm_checkpoint.jsonl; do
  [ -e "$file" ] || continue
  backup_file "$file" "$BACKUP_DIR/reprocess"
done

mapfile -t scan_port_files < <(find data -maxdepth 1 -type f -name '3*_scan_ports.csv' | sort)
total=${#scan_port_files[@]}
index=0

for scan_ports in "${scan_port_files[@]}"; do
  index=$((index + 1))
  stem=$(basename "$scan_ports" _scan_ports.csv)
  set_status "phase=reprocess index=$index total=$total current=$stem"
  log "[$index/$total] reprocess start: $stem"

  llm_stage="$REPROCESS_DIR/${stem}_llm.csv"
  checkpoint_stage="$REPROCESS_DIR/${stem}_llm_checkpoint.jsonl"
  final_stage="$REPROCESS_DIR/${stem}_llm_最终版.xlsx"

  if [ -f "$llm_stage" ] && [ -f "$final_stage" ]; then
    cp -p "$llm_stage" "$ROOT/data/${stem}_llm.csv"
    [ ! -f "$checkpoint_stage" ] || cp -p "$checkpoint_stage" "$ROOT/data/${stem}_llm_checkpoint.jsonl"
    cp -p "$final_stage" "$ROOT/data/${stem}_llm_最终版.xlsx"
    log "[$index/$total] reprocess reused: $stem"
    continue
  fi

  if [ "$(count_rows "$scan_ports")" -eq 0 ]; then
    log "[$index/$total] reprocess skipped (no open ports): $stem"
    continue
  fi

  python3 scan_llm.py \
    --input "$ROOT/$scan_ports" \
    --output "$llm_stage" \
    --checkpoint "$checkpoint_stage" \
    --config "$ROOT/llm_scan_rules.yaml"

  python3 finalize_llm_results.py "$llm_stage" \
    --reported-source "$ROOT/data/${stem}_result.csv" \
    -o "$final_stage"

  cp -p "$llm_stage" "$ROOT/data/${stem}_llm.csv"
  cp -p "$checkpoint_stage" "$ROOT/data/${stem}_llm_checkpoint.jsonl"
  cp -p "$final_stage" "$ROOT/data/${stem}_llm_最终版.xlsx"
  log "[$index/$total] reprocess complete: $stem"
done

provinces=(3电信湖南 3联通青海 3联通天津 3移动河北 3联通山西)
province_total=${#provinces[@]}
province_index=0

for stem in "${provinces[@]}"; do
  province_index=$((province_index + 1))
  set_status "phase=port_rescan index=$province_index total=$province_total current=$stem step=expand"
  log "[$province_index/$province_total] full expansion start: $stem"

  province_dir="$PORT_DIR/$stem"
  mkdir -p "$province_dir"
  if [ -f "$province_dir/COMPLETE" ]; then
    log "[$province_index/$province_total] full rescan reused: $stem"
    continue
  fi
  python3 ip_ping_check.py \
    --data-dir "$ROOT/data/${stem}.xlsx" \
    --output-dir "$province_dir" \
    --col-start 起始IP \
    --col-end 终止IP \
    --col-unit 使用单位信息 \
    --skip-ping \
    --dedup-ip \
    --max-expand 2048 \
    --expand-all

  full_result="$province_dir/${stem}_result.csv"
  scan_result="$province_dir/${stem}_scan_result.csv"
  cache="$province_dir/${stem}_port_cache.json"
  checkpoint="$province_dir/${stem}_port_checkpoint.jsonl"
  scan_ports="$province_dir/${stem}_scan_ports.csv"
  llm="$province_dir/${stem}_llm.csv"
  llm_checkpoint="$province_dir/${stem}_llm_checkpoint.jsonl"
  final="$province_dir/${stem}_llm_最终版.xlsx"

  if [ ! -f "$cache" ] && [ -f "$ROOT/data/${stem}_port_cache.json" ]; then
    cp -p "$ROOT/data/${stem}_port_cache.json" "$cache"
  fi

  ip_rows=$(count_rows "$full_result")
  mode=pn
  extra=()
  if [ "$ip_rows" -gt 50000 ]; then
    mode=host-discovery
    extra+=(--host-discovery)
  fi
  set_status "phase=port_rescan index=$province_index total=$province_total current=$stem step=ports ip_rows=$ip_rows mode=$mode"
  log "[$province_index/$province_total] port scan start: $stem ip_rows=$ip_rows mode=$mode"

  python3 ip_port_scan.py \
    --input "$full_result" \
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

  set_status "phase=port_rescan index=$province_index total=$province_total current=$stem step=llm"
  python3 expand_scan_ports.py --input "$scan_result" --output "$scan_ports"
  python3 scan_llm.py \
    --input "$scan_ports" \
    --output "$llm" \
    --checkpoint "$llm_checkpoint" \
    --config "$ROOT/llm_scan_rules.yaml"
  python3 finalize_llm_results.py "$llm" \
    --reported-source "$full_result" \
    -o "$final"

  province_backup="$BACKUP_DIR/port_rescan/$stem"
  for suffix in result.csv scan_result.csv port_cache.json port_checkpoint.jsonl scan_ports.csv llm.csv llm_checkpoint.jsonl llm_最终版.xlsx; do
    backup_file "$ROOT/data/${stem}_$suffix" "$province_backup"
  done

  cp -p "$full_result" "$ROOT/data/${stem}_result.csv"
  cp -p "$scan_result" "$ROOT/data/${stem}_scan_result.csv"
  cp -p "$cache" "$ROOT/data/${stem}_port_cache.json"
  cp -p "$checkpoint" "$ROOT/data/${stem}_port_checkpoint.jsonl"
  cp -p "$scan_ports" "$ROOT/data/${stem}_scan_ports.csv"
  cp -p "$llm" "$ROOT/data/${stem}_llm.csv"
  cp -p "$llm_checkpoint" "$ROOT/data/${stem}_llm_checkpoint.jsonl"
  cp -p "$final" "$ROOT/data/${stem}_llm_最终版.xlsx"
  touch "$province_dir/COMPLETE"
  log "[$province_index/$province_total] full rescan complete: $stem"
done

set_status "phase=complete current=none"
touch "$LOG_DIR/COMPLETE"
log "strategy v3 pipeline complete"
