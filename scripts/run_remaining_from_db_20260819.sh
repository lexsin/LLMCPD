#!/usr/bin/env bash
set -eEuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=rescan_remaining_from_db_20260819
RUN_DIR="$ROOT/data/$RUN_ID"
LOG_DIR="$ROOT/logs/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"
LOCK_FILE="$RUN_DIR/runner.lock"

LOCATIONS=(
  "2中国移动广东"
  "2中国移动贵州"
  "2电信四川"
  "2联通安徽"
  "2联通河北"
  "2联通湖北"
  "2联通湖南"
  "3电信山东"
  "3电信黑龙江"
  "3移动内蒙"
  "3移动宁夏"
  "3移动山西"
  "3移动江西"
  "3移动河北"
  "3移动西藏"
  "3移动辽宁"
  "3移动陕西"
  "3移动黑龙江"
  "3联通吉林"
  "3联通江苏"
  "3联通陕西"
  "3联通青海"
  "联通吉林"
)

mkdir -p "$RUN_DIR" "$LOG_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "已有续扫任务正在运行: $LOCK_FILE" >&2; exit 1; }

log() { echo "[$(date '+%F %T')] $*"; }
status() { printf '%s\n' "$*" > "$STATUS_FILE"; }

run_one() {
  local index="$1" location="$2" total="${#LOCATIONS[@]}"
  local stage="$RUN_DIR/$location"
  local input="$stage/input.csv"
  local result="$stage/input_result.csv"
  local scan_result="$stage/input_scan_result.csv"
  local scan_ports="$stage/input_scan_ports.csv"
  local cache="$stage/input_port_cache.json"
  local checkpoint="$stage/input_port_checkpoint.jsonl"
  local llm="$stage/input_llm.csv"
  local llm_checkpoint="$stage/input_llm_checkpoint.jsonl"
  local final="$stage/${location}_llm_最终版.xlsx"
  local mode=pn
  local extra=()

  if [ -f "$stage/COMPLETE" ]; then
    log "[$index/$total] 跳过已完成: $location"
    return
  fi

  mkdir -p "$stage"
  status "phase=export index=$index total=$total current=$location"
  python3 "$ROOT/ip_source_db.py" export --location "$location" --output "$input"

  status "phase=expand index=$index total=$total current=$location"
  python3 "$ROOT/ip_ping_check.py" \
    --data-dir "$input" --output-dir "$stage" \
    --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 \
    --skip-ping --dedup-ip --max-expand 2048 --expand-all

  local ip_rows=$(( $(wc -l < "$result") - 1 ))
  if [ "$ip_rows" -gt 50000 ]; then
    mode=host-discovery
    extra+=(--host-discovery)
  fi
  status "phase=ports index=$index total=$total current=$location ip_rows=$ip_rows mode=$mode"
  python3 "$ROOT/ip_port_scan.py" \
    --input "$result" --output "$scan_result" --cache "$cache" --checkpoint "$checkpoint" \
    --batch-size 500 --parallel-workers 12 --verify-workers 12 --min-rate 3000 \
    --max-retries 1 --host-timeout 120s --low-open-confirm "${extra[@]}" --resume

  status "phase=expand-ports index=$index total=$total current=$location"
  set +e
  python3 "$ROOT/expand_scan_ports.py" --input "$scan_result" --output "$scan_ports"
  local expand_rc=$?
  set -e
  if [ "$expand_rc" -ne 0 ]; then
    log "[$index/$total] 无开放端口或端口展开失败，跳过 LLM/截图: $location"
    touch "$stage/COMPLETE"
    status "phase=complete-empty index=$index total=$total current=$location"
    return
  fi

  status "phase=llm index=$index total=$total current=$location"
  python3 "$ROOT/scan_llm.py" \
    --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" \
    --config "$ROOT/llm_scan_rules.yaml"
  python3 "$ROOT/finalize_llm_results.py" "$llm" --reported-source "$result" -o "$final"

  status "phase=screenshot index=$index total=$total current=$location"
  python3 "$ROOT/screenshot_evidence.py" retry-blank --input "$final" --output "$final" \
    --assets "$stage/screenshot_assets" || log "[$index/$total] 截图补空失败，保留最终版: $location"

  touch "$stage/COMPLETE"
  log "[$index/$total] 完成: $location"
}

for i in "${!LOCATIONS[@]}"; do
  run_one "$((i + 1))" "${LOCATIONS[$i]}"
done

status "phase=complete total=${#LOCATIONS[@]} current=none"
touch "$LOG_DIR/COMPLETE"
log "全部续扫完成"
