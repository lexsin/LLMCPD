#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=/home/lixiao/llm-detect/TEST
ISO="$ROOT/strategy_v7_active_gpu_20260916"
RUN_ID="${RUN_ID:-rescan_all_isolated_v7_active_gpu_20260916}"
EXPECTED_LOCATIONS="${EXPECTED_LOCATIONS:-41}"
RUN_DIR="$ROOT/data/$RUN_ID"
LOG_DIR="$ROOT/logs/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"
MASTER_LOG="$LOG_DIR/master.log"
LOCK_FILE="$RUN_DIR/runner.lock"
FULL_PORT_SCAN="${FULL_PORT_SCAN:-1}"
FULL_PORT_MODE="${FULL_PORT_MODE:-candidates}"
FULL_PORT_MAX_TARGETS="${FULL_PORT_MAX_TARGETS:-50}"
FULL_PORT_MAX_RATE="${FULL_PORT_MAX_RATE:-200}"
FULL_PORT_MIN_RATE="${FULL_PORT_MIN_RATE:-100}"
FULL_PORT_WORKERS="${FULL_PORT_WORKERS:-6}"
FULL_PORT_MAX_RETRIES="${FULL_PORT_MAX_RETRIES:-0}"
FULL_PORT_HOST_TIMEOUT="${FULL_PORT_HOST_TIMEOUT:-40m}"
FULL_PORT_PROCESS_TIMEOUT="${FULL_PORT_PROCESS_TIMEOUT:-2700}"
FULL_PORT_EXECUTOR="${FULL_PORT_EXECUTOR:-local}"
FULL_PORT_REMOTE_CONFIG="${FULL_PORT_REMOTE_CONFIG:-}"
ACTIVE_GPU_RECHECK="${ACTIVE_GPU_RECHECK:-1}"
ACTIVE_GPU_CONCURRENCY="${ACTIVE_GPU_CONCURRENCY:-4}"
ACTIVE_GPU_TOKENS="${ACTIVE_GPU_TOKENS:-6}"
ACTIVE_GPU_POLL_INTERVAL="${ACTIVE_GPU_POLL_INTERVAL:-0.5}"
ACTIVE_GPU_METRICS_INTERVAL="${ACTIVE_GPU_METRICS_INTERVAL:-2}"
ACTIVE_GPU_TIMEOUT_OBSERVATION="${ACTIVE_GPU_TIMEOUT_OBSERVATION:-300}"
ACTIVE_GPU_DELAYED_SAMPLES="${ACTIVE_GPU_DELAYED_SAMPLES:-2,10}"
mkdir -p "$RUN_DIR" "$LOG_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "已有全量隔离扫描任务运行中: $LOCK_FILE" >&2; exit 1; }
exec > >(tee -a "$MASTER_LOG") 2>&1
python3 "$ISO/screenshot_evidence.py" check
case "$FULL_PORT_EXECUTOR" in
  local|remote) ;;
  *) echo "FULL_PORT_EXECUTOR仅支持local或remote: $FULL_PORT_EXECUTOR" >&2; exit 1 ;;
esac
if [ "$FULL_PORT_SCAN" = "1" ] && [ "$FULL_PORT_EXECUTOR" = "remote" ]; then
  [ -n "$FULL_PORT_REMOTE_CONFIG" ] || {
    echo "远端全端口扫描需要FULL_PORT_REMOTE_CONFIG" >&2
    exit 1
  }
  python3 "$ISO/remote_full_port_runner.py" \
    --config "$FULL_PORT_REMOTE_CONFIG" \
    --worker-script "$ISO/full_port_recheck.py" \
    --run-id "$RUN_ID" --preflight
fi
mapfile -t LOCATIONS < <(
  sqlite3 "$ROOT/data/llm_detect.sqlite3" \
    "select distinct location from source_ip_ranges order by location"
)
[ "${#LOCATIONS[@]}" -eq "$EXPECTED_LOCATIONS" ] || {
  echo "基础企业数量异常，期望$EXPECTED_LOCATIONS，实际${#LOCATIONS[@]}" >&2
  exit 1
}
log() { echo "[$(date '+%F %T')] $*"; }
status() {
  local tmp="$STATUS_FILE.tmp"
  printf '%s\n' "$*" > "$tmp"
  mv -f "$tmp" "$STATUS_FILE"
}
run_one() {
  local index="$1" location="$2" attempt="$3" total="${#LOCATIONS[@]}"
  local stage="$RUN_DIR/$location"
  local input="$stage/input.csv"
  local result="$stage/input_result.csv"
  local scan_result="$stage/input_scan_result.csv"
  local scan_ports="$stage/input_scan_ports.csv"
  local cache="$stage/input_port_cache.json"
  local port_checkpoint="$stage/input_port_checkpoint.jsonl"
  local llm="$stage/input_llm.csv"
  local llm_checkpoint="$stage/input_llm_checkpoint.jsonl"
  local full_port_new="$stage/full_port_new_ports.csv"
  local full_port_checkpoint="$stage/full_port_checkpoint.jsonl"
  local full_port_summary="$stage/full_port_summary.json"
  local full_port_llm="$stage/full_port_new_llm.csv"
  local full_port_llm_checkpoint="$stage/full_port_new_llm_checkpoint.jsonl"
  local full_port_llm_rechecked="$stage/full_port_new_llm_rechecked.csv"
  local full_port_gpu_checkpoint="$stage/full_port_new_gpu_checkpoint.jsonl"
  local llm_merged="$stage/input_llm_with_full_port.csv"
  local llm_rechecked="$stage/input_llm_gpu_low_rechecked.csv"
  local gpu_low_checkpoint="$stage/gpu_low_recheck_checkpoint.jsonl"
  local active_gpu_output="$stage/input_llm_active_gpu_rechecked.csv"
  local active_gpu_checkpoint="$stage/active_gpu_recheck_checkpoint.jsonl"
  local evidence_assets="$stage/evidence_screenshots"
  local evidence_manifest="$evidence_assets/manifest.json"
  local final_input="$llm_rechecked"
  local final="$stage/${location}_llm_最终版.xlsx"
  local mode=pn
  local host_args=()
  [ ! -f "$stage/COMPLETE" ] || {
    log "[$index/$total] 已完成，跳过: $location"
    return 0
  }
  mkdir -p "$stage"
  rm -f "$stage/FAILED"
  status "phase=export index=$index total=$total current=$location attempt=$attempt"
  if [ ! -s "$input" ]; then
    python3 "$ISO/ip_source_db.py" export \
      --location "$location" --output "$input" || return $?
  fi
  status "phase=expand index=$index total=$total current=$location attempt=$attempt"
  if [ ! -s "$result" ]; then
    python3 "$ISO/ip_ping_check.py" \
      --data-dir "$input" --output-dir "$stage" \
      --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 \
      --skip-ping --dedup-ip --max-expand 2048 --expand-all || return $?
  fi
  local ip_rows=$(( $(wc -l < "$result") - 1 ))
  if [ "$ip_rows" -gt 50000 ]; then
    mode=host-discovery
    host_args+=(--host-discovery)
  fi
  status "phase=ports index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/ip_port_scan.py" \
    --input "$result" --output "$scan_result" --cache "$cache" \
    --checkpoint "$port_checkpoint" --batch-size 500 \
    --parallel-workers 12 --verify-workers 12 --min-rate 3000 \
    --max-retries 1 --host-timeout 120s \
    "${host_args[@]}" --resume || return $?
  status "phase=expand-ports index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  if ! python3 "$ISO/expand_scan_ports.py" \
      --input "$scan_result" --output "$scan_ports"; then
    status "phase=finalize-empty index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
    python3 "$ISO/finalize_llm_results.py" "$scan_result" \
      -o "$final" || return $?
    [ -s "$final" ] || { echo "空结果汇总文件缺失或为空: $final" >&2; return 1; }
    touch "$stage/COMPLETE_EMPTY" "$stage/COMPLETE"
    log "[$index/$total] 无开放端口，完成: $location"
    return 0
  fi
  status "phase=llm-npu index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/scan_llm.py" \
    --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" \
    --config "$ISO/llm_scan_rules.yaml" --resume || return $?
  status "phase=gpu-low-recheck index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/gpu_low_recheck.py" \
    --input "$llm" --output "$llm_rechecked" \
    --checkpoint "$gpu_low_checkpoint" \
    --config "$ISO/llm_scan_rules.yaml" \
    --concurrency 20 --timeout 5 --resume || return $?
  status "phase=evidence-screenshot index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/screenshot_evidence.py" capture-csv \
    --input "$llm_rechecked" --assets "$evidence_assets" \
    --manifest "$evidence_manifest" || return $?
  if [ "$FULL_PORT_SCAN" = "1" ]; then
    local full_port_rc=0
    if [ "$FULL_PORT_EXECUTOR" = "remote" ]; then
      status "phase=full-port-remote index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode remote_state=starting"
      if python3 "$ISO/remote_full_port_runner.py" \
        --config "$FULL_PORT_REMOTE_CONFIG" \
        --worker-script "$ISO/full_port_recheck.py" \
        --run-id "$RUN_ID" --job-id "${index}_${location}" \
        --status-file "$STATUS_FILE" \
        --status-prefix "phase=full-port-remote index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode" \
        --ports-input "$scan_ports" --llm-input "$llm_rechecked" \
        --output "$full_port_new" --checkpoint "$full_port_checkpoint" \
        --summary "$full_port_summary" --mode "$FULL_PORT_MODE" \
        --max-targets "$FULL_PORT_MAX_TARGETS" \
        --max-rate "$FULL_PORT_MAX_RATE" --min-rate "$FULL_PORT_MIN_RATE" \
        --workers "$FULL_PORT_WORKERS" \
        --max-retries "$FULL_PORT_MAX_RETRIES" \
        --host-timeout "$FULL_PORT_HOST_TIMEOUT" \
        --process-timeout "$FULL_PORT_PROCESS_TIMEOUT"; then
        full_port_rc=0
      else
        full_port_rc=$?
      fi
    else
      status "phase=full-port index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
      if python3 "$ISO/full_port_recheck.py" \
        --ports-input "$scan_ports" --llm-input "$llm_rechecked" \
        --output "$full_port_new" --checkpoint "$full_port_checkpoint" \
        --summary "$full_port_summary" --mode "$FULL_PORT_MODE" \
        --max-targets "$FULL_PORT_MAX_TARGETS" \
        --max-rate "$FULL_PORT_MAX_RATE" --min-rate "$FULL_PORT_MIN_RATE" \
        --workers "$FULL_PORT_WORKERS" \
        --max-retries "$FULL_PORT_MAX_RETRIES" \
        --host-timeout "$FULL_PORT_HOST_TIMEOUT" \
        --process-timeout "$FULL_PORT_PROCESS_TIMEOUT" \
        --resume; then
        full_port_rc=0
      else
        full_port_rc=$?
      fi
    fi
    if [ "$full_port_rc" -ne 0 ]; then
      if [ "$full_port_rc" -ne 2 ]; then return "$full_port_rc"; fi
      log "[$index/$total] 部分全端口候选失败或超时，继续处理已完成结果: $location"
    fi
    if [ -s "$full_port_new" ] && [ "$(wc -l < "$full_port_new")" -gt 1 ]; then
      status "phase=full-port-llm index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
      python3 "$ISO/scan_llm.py" \
        --input "$full_port_new" --output "$full_port_llm" \
        --checkpoint "$full_port_llm_checkpoint" \
        --config "$ISO/llm_scan_rules.yaml" --resume || return $?
      python3 "$ISO/gpu_low_recheck.py" \
        --input "$full_port_llm" --output "$full_port_llm_rechecked" \
        --checkpoint "$full_port_gpu_checkpoint" \
        --config "$ISO/llm_scan_rules.yaml" \
        --concurrency 20 --timeout 5 --resume || return $?
      python3 "$ISO/screenshot_evidence.py" capture-csv \
        --input "$full_port_llm_rechecked" --assets "$evidence_assets" \
        --manifest "$evidence_manifest" || return $?
      python3 "$ISO/merge_llm_results.py" \
        --base "$llm_rechecked" --incremental "$full_port_llm_rechecked" \
        --output "$llm_merged" || return $?
      final_input="$llm_merged"
    fi
  fi
  if [ "$ACTIVE_GPU_RECHECK" = "1" ]; then
    status "phase=active-gpu-recheck index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
    python3 "$ISO/active_gpu_recheck.py" \
      --input "$final_input" --output "$active_gpu_output" \
      --checkpoint "$active_gpu_checkpoint" \
      --assets "$evidence_assets" --manifest "$evidence_manifest" \
      --concurrency "$ACTIVE_GPU_CONCURRENCY" \
      --tokens "$ACTIVE_GPU_TOKENS" \
      --poll-interval "$ACTIVE_GPU_POLL_INTERVAL" \
      --metrics-interval "$ACTIVE_GPU_METRICS_INTERVAL" \
      --timeout-observation "$ACTIVE_GPU_TIMEOUT_OBSERVATION" \
      --delayed-samples "$ACTIVE_GPU_DELAYED_SAMPLES" \
      --resume || return $?
    final_input="$active_gpu_output"
  fi
  python3 "$ISO/screenshot_evidence.py" capture-csv \
    --input "$final_input" --assets "$evidence_assets" \
    --manifest "$evidence_manifest" || return $?
  status "phase=finalize index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/finalize_llm_results.py" "$final_input" \
    --screenshot-manifest "$evidence_manifest" \
    -o "$final" || return $?
  [ -s "$final" ] || { echo "最终汇总文件缺失或为空: $final" >&2; return 1; }
  touch "$stage/COMPLETE"
  log "[$index/$total] 完成: $location ip_rows=$ip_rows mode=$mode"
}
declare -a FAILED=()
for i in "${!LOCATIONS[@]}"; do
  location="${LOCATIONS[$i]}"
  if run_one "$((i + 1))" "$location" 1; then
    :
  else
    rc=$?
    printf '%s\n' "attempt=1 rc=$rc time=$(date '+%F %T')" > "$RUN_DIR/$location/FAILED"
    FAILED+=("$location")
    log "[$((i + 1))/${#LOCATIONS[@]}] 首次失败，继续下一家: $location rc=$rc"
  fi
done
if [ "${#FAILED[@]}" -gt 0 ]; then
  log "开始断点重试失败企业，数量=${#FAILED[@]}"
  for location in "${FAILED[@]}"; do
    index=0
    for i in "${!LOCATIONS[@]}"; do
      [ "${LOCATIONS[$i]}" != "$location" ] || index="$((i + 1))"
    done
    if run_one "$index" "$location" 2; then
      rm -f "$RUN_DIR/$location/FAILED"
      log "[$index/${#LOCATIONS[@]}] retry succeeded: $location"
    else
      rc=$?
      printf '%s\n' "attempt=2 rc=$rc time=$(date '+%F %T')" > "$RUN_DIR/$location/FAILED"
      log "[$index/${#LOCATIONS[@]}] 重试失败: $location rc=$rc"
    fi
  done
fi
complete=$(find "$RUN_DIR" -mindepth 2 -maxdepth 2 -name COMPLETE | wc -l)
failed=$(find "$RUN_DIR" -mindepth 2 -maxdepth 2 -name FAILED | wc -l)
status "phase=complete total=${#LOCATIONS[@]} complete=$complete failed=$failed current=none"
printf 'total=%d\ncomplete=%d\nfailed=%d\nfinished=%s\n' \
  "${#LOCATIONS[@]}" "$complete" "$failed" "$(date '+%F %T')" > "$LOG_DIR/SUMMARY"
touch "$LOG_DIR/COMPLETE"
log "全量隔离扫描结束: total=${#LOCATIONS[@]} complete=$complete failed=$failed"
