#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
ISO="$ROOT/strategy_v5_fullport_20260911"
RUN_ID=scan_batch2_source_policy_v5_fullport_20260911
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

mkdir -p "$RUN_DIR" "$LOG_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "Rerun already active: $LOCK_FILE" >&2; exit 1; }
exec >>"$MASTER_LOG" 2>&1
python3 "$ISO/screenshot_evidence.py" check

mapfile -t ALL_LOCATIONS < <(
  sqlite3 "$ROOT/data/llm_detect.sqlite3"     "select distinct location from source_ip_ranges_batch2 order by location"
)

declare -a LOCATIONS=()
for location in "${ALL_LOCATIONS[@]}"; do
  case "$location" in
    "2中国移动广东"|"2中国移动广西"|"2中国移动贵州"|"2电信四川"|"2电信浙江")
      continue
      ;;
  esac
  LOCATIONS+=("$location")
done

[ "${#ALL_LOCATIONS[@]}" -eq 47 ] || {
  echo "Expected 47 batch-2 enterprises, got ${#ALL_LOCATIONS[@]}" >&2
  exit 1
}
[ "${#LOCATIONS[@]}" -eq 42 ] || {
  echo "Expected 42 pending batch-2 enterprises, got ${#LOCATIONS[@]}" >&2
  exit 1
}

log() { echo "[$(date '+%F %T')] $*"; }
status() {
  local tmp="$STATUS_FILE.tmp"
  printf '%s\n' "$*" >"$tmp"
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
  local rechecked="$stage/input_llm_gpu_low_rechecked.csv"
  local gpu_checkpoint="$stage/gpu_low_recheck_checkpoint.jsonl"
  local final_input="$rechecked"
  local final="$stage/${location}_llm_最终版.xlsx"
  local mode=source-policy

  if [ -f "$stage/COMPLETE" ]; then
    log "[$index/$total] completed, skip: $location"
    return 0
  fi

  mkdir -p "$stage"
  status "phase=export index=$index total=$total current=$location attempt=$attempt"
  if [ ! -s "$input" ]; then
    python3 "$ISO/ip_source_db_batch2.py" export       --location "$location" --output "$input" || return $?
  fi

  status "phase=expand index=$index total=$total current=$location attempt=$attempt"
  if [ ! -s "$result" ]; then
    python3 "$ISO/ip_ping_check.py"       --data-dir "$input" --output-dir "$stage"       --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息       --skip-ping --dedup-ip --max-expand 2048 --expand-all || return $?
  fi

  local ip_rows=$(( $(wc -l <"$result") - 1 ))

  status "phase=ports index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/scan_ports_by_source_type.py" --source "$input" --input "$result" --output "$scan_result" --work-dir "$stage/source_type_port_scan" --scanner "$ISO/ip_port_scan.py" --batch-size 500 --parallel-workers 12 --verify-workers 12 --min-rate 3000 --max-retries 1 --host-timeout 120s || return $?
  status "phase=expand-ports index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  if ! python3 "$ISO/expand_scan_ports.py"       --input "$scan_result" --output "$scan_ports"; then
    status "phase=finalize-empty index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
    python3 "$ISO/finalize_llm_results.py" "$scan_result" \
      -o "$final" || return $?
    [ -s "$final" ] || { echo "empty final workbook missing or empty: $final" >&2; return 1; }
    touch "$stage/COMPLETE_EMPTY" "$stage/COMPLETE"
    log "[$index/$total] no open ports, complete: $location"
    return 0
  fi

  status "phase=llm-npu index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/scan_llm.py"     --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint"     --config "$ISO/llm_scan_rules.yaml" --resume || return $?

  status "phase=gpu-low-recheck index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/gpu_low_recheck.py"     --input "$llm" --output "$rechecked" --checkpoint "$gpu_checkpoint"     --config "$ISO/llm_scan_rules.yaml" --resume || return $?

  if [ "$FULL_PORT_SCAN" = "1" ]; then
    status "phase=full-port index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
    python3 "$ISO/full_port_recheck.py" \
      --ports-input "$scan_ports" --llm-input "$rechecked" \
      --output "$full_port_new" --checkpoint "$full_port_checkpoint" \
      --summary "$full_port_summary" --mode "$FULL_PORT_MODE" \
      --max-targets "$FULL_PORT_MAX_TARGETS" \
      --max-rate "$FULL_PORT_MAX_RATE" --min-rate "$FULL_PORT_MIN_RATE" \
      --workers "$FULL_PORT_WORKERS" \
      --max-retries "$FULL_PORT_MAX_RETRIES" \
      --host-timeout "$FULL_PORT_HOST_TIMEOUT" \
      --process-timeout "$FULL_PORT_PROCESS_TIMEOUT" \
      --resume || {
        rc=$?
        if [ "$rc" -ne 2 ]; then return "$rc"; fi
        log "[$index/$total] partial full-port failures; continue completed results: $location"
      }
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
      python3 "$ISO/merge_llm_results.py" \
        --base "$rechecked" --incremental "$full_port_llm_rechecked" \
        --output "$llm_merged" || return $?
      final_input="$llm_merged"
    fi
  fi

  status "phase=finalize index=$index total=$total current=$location attempt=$attempt ip_rows=$ip_rows mode=$mode"
  python3 "$ISO/finalize_llm_results.py" "$final_input" -o "$final" || return $?
  [ -s "$final" ] || { echo "final workbook missing or empty: $final" >&2; return 1; }

  touch "$stage/COMPLETE"
  log "[$index/$total] complete: $location ip_rows=$ip_rows mode=$mode"
}

log "Batch-2 scan started on $(hostname): total=${#LOCATIONS[@]}"
sha256sum "$ISO/ip_port_scan.py" "$ISO/scan_llm.py"   "$ISO/gpu_low_recheck.py" "$ISO/finalize_llm_results.py" "$ISO/screenshot_evidence.py"

declare -a FAILED=()
for i in "${!LOCATIONS[@]}"; do
  location="${LOCATIONS[$i]}"
  index="$((i + 1))"
  company_log="$LOG_DIR/$(printf '%02d' "$index")_${location}.log"
  if run_one "$index" "$location" 1 >>"$company_log" 2>&1; then
    :
  else
    rc=$?
    printf 'attempt=1 rc=%d time=%s\n' "$rc" "$(date '+%F %T')" >"$RUN_DIR/$location/FAILED"
    FAILED+=("$location")
    log "[$index/${#LOCATIONS[@]}] failed, continue: $location rc=$rc"
  fi
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  log "Retrying failed enterprises: ${#FAILED[@]}"
  for location in "${FAILED[@]}"; do
    index=0
    for i in "${!LOCATIONS[@]}"; do
      [ "${LOCATIONS[$i]}" != "$location" ] || index="$((i + 1))"
    done
    company_log="$LOG_DIR/$(printf '%02d' "$index")_${location}.log"
    if run_one "$index" "$location" 2 >>"$company_log" 2>&1; then
      mv -f "$RUN_DIR/$location/FAILED" "$RUN_DIR/$location/FAILED.attempt1" 2>/dev/null || true
    else
      rc=$?
      printf 'attempt=2 rc=%d time=%s\n' "$rc" "$(date '+%F %T')" >"$RUN_DIR/$location/FAILED"
      log "[$index/${#LOCATIONS[@]}] retry failed: $location rc=$rc"
    fi
  done
fi

complete=$(find "$RUN_DIR" -mindepth 2 -maxdepth 2 -name COMPLETE | wc -l)
failed=$(find "$RUN_DIR" -mindepth 2 -maxdepth 2 -name FAILED | wc -l)
status "phase=complete total=${#LOCATIONS[@]} complete=$complete failed=$failed current=none"
printf 'total=%d\ncomplete=%d\nfailed=%d\nfinished=%s\n'   "${#LOCATIONS[@]}" "$complete" "$failed" "$(date '+%F %T')" >"$LOG_DIR/SUMMARY"
touch "$LOG_DIR/COMPLETE"
log "Batch-2 scan finished: total=${#LOCATIONS[@]} complete=$complete failed=$failed"
