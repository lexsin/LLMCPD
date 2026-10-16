#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
ISO="$ROOT/strategy_v7_active_gpu_20260916"
SOURCE_RUN="${SOURCE_RUN:-rescan_first_batch_full_pipeline_20260913}"
SOURCE_DIR="$ROOT/data/$SOURCE_RUN"
OVERLAY_ID="${OVERLAY_ID:-${SOURCE_RUN}_active_gpu_overlay_v7_20260916}"
OUT_DIR="$ROOT/data/$OVERLAY_ID"
LOG_DIR="$ROOT/logs/$OVERLAY_ID"
STATUS_FILE="$LOG_DIR/status.txt"
MASTER_LOG="$LOG_DIR/master.log"
CONCURRENCY="${ACTIVE_GPU_CONCURRENCY:-4}"
TOKENS="${ACTIVE_GPU_TOKENS:-6}"
POLL_INTERVAL="${ACTIVE_GPU_POLL_INTERVAL:-0.5}"
METRICS_INTERVAL="${ACTIVE_GPU_METRICS_INTERVAL:-2}"
TIMEOUT_OBSERVATION="${ACTIVE_GPU_TIMEOUT_OBSERVATION:-300}"
DELAYED_SAMPLES="${ACTIVE_GPU_DELAYED_SAMPLES:-2,10}"
WAIT_SECONDS="${ACTIVE_GPU_WAIT_SECONDS:-60}"
REPORTED_TABLE="${REPORTED_IP_TABLE:-第二批上报算力}"
OVERALL_REPORT="$OUT_DIR/41家企业结果汇总_主动探测.xlsx"

mkdir -p "$OUT_DIR" "$LOG_DIR"
exec 9>"$OUT_DIR/runner.lock"
flock -n 9 || { echo "主动GPU补扫任务已在运行: $OUT_DIR/runner.lock" >&2; exit 1; }
exec > >(tee -a "$MASTER_LOG") 2>&1

log() { echo "[$(date '+%F %T')] $*"; }
status() {
  local temporary="$STATUS_FILE.tmp"
  printf '%s\n' "$*" > "$temporary"
  mv -f "$temporary" "$STATUS_FILE"
}

mapfile -t LOCATIONS < <(
  sqlite3 "$ROOT/data/llm_detect.sqlite3" \
    "select distinct location from source_ip_ranges order by location"
)
[ "${#LOCATIONS[@]}" -eq 41 ] || {
  echo "企业数量异常，期望41，实际${#LOCATIONS[@]}" >&2
  exit 1
}

source_result() {
  local source_stage="$1"
  if [ -s "$source_stage/input_llm_with_full_port.csv" ]; then
    printf '%s\n' "$source_stage/input_llm_with_full_port.csv"
  elif [ -s "$source_stage/input_llm_gpu_low_rechecked.csv" ]; then
    printf '%s\n' "$source_stage/input_llm_gpu_low_rechecked.csv"
  fi
  return 0
}

process_unit() {
  local index="$1" location="$2"
  local source_stage="$SOURCE_DIR/$location"
  local stage="$OUT_DIR/$location"
  mkdir -p "$stage"
  local source_csv
  source_csv="$(source_result "$source_stage")"
  if [ -z "$source_csv" ]; then
    local original_final
    original_final="$(find "$source_stage" -maxdepth 1 -type f -name '*最终版.xlsx' -print -quit)"
    if [ -n "$original_final" ]; then
      cp -f "$original_final" "$stage/${location}_llm_最终版_主动探测.xlsx"
    fi
    touch "$stage/COMPLETE"
    log "[$index/41] 无可主动探测的结果CSV，直接完成: $location"
    return 0
  fi
  local output_csv="$stage/input_llm_active_gpu_rechecked.csv"
  local checkpoint="$stage/active_gpu_recheck_checkpoint.jsonl"
  local assets="$stage/evidence_screenshots"
  local manifest="$assets/manifest.json"
  local final="$stage/${location}_llm_最终版_主动探测.xlsx"

  status "phase=active-gpu index=$index total=41 current=$location"
  python3 "$ISO/active_gpu_recheck.py" \
    --input "$source_csv" --output "$output_csv" \
    --checkpoint "$checkpoint" --assets "$assets" --manifest "$manifest" \
    --concurrency "$CONCURRENCY" --tokens "$TOKENS" \
    --poll-interval "$POLL_INTERVAL" --delayed-samples "$DELAYED_SAMPLES" \
    --metrics-interval "$METRICS_INTERVAL" \
    --timeout-observation "$TIMEOUT_OBSERVATION" \
    --resume

  status "phase=finalize index=$index total=41 current=$location"
  python3 "$ISO/finalize_llm_results.py" "$output_csv" \
    --screenshot-manifest "$manifest" --screenshot-manifest-only \
    -o "$final"
  [ -s "$final" ]
  touch "$stage/COMPLETE"
  log "[$index/41] 主动GPU补扫完成: $location"
}

while :; do
  progress=0
  waiting=0
  failed=0
  for index in "${!LOCATIONS[@]}"; do
    location="${LOCATIONS[$index]}"
    stage="$OUT_DIR/$location"
    if [ -f "$stage/COMPLETE" ]; then
      progress=$((progress + 1))
      continue
    fi
    if [ ! -f "$SOURCE_DIR/$location/COMPLETE" ]; then
      waiting=$((waiting + 1))
      continue
    fi
    if process_unit "$((index + 1))" "$location"; then
      progress=$((progress + 1))
      rm -f "$stage/FAILED"
    else
      rc=$?
      mkdir -p "$stage"
      printf 'rc=%d time=%s\n' "$rc" "$(date '+%F %T')" > "$stage/FAILED"
      failed=$((failed + 1))
      log "[$((index + 1))/41] 主动GPU补扫失败: $location rc=$rc"
    fi
  done
  progress=$(find "$OUT_DIR" -mindepth 2 -maxdepth 2 -name COMPLETE | wc -l)
  failed=$(find "$OUT_DIR" -mindepth 2 -maxdepth 2 -name FAILED | wc -l)
  if [ "$progress" -eq 41 ]; then
    status "phase=overall-summary total=41 complete=$progress failed=$failed current=none"
    python3 "$ISO/merge_completed_results.py" \
      --root "$OUT_DIR" --output "$OVERALL_REPORT" \
      --database "$ROOT/data/llm_detect.sqlite3" \
      --reported-table "$REPORTED_TABLE" \
      --result-suffix "_llm_最终版_主动探测.xlsx"
    [ -s "$OVERALL_REPORT" ] || { echo "总体汇总文件缺失或为空: $OVERALL_REPORT" >&2; exit 1; }
    status "phase=complete total=41 complete=$progress failed=$failed current=none"
    printf 'total=41\ncomplete=%d\nfailed=%d\nfinished=%s\n' \
      "$progress" "$failed" "$(date '+%F %T')" > "$LOG_DIR/SUMMARY"
    touch "$LOG_DIR/COMPLETE"
    log "41家主动GPU补扫全部完成"
    exit 0
  fi
  status "phase=waiting total=41 complete=$progress failed=$failed waiting_source=$waiting current=none"
  log "本轮完成=$progress，失败=$failed，等待原流水线=$waiting；${WAIT_SECONDS}秒后继续"
  sleep "$WAIT_SECONDS"
done
