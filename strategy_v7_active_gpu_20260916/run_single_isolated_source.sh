#!/usr/bin/env bash
# Run one source file outside the first- and second-batch SQLite inventories.
set -Eeuo pipefail

ROOT=/home/lixiao/llm-detect/TEST
# Keep an isolated copy self-contained when it is run on another scanner.
ISO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RUN_ID="${RUN_ID:?set RUN_ID}"
LOCATION="${LOCATION:?set LOCATION}"
SOURCE_CSV="${SOURCE_CSV:?set SOURCE_CSV}"

RUN_DIR="$ROOT/data/$RUN_ID"
LOG_DIR="$ROOT/logs/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"
MASTER_LOG="$LOG_DIR/master.log"
STAGE="$RUN_DIR/$LOCATION"

FULL_PORT_SCAN="${FULL_PORT_SCAN:-1}"
FULL_PORT_MAX_TARGETS="${FULL_PORT_MAX_TARGETS:-50}"
FULL_PORT_MAX_RATE="${FULL_PORT_MAX_RATE:-200}"
FULL_PORT_MIN_RATE="${FULL_PORT_MIN_RATE:-100}"
FULL_PORT_WORKERS="${FULL_PORT_WORKERS:-6}"
ACTIVE_GPU_RECHECK="${ACTIVE_GPU_RECHECK:-1}"

mkdir -p "$STAGE" "$LOG_DIR"
exec 9>"$RUN_DIR/runner.lock"
flock -n 9 || { echo "独立扫描已在运行: $RUN_DIR/runner.lock" >&2; exit 1; }
exec > >(tee -a "$MASTER_LOG") 2>&1

status() {
  local tmp="$STATUS_FILE.tmp"
  printf '%s\n' "$*" > "$tmp"
  mv -f "$tmp" "$STATUS_FILE"
}

INPUT="$STAGE/input.csv"
EXPANDED="$STAGE/input_result.csv"
PORTS="$STAGE/input_scan_result.csv"
SCAN_PORTS="$STAGE/input_scan_ports.csv"
LLM="$STAGE/input_llm.csv"
LOW_RECHECKED="$STAGE/input_llm_gpu_low_rechecked.csv"
FULL_PORT_NEW="$STAGE/full_port_new_ports.csv"
FULL_PORT_LLM="$STAGE/full_port_new_llm.csv"
FULL_PORT_RECHECKED="$STAGE/full_port_new_llm_rechecked.csv"
MERGED="$STAGE/input_llm_with_full_port.csv"
ACTIVE="$STAGE/input_llm_active_gpu_rechecked.csv"
ASSETS="$STAGE/evidence_screenshots"
MANIFEST="$ASSETS/manifest.json"
FINAL="$STAGE/${LOCATION}_llm_最终版.xlsx"
FINAL_INPUT="$LOW_RECHECKED"

[ -f "$STAGE/COMPLETE" ] && { echo "已完成: $FINAL"; exit 0; }
[ -s "$SOURCE_CSV" ] || { echo "source CSV missing or empty: $SOURCE_CSV" >&2; exit 1; }
python3 "$ISO/screenshot_evidence.py" check

status "phase=prepare total=1 current=$LOCATION"
cp -f "$SOURCE_CSV" "$INPUT"

status "phase=expand total=1 current=$LOCATION"
if [ ! -s "$EXPANDED" ]; then
  python3 "$ISO/ip_ping_check.py" \
    --data-dir "$INPUT" --output-dir "$STAGE" \
    --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 \
    --skip-ping --dedup-ip --max-expand 2048 --expand-all
fi
IP_ROWS=$(( $(wc -l < "$EXPANDED") - 1 ))

status "phase=ports total=1 current=$LOCATION ip_rows=$IP_ROWS mode=source-type-policy"
# Below 50,000 expanded IPs every target is scanned with -Pn.  At or above
# that threshold only IPs supplied as explicit single-IP records use -Pn;
# range-derived IPs retain host discovery.  The splitter keeps independent
# checkpoints and merges both modes back into PORTS for subsequent stages.
python3 "$ISO/scan_ports_by_source_type.py" \
  --source "$INPUT" --input "$EXPANDED" --output "$PORTS" \
  --work-dir "$STAGE/port_scan_modes" --scanner "$ISO/ip_port_scan.py" \
  --batch-size 500 --parallel-workers 12 --verify-workers 12 --min-rate 3000 \
  --max-retries 1 --host-timeout 120s

status "phase=expand-ports total=1 current=$LOCATION ip_rows=$IP_ROWS"
if ! python3 "$ISO/expand_scan_ports.py" --input "$PORTS" --output "$SCAN_PORTS"; then
  status "phase=finalize-empty total=1 current=$LOCATION ip_rows=$IP_ROWS"
  python3 "$ISO/finalize_llm_results.py" "$PORTS" -o "$FINAL"
  touch "$STAGE/COMPLETE_EMPTY" "$STAGE/COMPLETE"
  status "phase=complete total=1 complete=1 failed=0 current=none"
  exit 0
fi

status "phase=llm-npu total=1 current=$LOCATION ip_rows=$IP_ROWS"
python3 "$ISO/scan_llm.py" \
  --input "$SCAN_PORTS" --output "$LLM" --checkpoint "$STAGE/input_llm_checkpoint.jsonl" \
  --config "$ISO/llm_scan_rules.yaml" --resume

status "phase=gpu-low-recheck total=1 current=$LOCATION ip_rows=$IP_ROWS"
python3 "$ISO/gpu_low_recheck.py" \
  --input "$LLM" --output "$LOW_RECHECKED" \
  --checkpoint "$STAGE/gpu_low_recheck_checkpoint.jsonl" \
  --config "$ISO/llm_scan_rules.yaml" --concurrency 20 --timeout 5 --resume

status "phase=evidence-screenshot total=1 current=$LOCATION ip_rows=$IP_ROWS"
python3 "$ISO/screenshot_evidence.py" capture-csv \
  --input "$LOW_RECHECKED" --assets "$ASSETS" --manifest "$MANIFEST"

if [ "$FULL_PORT_SCAN" = "1" ]; then
  status "phase=full-port total=1 current=$LOCATION ip_rows=$IP_ROWS"
  set +e
  python3 "$ISO/full_port_recheck.py" \
    --ports-input "$SCAN_PORTS" --llm-input "$LOW_RECHECKED" \
    --output "$FULL_PORT_NEW" --checkpoint "$STAGE/full_port_checkpoint.jsonl" \
    --summary "$STAGE/full_port_summary.json" --mode candidates \
    --max-targets "$FULL_PORT_MAX_TARGETS" --max-rate "$FULL_PORT_MAX_RATE" \
    --min-rate "$FULL_PORT_MIN_RATE" --workers "$FULL_PORT_WORKERS" \
    --max-retries 0 --host-timeout 40m --process-timeout 2700 --resume
  FULL_PORT_RC=$?
  set -e
  [ "$FULL_PORT_RC" -eq 0 ] || [ "$FULL_PORT_RC" -eq 2 ] || exit "$FULL_PORT_RC"
  if [ -s "$FULL_PORT_NEW" ] && [ "$(wc -l < "$FULL_PORT_NEW")" -gt 1 ]; then
    status "phase=full-port-llm total=1 current=$LOCATION ip_rows=$IP_ROWS"
    python3 "$ISO/scan_llm.py" \
      --input "$FULL_PORT_NEW" --output "$FULL_PORT_LLM" \
      --checkpoint "$STAGE/full_port_new_llm_checkpoint.jsonl" \
      --config "$ISO/llm_scan_rules.yaml" --resume
    python3 "$ISO/gpu_low_recheck.py" \
      --input "$FULL_PORT_LLM" --output "$FULL_PORT_RECHECKED" \
      --checkpoint "$STAGE/full_port_new_gpu_checkpoint.jsonl" \
      --config "$ISO/llm_scan_rules.yaml" --concurrency 20 --timeout 5 --resume
    python3 "$ISO/screenshot_evidence.py" capture-csv \
      --input "$FULL_PORT_RECHECKED" --assets "$ASSETS" --manifest "$MANIFEST"
    python3 "$ISO/merge_llm_results.py" \
      --base "$LOW_RECHECKED" --incremental "$FULL_PORT_RECHECKED" --output "$MERGED"
    FINAL_INPUT="$MERGED"
  fi
fi

if [ "$ACTIVE_GPU_RECHECK" = "1" ]; then
  status "phase=active-gpu-recheck total=1 current=$LOCATION ip_rows=$IP_ROWS"
  python3 "$ISO/active_gpu_recheck.py" \
    --input "$FINAL_INPUT" --output "$ACTIVE" \
    --checkpoint "$STAGE/active_gpu_recheck_checkpoint.jsonl" \
    --assets "$ASSETS" --manifest "$MANIFEST" \
    --concurrency 4 --tokens 6 --poll-interval 0.5 --metrics-interval 2 \
    --timeout-observation 300 --delayed-samples 2,10 --resume
  FINAL_INPUT="$ACTIVE"
fi

status "phase=evidence-screenshot-final total=1 current=$LOCATION ip_rows=$IP_ROWS"
python3 "$ISO/screenshot_evidence.py" capture-csv \
  --input "$FINAL_INPUT" --assets "$ASSETS" --manifest "$MANIFEST"
status "phase=finalize total=1 current=$LOCATION ip_rows=$IP_ROWS"
python3 "$ISO/finalize_llm_results.py" "$FINAL_INPUT" \
  --screenshot-manifest "$MANIFEST" -o "$FINAL"
[ -s "$FINAL" ]
touch "$STAGE/COMPLETE"
status "phase=complete total=1 complete=1 failed=0 current=none"
echo "完成: $FINAL"
