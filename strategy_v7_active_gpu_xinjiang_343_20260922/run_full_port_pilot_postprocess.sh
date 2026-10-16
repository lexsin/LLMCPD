#!/usr/bin/env bash
set -Eeuo pipefail

WORK_DIR="${1:?work directory required}"
SCAN_PID="${2:?full-port scanner pid required}"
ISO="${3:-/home/lixiao/llm-detect/TEST/strategy_v5_fullport_20260911}"
LOG="$WORK_DIR/postprocess.log"
FINAL_XLSX="${FINAL_XLSX:-$WORK_DIR/pilot_final_最终版.xlsx}"

finalize_report() {
  echo "[$(date '+%F %T')] generating final workbook with screenshots"
  python3 "$ISO/finalize_llm_results.py" \
    "$WORK_DIR/pilot_final.csv" -o "$FINAL_XLSX"
  [ -s "$FINAL_XLSX" ] || {
    echo "final workbook missing or empty: $FINAL_XLSX" >&2
    return 1
  }
}

exec >>"$LOG" 2>&1
echo "[$(date '+%F %T')] waiting for full-port pid=$SCAN_PID"
while kill -0 "$SCAN_PID" 2>/dev/null; do
  sleep 30
done
echo "[$(date '+%F %T')] full-port process ended"

new_ports="$WORK_DIR/full_port_new_ports.csv"
if [ ! -s "$new_ports" ]; then
  echo "full-port output missing" >&2
  touch "$WORK_DIR/POSTPROCESS_FAILED"
  exit 1
fi

if [ "$(wc -l < "$new_ports")" -le 1 ]; then
  cp -f "$WORK_DIR/pilot_rechecked.csv" "$WORK_DIR/pilot_final.csv"
  python3 "$ISO/pilot_compare.py" \
    --baseline "$WORK_DIR/pilot_rechecked.csv" \
    --final "$WORK_DIR/pilot_final.csv" \
    --output "$WORK_DIR/pilot_comparison.json" \
    --text-output "$WORK_DIR/pilot_comparison.txt"
  finalize_report
  touch "$WORK_DIR/COMPLETE"
  echo "[$(date '+%F %T')] no new ports"
  exit 0
fi

python3 "$ISO/scan_llm.py" \
  --input "$new_ports" \
  --output "$WORK_DIR/full_port_new_llm.csv" \
  --checkpoint "$WORK_DIR/full_port_new_llm_checkpoint.jsonl" \
  --config "$ISO/llm_scan_rules.yaml" --resume

python3 "$ISO/gpu_low_recheck.py" \
  --input "$WORK_DIR/full_port_new_llm.csv" \
  --output "$WORK_DIR/full_port_new_llm_rechecked.csv" \
  --checkpoint "$WORK_DIR/full_port_new_gpu_checkpoint.jsonl" \
  --config "$ISO/llm_scan_rules.yaml" \
  --concurrency 20 --timeout 5 --resume

python3 "$ISO/merge_llm_results.py" \
  --base "$WORK_DIR/pilot_rechecked.csv" \
  --incremental "$WORK_DIR/full_port_new_llm_rechecked.csv" \
  --output "$WORK_DIR/pilot_final.csv"

python3 "$ISO/pilot_compare.py" \
  --baseline "$WORK_DIR/pilot_rechecked.csv" \
  --final "$WORK_DIR/pilot_final.csv" \
  --output "$WORK_DIR/pilot_comparison.json" \
  --text-output "$WORK_DIR/pilot_comparison.txt"

finalize_report
touch "$WORK_DIR/COMPLETE"
echo "[$(date '+%F %T')] postprocess complete"
