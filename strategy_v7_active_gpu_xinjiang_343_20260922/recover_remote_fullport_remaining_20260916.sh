#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=/home/lixiao/llm-detect/TEST
ISO="$ROOT/strategy_v6_remote_fullport_20260915"
RUN_ID=rescan_first_batch_full_pipeline_20260913
RUN_DIR="$ROOT/data/$RUN_ID"
CONFIG="$ROOT/config/full_port_remote_237.ini"
RECOVERY_LOG="$ROOT/logs/$RUN_ID/remote_fullport_remaining_20260916.log"
RECOVERY_STATUS="$ROOT/logs/$RUN_ID/remote_fullport_remaining_20260916.status"
declare -a UNITS=(
  '38|电信甘肃'
  '39|联通北京'
  '40|联通吉林'
)
exec > >(tee -a "$RECOVERY_LOG") 2>&1
log() { echo "[$(date '+%F %T')] $*"; }
for unit in "${UNITS[@]}"; do
  index="${unit%%|*}"
  location="${unit#*|}"
  stage="$RUN_DIR/$location"
  ports="$stage/input_scan_ports.csv"
  llm="$stage/input_llm_gpu_low_rechecked.csv"
  new_ports="$stage/full_port_new_ports.csv"
  checkpoint="$stage/full_port_checkpoint.jsonl"
  summary="$stage/full_port_summary.json"
  incremental_llm="$stage/full_port_new_llm.csv"
  incremental_checkpoint="$stage/full_port_new_llm_checkpoint.jsonl"
  incremental_gpu="$stage/full_port_new_llm_rechecked.csv"
  incremental_gpu_checkpoint="$stage/full_port_new_gpu_checkpoint.jsonl"
  merged="$stage/input_llm_with_full_port.csv"
  final="$stage/${location}_llm_最终版.xlsx"
  log "[$index/41] recovering remote full-port output: $location"
  printf 'phase=remote-full-port-recovery index=%s total=41 current=%s\n' "$index" "$location" > "$RECOVERY_STATUS"
  python3 "$ISO/remote_full_port_runner.py" \
    --config "$CONFIG" --worker-script "$ISO/full_port_recheck.py" \
    --run-id "$RUN_ID" --job-id "${index}_${location}" \
    --status-file "$RECOVERY_STATUS" \
    --status-prefix "phase=remote-full-port-recovery index=$index total=41 current=$location" \
    --ports-input "$ports" --llm-input "$llm" \
    --output "$new_ports" --checkpoint "$checkpoint" --summary "$summary" \
    --mode candidates --max-targets 50 --max-rate 200 --min-rate 100 --workers 6 \
    --max-retries 0 --host-timeout 40m --process-timeout 2700
  final_input="$llm"
  if [ -s "$new_ports" ] && [ "$(wc -l < "$new_ports")" -gt 1 ]; then
    log "[$index/41] incremental LLM and GPU review: $location"
    python3 "$ISO/scan_llm.py" --input "$new_ports" --output "$incremental_llm" --checkpoint "$incremental_checkpoint" --config "$ISO/llm_scan_rules.yaml" --resume
    python3 "$ISO/gpu_low_recheck.py" --input "$incremental_llm" --output "$incremental_gpu" --checkpoint "$incremental_gpu_checkpoint" --config "$ISO/llm_scan_rules.yaml" --concurrency 20 --timeout 5 --resume
    python3 "$ISO/merge_llm_results.py" --base "$llm" --incremental "$incremental_gpu" --output "$merged"
    final_input="$merged"
  fi
  log "[$index/41] finalizing with screenshots: $location"
  python3 "$ISO/finalize_llm_results.py" "$final_input" -o "$final"
  [ -s "$final" ] || { log "[$index/41] final workbook missing: $location"; exit 1; }
  rm -f "$stage/FAILED"
  touch "$stage/COMPLETE"
  log "[$index/41] recovered: $location"
done
log 'remote full-port recovery completed'
