#!/usr/bin/env bash
set -euo pipefail
cd /home/lixiao/llm-detect/TEST || exit 1
mkdir -p logs scripts
MASTER_LOG="logs/run_3_prefix_pipeline_master.log"
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$MASTER_LOG"; }
count_rows(){
  local f="$1"
  if [ -f "$f" ]; then
    local n
    n=$(wc -l < "$f" || echo 0)
    if [ "$n" -gt 0 ]; then echo $((n-1)); else echo 0; fi
  else
    echo 0
  fi
}
run_one(){
  local xlsx="$1"
  local stem
  stem="$(basename "$xlsx" .xlsx)"
  local result="data/${stem}_result.csv"
  local scan_result="data/${stem}_scan_result.csv"
  local cache="data/${stem}_port_cache.json"
  local checkpoint="data/${stem}_port_checkpoint.jsonl"
  local scan_ports="data/${stem}_scan_ports.csv"
  local llm="data/${stem}_llm.csv"
  local llm_checkpoint="data/${stem}_llm_checkpoint.jsonl"
  local final="data/${stem}_llm_最终版.xlsx"
  local expand_log="logs/${stem}_expand.log"
  local port_log="logs/${stem}_port.log"
  local ports_log="logs/${stem}_expand_ports.log"
  local llm_log="logs/${stem}_llm.log"
  local final_log="logs/${stem}_finalize.log"

  log "===== start ${stem} ====="
  if [ -f "$final" ]; then
    log "${stem} final exists; skip"
    return 0
  fi

  if [ ! -f "$result" ]; then
    log "${stem} expand ip start --max-expand 2048 --expand-all"
    python3 ip_ping_check.py --data-dir "$xlsx" --output-dir data --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 --skip-ping --dedup-ip --max-expand 2048 --expand-all > "$expand_log" 2>&1
    log "${stem} expand ip done"
  else
    log "${stem} result exists; skip expand"
  fi

  local ip_rows
  ip_rows=$(count_rows "$result")
  local mode="pn"
  local extra=()
  if [ "$ip_rows" -gt 50000 ]; then
    mode="host-discovery"
    extra+=(--host-discovery)
  fi
  log "${stem} ip_rows=${ip_rows} mode=${mode}"

  if [ ! -f "$scan_result" ]; then
    log "${stem} port scan start"
    python3 ip_port_scan.py --input "$result" --output "$scan_result" --cache "$cache" --checkpoint "$checkpoint" --batch-size 500 --parallel-workers 4 --verify-workers 8 --min-rate 1000 --low-open-confirm "${extra[@]}" --resume > "$port_log" 2>&1
    log "${stem} port scan done"
  else
    log "${stem} scan_result exists; skip port scan"
  fi

  if [ ! -f "$scan_ports" ]; then
    log "${stem} expand_scan_ports start"
    python3 expand_scan_ports.py --input "$scan_result" --output "$scan_ports" > "$ports_log" 2>&1
    log "${stem} expand_scan_ports done"
  else
    log "${stem} scan_ports exists; skip expand_scan_ports"
  fi

  log "${stem} scan_llm start/resume"
  python3 scan_llm.py --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" --resume > "$llm_log" 2>&1
  log "${stem} finalize start"
  python3 finalize_llm_results.py "$llm" --reported-source "$result" -o "$final" > "$final_log" 2>&1
  log "${stem} final done: $final"
}

log "3-prefix pipeline runner started pid=$$"
while IFS= read -r xlsx; do
  run_one "$xlsx"
done < <(find data -maxdepth 1 -type f -name '3*.xlsx' | sort)
log "3-prefix pipeline runner finished"