#!/usr/bin/env bash
set -u
cd /home/lixiao/llm-detect/TEST || exit 1
mkdir -p logs
MASTER_LOG="logs/run_2048_remaining_master.log"
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$MASTER_LOG"; }

wait_existing_stem(){
  local stem="$1"
  while pgrep -af -- "$stem" | grep -E 'ip_port_scan.py|scan_llm.py|finalize_llm_results.py|expand_scan_ports.py' | grep -v grep >/dev/null; do
    log "waiting existing process for $stem"
    pgrep -af -- "$stem" | grep -E 'ip_port_scan.py|scan_llm.py|finalize_llm_results.py|expand_scan_ports.py' | grep -v grep | tee -a "$MASTER_LOG" || true
    sleep 120
  done
}

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
  local orig="$1"
  local mode="$2"
  local stem="${orig}_2048"
  local old_result="data/${orig}_result.csv"
  local result="data/${stem}_result.csv"
  local old_cache="data/${orig}_port_cache.json"
  local cache="data/${stem}_port_cache.json"
  local checkpoint="data/${stem}_port_checkpoint.jsonl"
  local scan_result="data/${stem}_scan_result.csv"
  local scan_ports="data/${stem}_scan_ports.csv"
  local llm="data/${stem}_llm.csv"
  local llm_checkpoint="data/${stem}_llm_checkpoint.jsonl"
  local final="data/${stem}_llm_最终版.xlsx"
  local port_log="logs/${stem}_port.log"
  local llm_log="logs/${stem}_llm.log"
  local final_log="logs/${stem}_finalize.log"

  log "===== start $stem mode=$mode ====="
  wait_existing_stem "$stem"

  if [ ! -f "$result" ]; then
    log "expand missing $result"
    python3 ip_ping_check.py --data-dir "data/${orig}.xlsx" --output-dir data --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 --skip-ping --dedup-ip --max-expand 2048 2>&1 | tee -a "$MASTER_LOG"
  fi

  local old_count new_count delta
  old_count=$(count_rows "$old_result")
  new_count=$(count_rows "$result")
  delta=$((new_count-old_count))
  log "$stem counts old=$old_count new=$new_count delta=$delta"

  if [ "$delta" -le 0 ]; then
    log "$stem unchanged; skip incremental scan"
    return 0
  fi

  if [ ! -f "$final" ]; then
    if [ ! -f "$scan_result" ]; then
      if [ -f "$old_cache" ] && [ ! -f "$cache" ]; then
        cp -f "$old_cache" "$cache"
        log "$stem copied old port cache"
      fi
      local extra=()
      if [ "$mode" = "host" ]; then extra+=(--host-discovery); fi
      log "$stem port scan start (${mode})"
      python3 ip_port_scan.py --input "$result" --output "$scan_result" --cache "$cache" --checkpoint "$checkpoint" --batch-size 500 --parallel-workers 8 --verify-workers 16 "${extra[@]}" --resume > "$port_log" 2>&1
      log "$stem port scan done"
    else
      log "$stem scan_result exists; skip port scan"
    fi

    if [ ! -f "$scan_ports" ]; then
      log "$stem expand_scan_ports start"
      python3 expand_scan_ports.py --input "$scan_result" --output "$scan_ports" 2>&1 | tee -a "$MASTER_LOG"
    fi

    log "$stem scan_llm start/resume"
    python3 scan_llm.py --input "$scan_ports" --output "$llm" --checkpoint "$llm_checkpoint" --resume > "$llm_log" 2>&1
    log "$stem finalize start"
    python3 finalize_llm_results.py "$llm" --reported-source "$result" -o "$final" > "$final_log" 2>&1
    log "$stem final done: $final"
  else
    log "$stem final exists; skip"
  fi
}

log "2048 remaining background runner started pid=$$"
wait_existing_stem "2电信浙江_2048"
if [ ! -f "data/2电信浙江_2048_llm_最终版.xlsx" ]; then
  run_one "2电信浙江" "pn"
else
  log "2电信浙江_2048 final already exists"
fi
run_one "2中国移动广东" "host"
run_one "2中联网络湖北" "pn"
run_one "2中联网络河南" "host"
log "2048 remaining background runner finished"