#!/usr/bin/env bash
set -eEuo pipefail
ROOT=/home/lixiao/llm-detect/TEST
RUN_ID=rescan_requested_20260813
RUN_DIR="$ROOT/data/$RUN_ID"; LOG_DIR="$ROOT/logs/$RUN_ID"; BACKUP_DIR="$ROOT/backups/$RUN_ID"
STATUS_FILE="$LOG_DIR/status.txt"; MASTER_LOG="$LOG_DIR/master_accelerated_20260817.log"
mkdir -p "$RUN_DIR" "$LOG_DIR" "$BACKUP_DIR"; cd "$ROOT"
exec > >(tee -a "$MASTER_LOG") 2>&1
log(){ echo "[$(date '+%F %T')] $*"; }
status(){ printf '%s\n' "$*" > "$STATUS_FILE"; }
backup(){ local s=$1 d="$BACKUP_DIR/$1"; mkdir -p "$d"; for x in .xlsx _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do [ ! -f "$ROOT/data/$s$x" ] || cp -p "$ROOT/data/$s$x" "$d/"; done; }
post(){ local i=$1 s=$2 st="$RUN_DIR/$2"; local r="$st/$s"_result.csv o="$st/$s"_scan_result.csv p="$st/$s"_scan_ports.csv l="$st/$s"_llm.csv c="$st/$s"_llm_checkpoint.jsonl f="$st/$s"_llm_最终版.xlsx; log "[$i/17] LLM start: $s"; python3 expand_scan_ports.py --input "$o" --output "$p"; python3 scan_llm.py --input "$p" --output "$l" --checkpoint "$c" --config "$ROOT/llm_scan_rules.yaml"; python3 finalize_llm_results.py "$l" --reported-source "$r" -o "$f"; for x in _result.csv _scan_result.csv _scan_ports.csv _port_cache.json _port_checkpoint.jsonl _llm.csv _llm_checkpoint.jsonl _llm_最终版.xlsx; do cp -p "$st/$s$x" "$ROOT/data/$s$x"; done; touch "$st/COMPLETE"; log "[$i/17] complete: $s"; }
port(){
  local i=$1 s=$2 src="${3:-}" st="$RUN_DIR/$2"
  if [ -n "$src" ]; then log "[$i/17] prepare: $s"; backup "$s"; mkdir -p "$st"; cp -p "$ROOT/data/$src" "$st/$s.xlsx"; status "phase=rescan index=$i total=17 current=$s step=expand"; python3 ip_ping_check.py --data-dir "$st/$s.xlsx" --output-dir "$st" --col-start 起始IP --col-end 终止IP --col-unit 使用单位信息 --skip-ping --dedup-ip --max-expand 2048 --expand-all; fi
  local r="$st/$s"_result.csv o="$st/$s"_scan_result.csv a="$st/$s"_port_cache.json c="$st/$s"_port_checkpoint.jsonl m=pn; local n; n=$(( $(wc -l < "$r") - 1 ))
  if [ "$n" -gt 50000 ]; then m=host-discovery; fi
  status "phase=rescan index=$i total=17 current=$s step=ports ip_rows=$n mode=$m workers=12 min_rate=2000"
  log "[$i/17] port scan: $s ip_rows=$n mode=$m workers=12 min_rate=2000"
  if [ "$m" = host-discovery ]; then python3 ip_port_scan.py --input "$r" --output "$o" --cache "$a" --checkpoint "$c" --batch-size 500 --parallel-workers 12 --verify-workers 16 --min-rate 2000 --low-open-confirm --host-discovery --resume; else python3 ip_port_scan.py --input "$r" --output "$o" --cache "$a" --checkpoint "$c" --batch-size 500 --parallel-workers 12 --verify-workers 16 --min-rate 2000 --low-open-confirm --resume; fi
}
llm_pid=""
trap '[ -z "$llm_pid" ] || kill "$llm_pid" 2>/dev/null || true; exit 130' INT TERM
port 6 3电信湖南
post 6 3电信湖南 & llm_pid=$!
while IFS="|" read -r i s x; do
  port "$i" "$s" "$x"; wait "$llm_pid"; post "$i" "$s" & llm_pid=$!
done <<'TASKS'
7|3联通山西|3联通山西.xlsx
8|3联通天津|3联通天津.xlsx
9|3联通浙江|3联通浙江.xlsx
10|3联通重庆|3联通重庆.xlsx
11|3移动河南|3移动河南.xlsx
12|3移动湖南|3移动湖南.xlsx
13|3移动江苏|3移动江苏.xlsx
14|3移动青海|3移动青海.xlsx
15|3移动四川|3移动四川.xlsx
16|3移动云南|3移动云南.xlsx
17|3移动浙江|3移动浙江.xlsx
TASKS
wait "$llm_pid"
status "phase=complete current=none workers=12 min_rate=2000 llm_overlap=enabled"
touch "$LOG_DIR/COMPLETE"; log "accelerated requested rescan pipeline complete"
