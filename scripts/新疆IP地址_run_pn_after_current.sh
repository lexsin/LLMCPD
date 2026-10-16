#!/usr/bin/env bash
set -u
cd /home/lixiao/llm-detect/TEST || exit 1
mkdir -p logs
log(){ echo "[$(date '+%F %T')] $*" >> logs/新疆IP地址_pn_pipeline.log; }
log "wait current 新疆IP地址 pipeline"
while pgrep -af -- "新疆IP地址" | grep -E "ip_port_scan.py|scan_llm.py|finalize_llm_results.py|expand_scan_ports.py" | grep -v "_pn_" | grep -v grep >/dev/null; do
  sleep 300
done
log "start -Pn port scan"
python3 ip_port_scan.py --input data/新疆IP地址_result.csv --output data/新疆IP地址_pn_scan_result.csv --cache data/新疆IP地址_pn_port_cache.json --checkpoint data/新疆IP地址_pn_port_checkpoint.jsonl --batch-size 500 --parallel-workers 8 --verify-workers 16 --resume > logs/新疆IP地址_pn_port.log 2>&1 && \
log "expand ports" && \
python3 expand_scan_ports.py --input data/新疆IP地址_pn_scan_result.csv --output data/新疆IP地址_pn_scan_ports.csv > logs/新疆IP地址_pn_expand.log 2>&1 && \
log "scan llm" && \
python3 scan_llm.py --input data/新疆IP地址_pn_scan_ports.csv --output data/新疆IP地址_pn_llm.csv --checkpoint data/新疆IP地址_pn_llm_checkpoint.jsonl --resume > logs/新疆IP地址_pn_llm.log 2>&1 && \
log "finalize" && \
python3 finalize_llm_results.py data/新疆IP地址_pn_llm.csv --reported-source data/新疆IP地址_result.csv -o data/新疆IP地址_pn_llm_最终版.xlsx > logs/新疆IP地址_pn_finalize.log 2>&1 && \
log "done"