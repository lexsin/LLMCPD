#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE_DIR"

PY="/root/miniconda3/envs/xgb-lx/bin/python"
DATA_DIR="$BASE_DIR/data"
LOG_DIR="$BASE_DIR/logs"
INPUT="$DATA_DIR/xinjian2.xlsx"
OLD_INPUT="$DATA_DIR/xinjiangIP.xlsx"
NEW_IPS="$DATA_DIR/xinjiang2_new_ips.csv"
SCAN_OUT="$DATA_DIR/xinjiang2_scan_result.csv"
EXPANDED="$DATA_DIR/xinjiang2_expanded.csv"
LLM_OUT="$DATA_DIR/xinjiang2_llm.csv"
PORT_CACHE="$DATA_DIR/xinjiang2_port_cache.json"
PORT_CKPT="$DATA_DIR/xinjiang2_port_checkpoint.jsonl"
PORT_TMP="$DATA_DIR/xinjiang2_scan_tmp"
LLM_CKPT="$DATA_DIR/xinjiang2_llm_checkpoint.jsonl"
WATCH_LOG="$LOG_DIR/xinjiang2_watch.log"
PORT_LOG="$LOG_DIR/xinjiang2_port_scan.log"
LLM_LOG="$LOG_DIR/xinjiang2_llm_scan.log"
LOCK="$BASE_DIR/xinjiang2_watch.lock"

mkdir -p "$LOG_DIR" "$PORT_TMP"
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "watch already running: $LOCK" >&2
    exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

log() {
    printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$WATCH_LOG"
}

count_lines() {
    if [[ -f "$1" ]]; then wc -l < "$1"; else echo 0; fi
}

log "阶段 1/4：展开 xinjiang2 并剔除 xinjiangIP.xlsx 已扫描 IP"
"$PY" generate_xinjiang2_new_ips.py \
    --new "$INPUT" --old "$OLD_INPUT" --output "$NEW_IPS" | tee -a "$WATCH_LOG"

expected=$(( $(count_lines "$NEW_IPS") - 1 ))
if (( expected <= 0 )); then
    log "没有新增 IP，结束"
    exit 0
fi

log "阶段 2/4：端口扫描，新增 IP: $expected"
nohup "$PY" ip_port_scan.py \
    --input "$NEW_IPS" \
    --output "$SCAN_OUT" \
    --xml xinjiang2_scan.xml \
    --ip-list xinjiang2_ips.txt \
    --cache "$PORT_CACHE" \
    --checkpoint "$PORT_CKPT" \
    --tmp-dir "$PORT_TMP" \
    --batch-size 100 \
    --parallel-workers 3 \
    --resume \
    --anomaly-threshold 80 \
    --verify-workers 8 \
    --verify-host-timeout 15s \
    --verify-max-retries 0 \
    --verify-proc-timeout 25 \
    >"$PORT_LOG" 2>&1 </dev/null &
port_pid=$!
while kill -0 "$port_pid" 2>/dev/null; do
    log "端口扫描进度: $(count_lines "$PORT_CKPT")/$expected"
    sleep 30
done
wait "$port_pid"

log "阶段 3/4：展开开放端口"
"$PY" expand_scan_ports.py --input "$SCAN_OUT" --output "$EXPANDED" |
    tee -a "$WATCH_LOG"
targets=$(( $(count_lines "$EXPANDED") - 1 ))
if (( targets <= 0 )); then
    log "未发现开放端口，结束"
    exit 0
fi

log "阶段 4/4：LLM/GPU 扫描，目标: $targets"
nohup "$PY" -u scan_llm.py \
    --input "$EXPANDED" \
    --output "$LLM_OUT" \
    --checkpoint "$LLM_CKPT" \
    --batch-size 2000 \
    --resume \
    >"$LLM_LOG" 2>&1 </dev/null &
llm_pid=$!
while kill -0 "$llm_pid" 2>/dev/null; do
    log "LLM/GPU 扫描进度: $(count_lines "$LLM_CKPT")/$targets"
    sleep 30
done
wait "$llm_pid"

log "全部完成，结果保存在 $LLM_OUT"
