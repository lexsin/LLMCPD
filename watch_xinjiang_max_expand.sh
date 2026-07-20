#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$BASE_DIR"

PY="/root/miniconda3/envs/xgb-lx/bin/python"
DATA_DIR="$BASE_DIR/data"
LOG_DIR="$BASE_DIR/logs"
MISSING="$DATA_DIR/xinjiangIP_max_expand_missing.csv"
SCAN_OUT="$DATA_DIR/xinjiangIP_max_expand_missing_scan_result.csv"
EXPANDED="$DATA_DIR/xinjiangIP_max_expand_missing_expanded.csv"
LLM_OUT="$DATA_DIR/xinjiangIP_max_expand_missing_llm.csv"
PORT_CACHE="$DATA_DIR/xinjiangIP_max_expand_port_cache.json"
PORT_CKPT="$DATA_DIR/xinjiangIP_max_expand_port_checkpoint.jsonl"
PORT_TMP="$DATA_DIR/xinjiangIP_max_expand_scan_tmp"
LLM_CKPT="$DATA_DIR/xinjiangIP_max_expand_llm_checkpoint.jsonl"
WATCH_LOG="$LOG_DIR/xinjiang_max_expand_watch.log"
PORT_LOG="$LOG_DIR/xinjiang_max_expand_port_scan.log"
LLM_LOG="$LOG_DIR/xinjiang_max_expand_llm_scan.log"
LOCK="$BASE_DIR/xinjiang_max_expand_watch.lock"

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
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file"
    else
        echo 0
    fi
}

log "生成 max_expand=256 漏检 IP 清单"
"$PY" generate_xinjiang_max_expand_missing.py \
    --input "$DATA_DIR/xinjiangIP.xlsx" \
    --scanned "$DATA_DIR/xinjiangIP_result.csv" \
    --output "$MISSING" \
    --max-expand 256 | tee -a "$WATCH_LOG"

expected=$(( $(count_lines "$MISSING") - 1 ))
if (( expected <= 0 )); then
    log "没有待补扫 IP，结束"
    exit 0
fi
log "待补扫 IP: $expected"

port_pattern="ip_port_scan.py --input $MISSING"
if ! pgrep -f "$port_pattern" >/dev/null; then
    log "启动端口补扫"
    nohup "$PY" ip_port_scan.py \
        --input "$MISSING" \
        --output "$SCAN_OUT" \
        --xml xinjiangIP_max_expand_scan.xml \
        --ip-list xinjiangIP_max_expand_ips.txt \
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
fi

while pgrep -f "$port_pattern" >/dev/null; do
    done_count=$(count_lines "$PORT_CKPT")
    log "端口扫描进度: $done_count/$expected"
    sleep 60
done

if [[ ! -s "$SCAN_OUT" ]]; then
    log "端口扫描未生成结果，查看 $PORT_LOG"
    exit 2
fi
log "端口扫描完成，展开开放端口"
"$PY" expand_scan_ports.py --input "$SCAN_OUT" --output "$EXPANDED" | tee -a "$WATCH_LOG"

target_count=$(( $(count_lines "$EXPANDED") - 1 ))
if (( target_count <= 0 )); then
    log "补扫未发现开放端口，独立结果已保存，结束"
    exit 0
fi

llm_pattern="scan_llm.py --input $EXPANDED"
if ! pgrep -f "$llm_pattern" >/dev/null; then
    log "启动 LLM/GPU 扫描，目标: $target_count"
    nohup "$PY" -u scan_llm.py \
        --input "$EXPANDED" \
        --output "$LLM_OUT" \
        --checkpoint "$LLM_CKPT" \
        --batch-size 2000 \
        --resume \
        >"$LLM_LOG" 2>&1 </dev/null &
fi

while pgrep -f "$llm_pattern" >/dev/null; do
    done_count=$(count_lines "$LLM_CKPT")
    log "LLM/GPU 扫描进度: $done_count/$target_count"
    sleep 60
done

if [[ ! -s "$LLM_OUT" ]]; then
    log "LLM/GPU 扫描未生成结果，查看 $LLM_LOG"
    exit 3
fi

log "全部完成，补扫结果独立保存在 $LLM_OUT"
