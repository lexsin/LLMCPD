#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/home/lixiao/llm-detect/TEST"
INPUT_SCAN="${BASE_DIR}/data/ty_result_scan_result.csv"
EXPANDED="${BASE_DIR}/data/ty_result_expanded.csv"
LLM_OUT="${BASE_DIR}/data/ty_result_llm.csv"
LLM_CKPT="${BASE_DIR}/data/ty_result_llm_checkpoint.jsonl"
LOG_DIR="${BASE_DIR}/logs"
WATCH_LOG="${LOG_DIR}/ty_after_port_scan_watcher.log"
LLM_LOG="${LOG_DIR}/ty_scan_llm.log"
LOCK_FILE="${BASE_DIR}/ty_after_port_scan_watcher.lock"

mkdir -p "${LOG_DIR}"
exec >>"${WATCH_LOG}" 2>&1

echo "[$(date '+%F %T')] watcher starting"

if [[ -e "${LOCK_FILE}" ]] && kill -0 "$(cat "${LOCK_FILE}")" 2>/dev/null; then
  echo "[$(date '+%F %T')] watcher already running as PID $(cat "${LOCK_FILE}")"
  exit 0
fi
echo "$$" > "${LOCK_FILE}"
trap 'rm -f "${LOCK_FILE}"' EXIT

cd "${BASE_DIR}"

PORT_PATTERN="python3 ip_port_scan.py --input data/ty_result.csv"
if pgrep -f "${PORT_PATTERN}" >/dev/null 2>&1; then
  echo "[$(date '+%F %T')] waiting for matching ip_port_scan.py process"
  while pgrep -f "${PORT_PATTERN}" >/dev/null 2>&1; do
    sleep 60
  done
  # Avoid treating a controlled restart as completion.
  sleep 15
  if pgrep -f "${PORT_PATTERN}" >/dev/null 2>&1; then
    echo "[$(date '+%F %T')] ip_port_scan.py restarted; returning to wait loop"
    while pgrep -f "${PORT_PATTERN}" >/dev/null 2>&1; do
      sleep 60
    done
  fi
  echo "[$(date '+%F %T')] no matching ip_port_scan.py process remains"
else
  echo "[$(date '+%F %T')] no matching ip_port_scan.py process found; continuing"
fi

if [[ ! -s "${INPUT_SCAN}" ]]; then
  echo "[$(date '+%F %T')] missing scan result: ${INPUT_SCAN}"
  exit 1
fi

echo "[$(date '+%F %T')] running expand_scan_ports.py"
python3 expand_scan_ports.py \
  --input "${INPUT_SCAN}" \
  --output "${EXPANDED}"
echo "[$(date '+%F %T')] expand_scan_ports.py finished: ${EXPANDED}"

if pgrep -f "python3 scan_llm.py --input ${EXPANDED}" >/dev/null 2>&1; then
  echo "[$(date '+%F %T')] scan_llm.py already running for ${EXPANDED}"
  exit 0
fi

echo "[$(date '+%F %T')] starting scan_llm.py in background"
nohup python3 scan_llm.py \
  --input "${EXPANDED}" \
  --output "${LLM_OUT}" \
  --checkpoint "${LLM_CKPT}" \
  --resume \
  >>"${LLM_LOG}" 2>&1 &
LLM_PID="$!"
echo "[$(date '+%F %T')] scan_llm.py started as PID ${LLM_PID}; log: ${LLM_LOG}"
