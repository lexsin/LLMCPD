#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/home/lixiao/llm-detect/TEST"
SCAN_PATTERN="python3 ip_port_scan.py --input data/ty_result.csv"
LOG_DIR="${BASE_DIR}/logs"
SCAN_LOG="${LOG_DIR}/ty_ip_port_scan_optimized.log"
WATCH_LOG="${LOG_DIR}/ty_after_port_scan_watcher.log"

cd "${BASE_DIR}"
mkdir -p "${LOG_DIR}"

if [[ -f ty_after_port_scan_watcher.lock ]]; then
  WATCH_PID="$(cat ty_after_port_scan_watcher.lock)"
  if kill -0 "${WATCH_PID}" 2>/dev/null; then
    echo "Stopping old watcher PID ${WATCH_PID}"
    kill -TERM "${WATCH_PID}"
    for _ in $(seq 1 10); do
      kill -0 "${WATCH_PID}" 2>/dev/null || break
      sleep 1
    done
  fi
  rm -f ty_after_port_scan_watcher.lock
fi

OLD_PID="$(pgrep -f "${SCAN_PATTERN}" | head -n 1 || true)"
if [[ -n "${OLD_PID}" ]]; then
  echo "Stopping old ip_port_scan.py PID ${OLD_PID}"
  kill -TERM "${OLD_PID}"
  for _ in $(seq 1 45); do
    kill -0 "${OLD_PID}" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    echo "Old ip_port_scan.py PID ${OLD_PID} did not exit"
    exit 2
  fi
fi

echo "Starting optimized ip_port_scan.py"
nohup python3 ip_port_scan.py \
  --input data/ty_result.csv \
  --batch-size 100 \
  --parallel-workers 3 \
  --resume \
  --anomaly-threshold 80 \
  --verify-workers 8 \
  --verify-host-timeout 15s \
  --verify-max-retries 0 \
  --verify-proc-timeout 25 \
  >"${SCAN_LOG}" 2>&1 </dev/null &
NEW_PID="$!"
echo "Optimized ip_port_scan.py PID ${NEW_PID}"

sleep 2
if ! kill -0 "${NEW_PID}" 2>/dev/null; then
  echo "Optimized scanner exited during startup"
  tail -n 50 "${SCAN_LOG}" || true
  exit 3
fi

echo "Starting updated watcher"
nohup ./run_after_port_scan_ty.sh >/dev/null 2>&1 </dev/null &
NEW_WATCH_PID="$!"
echo "Updated watcher PID ${NEW_WATCH_PID}"

sleep 2
echo "--- scanner log ---"
tail -n 20 "${SCAN_LOG}" || true
echo "--- watcher log ---"
tail -n 20 "${WATCH_LOG}" || true
