#!/usr/bin/env python3
import asyncio
import csv
import tempfile
from collections import Counter
from pathlib import Path

import scan_llm
from scan_config import get_default_config
from scan_llm import (
    OUTPUT_FIELDNAMES,
    ProbeResult,
    TargetState,
    _apply_service_classification,
    phase_gpu_probe,
    run_gpu_rescan,
)


async def test_retry_then_success():
    cfg = get_default_config()
    cfg.runtime.gpu_probe.retries = 2
    cfg.runtime.gpu_probe.retry_delays = [0, 0]
    calls = Counter()
    original = scan_llm._extra_get

    async def fake_get(session, proto, ip, port, path, timeout):
        calls[path] += 1
        if path == "/metrics" and calls[path] < 3:
            return ProbeResult(error="timeout")
        if path == "/metrics":
            return ProbeResult(status=200, body="DCGM_FI_DEV_GPU_UTIL 85")
        return ProbeResult(status=404, body="not found")

    scan_llm._extra_get = fake_get
    try:
        state = TargetState(ip="127.0.0.1", port="9400", protocol="http")
        await phase_gpu_probe([state], 999, cfg)
        _apply_service_classification(state, cfg)
        assert calls["/metrics"] == 3
        assert state.gpu_probe_detail["/metrics"]["attempts"] == 3
        assert state.gpu_likelihood == "高"
        assert state.service_type == "GPU算力服务"
    finally:
        scan_llm._extra_get = original


async def test_gpu_rescan_preserves_llm_counts():
    cfg = get_default_config()
    cfg.runtime.gpu_probe.retries = 0
    original = scan_llm._extra_get

    async def fake_get(session, proto, ip, port, path, timeout):
        if ip == "10.0.0.3" and path == "/metrics":
            return ProbeResult(status=200, body="DCGM_FI_DEV_GPU_UTIL 50")
        return ProbeResult(status=404, body="not found")

    scan_llm._extra_get = fake_get
    try:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.csv"
            output = root / "output.csv"
            checkpoint = root / "checkpoint.jsonl"
            rows = [
                {
                    "ip": "10.0.0.1", "port": "11434", "protocol": "http",
                    "is_llm": "确认", "service_type": "LLM服务",
                    "deploy_tool": "ollama",
                },
                {
                    "ip": "10.0.0.2", "port": "9090", "protocol": "https",
                    "is_llm": "疑似", "service_type": "AI前端服务",
                },
                {
                    "ip": "10.0.0.3", "port": "9400", "protocol": "http",
                    "is_llm": "否", "service_type": "普通Web",
                },
            ]
            with source.open("w", encoding="utf-8-sig", newline="") as target:
                writer = csv.DictWriter(
                    target, fieldnames=OUTPUT_FIELDNAMES,
                    quoting=csv.QUOTE_NONNUMERIC, extrasaction="ignore",
                )
                writer.writeheader()
                writer.writerows(rows)

            await run_gpu_rescan(
                source, output, checkpoint, cfg, batch_size=2, resume=False
            )
            with output.open(encoding="utf-8-sig", newline="") as result:
                updated = list(csv.DictReader(result))
            assert Counter(row["is_llm"] for row in updated) == {
                "确认": 1, "疑似": 1, "否": 1,
            }
            gpu_row = next(row for row in updated if row["port"] == "9400")
            assert gpu_row["gpu_likelihood"] == "高"
            assert gpu_row["service_type"] == "GPU算力服务"
            assert '"attempts":1' in gpu_row["gpu_probe_detail"]
    finally:
        scan_llm._extra_get = original


asyncio.run(test_retry_then_success())
asyncio.run(test_gpu_rescan_preserves_llm_counts())
print("validated retry recovery and GPU-only rescan invariants")
