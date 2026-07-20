#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path


service_root = Path(__file__).resolve().parents[1] / "service"
sys.path.insert(0, str(service_root))

from llm_detect.adapters.llm_prober import load_scan_config, probe_endpoints


async def main():
    cfg = load_scan_config(None)
    rows = await probe_endpoints(
        [("222.81.173.40", 9400)],
        cfg,
        concurrency_override=100,
    )
    assert len(rows) == 1
    row = rows[0]
    fingerprint = row["fingerprint"]
    assert row["asset_verdict"] == 0
    assert row["probe_shape"] == "FRAMEWORK"
    assert row["app_type_code"] == 2
    assert fingerprint["service_type"] == "GPU算力服务"
    assert fingerprint["gpu_likelihood"] == "高"
    assert fingerprint["gpu_probe_detail"]["/metrics"]["status"] == 200
    print(row)


asyncio.run(main())
