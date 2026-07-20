#!/usr/bin/env python3
import asyncio

from scan_config import get_default_config
from scan_llm import (
    TargetState,
    _analysis_text,
    _apply_service_classification,
    phase_gpu_probe,
)


async def main():
    cfg = get_default_config()
    state = TargetState(
        ip="222.81.173.40",
        port="9400",
        protocol="http",
    )
    await phase_gpu_probe([state], None, cfg)
    _apply_service_classification(state, cfg)
    state.analysis = _analysis_text(state)
    metrics = state.probes.get("/metrics")
    assert metrics and metrics.status == 200, state.gpu_probe_detail
    assert "NVIDIA GeForce RTX 5090" in metrics.body
    assert state.gpu_likelihood == "高", state.gpu_evidence
    assert state.service_type == "GPU算力服务", state.service_type
    print(state.to_row())


asyncio.run(main())
