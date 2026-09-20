#!/usr/bin/env python3
from scan_config import get_default_config
from scan_llm import ProbeResult, TargetState, _apply_service_classification


cfg = get_default_config()


def classify(probes):
    state = TargetState(
        ip="127.0.0.1",
        port="8000",
        protocol="http",
        probes=probes,
    )
    _apply_service_classification(state, cfg)
    return state


cases = [
    classify({"/metrics": ProbeResult(status=404, body="not found")}),
    classify({"/metrics": ProbeResult(error="timeout")}),
    classify({"/api/ps": ProbeResult(status=200, body="not-json")}),
    classify({
        "/api/ps": ProbeResult(
            status=200,
            body='{"models":[{"name":"cpu-model","size_vram":0}]}',
        )
    }),
]

for state in cases:
    assert state.gpu_likelihood == "未知", (
        state.gpu_likelihood,
        state.gpu_evidence,
    )
    assert state.service_type == "普通Web", state.service_type

print("validated GPU probe 404, timeout, invalid JSON and zero-VRAM cases")
