#!/usr/bin/env python3
import asyncio

import scan_llm
from scan_config import get_default_config
from scan_llm import (
    ProbeResult,
    TargetState,
    _analysis_text,
    _apply_service_classification,
    phase_gpu_probe,
)


cfg = get_default_config()


def classify(is_llm, tool="", body="", evidence=None, probes=None):
    state = TargetState(
        ip="127.0.0.1",
        port="8000",
        protocol="http",
        is_llm=is_llm,
        deploy_tool=tool,
        probes=probes or {"/": ProbeResult(status=200, body=body)},
        evidence=evidence or [],
    )
    _apply_service_classification(state, cfg)
    state.analysis = _analysis_text(state)
    return state


cases = [
    (classify("疑似", body="aichat frontend"), "低", "AI前端服务"),
    (classify("疑似", body="aichat frontend using nvidia gpu"), "中", "AI前端服务"),
    (classify("确认", tool="vllm"), "中", "LLM服务"),
    (classify(
        "否",
        probes={"/metrics": ProbeResult(status=200, body="DCGM_FI_DEV_GPU_UTIL 85")},
    ), "高", "GPU算力服务"),
    (classify(
        "否",
        probes={"/metrics": ProbeResult(
            status=200, body="nv_inference_request_success 12"
        )},
    ), "中", "GPU算力服务"),
    (classify(
        "确认",
        tool="ollama",
        probes={"/api/ps": ProbeResult(
            status=200,
            body='{"models":[{"name":"qwen","size_vram":4096}]}',
        )},
    ), "高", "LLM服务"),
    (classify(
        "确认",
        tool="ollama",
        probes={"/api/ps": ProbeResult(
            status=200,
            body='{"models":[{"name":"qwen","size_vram":0}]}',
        )},
    ), "中", "LLM服务"),
    (classify(
        "否",
        probes={"/metrics": ProbeResult(
            status=200, body="process_cpu_seconds_total 12"
        )},
    ), "未知", "普通Web"),
    (classify("否", body="ordinary page mentions gpu"), "未知", "普通Web"),
]

for index, (state, likelihood, service_type) in enumerate(cases, 1):
    assert state.gpu_likelihood == likelihood, (
        index, state.gpu_likelihood, state.gpu_evidence,
    )
    assert state.service_type == service_type, (index, state.service_type)
    if likelihood != "未知":
        assert state.analysis, (index, state.analysis)


async def validate_probe_paths():
    calls = []
    original = scan_llm._extra_get

    async def fake_get(session, proto, ip, port, path, timeout):
        calls.append(path)
        if path == "/metrics":
            return ProbeResult(status=200, body="nv_gpu_utilization 1")
        return ProbeResult(
            status=200,
            body='{"models":[{"name":"qwen","size_vram":1024}]}',
        )

    scan_llm._extra_get = fake_get
    try:
        state = TargetState(
            ip="127.0.0.1", port="8000", protocol="http",
            probes={"/": ProbeResult(status=200, body="ok")},
        )
        await phase_gpu_probe([state], 2, cfg)
        assert calls == ["/metrics", "/api/ps"], calls
        assert state.probes["/metrics"].status == 200
        assert state.probes["/api/ps"].status == 200
    finally:
        scan_llm._extra_get = original


asyncio.run(validate_probe_paths())
print("validated %d GPU likelihood cases and independent probe paths" % len(cases))
