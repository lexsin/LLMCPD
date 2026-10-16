#!/usr/bin/env python3
import asyncio

import scan_llm
from scan_config import get_default_config
from scan_llm import (
    ProbeResult,
    TargetState,
    _apply_service_classification,
    _openapi_hardware_paths,
    _read_limited_content,
    phase_gpu_discovery,
)


cfg = get_default_config()


def classify(probes, is_llm="确认", tool="vllm"):
    state = TargetState(
        ip="127.0.0.1",
        port="8000",
        protocol="http",
        is_llm=is_llm,
        deploy_tool=tool,
        probes=probes,
    )
    _apply_service_classification(state, cfg)
    return state


vllm_runtime = classify({
    "/metrics": ProbeResult(
        status=200,
        body=(
            'vllm:cache_config_info{gpu_memory_utilization="0.65"} 1\n'
            'vllm:gpu_cache_usage_perc{model_name="qwen"} 0.01\n'
        ),
    ),
})
assert vllm_runtime.gpu_likelihood == "高", vllm_runtime.gpu_evidence
assert "vllm_gpu_cache_usage" in vllm_runtime.gpu_evidence


accelerator_conflict = classify({
    "/v1/models": ProbeResult(
        status=200,
        body='{"data":[{"id":"qwen","accelerators":["0","1"]}]}',
    ),
    "/v1/cluster/info": ProbeResult(
        status=200,
        body='[{"gpu_count":0,"gpu_vram_total":0}]',
    ),
}, tool="xinference")
assert accelerator_conflict.gpu_likelihood == "低"
assert "cluster_gpu_count=0" in accelerator_conflict.gpu_evidence


vllm_zero_runtime = classify({
    "/metrics": ProbeResult(
        status=200,
        body=(
            'vllm:cache_config_info{num_gpu_blocks="0",'
            'gpu_memory_utilization="0"} 1\n'
            'vllm:num_requests_running 1\n'
        ),
    ),
})
assert vllm_zero_runtime.gpu_likelihood == "中"
assert "vllm_gpu_requests_running" not in vllm_zero_runtime.gpu_evidence


bare_gpu_count = classify({
    "/v1/cluster/info": ProbeResult(
        status=200,
        body='[{"gpu_count":4,"gpu_vram_total":0}]',
    ),
}, is_llm="否", tool="")
assert bare_gpu_count.gpu_likelihood == "中"


dcgm_help_only = classify({
    "/metrics": ProbeResult(
        status=200,
        body=(
            "# HELP DCGM_FI_DEV_GPU_UTIL GPU utilization\n"
            "# TYPE DCGM_FI_DEV_GPU_UTIL gauge\n"
        ),
    ),
}, is_llm="否", tool="")
assert dcgm_help_only.gpu_likelihood != "高"


dcgm_idle_device = classify({
    "/metrics": ProbeResult(
        status=200,
        body=(
            '# HELP DCGM_FI_DEV_GPU_UTIL GPU utilization\n'
            '# TYPE DCGM_FI_DEV_GPU_UTIL gauge\n'
            'DCGM_FI_DEV_GPU_UTIL{gpu="0",UUID="GPU-idle",'
            'device="nvidia0",modelName="NVIDIA A100"} 0\n'
        ),
    ),
}, is_llm="否", tool="")
assert dcgm_idle_device.gpu_likelihood == "高"
assert "value=0" in dcgm_idle_device.gpu_evidence
assert "uuid=GPU-idle" in dcgm_idle_device.gpu_evidence


hardware_inventory = classify({
    "/v1/cluster/info": ProbeResult(
        status=200,
        body='[{"gpu_count":4,"gpu_vram_total":343597383680}]',
    ),
}, is_llm="否", tool="")
assert hardware_inventory.gpu_likelihood == "高"
assert hardware_inventory.service_type == "GPU算力服务"


paths = _openapi_hardware_paths(
    '{"paths":{'
    '"/v1/cluster/info":{"get":{}},'
    '"/v1/cluster/auth":{"get":{}},'
    '"/v1/devices/{id}":{"get":{}},'
    '"/v1/workers":{"post":{}},'
    '"/v1/hardware":{"get":{}},'
    '"/v1/gpu/reset":{"get":{}},'
    '"/v1/gpu/reboot":{"get":{}},'
    '"/v1/gpu/scale":{"get":{}},'
    '"/v1/gpu/allocate":{"get":{}},'
    '"/v1/gpu/config":{"get":{"requestBody":{}}}'
    '}}'
)
assert paths == ["/v1/hardware", "/v1/cluster/info"], paths


async def validate_adaptive_probe():
    calls = []
    original = scan_llm._extra_get

    async def fake_get(session, proto, ip, port, path, timeout):
        calls.append((port, path))
        return ProbeResult(status=404, body="")

    scan_llm._extra_get = fake_get
    try:
        generic = TargetState(
            ip="127.0.0.1", port="8080", protocol="http",
            probes={"/": ProbeResult(status=200, body="ordinary web")},
        )
        ai = TargetState(
            ip="127.0.0.1", port="8000", protocol="http", is_llm="确认",
            probes={"/": ProbeResult(status=200, body="vllm")},
        )
        ollama = TargetState(
            ip="127.0.0.1", port="11434", protocol="http",
            probes={"/": ProbeResult(status=200, body="Ollama is running")},
        )
        await phase_gpu_discovery([generic, ai, ollama], None, cfg)
    finally:
        scan_llm._extra_get = original

    generic_paths = [path for port, path in calls if port == "8080"]
    ai_paths = [path for port, path in calls if port == "8000"]
    ollama_paths = [path for port, path in calls if port == "11434"]
    assert generic_paths == ["/metrics"], generic_paths
    assert "/metrics" in ai_paths and "/api/ps" in ai_paths, ai_paths
    assert "/metrics" in ollama_paths and "/api/ps" in ollama_paths, ollama_paths


class PartialReader:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, limit):
        if not self.chunks:
            return b""
        return self.chunks.pop(0)[:limit]


async def validate_partial_reads():
    raw = await _read_limited_content(
        PartialReader([b"first", b"-second", b"-third"]), 18
    )
    assert raw == b"first-second-third", raw


async def validate_openapi_budget():
    calls = []
    original = scan_llm._gpu_probe_path

    async def fake_probe(sem, session, state, path, config, **kwargs):
        calls.append((path, kwargs))
        state.probes[path] = ProbeResult(status=404, body="")

    scan_llm._gpu_probe_path = fake_probe
    try:
        state = TargetState(
            ip="127.0.0.1", port="8000", protocol="http", is_llm="确认",
        )
        await scan_llm.phase_gpu_openapi([state], None, cfg)
    finally:
        scan_llm._gpu_probe_path = original

    expected = list(scan_llm.GPU_OPENAPI_DOC_PATHS[:3])
    assert [path for path, _ in calls] == expected, calls
    assert all(
        options == {"timeout_override": 5, "retries_override": 0}
        for _, options in calls
    ), calls


asyncio.run(validate_adaptive_probe())
asyncio.run(validate_partial_reads())
asyncio.run(validate_openapi_budget())
print("validated adaptive GPU discovery, runtime evidence, and OpenAPI safety")
