#!/usr/bin/env python3

import asyncio

import active_gpu_inference_probe as active_probe
from active_gpu_recheck import (
    choose_model,
    is_candidate,
    updated_row,
    video_history_probe,
)
try:
    from scan_llm import ProbeResult, TargetState, _gpu_evidence_tiers, _read_metrics_content
    from scan_config import get_default_config
    HAS_SCAN_LLM = True
except (ImportError, SystemExit):
    HAS_SCAN_LLM = False


class FakeContent:
    def __init__(self, chunks):
        self.chunks = chunks

    async def iter_any(self):
        for chunk in self.chunks:
            yield chunk


async def verify_streaming_metrics():
    prefix = b"ordinary_metric 1\n" * 70000  # GPU evidence is beyond one MiB.
    tail = b'DCGM_FI_DEV_GPU_UTIL{gpu="0"} 37\n'
    body = await _read_metrics_content(FakeContent([prefix, tail]))
    assert tail in body
    assert len(body) < 3 * 1024 * 1024


def verify_active_selection_and_promotion():
    row = {
        "ip": "192.0.2.10", "port": "11434", "protocol": "http",
        "gpu_likelihood": "中", "is_llm": "确认", "deploy_tool": "ollama",
        "model_info": "remote:cloud,qwen2.5:7b", "gpu_evidence": "framework=ollama",
        "link": "http://192.0.2.10:11434/api/tags",
    }
    assert is_candidate(row)
    assert choose_model("ollama", row["model_info"]) == "qwen2.5:7b"
    result = {
        "base_url": "http://192.0.2.10:11434", "model": "qwen2.5:7b",
        "first_direct_evidence_at": "after-2s",
        "direct_gpu_evidence": ["/api/ps:size_vram=1024 model=qwen2.5:7b"],
        "inference": {"path": "/api/generate", "status": 200},
    }
    promoted = updated_row(row, result)
    assert promoted["gpu_likelihood"] == "高"
    assert promoted["active_probe_status"] == "promoted_high"
    assert "/api/ps" in promoted["link"]


def verify_model_inventory_is_configuration_evidence():
    state = TargetState(ip="192.0.2.10", port="30010", protocol="http")
    state.probes["/v1/models"] = ProbeResult(
        status=200,
        body='{"data":[{"id":"MiniMax-H3-fl2v","num_gpus":1,"task_type":"TI2V"}]}',
    )
    direct, inferred = _gpu_evidence_tiers(state, get_default_config())
    assert not direct
    assert inferred == ["/v1/models:num_gpus=1 model=MiniMax-H3-fl2v task_type=TI2V"]


def verify_configuration_only_high_is_rechecked_and_downgraded():
    row = {
        "ip": "192.0.2.10", "port": "30010", "protocol": "http",
        "gpu_likelihood": "高", "is_llm": "确认", "deploy_tool": "sglang",
        "model_info": "MiniMax-H3-fl2v",
        "gpu_evidence": "/v1/models:num_gpus=1 model=MiniMax-H3-fl2v",
    }
    assert is_candidate(row)
    revised = updated_row(row, {
        "base_url": "http://192.0.2.10:30010", "model": "MiniMax-H3-fl2v",
        "direct_gpu_evidence": [],
        "configuration_gpu_evidence": ["/v1/models:num_gpus=1 model=MiniMax-H3-fl2v"],
        "inference": {"path": "/v1/chat/completions", "status": 404},
        "model_task_type": "TI2V",
    })
    assert revised["gpu_likelihood"] == "中"
    assert revised["active_probe_status"] == "inference_failed"


def verify_read_timeout_keeps_fast_ps_observation():
    calls = {"ps": 0, "metrics": 0}

    def snapshot(label, direct=None, metrics=None):
        return {
            "label": label, "time": "2026-09-17 00:00:00.000",
            "metrics_status": 200, "metrics_error": "", "metrics_scanned_bytes": 10,
            "metrics_values": metrics or {}, "api_ps_status": 200, "api_ps_error": "",
            "direct_gpu_evidence": direct or [], "_evidence_url": "http://example/evidence",
            "_evidence_body": "evidence", "_evidence_status": 200,
        }

    def fake_metrics(base_url, label):
        calls["metrics"] += 1
        return snapshot(label, metrics={"request_total": float(calls["metrics"])})

    def fake_ps(base_url, label):
        calls["ps"] += 1
        direct = []
        if calls["ps"] >= 3:
            direct = ["/api/ps:size_vram=1024 model=test"]
        return snapshot(label, direct=direct)

    class TimeoutSession:
        def post(self, *args, **kwargs):
            raise active_probe.requests.exceptions.ReadTimeout("server still loading")

    original_new_session = active_probe.new_session
    original_metrics = active_probe.read_metrics_snapshot
    original_ps = active_probe.read_ps_snapshot
    try:
        active_probe.new_session = lambda: TimeoutSession()
        active_probe.read_metrics_snapshot = fake_metrics
        active_probe.read_ps_snapshot = fake_ps
        result = active_probe.run_one(
            "ollama", "http://192.0.2.10:11434", "test",
            timeout=1, poll_interval=0.01, metrics_interval=0.05,
            timeout_observation=0.3, delayed_samples=(),
        )
    finally:
        active_probe.new_session = original_new_session
        active_probe.read_metrics_snapshot = original_metrics
        active_probe.read_ps_snapshot = original_ps

    assert result["inference"]["timed_out"] is True
    assert result["recommended_gpu_likelihood"] == "高"
    assert "/api/ps:size_vram=1024 model=test" in result["direct_gpu_evidence"]
    assert result["timeout_observation_elapsed_seconds"] > 0
    assert calls["ps"] > calls["metrics"]


def verify_sglang_native_generate_payload_and_route_discovery():
    path, payload = active_probe.inference_request(
        "sglang", "text-model", 6, "/generate"
    )
    assert path == "/generate"
    assert payload == {
        "text": "Reply with OK.",
        "sampling_params": {"temperature": 0, "max_new_tokens": 6},
    }


def verify_video_history_requires_complete_runtime_evidence():
    completed = {
        "data": [{
            "id": "video-1", "model": "MiniMax-H3-fl2v",
            "status": "completed", "peak_memory_mb": 10626.0,
            "num_outputs": 1, "file_path": "outputs/video-1.mp4",
        }]
    }
    captured = []
    original_get_text = __import__("active_gpu_recheck").get_text
    try:
        __import__("active_gpu_recheck").get_text = lambda *args, **kwargs: (
            200, __import__("json").dumps(completed), ""
        )
        result = video_history_probe(
            "http://182.140.218.64:30010",
            "MiniMax-H3-fl2v",
            ["MiniMax-H3-fl2v"],
            evidence_callback=captured.append,
        )
    finally:
        __import__("active_gpu_recheck").get_text = original_get_text
    assert result["recommended_gpu_likelihood"] == "高"
    assert "peak_memory_mb=10626" in result["direct_gpu_evidence"][0]
    assert "10.4 GiB" in result["direct_gpu_evidence"][0]
    assert captured[0]["_evidence_url"].endswith("/v1/videos?limit=10")

    invalid_records = [
        {"status": "running", "peak_memory_mb": 10626, "num_outputs": 1},
        {"status": "completed", "model": "other", "peak_memory_mb": 10626, "num_outputs": 1},
        {"status": "completed", "model": "MiniMax-H3-fl2v", "peak_memory_mb": 0, "num_outputs": 1},
        {"status": "completed", "model": "MiniMax-H3-fl2v", "peak_memory_mb": 10626, "num_outputs": 0},
    ]
    try:
        __import__("active_gpu_recheck").get_text = lambda *args, **kwargs: (
            200, __import__("json").dumps({"data": invalid_records}), ""
        )
        result = video_history_probe(
            "http://192.0.2.10:30010",
            "MiniMax-H3-fl2v",
            ["MiniMax-H3-fl2v"],
        )
    finally:
        __import__("active_gpu_recheck").get_text = original_get_text
    assert result["recommended_gpu_likelihood"] == "中"
    assert result["direct_gpu_evidence"] == []


def verify_passive_video_row_status_and_wording():
    row = {
        "ip": "182.140.218.64", "port": "30010", "protocol": "http",
        "gpu_likelihood": "中", "is_llm": "确认", "deploy_tool": "sglang",
        "model_info": "MiniMax-H3-fl2v", "gpu_evidence": "",
    }
    evidence = (
        "GET /v1/videos?limit=10: completed video id=video-1 "
        "model=MiniMax-H3-fl2v peak_memory_mb=10626 (10.4 GiB)"
    )
    revised = updated_row(row, {
        "base_url": "http://182.140.218.64:30010",
        "model": "MiniMax-H3-fl2v",
        "probe_mode": "passive_video_history",
        "direct_gpu_evidence": [evidence],
        "first_direct_evidence_at": "video-history",
        "inference": {"path": "/v1/videos?limit=10", "status": 200},
        "model_task_type": "TI2V",
    })
    assert revised["gpu_likelihood"] == "高"
    assert revised["active_probe_status"] == "passive_video_gpu_confirmed"
    assert "主动推理" not in revised["分析"]
    assert revised["link"] == "http://182.140.218.64:30010/v1/videos?limit=10"


if __name__ == "__main__":
    if HAS_SCAN_LLM:
        asyncio.run(verify_streaming_metrics())
    verify_active_selection_and_promotion()
    if HAS_SCAN_LLM:
        verify_model_inventory_is_configuration_evidence()
    verify_configuration_only_high_is_rechecked_and_downgraded()
    verify_read_timeout_keeps_fast_ps_observation()
    verify_sglang_native_generate_payload_and_route_discovery()
    verify_video_history_requires_complete_runtime_evidence()
    verify_passive_video_row_status_and_wording()
    print("active_gpu_v7_tests=passed")
