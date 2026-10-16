#!/usr/bin/env python3
"""Regression coverage for evidence-aware GPU response screenshots."""
from screenshot_evidence import response_card_lines


metrics = "\n".join(
    ["http_requests_total %d" % index for index in range(50)]
    + [
        "vllm_gpu_cache_usage 0.14",
    ] * 40 + [
        "vllm_gpu_blocks{engine=\"0\"} 1107",
        "gpu_memory_utilization 0.93",
        "gpu_memory_utilization 0.93",
    ]
)
lines, found = response_card_lines(
    "text/plain; charset=utf-8",
    metrics.encode("utf-8"),
    "GPU 指标：/metrics:vllm_gpu_blocks=1107 gpu_memory_utilization=0.93",
)

assert found is True
assert any("vllm_gpu_blocks" in line for line in lines)
assert any("gpu_memory_utilization" in line for line in lines)
assert sum("gpu_memory_utilization" in line for line in lines) == 1
assert not any("http_requests_total 0" == line for line in lines)
print("screenshot_evidence_content_tests=passed")
