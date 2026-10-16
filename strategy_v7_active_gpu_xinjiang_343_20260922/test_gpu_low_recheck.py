#!/usr/bin/env python3

import json
import unittest

from scan_config import get_default_config
from scan_llm import ProbeResult, TargetState
from gpu_low_recheck import (
    discover_paths,
    discover_same_ip_backends,
    discover_script_paths,
    is_safe_discovered_path,
    strict_gpu_evidence,
)


class LowGpuRecheckTests(unittest.TestCase):
    def setUp(self):
        self.cfg = get_default_config()

    def state(self):
        return TargetState(ip="192.0.2.10", port="8080", protocol="http")

    def test_dcgm_zero_sample_is_direct_device_evidence(self):
        state = self.state()
        state.probes["/metrics/cadvisor"] = ProbeResult(
            status=200,
            body=(
                'DCGM_FI_DEV_GPU_UTIL{gpu="0",UUID="GPU-12345678",'
                'modelName="NVIDIA A100"} 0\n'
            ),
        )
        direct, inferred = strict_gpu_evidence(state, self.cfg)
        self.assertTrue(any("DCGM_FI_DEV_GPU_UTIL" in item for item in direct))
        self.assertEqual([], inferred)

    def test_prometheus_dcgm_query_with_zero_value_is_direct(self):
        state = self.state()
        path = "/api/v1/query?query=DCGM_FI_DEV_GPU_UTIL"
        state.probes[path] = ProbeResult(
            status=200,
            body=json.dumps({
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [{
                        "metric": {"gpu": "0", "UUID": "GPU-12345678"},
                        "value": [1, "0"],
                    }],
                },
            }),
        )
        direct, _ = strict_gpu_evidence(state, self.cfg)
        self.assertTrue(any("valid_dcgm_samples=1" in item for item in direct))

    def test_positive_gpu_count_without_device_detail_is_inferred(self):
        state = self.state()
        state.probes["/api/resources"] = ProbeResult(
            status=200, body='{"gpu_count": 2}'
        )
        direct, inferred = strict_gpu_evidence(state, self.cfg)
        self.assertEqual([], direct)
        self.assertTrue(any("gpu_count=2" in item for item in inferred))

    def test_generic_gpu_word_is_not_device_evidence(self):
        state = self.state()
        state.probes["/api/resources"] = ProbeResult(
            status=200, body='{"message": "GPU acceleration supported"}'
        )
        direct, inferred = strict_gpu_evidence(state, self.cfg)
        self.assertEqual([], direct)
        self.assertEqual([], inferred)

    def test_discovered_paths_are_read_only_and_gpu_related(self):
        text = (
            'a="/api/gpu/status";'
            'b="/api/gpu/restart";'
            'c="/api/users";'
            'd="/cluster/resources"'
        )
        self.assertEqual(
            ["/api/gpu/status", "/cluster/resources"], discover_paths(text)
        )
        self.assertTrue(is_safe_discovered_path("/api/hardware"))
        self.assertFalse(is_safe_discovered_path("/api/device/delete"))

    def test_script_and_same_ip_backend_scope(self):
        body = (
            '<script src="/assets/app.js"></script>'
            '<script src="https://example.net/skip.js"></script>'
            'const api="http://192.0.2.10:9400";'
            'const external="http://198.51.100.20:9400";'
            'const template="http://${n.value}:9400";'
        )
        self.assertEqual(
            ["/assets/app.js"],
            discover_script_paths(body, "http://192.0.2.10:8080/"),
        )
        state = self.state()
        self.assertEqual(
            [("http", "9400")], discover_same_ip_backends(body, state)
        )


if __name__ == "__main__":
    unittest.main()
