#!/usr/bin/env python3
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "scan_ports_by_source_type.py"
spec = importlib.util.spec_from_file_location("source_policy", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(ip, start, end):
    return {"ip": ip, module.COL_START: start, module.COL_END: end}


small = [row("10.0.0.1", "10.0.0.0", "10.0.0.255")]
pn, discovery, policy = module.classify_rows(small, small)
assert policy == "all_pn_below_50000"
assert len(pn) == 1 and not discovery

expanded = [
    row("10.%d.%d.%d" % (index // 65536, (index // 256) % 256, index % 256), "range", "range-end")
    for index in range(50000)
]
conflict_ip = expanded[123]["ip"]
source = [
    row("", "10.0.0.0", "10.255.255.255"),
    row("", conflict_ip, conflict_ip),
]
pn, discovery, policy = module.classify_rows(expanded, source)
assert policy == "single_source_pn_range_source_discovery"
assert [item["ip"] for item in pn] == [conflict_ip]
assert len(discovery) == 49999

small_range = [row("192.0.2.%d" % index, "192.0.2.0", "192.0.2.255") for index in range(256)]
pn, discovery, policy = module.classify_rows(expanded + small_range, source + [row("", "192.0.2.0", "192.0.2.255")])
assert policy == "single_and_small_range_pn_range_source_discovery"
assert len(pn) == 257
assert {item["ip"] for item in small_range}.issubset({item["ip"] for item in pn})

# Single-IP records retain -Pn priority even when they already exceed 50,000;
# small ranges are not added once that initial group reaches the threshold.
many_singles = [row("172.16.%d.%d" % (index // 256, index % 256), "172.16.%d.%d" % (index // 256, index % 256), "172.16.%d.%d" % (index // 256, index % 256)) for index in range(50001)]
extra_small = [row("198.51.100.%d" % index, "198.51.100.0", "198.51.100.9") for index in range(10)]
pn, discovery, policy = module.classify_rows(many_singles + extra_small, many_singles + [row("", "198.51.100.0", "198.51.100.9")])
assert len(pn) == 50001
assert len(discovery) == 10

# Small-range expansion never takes the -Pn group beyond 50,000.
near_limit = [row("10.2.%d.%d" % (index // 256, index % 256), "10.2.%d.%d" % (index // 256, index % 256), "10.2.%d.%d" % (index // 256, index % 256)) for index in range(49900)]
too_large_to_fit = [row("203.0.113.%d" % index, "203.0.113.0", "203.0.113.255") for index in range(256)]
pn, discovery, policy = module.classify_rows(near_limit + too_large_to_fit, near_limit + [row("", "203.0.113.0", "203.0.113.255")])
assert len(pn) == 49900
assert len(discovery) == 256

print("source_type_scan_policy_tests=passed")
