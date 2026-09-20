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

print("source_type_scan_policy_tests=passed")
