#!/usr/bin/env python3
import importlib.util
import csv
import tempfile
import json
import sys
from pathlib import Path
from types import SimpleNamespace

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "full_port_recheck", here / "full_port_recheck.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

rows = [
    {"ip": "10.0.0.1", "port": "8000", "gpu_likelihood": "高", "is_llm": "是"},
    {"ip": "10.0.0.1", "port": "9400", "gpu_likelihood": "中", "is_llm": "是"},
    {"ip": "10.0.0.2", "port": "8000", "gpu_likelihood": "中", "is_llm": "是"},
    {"ip": "10.0.0.3", "port": "11434", "gpu_likelihood": "低", "deploy_tool": "Ollama"},
    {"ip": "10.0.0.4", "port": "443", "gpu_likelihood": "低", "service_type": "Web"},
    {"ip": "10.0.0.5", "port": "10250", "gpu_likelihood": "低", "service_type": "Web"},
    {"ip": "10.0.0.6", "port": "10250", "gpu_likelihood": "低", "service_type": "kubelet"},
]

candidates, skipped = module.select_candidates(rows, "candidates", 50)
assert skipped == 1
assert [item["ip"] for item in candidates] == [
    "10.0.0.2", "10.0.0.3", "10.0.0.6",
]
all_candidates, all_skipped = module.select_candidates(rows, "all", 50)
assert all_skipped == 1
assert "10.0.0.1" not in {item["ip"] for item in all_candidates}
assert "10.0.0.4" in {item["ip"] for item in all_candidates}

xml = """<?xml version='1.0'?><nmaprun><host><ports>
<port protocol='tcp' portid='9014'><state state='open'/></port>
<port protocol='tcp' portid='17446'><state state='open'/></port>
<port protocol='tcp' portid='22'><state state='closed'/></port>
</ports></host></nmaprun>"""
assert module.parse_open_ports(xml) == ["9014", "17446"]

captured = {}
original_run = module.subprocess.run
def fake_run(command, **kwargs):
    captured["command"] = command
    captured["kwargs"] = kwargs
    return SimpleNamespace(returncode=0, stdout=xml, stderr="")
module.subprocess.run = fake_run
try:
    scan_result = module.scan_one(
        {"ip": "10.0.0.2", "score": 100, "reasons": ["gpu_medium"]},
        SimpleNamespace(
            nmap_bin="nmap", max_rate=200, min_rate=100, max_retries=0,
            host_timeout="40m", process_timeout=2700,
        ),
    )
finally:
    module.subprocess.run = original_run
assert scan_result["status"] == "complete"
assert scan_result["ports"] == ["9014", "17446"]
assert "-Pn" in captured["command"] and "-p-" in captured["command"]
assert captured["command"][captured["command"].index("--host-timeout") + 1] == "40m"
assert captured["command"][captured["command"].index("--min-rate") + 1] == "100"
assert captured["command"][captured["command"].index("--max-retries") + 1] == "0"
assert captured["kwargs"]["timeout"] == 2700
assert captured["command"][captured["command"].index("--max-rate") + 1] == "200"

with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "new_ports.csv"
    port_rows = [
        {"ip": "10.0.0.2", "port": "8000", "owner": "test"},
    ]
    count = module.output_new_ports(
        output,
        port_rows,
        ["ip", "port", "owner"],
        {
            "10.0.0.2": {
                "status": "complete",
                "ports": ["8000", "9014", "17446"],
            }
        },
    )
    assert count == 2
    with output.open(encoding="utf-8-sig", newline="") as source:
        output_rows = list(csv.DictReader(source))
    assert [row["port"] for row in output_rows] == ["9014", "17446"]
    assert all(row["owner"] == "test" for row in output_rows)

with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory)
    ports_input = directory / "ports.csv"
    llm_input = directory / "llm.csv"
    output = directory / "new.csv"
    checkpoint = directory / "checkpoint.jsonl"
    summary = directory / "summary.json"
    module.write_csv(
        ports_input,
        [{"ip": "10.0.0.1", "port": "8000"}],
        ["ip", "port"],
    )
    module.write_csv(
        llm_input,
        [{"ip": "10.0.0.1", "port": "8000", "gpu_likelihood": "高"}],
        ["ip", "port", "gpu_likelihood"],
    )
    original_argv = sys.argv
    sys.argv = [
        "full_port_recheck.py",
        "--ports-input", str(ports_input),
        "--llm-input", str(llm_input),
        "--output", str(output),
        "--checkpoint", str(checkpoint),
        "--summary", str(summary),
        "--nmap-bin", "/must/not/be/executed",
    ]
    try:
        assert module.main() == 0
    finally:
        sys.argv = original_argv
    end_to_end = json.loads(summary.read_text(encoding="utf-8"))
    assert end_to_end["selected_candidates"] == 0
    assert end_to_end["skipped_gpu_high_ips"] == 1
    assert not checkpoint.exists()
print("full_port_recheck_tests=passed")
