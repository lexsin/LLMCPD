#!/usr/bin/env python3
import importlib.util
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "merge_llm_results", here / "merge_llm_results.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

base = [
    {"ip": "10.0.0.1", "port": "8000", "gpu_likelihood": "中"},
    {"ip": "10.0.0.2", "port": "80", "gpu_likelihood": "低"},
]
incremental = [
    {"ip": "10.0.0.1", "port": "9014", "gpu_likelihood": "高"},
    {"ip": "10.0.0.2", "port": "80", "gpu_likelihood": "中"},
]
merged = module.merge_rows(base, incremental)
assert [(row["ip"], row["port"]) for row in merged] == [
    ("10.0.0.1", "8000"), ("10.0.0.2", "80"), ("10.0.0.1", "9014"),
]
assert merged[1]["gpu_likelihood"] == "中"
print("merge_llm_results_tests=passed")
