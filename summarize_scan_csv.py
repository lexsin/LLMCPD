#!/usr/bin/env python3
import argparse
import csv
from collections import Counter
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("csv_path")
args = parser.parse_args()

path = Path(args.csv_path)
with path.open("r", encoding="utf-8-sig", newline="") as source:
    rows = list(csv.DictReader(line.replace("\0", "") for line in source))

print("rows=%d" % len(rows))
for field in (
    "is_llm", "service_type", "gpu_likelihood", "deploy_tool",
    "scan_status", "scan_confidence",
):
    counts = Counter((row.get(field) or "").strip() for row in rows)
    print("%s=%s" % (field, dict(counts)))

gpu_rows = [
    row for row in rows
    if (row.get("gpu_likelihood") or "").strip() in {"高", "中"}
]
print("gpu_rows=%d" % len(gpu_rows))
for row in gpu_rows[:20]:
    print(
        "%s:%s %s %s %s"
        % (
            row.get("ip"),
            row.get("port"),
            row.get("gpu_likelihood"),
            row.get("service_type"),
            row.get("gpu_evidence"),
        )
    )
