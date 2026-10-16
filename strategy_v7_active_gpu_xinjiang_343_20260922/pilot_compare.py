#!/usr/bin/env python3
"""Compare a full-port pilot result with its pre-scan baseline."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

LEVEL_RANK = {"未知": 0, "低": 1, "中": 2, "高": 3}


def read_rows(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def row_key(row):
    return str(row.get("ip") or "").strip(), str(row.get("port") or "").strip()


def max_levels(rows, field):
    result = {}
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        level = str(row.get(field) or "未知").strip()
        level = level if level in LEVEL_RANK else "未知"
        if ip and LEVEL_RANK[level] > LEVEL_RANK.get(result.get(ip, "未知"), 0):
            result[ip] = level
        elif ip:
            result.setdefault(ip, level)
    return result


def level_counts(levels):
    counts = Counter(levels.values())
    return {level: counts.get(level, 0) for level in ("高", "中", "低", "未知")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--final", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--text-output", type=Path)
    args = parser.parse_args()
    baseline, final = read_rows(args.baseline), read_rows(args.final)
    before_keys = {row_key(row) for row in baseline if all(row_key(row))}
    after_keys = {row_key(row) for row in final if all(row_key(row))}
    new_keys = sorted(after_keys - before_keys)
    report = {
        "baseline_rows": len(baseline),
        "final_rows": len(final),
        "new_port_count": len(new_keys),
        "new_ports": [{"ip": ip, "port": port} for ip, port in new_keys],
    }
    lines = [
        f"baseline_rows={len(baseline)}",
        f"final_rows={len(final)}",
        f"new_port_count={len(new_keys)}",
    ]
    for label, field in (("gpu", "gpu_likelihood"), ("npu", "npu_likelihood")):
        before, after = max_levels(baseline, field), max_levels(final, field)
        improved = []
        for ip in sorted(set(before) | set(after)):
            old, new = before.get(ip, "未知"), after.get(ip, "未知")
            if LEVEL_RANK[new] > LEVEL_RANK[old]:
                improved.append({"ip": ip, "before": old, "after": new})
        report[label] = {
            "baseline_ip_level_counts": level_counts(before),
            "final_ip_level_counts": level_counts(after),
            "improved_ips": improved,
        }
        lines.append(f"{label}_baseline={json.dumps(level_counts(before), ensure_ascii=False)}")
        lines.append(f"{label}_final={json.dumps(level_counts(after), ensure_ascii=False)}")
        lines.append(f"{label}_improved_ips={json.dumps(improved, ensure_ascii=False)}")
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.text_output:
        args.text_output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
