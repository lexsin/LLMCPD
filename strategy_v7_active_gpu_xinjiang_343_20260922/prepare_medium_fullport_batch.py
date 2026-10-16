#!/usr/bin/env python3
"""Build deduplicated full-port inputs for all GPU-medium IPs in a batch."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

HIGH = {"高", "high", "gpu_high"}
MEDIUM = {"中", "medium", "gpu_medium"}


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        return list(reader), list(reader.fieldnames or [])


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def norm(value):
    return str(value or "").strip().lower()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    llm_by_ip, ports_by_key = {}, {}
    llm_fields, port_fields = [], []
    companies_by_ip = {}
    for company_dir in sorted(p for p in args.batch_root.iterdir() if p.is_dir()):
        llm_path = company_dir / "input_llm_gpu_low_rechecked.csv"
        ports_path = company_dir / "input_scan_ports.csv"
        if not llm_path.exists() or not ports_path.exists():
            continue
        llm_rows, fields = read_csv(llm_path)
        llm_fields += [field for field in fields if field not in llm_fields]
        for row in llm_rows:
            ip = str(row.get("ip") or "").strip()
            if not ip:
                continue
            row["source_company"] = row.get("source_company") or company_dir.name
            llm_by_ip.setdefault(ip, []).append(row)
            companies_by_ip.setdefault(ip, set()).add(company_dir.name)
        port_rows, fields = read_csv(ports_path)
        port_fields += [field for field in fields if field not in port_fields]
        for row in port_rows:
            ip, port = str(row.get("ip") or "").strip(), str(row.get("port") or "").strip()
            if ip and port:
                row["source_company"] = row.get("source_company") or company_dir.name
                ports_by_key.setdefault((ip, port), row)

    selected = set()
    for ip, rows in llm_by_ip.items():
        levels = {norm(row.get("gpu_likelihood")) for row in rows}
        if levels & MEDIUM and not levels & HIGH:
            selected.add(ip)

    llm_rows = [row for ip in sorted(selected) for row in llm_by_ip[ip]]
    port_rows = [
        row for (ip, _), row in sorted(ports_by_key.items())
        if ip in selected
    ]
    if "source_company" not in llm_fields:
        llm_fields.append("source_company")
    if "source_company" not in port_fields:
        port_fields.append("source_company")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "medium_llm_baseline.csv", llm_rows, llm_fields)
    write_csv(args.output_dir / "medium_scan_ports.csv", port_rows, port_fields)
    company_counts = Counter()
    for ip in selected:
        for company in companies_by_ip.get(ip, ()):
            company_counts[company] += 1
    manifest = {
        "selected_unique_ips": len(selected),
        "baseline_rows": len(llm_rows),
        "existing_port_rows": len(port_rows),
        "company_ip_counts": dict(sorted(company_counts.items())),
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
