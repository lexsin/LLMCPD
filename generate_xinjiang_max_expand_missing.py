#!/usr/bin/env python3
import argparse
import csv
import ipaddress
from pathlib import Path

import pandas as pd


EXCLUDED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "106.124.128.0/20",
        "36.105.8.0/21",
        "36.105.16.0/20",
        "36.105.32.0/21",
        "36.107.160.0/20",
        "36.109.208.0/21",
        "36.109.216.0/22",
        "172.16.0.0/16",
    )
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--scanned", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--col-start", default="startIP")
    parser.add_argument("--col-end", default="endIP")
    parser.add_argument("--max-expand", type=int, default=256)
    args = parser.parse_args()

    with Path(args.scanned).open("r", encoding="utf-8-sig", newline="") as source:
        scanned = {
            row["ip"].strip()
            for row in csv.DictReader(source)
            if row.get("ip")
        }

    frame = pd.read_excel(args.input).where(lambda value: value.notna(), "")
    missing = {}
    truncated_segments = 0
    raw_missing = 0
    excluded_count = 0
    for _, row in frame.iterrows():
        start_text = str(row.get(args.col_start, "")).strip()
        end_text = str(row.get(args.col_end, "")).strip()
        try:
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
        except ValueError:
            continue
        size = int(end) - int(start) + 1
        if size <= args.max_expand:
            continue
        truncated_segments += 1
        raw_missing += size - 2
        for value in range(int(start) + 1, int(end)):
            address = ipaddress.ip_address(value)
            ip = str(address)
            if ip in scanned or ip in missing:
                continue
            if any(address in network for network in EXCLUDED_NETWORKS):
                excluded_count += 1
                continue
            missing[ip] = (start_text, end_text)

    ordered = sorted(
        missing,
        key=lambda value: (
            ipaddress.ip_address(value).version,
            int(ipaddress.ip_address(value)),
        ),
    )
    output = Path(args.output)
    temp = output.with_suffix(output.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=[args.col_start, args.col_end, "ip", "ping"])
        writer.writeheader()
        for ip in ordered:
            start_text, end_text = missing[ip]
            writer.writerow({args.col_start: start_text, args.col_end: end_text, "ip": ip, "ping": ""})
    temp.replace(output)
    print("truncated_segments=%d" % truncated_segments)
    print("raw_missing=%d" % raw_missing)
    print("already_scanned=%d" % len(scanned))
    print("excluded=%d" % excluded_count)
    print("unique_missing=%d" % len(ordered))
    print("output=%s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())