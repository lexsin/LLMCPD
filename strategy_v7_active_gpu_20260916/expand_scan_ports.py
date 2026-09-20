#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expand IPs_1_result_scan.csv: one row per open port, write IPs_1_result_scan_2.csv."""

import argparse
import csv
import sys
from pathlib import Path
from typing import List

COL_UNIT = "接入单位"
COL_START = "起始IP"
COL_END = "终止IP"
COL_IP = "ip"
COL_OPEN_PORTS = "open_ports"
COL_PORT = "port"
COL_PING = "ping"

PORT_SEP = ";"
FIELDNAMES = [COL_UNIT, COL_START, COL_END, COL_IP, COL_PORT, COL_PING]


def read_csv(path: Path) -> List[dict]:
    for encoding in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=encoding, newline="") as f:
                rows = list(csv.DictReader(f))
            print("Input encoding: %s" % encoding)
            return rows
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("csv", b"", 0, 1, "unsupported encoding")


def parse_ports(value: str) -> List[str]:
    if not value or not value.strip():
        return []
    sep = PORT_SEP if PORT_SEP in value else ","
    parts = [p.strip() for p in value.split(sep) if p.strip()]
    try:
        return sorted(set(parts), key=int)
    except ValueError:
        return sorted(set(parts))


def expand(rows: List[dict]) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        ports = parse_ports(row.get(COL_OPEN_PORTS, ""))
        if not ports:
            continue
        ip = row.get(COL_IP, "").strip()
        if not ip:
            continue
        base = {
            COL_UNIT: row.get(COL_UNIT, ""),
            COL_START: row.get(COL_START, ""),
            COL_END: row.get(COL_END, ""),
            COL_IP: ip,
            COL_PING: row.get(COL_PING, ""),
        }
        for port in ports:
            out.append({**base, COL_PORT: port})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Expand open_ports column into one row per port"
    )
    parser.add_argument("--input", default="IPs_1_result_scan.csv")
    parser.add_argument("--output", default="IPs_1_result_scan_2.csv")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / args.input
    output_path = base_dir / args.output

    if not input_path.is_file():
        print("Input not found: %s" % input_path, file=sys.stderr)
        return 1

    rows = read_csv(input_path)
    if not rows:
        print("Empty input CSV", file=sys.stderr)
        return 1

    expanded = expand(rows)
    if not expanded:
        print("No rows with open ports found", file=sys.stderr)
        return 1

    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, quoting=csv.QUOTE_NONNUMERIC)
        writer.writeheader()
        writer.writerows(expanded)

    unique_ips = len({r[COL_IP] for r in expanded})
    print("Input rows: %d" % len(rows))
    print("IPs with open ports: %d" % unique_ips)
    print("Expanded rows: %d" % len(expanded))
    print("Wrote -> %s" % output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
