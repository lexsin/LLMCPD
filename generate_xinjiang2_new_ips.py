#!/usr/bin/env python3
import argparse
import csv
import ipaddress
from pathlib import Path

import openpyxl


def expand_workbook(path: Path) -> set:
    sheet = openpyxl.load_workbook(path, read_only=True, data_only=True).active
    addresses = set()
    for row_number, row in enumerate(
        sheet.iter_rows(min_row=2, values_only=True), start=2
    ):
        if not row or row[0] is None or row[1] is None:
            continue
        start = ipaddress.ip_address(str(row[0]).strip())
        end = ipaddress.ip_address(str(row[1]).strip())
        if start.version != 4 or end.version != 4 or int(end) < int(start):
            raise ValueError(f"{path}:{row_number}: invalid IPv4 range")
        addresses.update(range(int(start), int(end) + 1))
    return addresses


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--new", required=True, type=Path)
    parser.add_argument("--old", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    old_ips = expand_workbook(args.old)
    new_ips = expand_workbook(args.new)
    new_only = sorted(new_ips - old_ips)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["起始IP", "终止IP", "ip", "ping"]
        )
        writer.writeheader()
        for value in new_only:
            ip = str(ipaddress.ip_address(value))
            writer.writerow({"起始IP": ip, "终止IP": ip, "ip": ip, "ping": ""})

    print(f"old_unique={len(old_ips)}")
    print(f"new_unique={len(new_ips)}")
    print(f"overlap={len(new_ips & old_ips)}")
    print(f"new_only={len(new_only)}")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
