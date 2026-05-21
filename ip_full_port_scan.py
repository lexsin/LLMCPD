#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full port scan (-p-) on a sample of IPs and merge into IPs_1_result_scan.csv."""

import argparse
import csv
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set

COL_UNIT = "\u63a5\u5165\u5355\u4f4d"
COL_START = "\u8d77\u59cbIP"
COL_END = "\u7ec8\u6b62IP"
COL_IP = "ip"
COL_OPEN_PORTS = "open_ports"
COL_ALL_PORTS = "all_open_ports"
COL_PING = "ping"
PORT_SEP = ";"


def read_csv_rows(path: Path) -> List[dict]:
    for encoding in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=encoding, newline="") as f:
                rows = list(csv.DictReader(f))
            print("Input encoding: %s" % encoding)
            return rows
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("csv", b"", 0, 1, "unsupported encoding")


def sample_ips_with_open_ports(rows: List[dict], count: int) -> List[str]:
    """Pick `count` unique IPs that already have HTTP open_ports."""
    seen: Set[str] = set()
    picked: List[str] = []
    for row in rows:
        ip = row.get(COL_IP, "").strip()
        ports = row.get(COL_OPEN_PORTS, "").strip()
        if not ip or ip in seen or not ports:
            continue
        seen.add(ip)
        picked.append(ip)
        if len(picked) >= count:
            break
    return picked


def write_ip_list(path: Path, ips: List[str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for ip in ips:
            f.write(ip + "\n")


def require_root() -> None:
    if os.geteuid() != 0:
        print(
            "SYN scan (-sS) requires root. Run: sudo python3 %s ..."
            % Path(__file__).name,
            file=sys.stderr,
        )
        sys.exit(1)


def run_nmap_full(ip_list_path: Path, xml_path: Path) -> None:
    cmd = [
        "nmap",
        "-sS",
        "-n",
        "-T4",
        "--min-rate",
        "3000",
        "--max-retries",
        "1",
        "--host-timeout",
        "600s",
        "--open",
        "-p-",
        "-iL",
        str(ip_list_path),
        "-oX",
        str(xml_path),
    ]
    print("Running: %s" % " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("nmap exited with code %d" % result.returncode, file=sys.stderr)
        sys.exit(result.returncode)


def parse_nmap_xml(xml_path: Path) -> Dict[str, str]:
    if not xml_path.is_file():
        print("XML not found: %s" % xml_path, file=sys.stderr)
        sys.exit(1)

    tree = ET.parse(xml_path)
    root = tree.getroot()
    open_by_ip: Dict[str, str] = {}

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        if not ip:
            continue

        ports: List[int] = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    try:
                        ports.append(int(port.get("portid", "0")))
                    except ValueError:
                        continue

        open_by_ip[ip] = PORT_SEP.join(str(p) for p in sorted(ports))

    return open_by_ip


def load_cache(path: Path) -> Dict[str, str]:
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path: Path, cache: Dict[str, str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=0)


def merge_into_rows(
    rows: List[dict], all_ports_by_ip: Dict[str, str]
) -> List[dict]:
    fieldnames = list(rows[0].keys()) if rows else []
    if COL_ALL_PORTS not in fieldnames:
        if COL_OPEN_PORTS in fieldnames:
            idx = fieldnames.index(COL_OPEN_PORTS) + 1
            fieldnames.insert(idx, COL_ALL_PORTS)
        else:
            fieldnames.append(COL_ALL_PORTS)

    output: List[dict] = []
    for row in rows:
        ip = row.get(COL_IP, "").strip()
        out = {k: row.get(k, "") for k in row}
        out[COL_ALL_PORTS] = all_ports_by_ip.get(ip, row.get(COL_ALL_PORTS, ""))
        output.append(out)
    return output, fieldnames


def main() -> int:
    parser = argparse.ArgumentParser(description="Full port scan sample and CSV merge")
    parser.add_argument("--input", default="IPs_1_result_scan.csv")
    parser.add_argument("--output", default="IPs_1_result_scan.csv")
    parser.add_argument("--xml", default="scan_full.xml")
    parser.add_argument("--ip-list", default="ips_full_scan.txt")
    parser.add_argument("--cache", default="full_port_scan_cache.json")
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--skip-scan", action="store_true")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    csv_path = base_dir / args.input
    output_path = base_dir / args.output
    xml_path = base_dir / args.xml
    ip_list_path = base_dir / args.ip_list
    cache_path = base_dir / args.cache

    if not csv_path.is_file():
        print("CSV not found: %s" % csv_path, file=sys.stderr)
        return 1

    rows = read_csv_rows(csv_path)
    if not rows:
        print("Empty CSV", file=sys.stderr)
        return 1

    sample_ips = sample_ips_with_open_ports(rows, args.sample)
    if len(sample_ips) < args.sample:
        print(
            "Only %d IPs with open_ports found (requested %d)"
            % (len(sample_ips), args.sample),
            file=sys.stderr,
        )
    if not sample_ips:
        print("No IPs with open_ports to sample", file=sys.stderr)
        return 1

    print("Sample IPs for full port scan (%d):" % len(sample_ips))
    for ip in sample_ips:
        print("  %s" % ip)

    write_ip_list(ip_list_path, sample_ips)

    if not args.skip_scan:
        require_root()
        run_nmap_full(ip_list_path, xml_path)
    elif not xml_path.is_file():
        print("--skip-scan set but XML missing: %s" % xml_path, file=sys.stderr)
        return 1

    scanned = parse_nmap_xml(xml_path)
    print("Scanned hosts with open ports: %d" % sum(1 for v in scanned.values() if v))
    for ip, ports in scanned.items():
        n = len(ports.split(PORT_SEP)) if ports else 0
        print("  %s: %d open ports" % (ip, n))

    cache = load_cache(cache_path)
    cache.update(scanned)
    save_cache(cache_path, cache)

    output_rows, fieldnames = merge_into_rows(rows, cache)
    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_NONNUMERIC,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(output_rows)

    filled = sum(1 for r in output_rows if r.get(COL_ALL_PORTS))
    print("Wrote %d rows -> %s (all_open_ports filled: %d)" % (
        len(output_rows), output_path, filled
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
