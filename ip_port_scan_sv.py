#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expand IPs_1_result_scan.csv by port and run nmap -sV for service detection."""

import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

COL_UNIT = "\u63a5\u5165\u5355\u4f4d"
COL_START = "\u8d77\u59cbIP"
COL_END = "\u7ec8\u6b62IP"
COL_IP = "ip"
COL_PORT = "port"
COL_SERVICE = "service"
COL_PING = "ping"
COL_OPEN_PORTS = "open_ports"

PORT_SEP = ";"
FIELDNAMES = [COL_UNIT, COL_START, COL_END, COL_IP, COL_PORT, COL_SERVICE, COL_PING]


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


def parse_ports_str(value: str) -> List[str]:
    if not value or not value.strip():
        return []
    if PORT_SEP in value:
        parts = value.split(PORT_SEP)
    else:
        parts = value.split(",")
    return sorted({p.strip() for p in parts if p.strip()}, key=int)


def expand_scan_rows(rows: List[dict]) -> List[dict]:
    """One output row per (ip, open port); skips rows with empty open_ports."""
    expanded: List[dict] = []
    for row in rows:
        ports = parse_ports_str(row.get(COL_OPEN_PORTS, ""))
        if not ports:
            continue
        base = {
            COL_UNIT: row.get(COL_UNIT, ""),
            COL_START: row.get(COL_START, ""),
            COL_END: row.get(COL_END, ""),
            COL_IP: row.get(COL_IP, "").strip(),
            COL_PING: row.get(COL_PING, ""),
            COL_SERVICE: "",
        }
        ip = base[COL_IP]
        if not ip:
            continue
        for port in ports:
            expanded.append({**base, COL_PORT: port})
    return expanded


def group_ports_by_ip(expanded: List[dict]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for row in expanded:
        ip = row[COL_IP]
        port = row[COL_PORT]
        grouped.setdefault(ip, []).append(port)
    for ip in grouped:
        grouped[ip] = sorted(set(grouped[ip]), key=int)
    return grouped


def require_root() -> None:
    if os.geteuid() != 0:
        print(
            "SYN scan (-sS) requires root. Run: sudo python3 %s ..."
            % Path(__file__).name,
            file=sys.stderr,
        )
        sys.exit(1)


def format_service(port_elem: ET.Element) -> str:
    svc = port_elem.find("service")
    if svc is None:
        return ""
    parts: List[str] = []
    for attr in ("name", "product", "version", "extrainfo"):
        value = (svc.get(attr) or "").strip()
        if value:
            parts.append(value)
    return " ".join(parts)


def parse_nmap_sv_xml(xml_path: Path) -> Dict[Tuple[str, str], str]:
    if not xml_path.is_file():
        return {}

    tree = ET.parse(xml_path)
    root = tree.getroot()
    services: Dict[Tuple[str, str], str] = {}

    for host in root.findall("host"):
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")
        if not ip:
            continue

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid", "")
            if not port_id:
                continue
            services[(ip, port_id)] = format_service(port)

    return services


def run_nmap_sv(ip: str, ports: List[str], xml_path: Path) -> None:
    port_spec = ",".join(ports)
    host_timeout = "%ds" % max(60, min(300, 30 + len(ports) * 8))
    cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-n",
        "-T4",
        "--version-intensity",
        "2",
        "--max-retries",
        "1",
        "--host-timeout",
        host_timeout,
        "--open",
        "-p",
        port_spec,
        ip,
        "-oX",
        str(xml_path),
    ]
    print("Running: %s" % " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print(
            "nmap exited with code %d for %s" % (result.returncode, ip),
            file=sys.stderr,
        )


def xml_path_for_ip(xml_dir: Path, ip: str) -> Path:
    digest = hashlib.md5(ip.encode("utf-8")).hexdigest()[:12]
    safe = ip.replace(":", "_")
    return xml_dir / ("%s_%s.xml" % (safe, digest))


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


def cache_key(ip: str, port: str) -> str:
    return "%s:%s" % (ip, port)


def scan_all_sv(
    grouped: Dict[str, List[str]],
    xml_dir: Path,
    cache: Dict[str, str],
    skip_scan: bool,
) -> Dict[str, str]:
    xml_dir.mkdir(parents=True, exist_ok=True)
    total = len(grouped)
    for idx, (ip, ports) in enumerate(sorted(grouped.items()), start=1):
        print("[%d/%d] %s (%d ports)" % (idx, total, ip, len(ports)))
        key_prefix = ip + ":"
        if skip_scan:
            xml_path = xml_path_for_ip(xml_dir, ip)
            found = parse_nmap_sv_xml(xml_path)
            for port in ports:
                cache[cache_key(ip, port)] = found.get((ip, port), "")
            continue

        xml_path = xml_path_for_ip(xml_dir, ip)
        pending = [
            p
            for p in ports
            if cache_key(ip, p) not in cache or not cache.get(cache_key(ip, p))
        ]
        if not pending:
            print("  cached, skip")
            continue

        run_nmap_sv(ip, pending, xml_path)
        found = parse_nmap_sv_xml(xml_path)
        for port in ports:
            cache[cache_key(ip, port)] = found.get((ip, port), cache.get(cache_key(ip, port), ""))

    return cache


def apply_services(rows: List[dict], cache: Dict[str, str]) -> List[dict]:
    out: List[dict] = []
    for row in rows:
        ip = row[COL_IP]
        port = row[COL_PORT]
        out.append(
            {
                COL_UNIT: row[COL_UNIT],
                COL_START: row[COL_START],
                COL_END: row[COL_END],
                COL_IP: ip,
                COL_PORT: port,
                COL_SERVICE: cache.get(cache_key(ip, port), ""),
                COL_PING: row[COL_PING],
            }
        )
    return out


def print_stats(rows: List[dict]) -> None:
    with_service = sum(1 for r in rows if r[COL_SERVICE])
    print("Expanded rows: %d" % len(rows))
    print("Rows with service detected: %d" % with_service)
    print("Rows without service: %d" % (len(rows) - with_service))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Expand scan CSV by port and run nmap -sV"
    )
    parser.add_argument("--input", default="IPs_1_result_scan.csv")
    parser.add_argument("--output", default="IPs_1_result_scan_1.csv")
    parser.add_argument("--xml-dir", default="scan_sv_xml")
    parser.add_argument("--cache", default="port_sv_cache.json")
    parser.add_argument("--skip-scan", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / args.input
    output_path = base_dir / args.output
    xml_dir = base_dir / args.xml_dir
    cache_path = base_dir / args.cache

    if not input_path.is_file():
        print("Input not found: %s" % input_path, file=sys.stderr)
        return 1

    rows = read_csv_rows(input_path)
    if not rows:
        print("Empty input CSV", file=sys.stderr)
        return 1

    expanded = expand_scan_rows(rows)
    if args.limit is not None:
        seen_ips: set = set()
        limited: List[dict] = []
        for row in expanded:
            if row[COL_IP] in seen_ips or len(seen_ips) < args.limit:
                seen_ips.add(row[COL_IP])
                limited.append(row)
        expanded = limited
        print("Limited to %d IP(s), %d row(s)" % (len(seen_ips), len(expanded)))

    if not expanded:
        print("No open ports to expand", file=sys.stderr)
        return 1

    grouped = group_ports_by_ip(expanded)
    print(
        "IPs with open ports: %d, expanded rows: %d"
        % (len(grouped), len(expanded))
    )

    cache = load_cache(cache_path)
    if not args.skip_scan:
        require_root()
    cache = scan_all_sv(grouped, xml_dir, cache, args.skip_scan)
    save_cache(cache_path, cache)

    output_rows = apply_services(expanded, cache)
    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=FIELDNAMES,
            quoting=csv.QUOTE_NONNUMERIC,
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print("Wrote %d rows -> %s" % (len(output_rows), output_path))
    print_stats(output_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
