#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch LLM/inference-oriented port scan via nmap and merge open_ports into CSV."""

import argparse
import csv
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

COL_UNIT = "\u63a5\u5165\u5355\u4f4d"
COL_START = "\u8d77\u59cbIP"
COL_END = "\u7ec8\u6b62IP"
COL_IP = "ip"
COL_OPEN_PORTS = "open_ports"
COL_PING = "ping"

# No open ports -> empty string (not "none")
# Semicolon separator avoids Excel treating "80,443" as one number with thousand separators
PORT_SEP = ";"
FIELDNAMES = [COL_UNIT, COL_START, COL_END, COL_IP, COL_OPEN_PORTS, COL_PING]

# ~488 ports: user list + legacy HTTP ports + LLM/inference/vector-DB extras
SCAN_PORTS = (
    "80,443,1234,1337,2222,2242,2379,2380,2381,3000,3001,3002,3003,3004,3005,3006,3007,3008,"
    "3009,3030,3080,3100,3128,3200,3210,3306,3307,3308,3333,3389,4000,4001,4002,4003,4040,"
    "4041,4042,4043,4044,4045,4173,4443,4891,5000,5001,5002,5003,5004,5005,5006,5007,5008,"
    "5009,5010,5050,5173,5174,5432,5433,5434,5555,5556,5557,5558,5566,5601,5672,5673,5800,"
    "6006,6333,6334,6335,6336,6337,6338,6379,6380,6381,6443,6444,6445,7000,7080,7443,7444,"
    "7445,7473,7474,7500,7687,7688,7689,7700,7860,7861,7862,7863,7864,7865,7866,7867,7868,"
    "7869,7870,7997,7998,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,"
    "8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8050,8070,8071,8072,"
    "8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8099,8100,8101,8102,8103,8104,"
    "8105,8106,8107,8108,8109,8110,8111,8112,8113,8114,8115,8116,8117,8118,8119,8120,8121,"
    "8122,8123,8124,8125,8126,8127,8128,8129,8130,8131,8132,8133,8134,8135,8136,8137,8138,"
    "8139,8140,8141,8142,8143,8144,8145,8146,8147,8148,8149,8150,8151,8152,8153,8154,8155,"
    "8156,8157,8158,8159,8160,8161,8162,8163,8164,8165,8166,8167,8168,8169,8180,8181,8188,"
    "8189,8265,8266,8267,8268,8443,8444,8445,8500,8501,8502,8503,8504,8505,8506,8765,8786,"
    "8787,8788,8789,8790,8793,8794,8800,8880,8881,8882,8883,8884,8885,8886,8887,8888,8889,"
    "9000,9001,9002,9003,9010,9011,9080,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,"
    "9100,9200,9201,9202,9203,9300,9301,9302,9380,9400,9401,9443,9444,9445,9996,9997,9998,"
    "9999,10001,10002,10003,10080,10081,10082,10248,10249,10250,10255,10256,10443,10444,"
    "10445,11400,11401,11402,11403,11404,11405,11406,11407,11408,11409,11410,11411,11412,"
    "11413,11414,11415,11416,11417,11418,11419,11420,11421,11422,11423,11424,11425,11426,"
    "11427,11428,11429,11430,11431,11432,11433,11434,11435,11436,11437,11438,11439,11440,"
    "11441,11442,11443,11444,11445,11446,11447,11448,11449,15672,15673,18080,18081,18082,"
    "18083,19120,19121,19122,19530,19531,19532,20000,20001,20002,20010,20011,20012,20013,"
    "20014,20015,20016,20017,20018,20019,20020,20021,20022,20023,20024,20025,20026,20027,"
    "20028,20029,20080,20443,21001,21002,21003,21004,21005,21006,23333,27017,27018,27019,"
    "30000,30001,30002,30003,30004,30005,30006,30007,30008,30009,30010,30011,30012,30013,"
    "30014,30015,30016,30017,30018,30019,30020,30021,30022,30023,30024,30025,30026,30027,"
    "30028,30029,39280,39281,39282,39283,39284,39285,39286,39287,39288,39289,40000,40001,"
    "40002,40010,40011,40012,40013,40014,40015,40016,40017,40018,40019,40020,40021,40022,"
    "40023,40024,40025,40026,40027,40028,40029,40080,40443,41640,41641,41642,41643,41644,"
    "41645,41646,41647,41648,41649,50050,50051,50052,50053,50054,50055,50056,50057,50058,"
    "50059,51820"
)


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


def extract_unique_ips(rows: List[dict], limit: Optional[int]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for row in rows:
        ip = row.get(COL_IP, "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        ordered.append(ip)
        if limit is not None and len(ordered) >= limit:
            break
    return ordered


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


def run_nmap(ip_list_path: Path, xml_path: Path) -> None:
    cmd = [
        "nmap",
        "-sS",
        "-n",
        "-T4",
        "--min-rate",
        "5000",
        "--max-retries",
        "1",
        "--host-timeout",
        "180s",
        "--open",
        "-p",
        SCAN_PORTS,
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


def normalize_ports_str(value: str) -> str:
    """Convert legacy comma-separated port lists to PORT_SEP format."""
    if not value or PORT_SEP in value:
        return value
    return PORT_SEP.join(p.strip() for p in value.split(",") if p.strip())


def load_cache(path: Path) -> Dict[str, str]:
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        return {
            str(k): normalize_ports_str(str(v)) for k, v in data.items()
        }
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path: Path, cache: Dict[str, str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=0)


def merge_results(
    rows: List[dict], open_by_ip: Dict[str, str]
) -> List[dict]:
    output: List[dict] = []
    for row in rows:
        ip = row.get(COL_IP, "").strip()
        output.append(
            {
                COL_UNIT: row.get(COL_UNIT, ""),
                COL_START: row.get(COL_START, ""),
                COL_END: row.get(COL_END, ""),
                COL_IP: ip,
                COL_OPEN_PORTS: open_by_ip.get(ip, ""),
                COL_PING: row.get(COL_PING, ""),
            }
        )
    return output


def print_stats(rows: List[dict]) -> None:
    with_ports = sum(1 for r in rows if r[COL_OPEN_PORTS])
    port_counter: Counter = Counter()
    for r in rows:
        if not r[COL_OPEN_PORTS]:
            continue
        for p in r[COL_OPEN_PORTS].split(PORT_SEP):
            p = p.strip()
            if p:
                port_counter[p] += 1

    print("Rows: %d" % len(rows))
    print("IPs with open ports: %d" % with_ports)
    print("IPs without open ports: %d" % (len(rows) - with_ports))
    if port_counter:
        print("Top ports:")
        for port, count in port_counter.most_common(10):
            print("  %s: %d" % (port, count))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Nmap LLM/inference port scan and CSV open_ports merge"
    )
    parser.add_argument("--input", default="IPs_1_result.csv")
    parser.add_argument("--output", default="IPs_1_result_scan.csv")
    parser.add_argument("--xml", default="scan.xml")
    parser.add_argument("--ip-list", default="ips_scan.txt")
    parser.add_argument("--cache", default="port_scan_cache.json")
    parser.add_argument("--skip-scan", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / args.input
    output_path = base_dir / args.output
    xml_path = base_dir / args.xml
    ip_list_path = base_dir / args.ip_list
    cache_path = base_dir / args.cache

    if not input_path.is_file():
        print("Input not found: %s" % input_path, file=sys.stderr)
        return 1

    try:
        rows = read_csv_rows(input_path)
    except UnicodeDecodeError:
        print("Cannot decode input CSV", file=sys.stderr)
        return 1

    if not rows:
        print("Empty input CSV", file=sys.stderr)
        return 1

    ips = extract_unique_ips(rows, args.limit)
    print("Unique IPs to scan: %d" % len(ips))
    write_ip_list(ip_list_path, ips)

    if not args.skip_scan:
        require_root()
        run_nmap(ip_list_path, xml_path)
    elif not xml_path.is_file():
        print("--skip-scan set but XML missing: %s" % xml_path, file=sys.stderr)
        return 1

    open_by_ip = parse_nmap_xml(xml_path)
    print("Hosts with open ports in XML: %d" % sum(1 for v in open_by_ip.values() if v))

    cache = load_cache(cache_path)
    cache.update(open_by_ip)
    save_cache(cache_path, cache)

    output_rows = merge_results(rows, cache)
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
