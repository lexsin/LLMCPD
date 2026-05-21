#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expand IP ranges from CSV and ping each address (Windows)."""

import argparse
import csv
import ipaddress
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

DEFAULT_MAX_EXPAND = 256
COL_UNIT = "\u63a5\u5165\u5355\u4f4d"
COL_START = "\u8d77\u59cbIP"
COL_END = "\u7ec8\u6b62IP"
FIELDNAMES = [COL_UNIT, COL_START, COL_END, "ip", "ping"]


def expand_range(
    start_str: str, end_str: str, max_expand: int = DEFAULT_MAX_EXPAND
) -> Tuple[List[str], bool]:
    start = ipaddress.ip_address(start_str.strip())
    end = ipaddress.ip_address(end_str.strip())
    if start > end:
        raise ValueError("%s > %s" % (start_str, end_str))

    size = int(end) - int(start) + 1
    if size > max_expand:
        return [str(start), str(end)], True

    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)], False


def ping_one(ip: str, timeout_sec: float) -> str:
    timeout_ms = int(timeout_sec * 1000)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "error"

    if addr.version == 6:
        cmd = ["ping", "-6", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="gbk",
            errors="replace",
            timeout=timeout_sec + 1,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "error"

    output = (result.stdout or "") + (result.stderr or "")
    time_cn = "\u65f6\u95f4"
    if result.returncode == 0 and (
        "TTL=" in output.upper()
        or (time_cn + "=") in output
        or "time=" in output.lower()
        or (time_cn + "<") in output
    ):
        return "success"
    return "error"


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


def collect_unique_ips(
    rows: List[dict],
    limit: Optional[int],
    max_expand: int = DEFAULT_MAX_EXPAND,
) -> Tuple[List[dict], Set[str]]:
    processed: List[dict] = []
    unique_ips: Set[str] = set()

    for idx, row in enumerate(rows):
        if limit is not None and idx >= limit:
            break

        start_ip = row[COL_START].strip()
        end_ip = row[COL_END].strip()
        try:
            ips, truncated = expand_range(start_ip, end_ip, max_expand)
        except ValueError as exc:
            print("[WARN] row %d: %s" % (idx + 2, exc), file=sys.stderr)
            continue

        if truncated:
            print(
                "[WARN] row %d: range > %d, only start/end kept: %s - %s"
                % (idx + 2, max_expand, start_ip, end_ip),
                file=sys.stderr,
            )

        processed.append(
            {
                COL_UNIT: row[COL_UNIT],
                COL_START: start_ip,
                COL_END: end_ip,
                "ips": ips,
            }
        )
        unique_ips.update(ips)

    return processed, unique_ips


def ping_all(
    ips: Set[str],
    cache: Dict[str, str],
    workers: int,
    timeout_sec: float,
    cache_path: Path,
) -> Dict[str, str]:
    pending = [ip for ip in ips if ip not in cache]
    total = len(pending)
    if not pending:
        return cache

    print("Ping targets: %d (cached: %d)" % (total, len(ips) - total))
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(ping_one, ip, timeout_sec): ip for ip in pending
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                cache[ip] = future.result()
            except Exception:
                cache[ip] = "error"
            done += 1
            if done % 100 == 0 or done == total:
                print("  Ping progress: %d/%d" % (done, total))
                save_cache(cache_path, cache)

    save_cache(cache_path, cache)
    return cache


def build_output_rows(
    processed: List[dict],
    cache: Dict[str, str],
    max_expand: int = DEFAULT_MAX_EXPAND,
) -> List[dict]:
    output: List[dict] = []
    for item in processed:
        base = {
            COL_UNIT: item[COL_UNIT],
            COL_START: item[COL_START],
            COL_END: item[COL_END],
        }
        ips: List[str] = item["ips"]
        pings = [cache.get(ip, "error") for ip in ips]

        if len(ips) <= max_expand:
            for ip, status in zip(ips, pings):
                output.append(dict(base, ip=ip, ping=status))
        else:
            # Only when a segment still has more than max_expand addresses after truncation
            output.append(
                dict(
                    base,
                    ip=",".join(ips),
                    ping=",".join(pings),
                )
            )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="IP range expand and ping check")
    parser.add_argument("--input", default="IPs_1.csv")
    parser.add_argument("--output", default="IPs_1_result.csv")
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--cache", default="ping_cache.json")
    parser.add_argument(
        "--max-expand",
        type=int,
        default=DEFAULT_MAX_EXPAND,
        help="Max addresses to enumerate per segment (default 256)",
    )
    args = parser.parse_args()
    max_expand = args.max_expand

    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / args.input
    output_path = base_dir / args.output
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

    print(
        "Read %d source rows (max_expand=%d, one row per IP)"
        % (len(rows), max_expand)
    )
    processed, unique_ips = collect_unique_ips(rows, args.limit, max_expand)
    print("Valid segments: %d, unique IPs: %d" % (len(processed), len(unique_ips)))

    cache = load_cache(cache_path)
    cache = ping_all(unique_ips, cache, args.workers, args.timeout, cache_path)

    output_rows = build_output_rows(processed, cache, max_expand)
    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(output_rows)

    print("Wrote %d rows -> %s" % (len(output_rows), output_path))
    success = sum(1 for v in cache.values() if v == "success")
    print("Ping stats: success=%d, error=%d" % (success, len(cache) - success))
    return 0


if __name__ == "__main__":
    sys.exit(main())
