#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Expand IP ranges from CSV/XLS and ping each address."""

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
INPUT_SUFFIXES = (".csv", ".xls", ".xlsx")


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

    if sys.platform == "win32":
        if addr.version == 6:
            cmd = ["ping", "-6", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        encoding = "gbk"
    else:
        wait_sec = max(1, int(timeout_sec))
        if addr.version == 6:
            cmd = ["ping", "-6", "-c", "1", "-W", str(wait_sec), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(wait_sec), ip]
        encoding = "utf-8"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding=encoding,
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
            print("  encoding: %s" % encoding)
            return rows
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("csv", b"", 0, 1, "unsupported encoding")


def read_excel_rows(path: Path) -> List[dict]:
    try:
        import pandas as pd
    except ImportError:
        print(
            "pandas required for Excel. Run: pip install pandas xlrd openpyxl",
            file=sys.stderr,
        )
        raise

    engine = "xlrd" if path.suffix.lower() == ".xls" else None
    df = pd.read_excel(path, engine=engine)
    df = df.where(df.notna(), "")
    rows = df.astype(str).to_dict(orient="records")
    # strip whitespace in string fields
    for row in rows:
        for k, v in list(row.items()):
            if isinstance(v, str):
                row[k] = v.strip()
    return rows


def read_input_rows(path: Path) -> List[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return read_csv_rows(path)
    if suffix in (".xls", ".xlsx"):
        return read_excel_rows(path)
    raise ValueError("unsupported file type: %s" % path.suffix)


def output_fieldnames(col_unit: Optional[str], col_start: str, col_end: str) -> List[str]:
    names: List[str] = []
    if col_unit:
        names.append(col_unit)
    names.extend([col_start, col_end, "ip", "ping"])
    return names


def collect_unique_ips(
    rows: List[dict],
    col_start: str,
    col_end: str,
    col_unit: Optional[str],
    limit: Optional[int],
    max_expand: int = DEFAULT_MAX_EXPAND,
) -> Tuple[List[dict], Set[str]]:
    processed: List[dict] = []
    unique_ips: Set[str] = set()

    for idx, row in enumerate(rows):
        if limit is not None and idx >= limit:
            break

        start_ip = str(row.get(col_start, "")).strip()
        end_ip = str(row.get(col_end, "")).strip()
        if not start_ip or not end_ip:
            print(
                "[WARN] row %d: missing %s or %s, skipped"
                % (idx + 2, col_start, col_end),
                file=sys.stderr,
            )
            continue

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

        item: Dict = {
            col_start: start_ip,
            col_end: end_ip,
            "ips": ips,
        }
        if col_unit:
            item[col_unit] = str(row.get(col_unit, "")).strip()
        processed.append(item)
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

    print("  ping targets: %d (cached: %d)" % (total, len(ips) - total))
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
                print("  ping progress: %d/%d" % (done, total))
                save_cache(cache_path, cache)

    save_cache(cache_path, cache)
    return cache


def build_output_rows(
    processed: List[dict],
    cache: Dict[str, str],
    col_start: str,
    col_end: str,
    col_unit: Optional[str],
    max_expand: int = DEFAULT_MAX_EXPAND,
    ping_default: str = "error",
) -> List[dict]:
    output: List[dict] = []
    for item in processed:
        base: Dict[str, str] = {
            col_start: item[col_start],
            col_end: item[col_end],
        }
        if col_unit:
            base[col_unit] = item.get(col_unit, "")

        ips: List[str] = item["ips"]
        pings = [cache.get(ip, ping_default) for ip in ips]

        if len(ips) <= max_expand:
            for ip, status in zip(ips, pings):
                output.append(dict(base, ip=ip, ping=status))
        else:
            output.append(
                dict(
                    base,
                    ip=",".join(ips),
                    ping=",".join(pings),
                )
            )
    return output


def build_output_rows_dedup(
    processed: List[dict],
    cache: Dict[str, str],
    col_start: str,
    col_end: str,
    col_unit: Optional[str],
    ping_default: str = "error",
) -> List[dict]:
    """One output row per unique IP; first segment wins for start/end/unit metadata."""
    first_meta: Dict[str, Dict[str, str]] = {}
    order: List[str] = []

    for item in processed:
        base: Dict[str, str] = {
            col_start: item[col_start],
            col_end: item[col_end],
        }
        if col_unit:
            base[col_unit] = item.get(col_unit, "")

        for ip in item["ips"]:
            if ip in first_meta:
                continue
            first_meta[ip] = dict(base)
            order.append(ip)

    output: List[dict] = []
    for ip in order:
        row = dict(first_meta[ip], ip=ip, ping=cache.get(ip, ping_default))
        output.append(row)
    return output


def count_expanded_ips(processed: List[dict]) -> int:
    return sum(len(item["ips"]) for item in processed)


def list_input_files(data_dir: Path) -> List[Path]:
    files = sorted(
        p for p in data_dir.iterdir()
        if p.is_file() and p.suffix.lower() in INPUT_SUFFIXES
    )
    return files


def resolve_inputs(path: Path) -> Tuple[List[Path], Path]:
    """
    Accept a directory or a single CSV/XLS file.
    Returns (input_files, default_output_directory).
    """
    if not path.exists():
        raise FileNotFoundError(path)

    if path.is_file():
        if path.suffix.lower() not in INPUT_SUFFIXES:
            raise ValueError(
                "unsupported file type %s (supported: %s)"
                % (path.suffix, ", ".join(INPUT_SUFFIXES))
            )
        return [path.resolve()], path.parent.resolve()

    if path.is_dir():
        files = list_input_files(path)
        if not files:
            raise ValueError(
                "no CSV/XLS files in %s (suffixes: %s)"
                % (path, ", ".join(INPUT_SUFFIXES))
            )
        return files, path.resolve()

    raise FileNotFoundError(path)


def process_file(
    input_path: Path,
    output_path: Path,
    col_start: str,
    col_end: str,
    col_unit: Optional[str],
    cache: Dict[str, str],
    cache_path: Path,
    workers: int,
    timeout_sec: float,
    limit: Optional[int],
    max_expand: int,
    skip_ping: bool = False,
    dedup_ip: bool = False,
) -> Tuple[int, Dict[str, str]]:
    print("\n=== %s ===" % input_path.name)

    try:
        rows = read_input_rows(input_path)
    except UnicodeDecodeError:
        print("  cannot decode file", file=sys.stderr)
        return 1, cache
    except Exception as exc:
        print("  read failed: %s" % exc, file=sys.stderr)
        return 1, cache

    if not rows:
        print("  empty input, skipped", file=sys.stderr)
        return 1, cache

    if col_start not in rows[0] or col_end not in rows[0]:
        print(
            "  columns not found (need %s, %s); got: %s"
            % (col_start, col_end, list(rows[0].keys())),
            file=sys.stderr,
        )
        return 1, cache

    print("  rows: %d (max_expand=%d)" % (len(rows), max_expand))
    processed, unique_ips = collect_unique_ips(
        rows, col_start, col_end, col_unit, limit, max_expand
    )
    expanded_total = count_expanded_ips(processed)
    print(
        "  segments: %d, expanded IPs: %d, unique IPs: %d"
        % (len(processed), expanded_total, len(unique_ips))
    )
    if dedup_ip:
        print("  output: deduplicated (--dedup-ip), %d rows" % len(unique_ips))

    if not processed:
        print("  no valid segments, skipped", file=sys.stderr)
        return 1, cache

    if skip_ping:
        print("  ping: skipped (--skip-ping)")
        ping_cache = cache
    else:
        ping_cache = ping_all(unique_ips, cache, workers, timeout_sec, cache_path)

    ping_default = "" if skip_ping else "error"
    if dedup_ip:
        output_rows = build_output_rows_dedup(
            processed,
            ping_cache,
            col_start,
            col_end,
            col_unit,
            ping_default=ping_default,
        )
    else:
        output_rows = build_output_rows(
            processed,
            ping_cache,
            col_start,
            col_end,
            col_unit,
            max_expand,
            ping_default=ping_default,
        )

    fieldnames = output_fieldnames(col_unit, col_start, col_end)
    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print("  wrote %d rows -> %s" % (len(output_rows), output_path))
    if not skip_ping:
        success = sum(1 for ip in unique_ips if ping_cache.get(ip) == "success")
        print("  ping: success=%d, error=%d" % (success, len(unique_ips) - success))
    return 0, ping_cache


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Expand IP ranges and ping check for files under data/"
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Input directory or single CSV/XLS file (default: data)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: input file's parent, or --data-dir if directory)",
    )
    parser.add_argument(
        "--col-start",
        default="START_IP",
        help="Column name for range start IP (default: START_IP)",
    )
    parser.add_argument(
        "--col-end",
        default="END_IP",
        help="Column name for range end IP (default: END_IP)",
    )
    parser.add_argument(
        "--col-unit",
        default=None,
        help="Optional column name for unit/org (omitted from output if unset)",
    )
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max source rows per file (for testing)",
    )
    parser.add_argument("--cache", default="ping_cache.json")
    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Only expand IP ranges; do not ping (ping column left empty)",
    )
    parser.add_argument(
        "--max-expand",
        type=int,
        default=DEFAULT_MAX_EXPAND,
        help="Max addresses to enumerate per segment (default 256)",
    )
    parser.add_argument(
        "--dedup-ip",
        action="store_true",
        help="After expand, output one row per unique IP (drop duplicate rows)",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    raw_input = Path(args.data_dir)
    input_root = raw_input if raw_input.is_absolute() else base_dir / raw_input
    cache_path = base_dir / args.cache

    try:
        input_files, default_output_dir = resolve_inputs(input_root)
    except FileNotFoundError:
        print("Input not found: %s" % input_root, file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.output_dir:
        raw_out = Path(args.output_dir)
        output_dir = raw_out if raw_out.is_absolute() else base_dir / raw_out
    else:
        output_dir = default_output_dir

    output_dir.mkdir(parents=True, exist_ok=True)
    cache = {} if args.skip_ping else load_cache(cache_path)

    print("Input: %s" % input_root)
    print("Output dir: %s" % output_dir)
    print("Columns: start=%s, end=%s" % (args.col_start, args.col_end))
    if args.skip_ping:
        print("Ping: disabled (--skip-ping)")
    if args.dedup_ip:
        print("Output: one row per unique IP (--dedup-ip)")
    if args.col_unit:
        print("Unit column: %s" % args.col_unit)
    print("Files to process: %d" % len(input_files))

    failed = 0
    for input_path in input_files:
        output_path = output_dir / ("%s_result.csv" % input_path.stem)
        rc, cache = process_file(
            input_path=input_path,
            output_path=output_path,
            col_start=args.col_start,
            col_end=args.col_end,
            col_unit=args.col_unit,
            cache=cache,
            cache_path=cache_path,
            workers=args.workers,
            timeout_sec=args.timeout,
            limit=args.limit,
            max_expand=args.max_expand,
            skip_ping=args.skip_ping,
            dedup_ip=args.dedup_ip,
        )
        if rc != 0:
            failed += 1

    print("\n=== Summary ===")
    print("Processed: %d, failed: %d" % (len(input_files), failed))
    if args.skip_ping:
        print("Ping: disabled (not run, cache not updated)")
    else:
        success_total = sum(1 for v in cache.values() if v == "success")
        print("Cache: %s (%d IPs)" % (cache_path, len(cache)))
        print("Ping cache stats: success=%d, error=%d" % (
            success_total, len(cache) - success_total
        ))
    return 1 if failed == len(input_files) else 0


if __name__ == "__main__":
    sys.exit(main())
