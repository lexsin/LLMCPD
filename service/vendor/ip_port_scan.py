#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch LLM/inference-oriented port scan via nmap and merge open_ports into CSV."""

import argparse
import copy
import ctypes
import csv
import ipaddress
import json
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

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
INTERRUPTED = False
BatchCallback = Callable[[int, Dict[str, str]], None]

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


@dataclass
class NmapOptions:
    ports: str = SCAN_PORTS
    min_rate: str = "5000"
    max_retries: str = "1"
    host_timeout: str = "180s"


@dataclass
class LowOpenConfirmConfig:
    enabled: bool
    rate_threshold: float
    min_open_ips: int
    sample_size: int
    expand_rate_threshold: float
    extra_ports: str
    nmap_options: NmapOptions


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


def normalize_ports_spec(value: str) -> str:
    return ",".join(
        p.strip()
        for p in value.replace("\n", ",").replace(";", ",").split(",")
        if p.strip()
    )


def load_ports_spec(ports: Optional[str], ports_file: Optional[str], base_dir: Path) -> str:
    parts: List[str] = []
    if ports:
        parts.append(ports)
    if ports_file:
        path = Path(ports_file)
        if not path.is_absolute():
            path = base_dir / path
        with path.open(encoding="utf-8") as f:
            parts.append(f.read())
    return normalize_ports_spec(",".join(parts))


def merge_ports_str(existing: str, added: str) -> str:
    ports: Set[int] = set()
    for value in (existing, added):
        for p in normalize_ports_str(value).split(PORT_SEP):
            p = p.strip()
            if not p:
                continue
            try:
                ports.add(int(p))
            except ValueError:
                continue
    return PORT_SEP.join(str(p) for p in sorted(ports))


def _handle_interrupt(signum, _frame) -> None:
    global INTERRUPTED
    INTERRUPTED = True
    raise KeyboardInterrupt


def install_signal_handlers() -> None:
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            signal.signal(sig, _handle_interrupt)


def split_ips_by_version(ips: List[str]) -> Tuple[List[str], List[str]]:
    v4: List[str] = []
    v6: List[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            print("[WARN] invalid IP skipped: %s" % ip, file=sys.stderr)
            continue
        if addr.version == 6:
            v6.append(ip)
        else:
            v4.append(ip)
    return v4, v6


def versioned_path(path: Path, tag: str) -> Path:
    return path.parent / ("%s_%s%s" % (path.stem, tag, path.suffix))


def format_elapsed(seconds: float) -> str:
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%dh%02dm%02ds" % (h, m, s)
    if m:
        return "%dm%02ds" % (m, s)
    return "%ds" % s


def chunked(items: List[str], size: int) -> List[List[str]]:
    if size <= 0:
        return [items]
    return [items[i : i + size] for i in range(0, len(items), size)]


def batch_path(base: Path, batch_idx: int) -> Path:
    return base.parent / ("%s_batch_%04d%s" % (base.stem, batch_idx, base.suffix))


def print_ip_progress(
    prefix: str,
    done_ips: int,
    total_ips: int,
    batch_idx: int,
    batch_total: int,
    t0: float,
) -> None:
    pct = (100.0 * done_ips / total_ips) if total_ips else 0.0
    elapsed = time.monotonic() - t0
    if done_ips > 0 and done_ips < total_ips:
        eta = elapsed / done_ips * (total_ips - done_ips)
        eta_s = format_elapsed(eta)
    else:
        eta_s = "-"
    print(
        "%sIP progress: %d/%d (%.1f%%) | batch %d/%d | elapsed %s | ETA %s"
        % (
            prefix,
            done_ips,
            total_ips,
            pct,
            batch_idx,
            batch_total,
            format_elapsed(elapsed),
            eta_s,
        ),
        flush=True,
    )


def require_root() -> None:
    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False
        if not is_admin:
            print(
                "SYN scan (-sS) requires Administrator. "
                "Re-run in an elevated (Administrator) command prompt.",
                file=sys.stderr,
            )
            sys.exit(1)
    elif hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            print(
                "SYN scan (-sS) requires root. Run: sudo python3 %s ..."
                % Path(__file__).name,
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        print(
            "[WARN] Cannot determine privilege level on this platform; proceeding anyway.",
            file=sys.stderr,
        )


def run_nmap_single(
    ip_list_path: Path,
    xml_path: Path,
    *,
    ipv6: bool = False,
    stats_every: Optional[str] = "60s",
    log_command: bool = True,
    exit_on_fail: bool = True,
    nmap_options: Optional[NmapOptions] = None,
) -> None:
    opts = nmap_options or NmapOptions()
    cmd = [
        "nmap",
        "-sS",
        "-n",
        "-T4",
        "--open",
        "-p",
        opts.ports,
        "-iL",
        str(ip_list_path),
        "-oX",
        str(xml_path),
    ]
    if opts.min_rate:
        cmd[4:4] = ["--min-rate", opts.min_rate]
    if opts.max_retries:
        cmd[4:4] = ["--max-retries", opts.max_retries]
    if opts.host_timeout:
        cmd[4:4] = ["--host-timeout", opts.host_timeout]
    if ipv6:
        cmd.insert(1, "-6")
    if stats_every:
        cmd.extend(["--stats-every", stats_every])

    if log_command:
        print("  nmap: %s" % " ".join(cmd))

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        msg = "nmap batch failed (exit %d): %s" % (result.returncode, xml_path)
        print("  %s" % msg, file=sys.stderr)
        if exit_on_fail:
            sys.exit(result.returncode)
        raise RuntimeError(msg)


def _run_batch_job(
    batch_idx: int,
    batch_ips: List[str],
    b_list: str,
    b_xml: str,
    ipv6: bool,
    stats_every: Optional[str],
    nmap_options: NmapOptions,
) -> Tuple[int, Dict[str, str]]:
    """Process-pool worker: run one nmap batch and return scan results."""
    write_ip_list(Path(b_list), batch_ips)
    run_nmap_single(
        Path(b_list),
        Path(b_xml),
        ipv6=ipv6,
        stats_every=stats_every,
        log_command=False,
        exit_on_fail=False,
        nmap_options=nmap_options,
    )
    batch_result: Dict[str, str] = {ip: "" for ip in batch_ips}
    batch_result.update(safe_parse_nmap_xml(Path(b_xml)))
    return batch_idx, batch_result


def _collect_open_from_batch_xmls(batch_xml_paths: List[Path]) -> Dict[str, str]:
    open_by_ip: Dict[str, str] = {}
    for p in batch_xml_paths:
        open_by_ip.update(safe_parse_nmap_xml(p))
    return open_by_ip


def _finish_batch_scan(
    prefix: str,
    kind: str,
    total_ips: int,
    t0: float,
    batch_xml_paths: List[Path],
    batch_list_paths: List[Path],
    xml_path: Path,
    keep_batch_files: bool,
    merge_xml: bool,
) -> None:
    if merge_xml and batch_xml_paths:
        print("%s  merging %d batch XML files..." % (prefix, len(batch_xml_paths)))
        merge_nmap_xml_files(batch_xml_paths, xml_path)
        open_by_ip = safe_parse_nmap_xml(xml_path)
    elif batch_xml_paths:
        print(
            "%s  skip XML merge (%d batch files); results already in cache/CSV"
            % (prefix, len(batch_xml_paths))
        )
        open_by_ip = _collect_open_from_batch_xmls(batch_xml_paths)
    else:
        open_by_ip = safe_parse_nmap_xml(xml_path) if xml_path.is_file() else {}

    if not keep_batch_files:
        for p in batch_xml_paths + batch_list_paths:
            try:
                p.unlink()
            except OSError:
                pass

    open_count = sum(1 for v in open_by_ip.values() if v)
    print(
        "%s%s done in %s | IPs: %d | hosts with open ports: %d"
        % (prefix, kind, format_elapsed(time.monotonic() - t0), total_ips, open_count)
    )


def merge_nmap_xml_files(batch_xml_paths: List[Path], out_path: Path) -> None:
    """Combine per-batch nmap XML files into one output XML."""
    root = ET.Element("nmaprun")
    for batch_path in batch_xml_paths:
        if not batch_path.is_file():
            continue
        try:
            batch_root = ET.parse(batch_path).getroot()
        except ET.ParseError:
            continue
        for host in batch_root.findall("host"):
            root.append(copy.deepcopy(host))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(out_path, encoding="utf-8", xml_declaration=True)


def safe_parse_nmap_xml(xml_path: Path) -> Dict[str, str]:
    """Like parse_nmap_xml but returns {} instead of sys.exit on missing/broken file."""
    try:
        return parse_nmap_xml(xml_path)
    except (FileNotFoundError, ET.ParseError, RuntimeError, OSError) as exc:
        print("[WARN] cannot parse nmap XML %s: %s" % (xml_path, exc), file=sys.stderr)
        return {}


def _safe_label(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)


def count_open_ips(result: Dict[str, str]) -> int:
    return sum(1 for ports in result.values() if ports)


def scan_ip_subset(
    ips: List[str],
    tmp_dir: Path,
    label: str,
    *,
    ipv6: bool,
    stats_every: Optional[str],
    nmap_options: NmapOptions,
) -> Dict[str, str]:
    safe = _safe_label(label)
    list_path = tmp_dir / ("%s.txt" % safe)
    xml_path = tmp_dir / ("%s.xml" % safe)
    write_ip_list(list_path, ips)
    result: Dict[str, str] = {ip: "" for ip in ips}
    try:
        run_nmap_single(
            list_path,
            xml_path,
            ipv6=ipv6,
            stats_every=stats_every,
            log_command=True,
            exit_on_fail=False,
            nmap_options=nmap_options,
        )
        result.update(safe_parse_nmap_xml(xml_path))
        return result
    except Exception as exc:
        print("[WARN] confirm scan failed (%s): %s" % (label, exc), file=sys.stderr)
        return result
    finally:
        for p in (list_path, xml_path):
            try:
                if p.is_file():
                    p.unlink()
            except OSError:
                pass


def count_new_open_ips(base: Dict[str, str], scanned: Dict[str, str]) -> int:
    return sum(1 for ip, ports in scanned.items() if ports and not base.get(ip))


def merge_extra_ports_into_batch(
    batch_result: Dict[str, str], extra_result: Dict[str, str]
) -> int:
    changed = 0
    for ip, ports in extra_result.items():
        if not ports:
            continue
        before = batch_result.get(ip, "")
        merged = merge_ports_str(before, ports)
        if merged != before:
            changed += 1
            batch_result[ip] = merged
    return changed


def append_confirm_checkpoint(path: Path, info: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"type": "low_open_confirm", "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")}
    payload.update(info)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")


def maybe_confirm_low_open_batch(
    batch_idx: int,
    batch_result: Dict[str, str],
    *,
    ipv6: bool,
    tmp_dir: Path,
    stats_every: Optional[str],
    config: Optional[LowOpenConfirmConfig],
) -> Optional[Dict[str, object]]:
    if not config or not config.enabled or not batch_result:
        return None

    total = len(batch_result)
    open_ips = count_open_ips(batch_result)
    open_rate = float(open_ips) / total if total else 0.0
    if open_rate >= config.rate_threshold and open_ips >= config.min_open_ips:
        return None

    ips = list(batch_result.keys())
    sample_ips = ips[: min(config.sample_size, len(ips))]
    print(
        "  [low-open] batch %d triggered: open_ips=%d/%d (%.3f%%), sample=%d"
        % (batch_idx, open_ips, total, open_rate * 100.0, len(sample_ips)),
        flush=True,
    )

    info: Dict[str, object] = {
        "batch_idx": batch_idx,
        "total_ips": total,
        "original_open_ips": open_ips,
        "original_open_rate": round(open_rate, 6),
        "sample_size": len(sample_ips),
        "current_rescan_new_open_ips": 0,
        "extra_sample_new_open_ips": 0,
        "extra_full_changed_ips": 0,
        "action": "sample_confirm_only",
    }

    sample_current = scan_ip_subset(
        sample_ips,
        tmp_dir,
        "confirm_batch_%04d_current_sample" % batch_idx,
        ipv6=ipv6,
        stats_every=stats_every,
        nmap_options=config.nmap_options,
    )
    current_new = count_new_open_ips(batch_result, sample_current)
    info["current_rescan_new_open_ips"] = current_new
    current_new_rate = float(current_new) / len(sample_ips) if sample_ips else 0.0

    if current_new_rate >= config.expand_rate_threshold:
        print(
            "  [low-open] batch %d current-port rescan found %d new open IPs; rescanning full batch"
            % (batch_idx, current_new),
            flush=True,
        )
        full_current = scan_ip_subset(
            ips,
            tmp_dir,
            "confirm_batch_%04d_current_full" % batch_idx,
            ipv6=ipv6,
            stats_every=stats_every,
            nmap_options=config.nmap_options,
        )
        batch_result.clear()
        batch_result.update(full_current)
        info["action"] = "rescan_current_ports"

    if config.extra_ports:
        extra_opts = NmapOptions(
            ports=config.extra_ports,
            min_rate=config.nmap_options.min_rate,
            max_retries=config.nmap_options.max_retries,
            host_timeout=config.nmap_options.host_timeout,
        )
        sample_extra = scan_ip_subset(
            sample_ips,
            tmp_dir,
            "confirm_batch_%04d_extra_sample" % batch_idx,
            ipv6=ipv6,
            stats_every=stats_every,
            nmap_options=extra_opts,
        )
        extra_new = count_new_open_ips(batch_result, sample_extra)
        info["extra_sample_new_open_ips"] = extra_new
        extra_new_rate = float(extra_new) / len(sample_ips) if sample_ips else 0.0

        if extra_new_rate >= config.expand_rate_threshold:
            print(
                "  [low-open] batch %d extra ports found %d new open IPs; scanning full batch extra ports"
                % (batch_idx, extra_new),
                flush=True,
            )
            full_extra = scan_ip_subset(
                ips,
                tmp_dir,
                "confirm_batch_%04d_extra_full" % batch_idx,
                ipv6=ipv6,
                stats_every=stats_every,
                nmap_options=extra_opts,
            )
            changed = merge_extra_ports_into_batch(batch_result, full_extra)
            info["extra_full_changed_ips"] = changed
            info["action"] = (
                "rescan_current_and_expand_extra"
                if info["action"] == "rescan_current_ports"
                else "expand_extra_ports"
            )
    print("  [low-open] batch %d action=%s" % (batch_idx, info["action"]), flush=True)
    return info


def run_nmap_scan(
    ips: List[str],
    ip_list_path: Path,
    xml_path: Path,
    *,
    ipv6: bool = False,
    stats_every: Optional[str] = "60s",
    step_label: str = "",
    batch_size: int = 100,
    keep_batch_files: bool = False,
    on_batch_done: Optional[BatchCallback] = None,
    parallel_workers: int = 1,
    merge_xml: bool = True,
    nmap_options: Optional[NmapOptions] = None,
) -> None:
    """
    Scan `ips` in batches.

    After each batch, `on_batch_done` is called with a dict of
    {ip: open_ports_str} for every IP in that batch (empty string
    means scanned but no open ports found).  Use this callback to
    flush cache / rewrite CSV incrementally and support resume.
    """
    prefix = ("[%s] " % step_label) if step_label else ""
    kind = "IPv6" if ipv6 else "IPv4"
    total_ips = len(ips)
    opts = nmap_options or NmapOptions()

    if total_ips == 0:
        return

    write_ip_list(ip_list_path, ips)
    t0 = time.monotonic()

    if batch_size <= 0 or total_ips <= batch_size:
        print(
            "%s%s scan: %d IPs (single run) -> %s"
            % (prefix, kind, total_ips, xml_path)
        )
        if stats_every:
            print("%s  nmap stats every %s" % (prefix, stats_every))
        run_nmap_single(
            ip_list_path,
            xml_path,
            ipv6=ipv6,
            stats_every=stats_every,
            log_command=True,
            nmap_options=opts,
        )
        # Build full result: all IPs → "" default, overwrite with actual XML results
        batch_result: Dict[str, str] = {ip: "" for ip in ips}
        batch_result.update(safe_parse_nmap_xml(xml_path))
        if on_batch_done:
            on_batch_done(1, batch_result)
        print_ip_progress(prefix, total_ips, total_ips, 1, 1, t0)
        open_count = sum(1 for v in batch_result.values() if v)
        print(
            "%s%s done in %s | hosts with open ports: %d"
            % (prefix, kind, format_elapsed(time.monotonic() - t0), open_count)
        )
        return

    batches = chunked(ips, batch_size)
    batch_total = len(batches)
    print(
        "%s%s scan: %d IPs in %d batches (batch_size=%d) -> %s"
        % (prefix, kind, total_ips, batch_total, batch_size, xml_path)
    )
    if stats_every:
        print("%s  nmap stats every %s (per batch)" % (prefix, stats_every))

    batch_xml_paths: List[Path] = []
    batch_list_paths: List[Path] = []
    jobs: List[Tuple[int, List[str], str, str, bool, Optional[str], NmapOptions]] = []

    for batch_idx, batch_ips in enumerate(batches, start=1):
        b_list = batch_path(ip_list_path, batch_idx)
        b_xml = batch_path(xml_path, batch_idx)
        batch_list_paths.append(b_list)
        batch_xml_paths.append(b_xml)
        if parallel_workers <= 1:
            write_ip_list(b_list, batch_ips)
        jobs.append(
            (
                batch_idx,
                batch_ips,
                str(b_list),
                str(b_xml),
                ipv6,
                stats_every,
                opts,
            )
        )

    done_ips = 0

    if parallel_workers <= 1:
        for job in jobs:
            batch_idx, batch_ips, b_list_s, b_xml_s, _, _, _ = job
            b_xml = Path(b_xml_s)
            print(
                "%s  batch %d/%d: scanning %d IPs..."
                % (prefix, batch_idx, batch_total, len(batch_ips)),
                flush=True,
            )
            run_nmap_single(
                Path(b_list_s),
                b_xml,
                ipv6=ipv6,
                stats_every=stats_every,
                log_command=False,
                nmap_options=opts,
            )
            done_ips += len(batch_ips)
            print_ip_progress(prefix, done_ips, total_ips, batch_idx, batch_total, t0)

            batch_result = {ip: "" for ip in batch_ips}
            batch_result.update(safe_parse_nmap_xml(b_xml))
            if on_batch_done:
                on_batch_done(batch_idx, batch_result)
    else:
        print(
            "%s  parallel workers: %d (flush/checkpoint on main thread)"
            % (prefix, parallel_workers)
        )
        with ProcessPoolExecutor(max_workers=parallel_workers) as pool:
            futures = {
                pool.submit(_run_batch_job, *job): job[0] for job in jobs
            }
            for fut in as_completed(futures):
                batch_idx = futures[fut]
                try:
                    _idx, batch_result = fut.result()
                except Exception as exc:
                    print(
                        "%s  batch %d failed: %s" % (prefix, batch_idx, exc),
                        file=sys.stderr,
                    )
                    raise
                done_ips += len(batch_result)
                print(
                    "%s  batch %d/%d done (%d IPs)"
                    % (prefix, batch_idx, batch_total, len(batch_result)),
                    flush=True,
                )
                print_ip_progress(
                    prefix, done_ips, total_ips, batch_idx, batch_total, t0
                )
                if on_batch_done:
                    on_batch_done(batch_idx, batch_result)

    _finish_batch_scan(
        prefix,
        kind,
        total_ips,
        t0,
        batch_xml_paths,
        batch_list_paths,
        xml_path,
        keep_batch_files,
        merge_xml,
    )


def parse_nmap_xml(xml_path: Path) -> Dict[str, str]:
    if not xml_path.is_file():
        raise FileNotFoundError("XML not found: %s" % xml_path)

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


def parse_nmap_xml_sv(xml_path: Path, exclude_tcpwrapped: bool = True) -> Dict[str, str]:
    """Like parse_nmap_xml but optionally filters ports whose service is 'tcpwrapped'.

    Used to post-process -sV scan results: tcpwrapped means TCP connected but no
    recognisable service responded, which is the typical fingerprint of a firewall
    that answers SYN on all ports without a real listener behind it.
    """
    if not xml_path.is_file():
        return {}
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        raise RuntimeError("broken -sV XML: %s" % xml_path)
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
                if state is None or state.get("state") != "open":
                    continue
                if exclude_tcpwrapped:
                    svc = port.find("service")
                    if svc is not None and svc.get("name") == "tcpwrapped":
                        continue
                try:
                    ports.append(int(port.get("portid", "0")))
                except ValueError:
                    continue

        open_by_ip[ip] = PORT_SEP.join(str(p) for p in sorted(ports))

    return open_by_ip


def merge_nmap_xml_results(
    v4_xml_path: Path,
    v6_xml_path: Path,
    legacy_xml_path: Path,
    v4_ips: List[str],
    v6_ips: List[str],
    skip_scan: bool,
) -> Optional[Dict[str, str]]:
    """Load and merge IPv4/IPv6 scan XML. Returns None if required XML is missing."""
    open_by_ip: Dict[str, str] = {}

    if v4_xml_path.is_file():
        open_by_ip.update(safe_parse_nmap_xml(v4_xml_path))
    elif legacy_xml_path.is_file():
        open_by_ip.update(safe_parse_nmap_xml(legacy_xml_path))
    elif skip_scan and v4_ips:
        print(
            "--skip-scan: IPv4 XML not found: %s (legacy: %s)"
            % (v4_xml_path, legacy_xml_path),
            file=sys.stderr,
        )
        return None

    if v6_xml_path.is_file():
        open_by_ip.update(safe_parse_nmap_xml(v6_xml_path))
    elif skip_scan and v6_ips:
        print(
            "--skip-scan: IPv6 XML not found: %s" % v6_xml_path,
            file=sys.stderr,
        )
        return None

    if skip_scan and not open_by_ip and (v4_ips or v6_ips):
        print("No scan XML found for --skip-scan", file=sys.stderr)
        return None

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
    tmp_path = path.with_name(path.name + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, separators=(",", ":"))
    tmp_path.replace(path)


def append_checkpoint(path: Path, batch_result: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    scan_time = time.strftime("%Y-%m-%d %H:%M:%S")
    with path.open("a", encoding="utf-8") as f:
        for ip, ports in sorted(batch_result.items()):
            f.write(
                json.dumps(
                    {"ip": ip, "open_ports": ports, "scan_time": scan_time},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )


def _verify_ports_sv(
    ip: str,
    ports_str: str,
    tmp_dir: Path,
    stats_every: Optional[str],
    host_timeout: str,
    max_retries: str,
    proc_timeout: int,
) -> str:
    """Re-scan a single IP with -sV --version-intensity 0 on its already-open ports.

    Returns a new semicolon-separated port string with tcpwrapped ports removed.
    Temporary files are written to tmp_dir and deleted after parsing.
    proc_timeout: Python-level wall-clock timeout (seconds) for the nmap subprocess.
    On timeout, returns the original ports_str unchanged.
    """
    ports_csv = ports_str.replace(PORT_SEP, ",")
    safe_ip = ip.replace(":", "_")
    list_path = tmp_dir / ("verify_%s.txt" % safe_ip)
    xml_path = tmp_dir / ("verify_%s.xml" % safe_ip)
    write_ip_list(list_path, [ip])
    cmd = [
        "nmap",
        "-sV",
        "--version-intensity",
        "0",
        "-n",
        "-T4",
        "--host-timeout",
        host_timeout,
        "--max-retries",
        max_retries,
        "--open",
        "-p",
        ports_csv,
        "-iL",
        str(list_path),
        "-oX",
        str(xml_path),
    ]
    if stats_every:
        cmd.extend(["--stats-every", stats_every])
    print("  [verify] %s: running -sV on %d ports..." % (ip, len(ports_str.split(PORT_SEP))), flush=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=proc_timeout)
    except subprocess.TimeoutExpired:
        print(
            "  [verify] %s: -sV timed out after %ds, keeping original SYN result" % (ip, proc_timeout),
            flush=True,
        )
        for p in (list_path, xml_path):
            try:
                p.unlink()
            except OSError:
                pass
        return ports_str
    if proc.returncode != 0:
        print(
            "  [verify] %s: -sV failed (exit %d), keeping original SYN result"
            % (ip, proc.returncode),
            flush=True,
        )
        for p in (list_path, xml_path):
            try:
                p.unlink()
            except OSError:
                pass
        return ports_str
    if not xml_path.is_file():
        print(
            "  [verify] %s: -sV XML missing, keeping original SYN result" % ip,
            flush=True,
        )
        for p in (list_path, xml_path):
            try:
                p.unlink()
            except OSError:
                pass
        return ports_str
    try:
        result = parse_nmap_xml_sv(xml_path, exclude_tcpwrapped=True)
    except RuntimeError as exc:
        print("  [verify] %s: %s, keeping original SYN result" % (ip, exc), flush=True)
        result = {ip: ports_str}
    for p in (list_path, xml_path):
        try:
            p.unlink()
        except OSError:
            pass
    return result.get(ip, "")


def verify_anomalous_ports(
    batch_result: Dict[str, str],
    anomaly_threshold: int,
    tmp_dir: Path,
    stats_every: Optional[str],
    verify_workers: int,
    verify_host_timeout: str,
    verify_max_retries: str,
    verify_proc_timeout: int,
) -> None:
    if anomaly_threshold <= 0:
        return
    anomalous = [
        (ip, ports_str)
        for ip, ports_str in batch_result.items()
        if ports_str and len(ports_str.split(PORT_SEP)) > anomaly_threshold
    ]
    if not anomalous:
        return

    workers = max(1, min(verify_workers, len(anomalous)))
    print(
        "  [verify] %d anomalous IPs, workers=%d" % (len(anomalous), workers),
        flush=True,
    )
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _verify_ports_sv,
                ip,
                ports_str,
                tmp_dir,
                stats_every,
                verify_host_timeout,
                verify_max_retries,
                verify_proc_timeout,
            ): (
                ip,
                ports_str,
            )
            for ip, ports_str in anomalous
        }
        for fut in as_completed(futures):
            ip, ports_str = futures[fut]
            try:
                verified = fut.result()
            except Exception as exc:
                print(
                    "  [verify] %s: verification failed (%s), keeping original SYN result"
                    % (ip, exc),
                    flush=True,
                )
                verified = ports_str
            verified_count = len(verified.split(PORT_SEP)) if verified else 0
            print(
                "  [verify] %s: %d ports (SYN) -> %d ports (sV)"
                % (ip, len(ports_str.split(PORT_SEP)), verified_count),
                flush=True,
            )
            batch_result[ip] = verified


def _cleanup_tmp_files(tmp_dir: Path, paths: List[Path]) -> None:
    """Delete intermediate files and remove tmp_dir if it becomes empty."""
    for p in paths:
        try:
            if p.is_file():
                p.unlink()
        except OSError:
            pass
    try:
        tmp_dir.rmdir()
    except OSError:
        pass


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


def default_output_path(input_path: Path) -> Path:
    return input_path.parent / ("%s_scan_result%s" % (input_path.stem, input_path.suffix))


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
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV (default: same dir as input, {stem}_scan_result{suffix})",
    )
    parser.add_argument("--xml", default="scan.xml")
    parser.add_argument("--ip-list", default="ips_scan.txt")
    parser.add_argument("--cache", default="port_scan_cache.json")
    parser.add_argument("--checkpoint", default="port_scan_checkpoint.jsonl")
    parser.add_argument("--skip-scan", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--stats-every",
        default="60s",
        help="nmap --stats-every interval for progress (default 60s); use 0 to disable",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="IPs per nmap batch for IP-level progress (default 100); 0 = all in one run",
    )
    parser.add_argument(
        "--keep-batch-files",
        action="store_true",
        help="Keep per-batch ip list and XML files after merge",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip IPs already recorded in cache and continue from last checkpoint",
    )
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=1,
        help="Run nmap batches in parallel (default 1); try 2-4, raises network load",
    )
    parser.add_argument(
        "--merge-xml",
        action="store_true",
        help="Merge per-batch XML into scan_v4/v6.xml after scan (default: yes if workers=1, no if workers>1)",
    )
    parser.add_argument(
        "--tmp-dir",
        default="cache",
        help="Directory for intermediate txt/xml files (default: cache/); cleaned up after scan",
    )
    parser.add_argument(
        "--anomaly-threshold",
        type=int,
        default=80,
        help="Re-verify with -sV --version-intensity 0 if open port count exceeds this (default 80; 0 = disable)",
    )
    parser.add_argument(
        "--verify-workers",
        type=int,
        default=8,
        help="Parallel -sV verification workers for anomalous IPs (default 8)",
    )
    parser.add_argument(
        "--verify-host-timeout",
        default="15s",
        help="nmap --host-timeout for anomalous-IP -sV verification (default 15s)",
    )
    parser.add_argument(
        "--verify-max-retries",
        default="0",
        help="nmap --max-retries for anomalous-IP -sV verification (default 0)",
    )
    parser.add_argument(
        "--verify-proc-timeout",
        type=int,
        default=25,
        help="Python wall-clock timeout in seconds for each -sV verification (default 25)",
    )
    parser.add_argument(
        "--low-open-confirm",
        action="store_true",
        help="Enable low-open batch confirmation scans (default off)",
    )
    parser.add_argument(
        "--low-open-rate-threshold",
        type=float,
        default=0.005,
        help="Trigger low-open confirmation below this open-IP ratio (default 0.005)",
    )
    parser.add_argument(
        "--low-open-min-open-ips",
        type=int,
        default=5,
        help="Trigger low-open confirmation when batch open IPs are below this count (default 5)",
    )
    parser.add_argument(
        "--confirm-sample-size",
        type=int,
        default=50,
        help="Number of IPs sampled for low-open confirmation (default 50)",
    )
    parser.add_argument(
        "--confirm-ports",
        default=None,
        help="Extra ports for low-open expansion; omitted means no extra-port expansion",
    )
    parser.add_argument(
        "--confirm-ports-file",
        default=None,
        help="File containing extra ports for low-open expansion",
    )
    parser.add_argument(
        "--confirm-min-rate",
        default="1000",
        help="nmap --min-rate for low-open confirmation scans (default 1000)",
    )
    parser.add_argument(
        "--confirm-max-retries",
        default="2",
        help="nmap --max-retries for low-open confirmation scans (default 2)",
    )
    parser.add_argument(
        "--confirm-host-timeout",
        default="300s",
        help="nmap --host-timeout for low-open confirmation scans (default 300s)",
    )
    parser.add_argument(
        "--confirm-expand-rate-threshold",
        type=float,
        default=0.01,
        help="Expand from sample to full batch when new-open sample ratio reaches this value (default 0.01)",
    )
    args = parser.parse_args()
    if args.parallel_workers < 1:
        print("--parallel-workers must be >= 1", file=sys.stderr)
        return 1
    if args.verify_workers < 1:
        print("--verify-workers must be >= 1", file=sys.stderr)
        return 1
    if args.verify_proc_timeout < 1:
        print("--verify-proc-timeout must be >= 1", file=sys.stderr)
        return 1
    if args.confirm_sample_size < 1:
        print("--confirm-sample-size must be >= 1", file=sys.stderr)
        return 1
    if args.low_open_min_open_ips < 0:
        print("--low-open-min-open-ips must be >= 0", file=sys.stderr)
        return 1
    if args.low_open_rate_threshold < 0 or args.confirm_expand_rate_threshold < 0:
        print("low-open thresholds must be >= 0", file=sys.stderr)
        return 1
    install_signal_handlers()
    stats_every: Optional[str] = args.stats_every
    if stats_every in ("0", ""):
        stats_every = None

    base_dir = Path(__file__).resolve().parent
    raw_input = Path(args.input)
    input_path = raw_input if raw_input.is_absolute() else base_dir / raw_input

    if args.output is None:
        output_path = default_output_path(input_path)
    else:
        raw_output = Path(args.output)
        output_path = raw_output if raw_output.is_absolute() else base_dir / raw_output

    tmp_dir = (base_dir / args.tmp_dir).resolve()
    tmp_dir.mkdir(parents=True, exist_ok=True)

    xml_path = tmp_dir / args.xml
    v4_xml_path = versioned_path(xml_path, "v4")
    v6_xml_path = versioned_path(xml_path, "v6")
    ip_list_path = tmp_dir / args.ip_list
    v4_list_path = versioned_path(ip_list_path, "v4")
    v6_list_path = versioned_path(ip_list_path, "v6")
    cache_path = base_dir / args.cache
    checkpoint_path = base_dir / args.checkpoint

    confirm_extra_ports = load_ports_spec(
        args.confirm_ports, args.confirm_ports_file, base_dir
    )
    low_open_config = LowOpenConfirmConfig(
        enabled=args.low_open_confirm,
        rate_threshold=args.low_open_rate_threshold,
        min_open_ips=args.low_open_min_open_ips,
        sample_size=args.confirm_sample_size,
        expand_rate_threshold=args.confirm_expand_rate_threshold,
        extra_ports=confirm_extra_ports,
        nmap_options=NmapOptions(
            ports=SCAN_PORTS,
            min_rate=args.confirm_min_rate,
            max_retries=args.confirm_max_retries,
            host_timeout=args.confirm_host_timeout,
        ),
    )

    merge_xml = args.merge_xml or (args.parallel_workers <= 1)

    print("Input:  %s" % input_path)
    print("Output: %s" % output_path)
    if args.parallel_workers > 1:
        print("Parallel workers: %d" % args.parallel_workers)
        if not merge_xml:
            print("XML merge: disabled (use --merge-xml to enable)")
    if args.low_open_confirm:
        print(
            "Low-open confirm: enabled | threshold %.3f%% or <%d open IPs | sample %d | extra ports: %s"
            % (
                args.low_open_rate_threshold * 100.0,
                args.low_open_min_open_ips,
                args.confirm_sample_size,
                "yes" if confirm_extra_ports else "no",
            )
        )

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
    v4_ips, v6_ips = split_ips_by_version(ips)
    total_all = len(v4_ips) + len(v6_ips)
    print(
        "Unique IPs: %d (IPv4: %d, IPv6: %d)"
        % (total_all, len(v4_ips), len(v6_ips))
    )
    write_ip_list(ip_list_path, ips)

    # Load cache early — used by both resume filtering and the flush callback
    cache = load_cache(cache_path)

    if args.resume and cache:
        already_done = set(cache.keys())
        v4_before, v6_before = len(v4_ips), len(v6_ips)
        v4_ips = [ip for ip in v4_ips if ip not in already_done]
        v6_ips = [ip for ip in v6_ips if ip not in already_done]
        skipped = (v4_before - len(v4_ips)) + (v6_before - len(v6_ips))
        print(
            "Resume: %d IPs already in cache (skipped), %d remaining"
            % (skipped, len(v4_ips) + len(v6_ips))
        )

    pipeline_t0 = time.monotonic()
    anomaly_threshold = args.anomaly_threshold

    # --- Per-batch flush callback -------------------------------------------
    # Called after every nmap batch with {ip: open_ports_str} for all IPs in
    # that batch (empty string = scanned, no open ports found).
    # Updates cache and appends a compact checkpoint; final CSV is written once.
    def make_flush_batch(is_v6: bool) -> BatchCallback:
        def flush_batch(batch_idx: int, batch_result: Dict[str, str]) -> None:
            confirm_info = maybe_confirm_low_open_batch(
                batch_idx,
                batch_result,
                ipv6=is_v6,
                tmp_dir=tmp_dir,
                stats_every=stats_every,
                config=low_open_config,
            )
            verify_anomalous_ports(
                batch_result,
                anomaly_threshold,
                tmp_dir,
                stats_every,
                args.verify_workers,
                args.verify_host_timeout,
                args.verify_max_retries,
                args.verify_proc_timeout,
            )
            cache.update(batch_result)
            save_cache(cache_path, cache)
            append_checkpoint(checkpoint_path, batch_result)
            if confirm_info:
                append_confirm_checkpoint(checkpoint_path, confirm_info)
            with_ports = sum(1 for v in cache.values() if v)
            print(
                "  [checkpoint] +%d IPs flushed | cache: %d total | "
                "%d with ports | checkpoint -> %s"
                % (
                    len(batch_result),
                    len(cache),
                    with_ports,
                    checkpoint_path,
                ),
                flush=True,
            )

        return flush_batch
    # -------------------------------------------------------------------------

    if not args.skip_scan:
        require_root()
        scan_steps: List[Tuple[str, List[str], Path, Path, bool]] = []
        if v4_ips:
            scan_steps.append(("IPv4", v4_ips, v4_list_path, v4_xml_path, False))
        if v6_ips:
            scan_steps.append(("IPv6", v6_ips, v6_list_path, v6_xml_path, True))

        if not scan_steps:
            if args.resume:
                print("All IPs already in cache — nothing to scan.")
            else:
                print("No valid IPs to scan", file=sys.stderr)
                return 1

        total_steps = len(scan_steps)
        for idx, (kind, targets, list_path, out_xml, is_v6) in enumerate(
            scan_steps, start=1
        ):
            try:
                run_nmap_scan(
                    targets,
                    list_path,
                    out_xml,
                    ipv6=is_v6,
                    stats_every=stats_every,
                    step_label="%d/%d %s" % (idx, total_steps, kind),
                    batch_size=args.batch_size,
                    keep_batch_files=args.keep_batch_files,
                    on_batch_done=make_flush_batch(is_v6),
                    parallel_workers=args.parallel_workers,
                    merge_xml=merge_xml,
                )
            except KeyboardInterrupt:
                save_cache(cache_path, cache)
                print(
                    "\nInterrupted. Cache saved to %s; resume with --resume."
                    % cache_path,
                    file=sys.stderr,
                )
                return 130
    elif not v4_ips and not v6_ips and not args.resume:
        print("No valid IPs to scan", file=sys.stderr)
        return 1

    # Final pass: merge XML results for --skip-scan path (no flush_batch ran)
    if args.skip_scan:
        print("Merging scan results from XML...")
        open_by_ip = merge_nmap_xml_results(
            v4_xml_path,
            v6_xml_path,
            xml_path,
            v4_ips,
            v6_ips,
            args.skip_scan,
        )
        if open_by_ip is None:
            return 1
        print(
            "Merged: %d hosts with open ports / %d targets"
            % (sum(1 for v in open_by_ip.values() if v), len(v4_ips) + len(v6_ips))
        )
        cache.update(open_by_ip)
        save_cache(cache_path, cache)

    # Write final CSV (covers --skip-scan and any resumed-but-unchanged rows)
    print("Writing final CSV (%d rows)..." % len(rows))
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
    print("Total elapsed: %s" % format_elapsed(time.monotonic() - pipeline_t0))

    _cleanup_tmp_files(tmp_dir, [
        ip_list_path, v4_list_path, v6_list_path,
        v4_xml_path, v6_xml_path, xml_path,
    ])
    print("Cleaned up tmp dir: %s" % tmp_dir)

    return 0


if __name__ == "__main__":
    sys.exit(main())
