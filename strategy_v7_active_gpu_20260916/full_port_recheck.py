#!/usr/bin/env python3
"""Rate-limited full-port recheck for strong AI/GPU candidate IPs."""

import argparse
import csv
import ipaddress
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

GPU_HIGH = {"high", "gpu_high", "高"}
GPU_MEDIUM = {"medium", "gpu_medium", "中"}
LLM_POSITIVE = {"yes", "true", "confirmed", "suspected", "是", "疑似"}
STRONG_TOOLS = ("vllm", "ollama", "xinference", "triton", "tgi", "sglang", "lmdeploy", "ray serve")
STRONG_SERVICES = ("vllm", "ollama", "xinference", "triton", "llm", "large language", "text generation", "model serving", "inference service")
STRONG_PORTS = {"8000", "8001", "8002", "8081", "8888", "9000", "9001", "9400", "9401", "9835", "11434"}
K8S_PORTS = {"6443", "10250"}


def read_csv(path):
    for encoding in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=encoding, newline="") as source:
                reader = csv.DictReader(source)
                return list(reader), list(reader.fieldnames or [])
        except UnicodeDecodeError:
            pass
    raise ValueError("unsupported CSV encoding: %s" % path)


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def norm(value):
    return str(value or "").strip().lower()


def grouped(rows):
    result = {}
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        if ip:
            result.setdefault(ip, []).append(row)
    return result


def candidate_score(rows):
    if any(norm(row.get("gpu_likelihood")) in GPU_HIGH for row in rows):
        return -1, ["already_gpu_high"]
    score, reasons = 0, []
    ports = {str(row.get("port") or "").strip() for row in rows}
    tool = " ".join(str(row.get("deploy_tool") or "") for row in rows).lower()
    service = " ".join(str(row.get("service_type") or "") for row in rows).lower()
    evidence = " ".join(
        "%s %s %s" % (
            row.get("gpu_evidence") or "",
            row.get("model_info") or "",
            row.get("evidence") or "",
        )
        for row in rows
    ).lower()
    if any(norm(row.get("gpu_likelihood")) in GPU_MEDIUM for row in rows):
        score += 100
        reasons.append("gpu_medium")
    if any(norm(row.get("is_llm")) in LLM_POSITIVE for row in rows):
        score += 80
        reasons.append("llm_positive")
    if any(marker in tool for marker in STRONG_TOOLS):
        score += 70
        reasons.append("strong_deploy_tool")
    if any(marker in service for marker in STRONG_SERVICES):
        score += 60
        reasons.append("strong_ai_service")
    if ports & STRONG_PORTS:
        score += 40
        reasons.append("strong_ai_port")
    if any(marker in evidence for marker in ("cuda", "nvidia", "dcgm", "accelerator")):
        score += 50
        reasons.append("accelerator_evidence")
    if ports & K8S_PORTS and any(
        marker in "%s %s %s" % (tool, service, evidence)
        for marker in ("kubernetes", "kubelet")
    ):
        score += 30
        reasons.append("verified_kubernetes")
    return score, reasons


def select_candidates(rows, mode, max_targets):
    selected, skipped_high = [], 0
    for ip, ip_rows in grouped(rows).items():
        score, reasons = candidate_score(ip_rows)
        if score < 0:
            skipped_high += 1
        elif mode == "all" or score > 0:
            selected.append({"ip": ip, "score": score, "reasons": reasons})
    selected.sort(key=lambda item: (-item["score"], item["ip"]))
    return selected[:max_targets], skipped_high


def parse_open_ports(xml_text):
    root = ET.fromstring(xml_text)
    ports = {
        port.get("portid")
        for port in root.findall(".//host/ports/port")
        if port.find("state") is not None
        and port.find("state").get("state") == "open"
        and port.get("portid")
    }
    return sorted(ports, key=int)


def scan_one(item, args):
    ip = item["ip"]
    command = [
        args.nmap_bin, "-Pn", "-sS", "-n", "-T3",
        "--max-rate", str(args.max_rate),
        "--max-retries", str(args.max_retries),
    ]
    min_rate = int(getattr(args, "min_rate", 0) or 0)
    if min_rate > 0:
        command.extend(["--min-rate", str(min_rate)])
    host_timeout = str(getattr(args, "host_timeout", "") or "").strip()
    if host_timeout.lower() not in {"", "0", "none", "off"}:
        command.extend(["--host-timeout", host_timeout])
    command.extend(["-p-", "-oX", "-"])
    if ipaddress.ip_address(ip).version == 6:
        command.append("-6")
    command.append(ip)
    started = time.monotonic()
    process_timeout = getattr(args, "process_timeout", None)
    if process_timeout is not None and int(process_timeout) <= 0:
        process_timeout = None
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True,
            timeout=process_timeout or None, check=False,
        )
        if completed.returncode == 0:
            status, ports, error = "complete", parse_open_ports(completed.stdout), ""
        else:
            status, ports = "failed", []
            error = (completed.stderr or completed.stdout)[-1000:]
    except subprocess.TimeoutExpired:
        status, ports, error = "timeout", [], "process timeout"
    except (OSError, ValueError, ET.ParseError) as exc:
        status, ports, error = "failed", [], "%s: %s" % (type(exc).__name__, exc)
    return {
        "ip": ip,
        "status": status,
        "ports": ports,
        "score": item["score"],
        "reasons": item["reasons"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "error": error,
        "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def load_checkpoint(path):
    result = {}
    if path.is_file():
        with path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    item = json.loads(line)
                    if item.get("ip"):
                        result[item["ip"]] = item
                except (json.JSONDecodeError, TypeError):
                    pass
    return result


def append_checkpoint(path, item):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as target:
        target.write(json.dumps(item, ensure_ascii=False) + "\n")
        target.flush()


def output_new_ports(path, port_rows, fields, results):
    known = {}
    for row in port_rows:
        ip = str(row.get("ip") or "").strip()
        port = str(row.get("port") or "").strip()
        known.setdefault(ip, set()).add(port)
    templates = {ip: rows[0] for ip, rows in grouped(port_rows).items()}
    output = []
    for ip in sorted(results):
        result = results[ip]
        if result.get("status") != "complete":
            continue
        for port in result.get("ports", []):
            if str(port) not in known.get(ip, set()):
                row = dict(templates.get(ip, {"ip": ip}))
                row["ip"], row["port"] = ip, str(port)
                output.append(row)
    fields = list(fields)
    for field in ("ip", "port"):
        if field not in fields:
            fields.append(field)
    write_csv(path, output, fields)
    return len(output)


def main():
    parser = argparse.ArgumentParser(
        description="Rate-limited full-port recheck for AI/GPU candidate IPs"
    )
    parser.add_argument("--ports-input", required=True, type=Path)
    parser.add_argument("--llm-input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--mode", choices=("candidates", "all"), default="candidates")
    parser.add_argument("--max-targets", type=int, default=50)
    parser.add_argument("--max-rate", type=int, default=200)
    parser.add_argument("--min-rate", type=int, default=100)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--host-timeout", default="40m")
    parser.add_argument("--max-retries", type=int, default=0)
    parser.add_argument("--process-timeout", type=int, default=2700)
    parser.add_argument("--nmap-bin", default="nmap")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if min(args.max_targets, args.max_rate, args.workers) < 1:
        parser.error("target, rate, and worker values must be positive")
    if args.min_rate < 0:
        parser.error("min-rate must be >= 0")
    if args.min_rate > 0 and args.min_rate > args.max_rate:
        parser.error("min-rate cannot exceed max-rate")
    if args.process_timeout is not None and args.process_timeout < 0:
        parser.error("process timeout must be >= 0")
    for path in (args.ports_input, args.llm_input):
        if not path.is_file():
            parser.error("file not found: %s" % path)

    port_rows, fields = read_csv(args.ports_input)
    llm_rows, _ = read_csv(args.llm_input)
    candidates, skipped_high = select_candidates(
        llm_rows, args.mode, args.max_targets
    )
    checkpoint = load_checkpoint(args.checkpoint) if args.resume else {}
    pending = [
        item for item in candidates
        if checkpoint.get(item["ip"], {}).get("status") != "complete"
    ]
    print(
        "Full-port candidates: selected=%d pending=%d skipped_gpu_high=%d"
        % (len(candidates), len(pending), skipped_high),
        flush=True,
    )
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_one, item, args): item for item in pending}
        for future in as_completed(futures):
            item = future.result()
            checkpoint[item["ip"]] = item
            append_checkpoint(args.checkpoint, item)
            print(
                "  %s status=%s open_ports=%d elapsed=%.1fs"
                % (
                    item["ip"], item["status"], len(item["ports"]),
                    item["elapsed_seconds"],
                ),
                flush=True,
            )
    current = {
        item["ip"]: checkpoint[item["ip"]]
        for item in candidates if item["ip"] in checkpoint
    }
    new_ports = output_new_ports(args.output, port_rows, fields, current)
    summary = {
        "mode": args.mode,
        "selected_candidates": len(candidates),
        "skipped_gpu_high_ips": skipped_high,
        "completed": sum(
            checkpoint.get(item["ip"], {}).get("status") == "complete"
            for item in candidates
        ),
        "failed_or_timed_out": sum(
            checkpoint.get(item["ip"], {}).get("status") in {"failed", "timeout"}
            for item in candidates
        ),
        "new_open_ports": new_ports,
        "max_rate_per_worker": args.max_rate,
        "min_rate_per_worker": args.min_rate,
        "host_timeout": args.host_timeout,
        "process_timeout": args.process_timeout,
        "max_retries": args.max_retries,
        "workers": args.workers,
    }
    summary_path = args.summary or args.output.with_suffix(".summary.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print("Full-port recheck complete: %s" % summary, flush=True)
    return 0 if not summary["failed_or_timed_out"] else 2


if __name__ == "__main__":
    sys.exit(main())
