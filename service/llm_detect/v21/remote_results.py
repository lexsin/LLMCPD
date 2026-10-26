"""Validate closed full-port outputs before they can feed another scan stage."""
import csv
import ipaddress
import json
from pathlib import Path


def read_endpoints(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        if reader.fieldnames is None or not {"ip", "port"}.issubset(reader.fieldnames):
            raise ValueError("CSV lacks ip/port")
        endpoints = []
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("incomplete CSV row")
            ip = str(ipaddress.ip_address(row["ip"]))
            port = read_port(row["port"])
            endpoints.append((ip, port))
        return endpoints


def read_port(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("invalid port")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


def validate_completed_results(output, summary, checkpoint, original, llm_input):
    counts = [summary[k] for k in ("selected_candidates", "completed", "failed_or_timed_out", "new_open_ports")]
    if any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in counts) or counts[0] != counts[1] + counts[2]:
        raise ValueError("inconsistent remote summary counts")
    known = set(read_endpoints(original))
    allowed = {ip for ip, _ in read_endpoints(llm_input)} & {ip for ip, _ in known}
    latest = {}
    for line in Path(checkpoint).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("invalid checkpoint record")
        ip = str(ipaddress.ip_address(row["ip"]))
        if ip not in allowed or row["status"] not in {"complete", "failed", "timeout"} or not isinstance(row["ports"], list):
            raise ValueError("checkpoint is outside the input or incomplete")
        ports = [read_port(port) for port in row["ports"]]
        if len(set(ports)) != len(ports) or (row["status"] != "complete" and ports):
            raise ValueError("invalid checkpoint ports")
        latest[ip] = (row["status"], ports)
    complete = sum(status == "complete" for status, _ in latest.values())
    if len(latest) != counts[0] or complete != counts[1] or len(latest) - complete != counts[2]:
        raise ValueError("checkpoint does not match summary")
    expected = {(ip, port) for ip, (status, ports) in latest.items() if status == "complete" for port in ports} - known
    actual = read_endpoints(output)
    if len(actual) != counts[3] or len(set(actual)) != len(actual) or set(actual) != expected:
        raise ValueError("CSV does not match completed checkpoint ports")
