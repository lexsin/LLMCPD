"""Ascend-only classification of existing HTTP evidence; no network I/O."""

import ipaddress
import json
import math
import re
from urllib.parse import urlsplit


# Ascend/mind-cluster Prometheus Metrics API; not a generic prefix match.
METRICS = {
    "npu_chip_info_utilization": (0, 100),
    "npu_chip_info_hbm_utilization": (0, 100),
    "npu_chip_info_hbm_total_memory": (1, 1048576),
    "npu_chip_info_hbm_used_memory": (0, 1048576),
    "npu_chip_info_temperature": (-50, 200),
    "npu_chip_info_power": (0, 10000),
}
SAMPLE = re.compile(
    r'^\s*(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<labels>[^}\n]*)\}'
    r'\s+(?P<value>[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)'
    r'(?:\s+\d+)?\s*$', re.MULTILINE)
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')
ASCEND = re.compile(r'\b(?:ascend(?:\s*[-_]?\s*\d+[a-z]*)?|mindie|vllm[-_]ascend|torch_npu)\b', re.I)
BACKEND_KEYS = {"backend", "device", "device_type", "platform", "runtime", "inference_backend"}


def _walk(value, instance="", depth=0):
    if depth > 32:
        return
    if isinstance(value, dict):
        instance = value.get("instance", instance)
        yield dict(value, instance=instance)
        for child in value.values():
            yield from _walk(child, instance, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child, instance, depth + 1)


def _local_instance(instance, ip):
    if not instance:
        return True
    try:
        host = urlsplit(instance if "://" in instance else "//" + instance).hostname
        return ipaddress.ip_address(host) == ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False


def classify(probes, ip):
    """Return level, auditable evidence, explicit Ascend backend flag."""
    direct, runtime, hints, foreign = [], [], [], []
    explicit_backend = False
    for path, probe in probes.items():
        if probe.status != 200 or probe.error:
            continue
        body = probe.body or ""
        if ASCEND.search(body):
            hints.append(path + ": Ascend/MindIE related content only")
        if "metrics" in path or "prometheus" in path:
            for match in SAMPLE.finditer(body):
                name = match["name"]
                if name not in METRICS:
                    continue
                labels = dict(LABEL.findall(match["labels"]))
                label_pattern = r'\s*[a-zA-Z_][a-zA-Z0-9_]*="(?:\\.|[^"\\])*"\s*'
                if not re.fullmatch(label_pattern + r'(?:,' + label_pattern + r')*,?\s*', match["labels"]):
                    continue
                if len(labels) != len(LABEL.findall(match["labels"])):
                    continue
                value = float(match["value"])
                low, high = METRICS[name]
                identity = any(labels.get(k) for k in ("id", "npu_id", "vdie_id", "uuid", "pcie_bus_info"))
                if not identity or not math.isfinite(value) or not low <= value <= high:
                    continue
                sample = "%s: %s{%s}=%s" % (path, name, match["labels"], match["value"])
                if not _local_instance(labels.get("instance", ""), ip):
                    foreign.append(sample)
                else:
                    direct.append(sample)
        # Specifications are documentation, not live device inventory.
        if any(word in path.lower() for word in ("openapi", "swagger", "api-docs")):
            continue
        try:
            data = json.loads(body)
        except (ValueError, TypeError, RecursionError):
            continue
        for obj in _walk(data):
            normalized = {str(k).lower(): v for k, v in obj.items()}
            backend = next((str(v) for k, v in normalized.items()
                            if k in BACKEND_KEYS and isinstance(v, str)
                            and (ASCEND.search(v) or v.lower() == "npu")), "")
            ascend_context = any(ASCEND.search(v) for v in normalized.values() if isinstance(v, str))
            assigned = normalized.get("accelerators")
            if isinstance(assigned, list) and normalized.get("npu_count") not in (0, "0"):
                ascend_assigned = [v for v in assigned if isinstance(v, str)
                                   and re.fullmatch(r"(?:ascend|ascend\d+[a-z]*|npu:ascend):?\d*", v, re.I)]
                if ascend_assigned and _local_instance(str(normalized.get("instance", "")), ip):
                    explicit_backend = True
                    runtime.append(path + ": accelerators=" + ",".join(ascend_assigned[:5]))
            if backend and ascend_context:
                if _local_instance(str(normalized.get("instance", "")), ip):
                    explicit_backend = True
                    runtime.append(path + ": backend=" + backend)
            model = next((str(normalized[k]) for k in ("model_name", "device_name", "chip_name", "name")
                          if k in normalized and isinstance(normalized[k], str)
                          and re.search(r'ascend\s*[-_]?\s*\d+', normalized[k], re.I)), "")
            device_id = next((str(normalized[k]) for k in ("id", "device_id", "npu_id", "uuid", "serial_number", "pcie_bus_info")
                              if k in normalized and normalized[k] is not None and str(normalized[k]) != ""), "")
            hardware_path = re.search(r"/(?:npu|ascend|devices|hardware|inventory)(?:/|$)", path, re.I)
            if model and device_id and hardware_path:
                evidence = "%s: device=%s id=%s" % (path, model, device_id)
                if _local_instance(str(normalized.get("instance", "")), ip):
                    direct.append(evidence)
                else:
                    foreign.append(evidence)
    if direct:
        return "高", "; ".join(direct[:5]) + "; NPU硬件资源证据，不代表正在运行大模型或企业自有", explicit_backend
    if runtime:
        return "中", "; ".join(runtime[:5]) + "; 昇腾运行后端线索，未取得设备硬件样本", explicit_backend
    if foreign:
        return "未知", "指标指向其他或无法核验的instance，不能归属当前IP: " + "; ".join(foreign[:2]), explicit_backend
    if hints:
        return "低", "; ".join(hints[:3]), explicit_backend
    return "未知", "未获得有效NPU证据，不代表不存在NPU资源", False


def accelerator_type(gpu, npu):
    types = []
    if gpu in {"高", "中", "high", "medium"}:
        types.append("GPU")
    if npu in {"高", "中", "high", "medium"}:
        types.append("NPU")
    return "+".join(types) or "未知"


def annotate_same_ip(rows):
    """Annotate separate-port evidence without upgrading the destination."""
    sources = {}
    for row in rows:
        if row.get("npu_likelihood") == "高":
            sources.setdefault(row.get("ip"), []).append(str(row.get("port", "")))
    changed = 0
    for row in rows:
        before = dict(row)
        row.setdefault("npu_likelihood", "未知")
        row.setdefault("npu_evidence", "")
        ports = [p for p in sources.get(row.get("ip"), []) if p != str(row.get("port", ""))]
        marker = "same_ip_npu_port="
        if ports and row.get("is_llm") == "确认" and marker not in row["npu_evidence"]:
            row["npu_evidence"] += "; " + marker + ",".join(sorted(set(ports))[:5]) + "; 同IP其他端口有NPU证据，未证明此LLM使用NPU"
        row["accelerator_type"] = accelerator_type(row.get("gpu_likelihood"), row.get("npu_likelihood"))
        changed += row != before
    return changed
