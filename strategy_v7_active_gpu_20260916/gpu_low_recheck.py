#!/usr/bin/env python3
"""Second-stage, read-only GPU discovery for rows currently classified low."""

import argparse
import asyncio
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote, urljoin, urlparse

import aiohttp

from scan_config import load_config
from scan_llm import (
    OUTPUT_FIELDNAMES,
    ProbeResult,
    ScanConfig,
    TargetState,
    _analysis_text,
    _extra_get,
    _gpu_evidence_tiers,
    _now,
    _row_to_state,
    phase_gpu_discovery,
    phase_gpu_openapi,
    read_csv_rows_preserve,
    write_csv_atomic,
)


GPU_HIGH = "\u9ad8"
GPU_MEDIUM = "\u4e2d"
GPU_LOW = "\u4f4e"
GPU = "GPU"
ANALYSIS_FIELD = "\u5206\u6790"

PROMETHEUS_METRICS = (
    "DCGM_FI_DEV_GPU_UTIL",
    "DCGM_FI_DEV_FB_USED",
    "DCGM_FI_DEV_FB_FREE",
    "nvidia_gpu_info",
)
BASE_PATHS = (
    "/metrics/cadvisor",
    "/api/v1/label/__name__/values",
    "/api/gpu",
    "/api/gpus",
    "/api/devices",
    "/api/hardware",
    "/api/resources",
    "/v1/cluster/info",
    "/api/v1/cluster/info",
)
GRADIO_PATHS = ("/config", "/info", "/gradio_api/info")
RAY_PATHS = (
    "/api/v0/cluster_metadata",
    "/api/cluster_status",
    "/nodes?view=summary",
)
BACKEND_PATHS = (
    "/metrics",
    "/metrics/",
    "/metrics/cadvisor",
    "/api/ps",
    "/api/gpu",
    "/api/gpus",
    "/api/devices",
    "/api/hardware",
    "/v1/cluster/info",
)
DISCOVERY_KEYWORDS = (
    "gpu", "nvidia", "dcgm", "nvml", "metrics", "hardware",
    "device", "accelerator", "cluster", "resource", "node",
)
DENY_KEYWORDS = (
    "start", "stop", "launch", "terminate", "delete", "remove",
    "register", "unregister", "download", "install", "update",
    "create", "login", "token", "kill", "shutdown", "restart",
    "reset", "reboot", "scale", "allocate", "release", "enable",
    "disable", "drain", "evict", "attach", "detach", "migrate",
)
SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*([\"'])(?P<src>.*?)\1",
    re.IGNORECASE | re.DOTALL,
)
PATH_LITERAL_RE = re.compile(r"[\"'](?P<path>/[^\"'\s<>]{1,180})[\"']")
ABSOLUTE_URL_RE = re.compile(r"https?://[^\"'\s<>]{3,240}", re.IGNORECASE)
DCGM_SAMPLE_RE = re.compile(
    r"^\s*(?P<metric>DCGM_FI_DEV_[A-Za-z0-9_:]+)"
    r"(?:\{(?P<labels>[^}]*)\})?\s+"
    r"(?P<value>(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)"
    r"(?:[eE][-+]?\d+)?|NaN|[-+]?Inf))"
    r"(?:\s+\d+)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
GPU_INFO_SAMPLE_RE = re.compile(
    r"^\s*(?P<metric>(?:nvidia_gpu_info|nv_gpu_info|"
    r"container_accelerator_memory_total_bytes))"
    r"(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+)",
    re.IGNORECASE | re.MULTILINE,
)
GPU_MODEL_RE = re.compile(
    r"\b(?:nvidia|geforce|tesla|quadro|amd\s+instinct|radeon\s+pro)\b",
    re.IGNORECASE,
)


def prometheus_query_paths(metrics: Iterable[str]) -> List[str]:
    return [
        "/api/v1/query?query=%s" % quote(metric, safe="")
        for metric in metrics
    ]


def is_safe_discovered_path(path: str) -> bool:
    if not path.startswith("/") or path.startswith("//"):
        return False
    if any(char in path for char in "{}<>"):
        return False
    low = path.lower()
    if any(keyword in low for keyword in DENY_KEYWORDS):
        return False
    return any(keyword in low for keyword in DISCOVERY_KEYWORDS)


def discover_paths(text: str, limit: int = 8) -> List[str]:
    found: List[str] = []
    for match in PATH_LITERAL_RE.finditer(text or ""):
        path = match.group("path")
        if is_safe_discovered_path(path) and path not in found:
            found.append(path)
        if len(found) >= limit:
            break
    return found


def discover_script_paths(root_body: str, base_url: str, limit: int = 4) -> List[str]:
    base = urlparse(base_url)
    found: List[str] = []
    for match in SCRIPT_SRC_RE.finditer(root_body or ""):
        parsed = urlparse(urljoin(base_url, match.group("src")))
        if parsed.hostname and parsed.hostname != base.hostname:
            continue
        if parsed.port and parsed.port != base.port:
            continue
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        if not parsed.path.lower().endswith(".js") or path in found:
            continue
        found.append(path)
        if len(found) >= limit:
            break
    return found


def discover_same_ip_backends(
    text: str, state: TargetState, limit: int = 3
) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    for raw in ABSOLUTE_URL_RE.findall(text or ""):
        try:
            parsed = urlparse(raw.rstrip("),.;"))
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        if hostname != state.ip:
            continue
        target = (parsed.scheme, str(port))
        if target != (state.protocol, state.port) and target not in found:
            found.append(target)
        if len(found) >= limit:
            break
    return found


async def probe_and_store(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    path: str,
    timeout: int,
    *,
    protocol: Optional[str] = None,
    port: Optional[str] = None,
) -> ProbeResult:
    proto = protocol or state.protocol
    target_port = port or state.port
    same_origin = proto == state.protocol and target_port == state.port
    key = path if same_origin else "%s://%s:%s%s" % (
        proto, state.ip, target_port, path
    )
    existing = state.probes.get(key)
    if existing and existing.status > 0:
        return existing
    async with sem:
        result = await _extra_get(
            session, proto, state.ip, target_port, path, timeout
        )
    state.probes[key] = result
    state.gpu_probe_detail["second_stage:" + key] = {
        "status": result.status,
        "error": result.error,
        "attempts": 1,
        "source": "network",
    }
    if result.status == 200:
        url = "%s://%s:%s%s" % (proto, state.ip, target_port, path)
        if url not in state.links:
            state.links.append(url)
    return result


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _json_gpu_facts(value: Any) -> Tuple[List[str], List[str]]:
    direct: List[str] = []
    inferred: List[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                low_key = str(key).lower()
                text = str(child or "")
                if low_key in {
                    "gpu_name", "modelname", "product_name", "device_name"
                } and GPU_MODEL_RE.search(text):
                    direct.append("%s=%s" % (low_key, text[:120]))
                if low_key in {"gpu_uuid", "device_uuid", "uuid"} and re.search(
                    r"\bGPU-[A-Fa-f0-9-]{8,}\b", text
                ):
                    direct.append("%s=%s" % (low_key, text[:120]))
                if low_key in {
                    "gpu_vram_total", "gpu_memory_total", "vram_total",
                    "size_vram", "gpu_memory_bytes",
                } and _numeric(child) > 0:
                    direct.append("%s=%g" % (low_key, _numeric(child)))
                if low_key in {"gpu_count", "gpu_num", "num_gpus"} and _numeric(
                    child
                ) > 0:
                    inferred.append("%s=%g" % (low_key, _numeric(child)))
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return direct, inferred


def strict_gpu_evidence(
    state: TargetState, cfg: ScanConfig
) -> Tuple[List[str], List[str]]:
    direct, inferred = _gpu_evidence_tiers(state, cfg)
    direct = list(direct)
    inferred = list(inferred)

    for path, probe in state.probes.items():
        if not probe or probe.status != 200 or not probe.body:
            continue
        body = probe.body
        for match in DCGM_SAMPLE_RE.finditer(body):
            labels = (match.group("labels") or "").replace("\n", " ")[:240]
            direct.append(
                "%s:%s value=%s%s"
                % (
                    path,
                    match.group("metric"),
                    match.group("value"),
                    (" labels=" + labels) if labels else "",
                )
            )
        for match in GPU_INFO_SAMPLE_RE.finditer(body):
            if _numeric(match.group("value")) <= 0:
                continue
            labels = (match.group("labels") or "").replace("\n", " ")[:240]
            direct.append(
                "%s:%s value=%s%s"
                % (
                    path,
                    match.group("metric"),
                    match.group("value"),
                    (" labels=" + labels) if labels else "",
                )
            )
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            payload = None
        if payload is not None:
            json_direct, json_inferred = _json_gpu_facts(payload)
            direct.extend("%s:%s" % (path, fact) for fact in json_direct)
            inferred.extend("%s:%s" % (path, fact) for fact in json_inferred)

        if "/api/v1/query?query=DCGM_FI_DEV_" in path:
            try:
                result = payload.get("data", {}).get("result", [])
            except AttributeError:
                result = []
            if result:
                direct.append("%s:valid_dcgm_samples=%d" % (path, len(result)))

    return list(dict.fromkeys(direct))[:8], list(dict.fromkeys(inferred))[:8]


def _prometheus_metric_names(state: TargetState) -> List[str]:
    probe = state.probes.get("/api/v1/label/__name__/values")
    if not probe or probe.status != 200:
        return []
    try:
        values = json.loads(probe.body).get("data", [])
    except (json.JSONDecodeError, AttributeError):
        return []
    if not isinstance(values, list):
        return []
    selected = [
        str(value) for value in values
        if re.search(r"^(?:DCGM_FI_DEV_|nvidia_gpu_|nv_gpu_)", str(value), re.I)
    ]
    return selected[:8]


async def second_stage_one(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
    timeout: int,
) -> Tuple[List[str], List[str]]:
    root = await probe_and_store(sem, session, state, "/", timeout)
    root_text = root.body if root.status == 200 else ""
    marker_text = "\n".join(
        [root_text, state.deploy_tool, state.service_type, state.model_info]
    ).lower()

    paths = list(BASE_PATHS) + prometheus_query_paths(PROMETHEUS_METRICS)
    if "gradio" in marker_text:
        paths.extend(GRADIO_PATHS)
    if "ray" in marker_text:
        paths.extend(RAY_PATHS)
    await asyncio.gather(*[
        probe_and_store(sem, session, state, path, timeout)
        for path in dict.fromkeys(paths)
    ])

    dynamic_metrics = _prometheus_metric_names(state)
    if dynamic_metrics:
        await asyncio.gather(*[
            probe_and_store(sem, session, state, path, timeout)
            for path in prometheus_query_paths(dynamic_metrics)
            if path not in state.probes
        ])

    scripts = discover_script_paths(
        root_text, "%s://%s:%s/" % (state.protocol, state.ip, state.port)
    )
    script_bodies: List[str] = []
    for script_path in scripts:
        async with sem:
            result = await _extra_get(
                session, state.protocol, state.ip, state.port, script_path, timeout
            )
        state.gpu_probe_detail["second_stage_script:" + script_path] = {
            "status": result.status,
            "error": result.error,
            "attempts": 1,
            "source": "network",
        }
        if result.status == 200 and result.body:
            script_bodies.append(result.body)

    discovered_paths: List[str] = []
    for body in [root_text] + script_bodies:
        for path in discover_paths(body):
            if path not in discovered_paths and path not in state.probes:
                discovered_paths.append(path)
    if discovered_paths:
        await asyncio.gather(*[
            probe_and_store(sem, session, state, path, timeout)
            for path in discovered_paths[:8]
        ])

    backend_targets: List[Tuple[str, str]] = []
    for body in [root_text] + script_bodies:
        for target in discover_same_ip_backends(body, state):
            if target not in backend_targets:
                backend_targets.append(target)
    backend_jobs = []
    for protocol, port in backend_targets[:3]:
        for path in BACKEND_PATHS + tuple(prometheus_query_paths(PROMETHEUS_METRICS)):
            backend_jobs.append(
                probe_and_store(
                    sem, session, state, path, timeout,
                    protocol=protocol, port=port,
                )
            )
    if backend_jobs:
        await asyncio.gather(*backend_jobs)

    return strict_gpu_evidence(state, cfg)


async def run_low_recheck(
    input_path: Path,
    output_path: Path,
    checkpoint_path: Path,
    cfg: ScanConfig,
    concurrency: int,
    timeout: int,
    resume: bool,
) -> Dict[str, int]:
    fieldnames, original_rows = read_csv_rows_preserve(input_path)
    for name in OUTPUT_FIELDNAMES + [
        "gpu_second_stage_status", "gpu_second_stage_direct_evidence",
        "gpu_second_stage_inferred_evidence",
    ]:
        if name not in fieldnames:
            fieldnames.append(name)

    updates: Dict[str, dict] = {}
    if resume and checkpoint_path.is_file():
        with checkpoint_path.open(encoding="utf-8") as source:
            for line in source:
                try:
                    item = json.loads(line)
                    updates[item["key"]] = item["row"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue

    selected = [
        row for row in original_rows
        if (row.get("gpu_likelihood") or "").strip() == GPU_LOW
        and (row.get("protocol") or "").strip() in {"http", "https"}
    ]
    pending = [
        row for row in selected
        if "%s:%s" % (row.get("ip"), row.get("port")) not in updates
    ]
    print(
        "GPU low second stage: rows=%d selected=%d pending=%d"
        % (len(original_rows), len(selected), len(pending))
    )

    states = [_row_to_state(row) for row in pending]
    if states:
        await phase_gpu_discovery(states, None, cfg)
        await phase_gpu_openapi(states, None, cfg)
        sem = asyncio.Semaphore(concurrency)
        connector = aiohttp.TCPConnector(
            limit=concurrency, ssl=False, enable_cleanup_closed=True,
            keepalive_timeout=20,
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            evidence = await asyncio.gather(*[
                second_stage_one(sem, session, state, cfg, timeout)
                for state in states
            ])

        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with checkpoint_path.open("a", encoding="utf-8") as checkpoint:
            for original, state, (direct, inferred) in zip(
                pending, states, evidence
            ):
                if direct:
                    state.gpu_likelihood = GPU_HIGH
                    state.gpu_evidence = "; ".join(direct)
                    state.scan_status = "gpu_confirmed_second_stage"
                    state.service_type = state.service_type or "GPU compute"
                    state.accelerator_type = GPU
                    stage_status = "promoted_high"
                elif inferred:
                    state.gpu_likelihood = GPU_MEDIUM
                    state.gpu_evidence = "; ".join(inferred)
                    state.scan_status = "gpu_inferred_second_stage"
                    state.accelerator_type = GPU
                    stage_status = "promoted_medium"
                else:
                    stage_status = "no_new_device_evidence"
                state.scan_time = _now()
                state.analysis = _analysis_text(state)
                updated = dict(original)
                updated.update(state.to_row())
                updated["gpu_second_stage_status"] = stage_status
                updated["gpu_second_stage_direct_evidence"] = "; ".join(direct)
                updated["gpu_second_stage_inferred_evidence"] = "; ".join(inferred)
                key = "%s:%s" % (state.ip, state.port)
                updates[key] = updated
                checkpoint.write(json.dumps(
                    {"key": key, "row": updated}, ensure_ascii=False
                ) + "\n")
                checkpoint.flush()

    final_rows = []
    for row in original_rows:
        key = "%s:%s" % (row.get("ip"), row.get("port"))
        final_rows.append(updates.get(key, row))
    write_csv_atomic(output_path, fieldnames, final_rows)

    summary = {
        "selected": len(selected),
        "promoted_high": sum(
            row.get("gpu_second_stage_status") == "promoted_high"
            for row in updates.values()
        ),
        "promoted_medium": sum(
            row.get("gpu_second_stage_status") == "promoted_medium"
            for row in updates.values()
        ),
        "unchanged": sum(
            row.get("gpu_second_stage_status") == "no_new_device_evidence"
            for row in updates.values()
        ),
    }
    print("GPU low second stage complete: %s" % summary)
    print("Output: %s" % output_path)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Second-stage GPU discovery for low-likelihood rows"
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.concurrency < 1 or args.timeout < 1:
        parser.error("concurrency and timeout must be positive")

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    checkpoint_path = Path(args.checkpoint).resolve()
    config_path = Path(args.config).resolve()
    for path in (input_path, config_path):
        if not path.is_file():
            parser.error("file not found: %s" % path)
    cfg = load_config(config_path)
    asyncio.run(run_low_recheck(
        input_path=input_path,
        output_path=output_path,
        checkpoint_path=checkpoint_path,
        cfg=cfg,
        concurrency=args.concurrency,
        timeout=args.timeout,
        resume=args.resume,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
