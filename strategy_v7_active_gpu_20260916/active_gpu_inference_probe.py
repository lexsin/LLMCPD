#!/usr/bin/env python3
"""Active inference probe with before/during/after GPU evidence sampling."""

import argparse
import json
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

METRICS_SCAN_LIMIT = 64 * 1024 * 1024
METRICS_RETAIN_LIMIT = 2 * 1024 * 1024
METRICS_PREFIX_LIMIT = 64 * 1024
GPU_MARKERS = (
    "gpu", "nvidia", "dcgm", "nvml", "cuda", "rocm", "accelerator",
    "vram", "hbm", "cache_config_info",
)
ACTIVITY_MARKERS = (
    "vllm", "sglang", "tgi", "inference", "request", "token",
    "generation", "completion", "embed", "queue", "worker",
)
GPU_METRIC_RE = re.compile(
    r"(?:^|[_:])(?:dcgm|nvidia_gpu|nv_gpu|gpu_(?:memory|cache|util|blocks)|cuda)(?:[_:]|$)",
    re.I,
)
ACTIVITY_METRIC_RE = re.compile(
    r"(?:request|inference|generation|completion|token|embed).*(?:total|count|sum)$",
    re.I,
)
SAMPLE_RE = re.compile(
    r"^(?!#)([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+"
    r"([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)"
    r"(?:\s|$)"
)


def new_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "Accept-Encoding": "identity",
        "User-Agent": "llm-detect-active-gpu-probe/2",
    })
    return session


def get_text(session: requests.Session, url: str, timeout: float = 8) -> Tuple[int, str, str]:
    try:
        response = session.get(url, timeout=(4, timeout), verify=False)
        return response.status_code, response.text[: 2 * 1024 * 1024], ""
    except requests.RequestException as exc:
        return 0, "", "%s: %s" % (type(exc).__name__, str(exc)[:240])


def stream_metrics(session: requests.Session, url: str, timeout: float = 8) -> Tuple[int, str, str, int]:
    """Consume metrics incrementally and keep relevant lines from the whole body."""
    try:
        response = session.get(url, timeout=(4, timeout), verify=False, stream=True)
        prefix: List[str] = []
        direct: List[str] = []
        activity: List[str] = []
        prefix_size = direct_size = activity_size = scanned = 0
        for raw_line in response.iter_lines(chunk_size=65536, decode_unicode=False):
            scanned += len(raw_line) + 1
            if scanned > METRICS_SCAN_LIMIT:
                break
            line = raw_line.decode("utf-8", errors="replace") + "\n"
            lowered = line.lower()
            encoded_size = len(line.encode("utf-8"))
            if prefix_size < METRICS_PREFIX_LIMIT:
                prefix.append(line)
                prefix_size += encoded_size
            if any(marker in lowered for marker in GPU_MARKERS) and direct_size < METRICS_RETAIN_LIMIT:
                direct.append(line)
                direct_size += encoded_size
            elif any(marker in lowered for marker in ACTIVITY_MARKERS) and activity_size < METRICS_RETAIN_LIMIT:
                activity.append(line)
                activity_size += encoded_size
        body = "".join(prefix) + "\n# filtered_gpu_metrics\n" + "".join(direct) + "".join(activity)
        return response.status_code, body, "", scanned
    except requests.RequestException as exc:
        return 0, "", "%s: %s" % (type(exc).__name__, str(exc)[:240]), 0


def metric_values(body: str) -> Dict[str, float]:
    values: Dict[str, float] = {}
    for line in body.splitlines():
        match = SAMPLE_RE.match(line)
        if not match:
            continue
        try:
            value = float(match.group(2))
        except ValueError:
            continue
        name = match.group(1)
        values[name] = values.get(name, 0.0) + value
    return values


def gpu_metric_evidence(values: Dict[str, float]) -> List[str]:
    return [
        "%s=%g" % (name, value)
        for name, value in sorted(values.items())
        if GPU_METRIC_RE.search(name) and value > 0
    ][:20]


def ollama_vram_evidence(body: str) -> List[str]:
    try:
        data = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return []
    hits = []
    for item in data.get("models") or []:
        if not isinstance(item, dict):
            continue
        try:
            size_vram = int(item.get("size_vram") or 0)
        except (TypeError, ValueError):
            size_vram = 0
        if size_vram > 0:
            hits.append("/api/ps:size_vram=%d model=%s" % (
                size_vram, item.get("name") or item.get("model") or "unknown"
            ))
    return hits[:10]


def inference_request(tool: str, model: str, tokens: int) -> Tuple[str, dict]:
    if tool == "ollama":
        return "/api/generate", {
            "model": model, "prompt": "Reply with OK.", "stream": False,
            "keep_alive": "5m", "options": {"num_predict": tokens, "temperature": 0},
        }
    if tool == "tgi":
        if re.search(r"(?:embed|bge|e5|gte)", model, re.I):
            return "/embed", {"inputs": "gpu probe"}
        return "/generate", {
            "inputs": "Reply with OK.",
            "parameters": {"max_new_tokens": tokens, "do_sample": False},
        }
    return "/v1/chat/completions", {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "max_tokens": tokens, "temperature": 0, "stream": False,
    }


def read_snapshot(base_url: str, label: str) -> dict:
    session = new_session()
    metrics_status, metrics_body, metrics_error, scanned = stream_metrics(
        session, base_url + "/metrics"
    )
    ps_status, ps_body, ps_error = get_text(session, base_url + "/api/ps")
    values = metric_values(metrics_body) if metrics_status == 200 else {}
    metric_hits = gpu_metric_evidence(values)
    vram_hits = ollama_vram_evidence(ps_body) if ps_status == 200 else []
    direct = list(dict.fromkeys(metric_hits + vram_hits))
    if vram_hits:
        evidence_url = base_url + "/api/ps"
        evidence_body = ps_body
        evidence_status = ps_status
    else:
        evidence_url = base_url + "/metrics"
        evidence_body = metrics_body
        evidence_status = metrics_status
    return {
        "label": label,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "metrics_status": metrics_status,
        "metrics_error": metrics_error,
        "metrics_scanned_bytes": scanned,
        "metrics_values": values,
        "api_ps_status": ps_status,
        "api_ps_error": ps_error,
        "direct_gpu_evidence": direct,
        "_evidence_url": evidence_url,
        "_evidence_body": evidence_body,
        "_evidence_status": evidence_status,
    }


def read_metrics_snapshot(base_url: str, label: str) -> dict:
    session = new_session()
    status, body, error, scanned = stream_metrics(session, base_url + "/metrics")
    values = metric_values(body) if status == 200 else {}
    return {
        "label": label,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "metrics_status": status,
        "metrics_error": error,
        "metrics_scanned_bytes": scanned,
        "metrics_values": values,
        "api_ps_status": 0,
        "api_ps_error": "",
        "direct_gpu_evidence": gpu_metric_evidence(values),
        "_evidence_url": base_url + "/metrics",
        "_evidence_body": body,
        "_evidence_status": status,
    }


def read_ps_snapshot(base_url: str, label: str) -> dict:
    session = new_session()
    status, body, error = get_text(session, base_url + "/api/ps", timeout=3)
    return {
        "label": label,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "metrics_status": 0,
        "metrics_error": "",
        "metrics_scanned_bytes": 0,
        "metrics_values": {},
        "api_ps_status": status,
        "api_ps_error": error,
        "direct_gpu_evidence": ollama_vram_evidence(body) if status == 200 else [],
        "_evidence_url": base_url + "/api/ps",
        "_evidence_body": body,
        "_evidence_status": status,
    }


def metric_deltas(before: Dict[str, float], after: Dict[str, float]) -> Dict[str, float]:
    result = {}
    for name, value in after.items():
        delta = value - before.get(name, 0.0)
        if delta > 0 and ACTIVITY_METRIC_RE.search(name):
            result[name] = delta
    return dict(sorted(result.items(), key=lambda item: (-item[1], item[0]))[:20])


EvidenceCallback = Callable[[dict], None]


def run_one(
    tool: str,
    base_url: str,
    model: str,
    timeout: int = 90,
    tokens: int = 6,
    poll_interval: float = 0.5,
    metrics_interval: float = 2.0,
    timeout_observation: float = 300.0,
    delayed_samples: Tuple[float, ...] = (2.0, 10.0),
    evidence_callback: Optional[EvidenceCallback] = None,
) -> dict:
    base_url = base_url.rstrip("/")
    snapshots: List[dict] = []
    evidence_notified = False
    snapshot_lock = threading.Lock()
    direct_evidence_event = threading.Event()

    def record(snapshot: dict) -> None:
        nonlocal evidence_notified
        notify = False
        with snapshot_lock:
            snapshots.append(snapshot)
            if snapshot["direct_gpu_evidence"]:
                direct_evidence_event.set()
                if not evidence_notified:
                    evidence_notified = True
                    notify = True
        if notify and evidence_callback:
            evidence_callback(snapshot)

    # Read both sources before inference, but keep them independent so a large
    # metrics response cannot delay the high-frequency Ollama /api/ps loop.
    record(read_metrics_snapshot(base_url, "before-metrics"))
    if tool == "ollama":
        record(read_ps_snapshot(base_url, "before-ps"))
    path, payload = inference_request(tool, model, tokens)
    inference: Dict[str, object] = {
        "path": path, "status": 0, "error": "", "error_type": "",
        "timed_out": False, "elapsed_seconds": 0.0,
    }

    def send() -> None:
        started = time.monotonic()
        try:
            response = new_session().post(
                base_url + path, json=payload, timeout=(5, timeout), verify=False,
            )
            inference["status"] = response.status_code
            inference["response_excerpt"] = response.text[:500]
        except requests.RequestException as exc:
            inference["error_type"] = type(exc).__name__
            inference["timed_out"] = isinstance(exc, requests.exceptions.ReadTimeout)
            inference["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:300])
        finally:
            inference["elapsed_seconds"] = round(time.monotonic() - started, 3)

    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    sampler_stop = threading.Event()

    def sample_loop(kind: str, interval: float) -> None:
        sample_index = 0
        reader = read_ps_snapshot if kind == "ps" else read_metrics_snapshot
        # The before samples were just collected. Wait one interval before the
        # first during-inference read to avoid an immediate duplicate request.
        while not sampler_stop.wait(max(0.05, interval)):
            record(reader(base_url, "during-%s-%d" % (kind, sample_index)))
            sample_index += 1

    samplers = []
    if tool == "ollama":
        samplers.append(threading.Thread(
            target=sample_loop, args=("ps", poll_interval), daemon=True,
        ))
    samplers.append(threading.Thread(
        target=sample_loop, args=("metrics", metrics_interval), daemon=True,
    ))
    for sampler in samplers:
        sampler.start()

    # Wait for the inference request. Once direct evidence exists, sampling is
    # stopped to reduce traffic, while the request thread is still allowed to
    # finish cleanly and preserve its HTTP outcome.
    while worker.is_alive():
        worker.join(0.1)
        if direct_evidence_event.is_set():
            sampler_stop.set()
    worker.join()

    observation_seconds = 0.0
    if inference.get("timed_out") and not direct_evidence_event.is_set():
        # A read timeout means the server accepted the request but did not
        # answer in time. It may still be loading the model, so keep observing
        # independently and stop as soon as runtime GPU evidence appears.
        observation_started = time.monotonic()
        direct_evidence_event.wait(max(0.0, timeout_observation))
        observation_seconds = round(time.monotonic() - observation_started, 3)
    sampler_stop.set()
    for sampler in samplers:
        sampler.join(timeout=10)

    completed_at = time.monotonic()
    if not direct_evidence_event.is_set():
        record(read_metrics_snapshot(base_url, "after-0s-metrics"))
        if tool == "ollama":
            record(read_ps_snapshot(base_url, "after-0s-ps"))
        for delay in delayed_samples:
            remaining = completed_at + delay - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            record(read_metrics_snapshot(base_url, "after-%gs-metrics" % delay))
            if tool == "ollama":
                record(read_ps_snapshot(base_url, "after-%gs-ps" % delay))

    metric_snapshots = [snapshot for snapshot in snapshots if snapshot["metrics_values"]]
    before_values = metric_snapshots[0]["metrics_values"] if metric_snapshots else {}
    after_values = metric_snapshots[-1]["metrics_values"] if metric_snapshots else {}
    direct = []
    first_evidence_at = ""
    for snapshot in snapshots:
        if snapshot["direct_gpu_evidence"] and not first_evidence_at:
            first_evidence_at = snapshot["label"]
        direct.extend(snapshot["direct_gpu_evidence"])
    direct = list(dict.fromkeys(direct))
    success = int(inference.get("status") or 0) in range(200, 300)
    recommendation = "高" if direct else "中"
    reason = (
        "主动推理期间获得GPU设备、显存或GPU专属指标"
        if direct else
        ("主动推理成功，但未获得GPU专属证据" if success else "主动推理未成功，保留原判定")
    )
    selected_indexes = {0, max(0, len(snapshots) - 1)}
    first_direct_index = None
    for index, snapshot in enumerate(snapshots):
        if snapshot["label"].startswith("after-0s"):
            selected_indexes.add(index)
        if snapshot["direct_gpu_evidence"] and first_direct_index is None:
            first_direct_index = index
    if first_direct_index is not None:
        selected_indexes.add(first_direct_index)
    public_snapshots = []
    for index in sorted(selected_indexes):
        snapshot = snapshots[index]
        public_snapshots.append({
            key: value for key, value in snapshot.items()
            if not key.startswith("_") and key != "metrics_values"
        })
    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": tool, "base_url": base_url, "model": model,
        "tokens": tokens, "poll_interval": poll_interval,
        "metrics_interval": metrics_interval,
        "timeout_observation": timeout_observation,
        "timeout_observation_elapsed_seconds": observation_seconds,
        "delayed_samples": list(delayed_samples),
        "inference": inference,
        "snapshots": public_snapshots,
        "first_direct_evidence_at": first_evidence_at,
        "activity_metric_deltas": metric_deltas(before_values, after_values),
        "direct_gpu_evidence": direct,
        "recommended_gpu_likelihood": recommendation,
        "reason": reason,
    }


def parse_target(value: str) -> Tuple[str, str, str]:
    parts = value.split(",", 2)
    if len(parts) != 3 or not all(part.strip() for part in parts):
        raise argparse.ArgumentTypeError("target must be tool,base_url,model")
    return tuple(part.strip() for part in parts)  # type: ignore[return-value]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", type=parse_target, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--tokens", type=int, default=6, choices=range(4, 9))
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--metrics-interval", type=float, default=2.0)
    parser.add_argument("--timeout-observation", type=float, default=300.0)
    parser.add_argument("--delayed-samples", default="2,10")
    args = parser.parse_args()
    delayed = tuple(float(item) for item in args.delayed_samples.split(",") if item.strip())
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for tool, base_url, model in args.target:
        print("probing %s %s model=%s" % (tool, base_url, model), flush=True)
        result = run_one(
            tool, base_url, model, timeout=args.timeout, tokens=args.tokens,
            poll_interval=args.poll_interval, metrics_interval=args.metrics_interval,
            timeout_observation=args.timeout_observation, delayed_samples=delayed,
        )
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print("saved %s" % output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
