#!/usr/bin/env python3
"""Actively recheck medium GPU candidates and preserve evidence screenshots."""

import argparse
from service_hooks import emit as service_emit, check_control, active_started, active_finished, bind_proof, ControlledStop
import csv
import hashlib
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

from active_gpu_inference_probe import get_text, new_session, run_one
from screenshot_evidence import (
    add_metadata,
    capture_response_card,
    detect_font,
    evidence_key,
    load_manifest,
    save_manifest,
)

SUPPORTED_TOOLS = {"ollama", "vllm", "sglang", "tgi", "llama.cpp"}
VIDEO_TASK_TYPES = {"TI2V", "T2V", "I2V"}
ACTIVE_FIELDS = [
    "active_probe_status", "active_probe_api", "active_probe_model",
    "active_probe_http_status", "active_probe_first_gpu_evidence_at",
    "active_probe_gpu_evidence", "active_probe_config_evidence", "active_probe_detail",
    "gpu_likelihood_before", "gpu_likelihood_after",
]


def read_csv_rows_preserve(path: Path) -> Tuple[List[str], List[dict]]:
    for encoding in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=encoding, newline="") as source:
                reader = csv.DictReader(line.replace("\0", "") for line in source)
                rows = list(reader)
                return list(reader.fieldnames or []), rows
        except UnicodeDecodeError:
            continue
    raise ValueError("Cannot decode %s" % path)


def write_csv_atomic(path: Path, fieldnames: List[str], rows: List[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(
            target,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_NONNUMERIC,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def choose_model(tool: str, value: str) -> str:
    candidates = [item.strip() for item in str(value or "").split(",") if item.strip()]
    candidates = [item for item in candidates if item.lower() not in {"unknown", "未知"}]
    if not candidates:
        return ""
    if tool == "ollama":
        local = [item for item in candidates if ":cloud" not in item.lower()]
        generative = [
            item for item in local
            if not re.search(r"(?:embed|bge|rerank|ocr|tts|asr)", item, re.I)
        ]
        return (generative or local or candidates)[0]
    return candidates[0]


def is_candidate(row: dict) -> bool:
    tool = str(row.get("deploy_tool") or "").strip().lower()
    likelihood = str(row.get("gpu_likelihood") or "").strip()
    evidence = str(row.get("gpu_evidence") or "")
    # Historical output may have promoted this service only because its own
    # /v1/models payload declared num_gpus. Recheck and correct that legacy
    # tier even though it is presently marked 高.
    config_only_high = (
        likelihood == "高"
        and "num_gpus" in evidence
        and not re.search(r"(?:DCGM|gpu_uuid|size_vram|vram_bytes|memory_used_bytes)", evidence, re.I)
    )
    return (
        (likelihood == "中" or config_only_high)
        and str(row.get("is_llm") or "").strip() == "确认"
        and str(row.get("protocol") or "").strip() in {"http", "https"}
        and tool in SUPPORTED_TOOLS
        and bool(choose_model(tool, row.get("model_info", "")))
    )


def row_key(row: dict) -> str:
    return evidence_key(row.get("ip"), row.get("port"), row.get("protocol"))


def model_inventory_evidence(base_url: str) -> Tuple[List[str], str, str, int, List[str]]:
    """Read service-declared GPU configuration; it is not runtime GPU proof."""
    status, body, _ = get_text(new_session(), base_url.rstrip("/") + "/v1/models")
    if status != 200:
        return [], "", body, status, []
    try:
        data = json.loads(body)
    except (TypeError, json.JSONDecodeError):
        return [], "", body, status, []
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return [], "", body, status, []
    evidence: List[str] = []
    task_type = ""
    models: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        model = str(item.get("id") or item.get("model_name") or "").strip()
        if model:
            models.append(model)
        task = str(item.get("task_type") or "").strip()
        task_type = task_type or task
        try:
            count = float(item.get("num_gpus") or 0)
        except (TypeError, ValueError):
            count = 0
        if count <= 0:
            continue
        value = "/v1/models:num_gpus=%g model=%s" % (count, model or "model")
        if task:
            value += " task_type=%s" % task
        evidence.append(value)
    return (
        list(dict.fromkeys(evidence))[:5],
        task_type,
        body,
        status,
        list(dict.fromkeys(models)),
    )


def sglang_model_profile(base_url: str, task_type: str, models: List[str]) -> dict:
    """Read SGLang metadata without triggering inference."""
    profile = {
        "task_type": task_type,
        "models": list(models),
        "model_type": "",
        "openapi_paths": [],
    }
    status, body, error = get_text(new_session(), base_url.rstrip("/") + "/model_info")
    profile["model_info_status"] = status
    profile["model_info_error"] = error
    if status == 200:
        try:
            data = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            profile["task_type"] = str(data.get("task_type") or profile["task_type"])
            profile["model_type"] = str(data.get("model_type") or "")
    status, body, error = get_text(new_session(), base_url.rstrip("/") + "/openapi.json")
    profile["openapi_status"] = status
    profile["openapi_error"] = error
    if status == 200:
        try:
            data = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            data = None
        paths = data.get("paths") if isinstance(data, dict) else None
        if isinstance(paths, dict):
            profile["openapi_paths"] = sorted(str(path) for path in paths)
    profile["is_video"] = (
        str(profile["task_type"]).upper() in VIDEO_TASK_TYPES
        or str(profile["model_type"]).lower() == "diffusion"
    )
    return profile


def _video_items(data: object) -> List[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("data", "videos", "items", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def video_history_probe(
    base_url: str,
    model: str,
    service_models: List[str],
    evidence_callback=None,
) -> dict:
    """Read existing video jobs. This function never submits a video job."""
    path = "/v1/videos?limit=10"
    url = base_url.rstrip("/") + path
    status, body, error = get_text(new_session(), url, timeout=12)
    result = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "sglang",
        "base_url": base_url.rstrip("/"),
        "model": model,
        "probe_mode": "passive_video_history",
        "inference": {
            "path": path,
            "method": "GET",
            "status": status,
            "error": error,
            "route_source": "video_model",
        },
        "direct_gpu_evidence": [],
        "first_direct_evidence_at": "",
        "reason": "视频历史读取失败" if status != 200 else "视频历史中未发现合格GPU运行时证据",
        "recommended_gpu_likelihood": "中",
    }
    if status != 200:
        return result
    try:
        data = json.loads(body)
    except (TypeError, json.JSONDecodeError) as exc:
        result["inference"]["error"] = "JSONDecodeError: %s" % str(exc)[:240]
        return result
    expected_models = {
        str(item).strip() for item in (service_models or [model]) if str(item).strip()
    }
    qualified = []
    for item in _video_items(data):
        record_model = str(item.get("model") or "").strip()
        if str(item.get("status") or "").lower() != "completed":
            continue
        if not record_model or record_model not in expected_models:
            continue
        try:
            peak_memory_mb = float(item.get("peak_memory_mb") or 0)
        except (TypeError, ValueError):
            peak_memory_mb = 0
        try:
            output_count = int(item.get("num_outputs") or 0)
        except (TypeError, ValueError):
            output_count = 0
        has_output = (
            output_count > 0
            or bool(str(item.get("file_path") or "").strip())
            or bool(item.get("file_paths"))
        )
        if peak_memory_mb <= 0 or not has_output:
            continue
        qualified.append((peak_memory_mb, item))
    if not qualified:
        return result
    peak_memory_mb, item = max(qualified, key=lambda pair: pair[0])
    gib = peak_memory_mb / 1024.0
    job_id = str(item.get("id") or item.get("video_id") or "unknown")
    record_model = str(item.get("model") or model)
    evidence = (
        "GET /v1/videos?limit=10: completed video id=%s model=%s "
        "peak_memory_mb=%g (%.1f GiB)"
        % (job_id, record_model, peak_memory_mb, gib)
    )
    result.update({
        "direct_gpu_evidence": [evidence],
        "first_direct_evidence_at": "video-history",
        "reason": "既有视频任务已完成，服务报告峰值GPU显存%.1f GiB" % gib,
        "recommended_gpu_likelihood": "高",
        "video_evidence": {
            "id": job_id,
            "model": record_model,
            "peak_memory_mb": peak_memory_mb,
            "peak_memory_gib": round(gib, 3),
        },
    })
    if evidence_callback:
        # Keep the real returned record, but show only the evidence-bearing
        # fields first so the screenshot visibly contains completion, output,
        # and peak-memory evidence instead of an unrelated earlier history row.
        screenshot_record = {
            key: item.get(key)
            for key in (
                "id", "object", "model", "status", "progress", "file_path",
                "file_paths", "num_outputs", "peak_memory_mb", "inference_time_s",
            )
            if key in item
        }
        evidence_callback({
            "label": "video-history",
            "time": result["time"],
            "direct_gpu_evidence": [evidence],
            "_evidence_url": url,
            "_evidence_body": json.dumps(
                screenshot_record, ensure_ascii=False, indent=2
            ),
            "_evidence_status": status,
        })
    return result


def run_target(
    row: dict,
    assets: Path,
    font_path: str,
    timeout: int,
    tokens: int,
    poll_interval: float,
    metrics_interval: float,
    timeout_observation: float,
    delayed_samples: Tuple[float, ...],
) -> Tuple[dict, dict]:
    tool = str(row.get("deploy_tool") or "").strip().lower()
    model = choose_model(tool, row.get("model_info", ""))
    protocol = str(row.get("protocol") or "").strip()
    ip = str(row.get("ip") or "").strip()
    port = str(row.get("port") or "").strip()
    base_url = "%s://%s:%s" % (protocol, ip, port)
    captured: Dict[str, str] = {}

    def capture_now(snapshot: dict) -> None:
        key = row_key(row)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
        path = assets / (digest + "_active_gpu.png")
        body = snapshot.get("_evidence_body", "")
        response = (
            int(snapshot.get("_evidence_status") or 200),
            "text/plain; charset=utf-8",
            str(body).encode("utf-8", errors="replace"),
        )
        url = str(snapshot.get("_evidence_url") or base_url)
        if capture_response_card(url, response, path, font_path):
            add_metadata(path, url, font_path)
            captured.update({
                "path": str(path.resolve()),
                "url": url,
                "captured_at": str(snapshot.get("time") or ""),
                "source": "active_gpu_recheck",
                "evidence_at": str(snapshot.get("label") or ""),
            })

    inventory, task_type, _, _, service_models = model_inventory_evidence(base_url)
    profile = (
        sglang_model_profile(base_url, task_type, service_models)
        if tool == "sglang" else {"task_type": task_type, "is_video": False}
    )
    if tool == "sglang" and profile.get("is_video"):
        result = video_history_probe(
            base_url, model, service_models, evidence_callback=capture_now
        )
    else:
        check_control()
        active_started(row)
        result = run_one(
            tool, base_url, model, timeout=timeout, tokens=tokens,
            poll_interval=poll_interval, metrics_interval=metrics_interval,
            timeout_observation=timeout_observation, delayed_samples=delayed_samples,
            evidence_callback=capture_now,
        )
    result["service_profile"] = profile
    if inventory:
        result["configuration_gpu_evidence"] = inventory
    result["model_task_type"] = str(profile.get("task_type") or task_type)
    return result, captured


def updated_row(original: dict, result: dict) -> dict:
    row = dict(original)
    before = str(row.get("gpu_likelihood") or "")
    direct = result.get("direct_gpu_evidence") or []
    configuration = result.get("configuration_gpu_evidence") or []
    inference = result.get("inference") or {}
    success = int(inference.get("status") or 0) in range(200, 300)
    passive_video = result.get("probe_mode") == "passive_video_history"
    row["gpu_likelihood_before"] = before
    if passive_video:
        row["active_probe_status"] = (
            "passive_video_gpu_confirmed" if direct else
            ("passive_video_no_gpu_evidence" if success else "passive_video_query_failed")
        )
    else:
        row["active_probe_status"] = "promoted_high" if direct else ("inference_succeeded_no_gpu_evidence" if success else "inference_failed")
    row["active_probe_api"] = str(inference.get("path") or "")
    row["active_probe_model"] = str(result.get("model") or "")
    row["active_probe_http_status"] = str(inference.get("status") or 0)
    row["active_probe_first_gpu_evidence_at"] = str(result.get("first_direct_evidence_at") or "")
    row["active_probe_gpu_evidence"] = "; ".join(str(item) for item in direct)
    row["active_probe_config_evidence"] = "; ".join(str(item) for item in configuration)
    row["active_probe_detail"] = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if direct:
        row["gpu_likelihood"] = "高"
        existing = str(row.get("gpu_evidence") or "").strip()
        active = "; ".join(str(item) for item in direct)
        row["gpu_evidence"] = "; ".join(item for item in (existing, active) if item)
        row["accelerator_type"] = "GPU"
        row["scan_status"] = "passive_video_gpu_confirmed" if passive_video else "active_gpu_confirmed"
        row["分析"] = (
            "既有视频任务已完成，并获取到服务报告的运行时GPU显存证据：%s" % active
            if passive_video else
            "主动推理成功，并获取到直接GPU证据：%s" % active
        )
        if str(result.get("model_task_type") or "").upper() in {"TI2V", "T2V", "I2V"}:
            row["service_type"] = "AI视频生成服务"
        if passive_video:
            evidence_url = str(result.get("base_url") or "") + "/v1/videos?limit=10"
        else:
            evidence_url = (
                str(result.get("base_url") or "")
                + ("/api/ps" if any("/api/ps" in str(item) for item in direct) else "/metrics")
            )
        links = [item for item in str(row.get("link") or "").split("|||") if item]
        if evidence_url and evidence_url not in links:
            links.append(evidence_url)
        row["link"] = "|||".join(links)
    elif configuration:
        # A positive num_gpus is a self-declared configuration value. It can
        # support a medium assessment, but cannot retain a legacy high tier.
        if before == "高":
            row["gpu_likelihood"] = "中"
            row["accelerator_type"] = "GPU"
        existing = str(row.get("gpu_evidence") or "").strip()
        config_text = "; ".join(str(item) for item in configuration)
        row["gpu_evidence"] = "; ".join(item for item in (existing, "服务配置佐证：" + config_text) if item)
        row["分析"] = "服务配置报告GPU数量，尚未取得运行时设备或推理计数器证据：%s" % config_text
        if str(result.get("model_task_type") or "").upper() in {"TI2V", "T2V", "I2V"}:
            row["service_type"] = "AI视频生成服务"
    row["gpu_likelihood_after"] = str(row.get("gpu_likelihood") or before)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="Active inference GPU recheck for medium candidates")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--tokens", type=int, default=6, choices=range(4, 9))
    parser.add_argument("--poll-interval", type=float, default=0.5)
    parser.add_argument("--metrics-interval", type=float, default=2.0)
    parser.add_argument("--timeout-observation", type=float, default=300.0)
    parser.add_argument("--delayed-samples", default="2,10")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-status", action="append", default=[], help="reprocess checkpoint rows with these statuses")
    args = parser.parse_args()
    delayed = tuple(float(item) for item in args.delayed_samples.split(",") if item.strip())
    fieldnames, rows = read_csv_rows_preserve(args.input)
    for field in ACTIVE_FIELDS:
        if field not in fieldnames:
            fieldnames.append(field)
    updates: Dict[str, dict] = {}
    if args.resume and args.checkpoint.is_file():
        with args.checkpoint.open(encoding="utf-8") as source:
            for line in source:
                try:
                    item = json.loads(line)
                    if item["row"].get("active_probe_status") not in set(args.retry_status):
                        updates[item["key"]] = item["row"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
    selected = [row for row in rows if is_candidate(row) and row_key(row) not in updates]
    if args.limit is not None:
        selected = selected[:args.limit]
    args.assets.mkdir(parents=True, exist_ok=True)
    args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
    font_path = str(detect_font())
    manifest = load_manifest(args.manifest)
    with args.checkpoint.open("a", encoding="utf-8") as checkpoint:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {}
            for row in selected:
                check_control()
                future = pool.submit(
                    run_target, row, args.assets, font_path, args.timeout,
                    args.tokens, args.poll_interval, args.metrics_interval,
                    args.timeout_observation, delayed,
                )
                futures[future] = row
            for future in as_completed(futures):
                original = futures[future]
                key = row_key(original)
                try:
                    result, captured = future.result()
                    row = updated_row(original, result)
                    if captured:
                        manifest[key] = bind_proof(row, captured)
                        save_manifest(args.manifest, manifest)
                except ControlledStop:
                    raise
                except Exception as exc:
                    row = dict(original)
                    row["gpu_likelihood_before"] = row.get("gpu_likelihood", "")
                    row["gpu_likelihood_after"] = row.get("gpu_likelihood", "")
                    row["active_probe_status"] = "probe_error"
                    row["active_probe_detail"] = json.dumps(
                        {"error": "%s: %s" % (type(exc).__name__, str(exc)[:500])},
                        ensure_ascii=False,
                    )
                updates[key] = row
                service_emit("RESULT", [row], reason="ACTIVE_RECHECK")
                checkpoint.write(json.dumps({"key": key, "row": row}, ensure_ascii=False) + "\n")
                checkpoint.flush()
                active_finished(row)
                check_control()
                print("active GPU recheck %s: %s" % (key, row.get("active_probe_status")), flush=True)
    final_rows = [updates.get(row_key(row), row) for row in rows]
    write_csv_atomic(args.output, fieldnames, final_rows)
    promoted = sum(
        row.get("active_probe_status") in {"promoted_high", "passive_video_gpu_confirmed"}
        for row in updates.values()
    )
    print("active GPU recheck complete: selected=%d promoted_high=%d" % (len(selected), promoted))
    print("output: %s" % args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

