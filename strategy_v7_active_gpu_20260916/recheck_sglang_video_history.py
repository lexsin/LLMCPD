#!/usr/bin/env python3
"""Passively recheck SGLang video history for an explicit target list."""

import argparse
import csv
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from active_gpu_recheck import video_history_probe
from screenshot_evidence import add_metadata, capture_response_card, detect_font


def target_key(target: dict) -> str:
    return "%s:%s:%s" % (
        str(target.get("ip") or "").strip(),
        str(target.get("port") or "").strip(),
        str(target.get("protocol") or "http").strip(),
    )


def read_targets(path: Path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source))
    required = {"ip", "port", "protocol", "model"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("input CSV must contain ip,port,protocol,model")
    return rows


def run_target(target: dict, assets: Path, font_path: str) -> dict:
    protocol = str(target.get("protocol") or "http").strip()
    ip = str(target.get("ip") or "").strip()
    port = str(target.get("port") or "").strip()
    model = str(target.get("model") or "").strip()
    base_url = "%s://%s:%s" % (protocol, ip, port)
    captured = {}

    def capture(snapshot: dict) -> None:
        digest = hashlib.sha256(target_key(target).encode("utf-8")).hexdigest()[:20]
        output = assets / (digest + "_video_history.png")
        response = (
            int(snapshot.get("_evidence_status") or 200),
            "application/json; charset=utf-8",
            str(snapshot.get("_evidence_body") or "").encode("utf-8", errors="replace"),
        )
        url = str(snapshot.get("_evidence_url") or base_url)
        if capture_response_card(url, response, output, font_path):
            add_metadata(output, url, font_path)
            captured.update({
                "path": str(output.resolve()),
                "url": url,
                "captured_at": str(snapshot.get("time") or ""),
                "source": "sglang_video_history",
                "evidence_at": "video-history",
            })

    result = video_history_probe(base_url, model, [model], evidence_callback=capture)
    return {"key": target_key(target), "target": target, "result": result, "capture": captured}


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive SGLang video-history GPU recheck")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--concurrency", type=int, default=8)
    args = parser.parse_args()

    targets = read_targets(args.input)
    args.assets.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    font_path = str(detect_font())
    completed = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = {
            pool.submit(run_target, target, args.assets, font_path): target
            for target in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                item = {
                    "key": target_key(target),
                    "target": target,
                    "result": {
                        "probe_mode": "passive_video_history",
                        "recommended_gpu_likelihood": "中",
                        "direct_gpu_evidence": [],
                        "inference": {"path": "/v1/videos?limit=10", "status": 0},
                        "reason": "%s: %s" % (type(exc).__name__, str(exc)[:500]),
                    },
                    "capture": {},
                }
            completed.append(item)
            print("%s %s" % (
                item["key"],
                item["result"].get("recommended_gpu_likelihood"),
            ), flush=True)

    completed.sort(key=lambda item: item["key"])
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(completed, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary.replace(args.output)
    high = sum(
        item["result"].get("recommended_gpu_likelihood") == "高"
        for item in completed
    )
    failed = sum(int(item["result"].get("inference", {}).get("status") or 0) != 200 for item in completed)
    print("complete total=%d high=%d medium=%d failed=%d" % (
        len(completed), high, len(completed) - high, failed,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
