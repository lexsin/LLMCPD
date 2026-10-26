"""Managed child entrypoint. No database credentials/connections enter scanner processes."""
from __future__ import annotations

import asyncio
import csv
import json
import os
import subprocess
import sys
from pathlib import Path

from .common import atomic_bytes, atomic_json, dumps, proof_hash
from .events import Outbox, read_event
from .inputs import expand_hosts


def write_csv(path, rows, fields=None):
    import io
    fields = fields or list(dict.fromkeys(k for row in rows for k in row)) or ["ip", "port"]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    atomic_bytes(path, buffer.getvalue().encode("utf-8-sig"))


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def durable_outputs(root):
    """A successful child exit is the stage-output durability boundary."""
    root = Path(root)
    files = [p for p in root.iterdir() if p.is_file() and p.suffix in {".csv",".jsonl",".json",".xlsx"}]
    files.extend((root / "evidence").glob("*.png"))
    for path in files:
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    if os.name == "posix":
        for directory in (root, root / "evidence"):
            if directory.exists():
                fd = os.open(str(directory), os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)


def stage_events(cfg):
    folder = Path(cfg["run_root"]) / "outbox" / f"{cfg['source_id']}_{cfg['stage']}"
    return [read_event(p) for p in sorted(folder.glob("*.json"))]


def restore_checkpoints(cfg):
    """Reconstruct native checkpoints only from durable payloads, never trust a cache alone."""
    root, stage = Path(cfg["source_root"]), cfg["stage"]
    events = stage_events(cfg)
    if stage == "ACTIVE_RECHECK":
        from active_gpu_recheck import row_key as result_key
    else:
        def result_key(row):
            return str(row["ip"]) + ":" + str(row["port"])
    updates = {}
    for event in events:
        if event["event_type"] == "RESULT":
            for row in event["rows"]:
                updates[result_key(row)] = row
    if stage in {"IDENTIFY", "FULL_IDENTIFY"}:
        import scan_llm
        prefix = "identify" if stage == "IDENTIFY" else "full_identify"
        if updates:
            scan_llm.write_csv_atomic(root / f"{prefix}.csv", list(dict.fromkeys(scan_llm.OUTPUT_FIELDNAMES + [k for r in updates.values() for k in r])), list(updates.values()))
        atomic_bytes(root / f"{prefix}.jsonl", "".join(dumps({"ip": r["ip"], "port": str(r["port"])}) + "\n" for r in updates.values()).encode("utf-8"))
    elif stage in {"GPU_RECHECK", "FULL_GPU_RECHECK", "ACTIVE_RECHECK"}:
        prefix = {"GPU_RECHECK": "low", "FULL_GPU_RECHECK": "full_low", "ACTIVE_RECHECK": "active"}[stage]
        if stage == "ACTIVE_RECHECK":
            for path in (root / "active_inflight").glob("*.json"):
                row = json.loads(path.read_text(encoding="utf-8"))
                key = result_key(row)
                if key not in updates:
                    row = dict(row, active_probe_status="UNKNOWN_INTERRUPTED",
                               gpu_likelihood_before=row.get("gpu_likelihood", ""), gpu_likelihood_after=row.get("gpu_likelihood", ""))
                    Outbox(cfg["run_root"], cfg["task_id"], cfg["run_id"], cfg["source_id"], stage).emit("RESULT", [row], reason="ACTIVE_INTERRUPTED")
                    updates[key] = row
        atomic_bytes(root / f"{prefix}.jsonl", "".join(dumps({"key": k, "row": row}) + "\n" for k, row in updates.items()).encode("utf-8"))
    elif stage == "PORT_SCAN":
        for mode in ("pn", "host_discovery"):
            cache = {}
            for event in events:
                if event["event_type"] == "PORTS":
                    for row in event["rows"]:
                        if row["scan_mode"] == ("PN" if mode == "pn" else "HOST_DISCOVERY"):
                            cache[row["ip"]] = ";".join(map(str, row["ports"]))
            atomic_json(root / "port_modes" / mode / "port_cache.json", cache)
    elif stage == "FULL_PORT":
        rows = [r for e in events if e["event_type"] == "FULL_PORT_HOST" for r in e["rows"]]
        atomic_bytes(root / "full.jsonl", "".join(dumps(r) + "\n" for r in rows).encode("utf-8"))


def execute(cfg):
    release, root = Path(cfg["release_path"]), Path(cfg["source_root"])
    root.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(release))
    import service_hooks  # forwards the filesystem fence to all scanner subprocesses
    os.environ["TZ"] = "UTC"
    import time
    if hasattr(time, "tzset"):
        time.tzset()
    stage, p = cfg["stage"], cfg["params"]
    restore_checkpoints(cfg)
    def command(name, *args):
        return subprocess.run([sys.executable, str(release / name), *map(str, args)], check=False).returncode
    def identify(source, prefix):
        import scan_llm
        targets = [(r["ip"], str(r["port"])) for r in read_csv(source)]
        checkpoint, output = root / f"{prefix}.jsonl", root / f"{prefix}.csv"
        if not targets:
            write_csv(output, [], scan_llm.OUTPUT_FIELDNAMES)
            return 0
        asyncio.run(scan_llm.run_pipeline(targets, output, checkpoint, scan_llm.load_checkpoint(checkpoint),
                    scan_llm.load_config(Path(cfg["rules_path"])), batch_size=p["identify"]["batch_size"]))
        return 0
    if stage == "EXPAND":
        source_rows = cfg["source_snapshot"]["rows"]
        hosts = expand_hosts(source_rows, cfg["max_expanded_hosts"])
        box = Outbox(cfg["run_root"], cfg["task_id"], cfg["run_id"], cfg["source_id"], stage)
        for start in range(0, len(hosts), 1000):
            box.emit("HOST", hosts[start:start + 1000])
        raw = [{"起始IP": r["start_ip"], "终止IP": r["end_ip"], "使用单位信息": r.get("unit_name", "")} for r in source_rows]
        write_csv(root / "input.csv", raw, ["起始IP", "终止IP", "使用单位信息"])
        # Preserve V7's first metadata row for legacy CSV presentation, separately
        # from the complete DB host/resource associations emitted above.
        by_id = {int(r["resource_id"]): r for r in source_rows}
        expanded = []
        for host in hosts:
            r = by_id[host["resources"][0]["resource_id"]]
            expanded.append({"ip": host["ip"], "起始IP": r["start_ip"], "终止IP": r["end_ip"], "使用单位信息": r.get("unit_name", ""), "ping": "skipped"})
        write_csv(root / "expanded.csv", expanded, ["ip", "起始IP", "终止IP", "使用单位信息", "ping"])
        return 0
    if stage == "PORT_SCAN":
        port = p["port_scan"]
        rc = command("scan_ports_by_source_type.py", "--source", root / "input.csv", "--input", root / "expanded.csv",
            "--output", root / "ports.csv", "--work-dir", root / "port_modes", "--scanner", release / "ip_port_scan.py",
            "--batch-size", port["batch_size"], "--parallel-workers", port["parallel_workers"], "--verify-workers", port["verify_workers"],
            "--min-rate", port["min_rate"], "--max-retries", port["max_retries"], "--host-timeout", f"{port['host_timeout_seconds']}s")
        if rc == 0:
            import expand_scan_ports
            rows = expand_scan_ports.expand(read_csv(root / "ports.csv"))
            write_csv(root / "endpoints.csv", rows, expand_scan_ports.FIELDNAMES)
        return rc
    if stage == "IDENTIFY":
        return identify(root / "endpoints.csv", "identify")
    if stage in {"GPU_RECHECK", "FULL_GPU_RECHECK"}:
        import gpu_low_recheck
        prefix, source = ("low", "identify") if stage == "GPU_RECHECK" else ("full_low", "full_identify")
        asyncio.run(gpu_low_recheck.run_low_recheck(root / f"{source}.csv", root / f"{prefix}.csv", root / f"{prefix}.jsonl",
                    gpu_low_recheck.load_config(Path(cfg["rules_path"])), p["gpu_recheck"]["concurrency"], p["gpu_recheck"]["timeout_seconds"], True))
        return 0
    if stage in {"EVIDENCE", "EVIDENCE_FINAL"}:
        source = "low" if stage == "EVIDENCE" else "active" if p["active_recheck"]["enabled"] else "merged"
        import screenshot_evidence as evidence
        rows = {evidence.evidence_key(r["ip"], r["port"], r.get("protocol")): r for r in read_csv(root / f"{source}.csv")}
        records = evidence.load_manifest(root / "manifest.json")
        records = {k: v for k, v in records.items() if k in rows and v.get("service_result_hash") == proof_hash(rows[k])}
        evidence.save_manifest(root / "manifest.json", records)
        return command("screenshot_evidence.py", "capture-csv", "--input", root / f"{source}.csv", "--assets", root / "evidence", "--manifest", root / "manifest.json")
    if stage == "FULL_PORT":
        full = p["full_port"]
        if not full["enabled"]:
            write_csv(root / "full_new.csv", [], ["ip", "port"])
            return 0
        return command("full_port_recheck.py", "--ports-input", root / "endpoints.csv", "--llm-input", root / "low.csv",
            "--output", root / "full_new.csv", "--checkpoint", root / "full.jsonl", "--summary", root / "full_summary.json",
            "--mode", "candidates", "--max-targets", full["max_targets"], "--max-rate", full["max_rate"], "--min-rate", full["min_rate"],
            "--workers", full["workers"], "--max-retries", full["max_retries"], "--host-timeout", f"{full['host_timeout_seconds']}s",
            "--process-timeout", full["process_timeout_seconds"], "--resume")
    if stage == "FULL_IDENTIFY":
        return identify(root / "full_new.csv", "full_identify")
    if stage == "MERGE":
        return command("merge_llm_results.py", "--base", root / "low.csv", "--incremental", root / "full_low.csv", "--output", root / "merged.csv")
    if stage == "ACTIVE_RECHECK":
        if not p["active_recheck"]["enabled"]:
            atomic_bytes(root / "active.csv", (root / "merged.csv").read_bytes())
            return 0
        active = p["active_recheck"]
        return command("active_gpu_recheck.py", "--input", root / "merged.csv", "--output", root / "active.csv",
            "--checkpoint", root / "active.jsonl", "--assets", root / "evidence", "--manifest", root / "manifest.json",
            "--concurrency", active["concurrency"], "--tokens", active["tokens"], "--poll-interval", active["poll_interval_seconds"],
            "--metrics-interval", active["metrics_interval_seconds"], "--timeout-observation", active["timeout_observation_seconds"],
            "--delayed-samples", ",".join(map(str, active["delayed_samples_seconds"])), "--resume")
    if stage == "FINALIZE":
        from .report_evidence import prepare_manifest
        manifest = prepare_manifest(root)
        return command("finalize_llm_results.py", root / "committed.csv", "--screenshot-manifest", manifest,
                       "--screenshot-manifest-only", "-o", root / "final.xlsx")
    raise ValueError(f"unsupported stage {stage}")


def main():
    from .processes import start_lease_guard
    start_lease_guard()
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    os.environ["LLM_SERVICE_CONTEXT"] = str(Path(sys.argv[1]).resolve())
    code = execute(cfg)
    if code in {0, 2}:
        durable_outputs(cfg["source_root"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
