"""Regression coverage for the four independently reproduced review findings."""
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from llm_detect.v21.common import ContractError, atomic_json, dumps, proof_hash
from llm_detect.v21.config import DEFAULT_RELEASE, SERVICE_ROOT
from llm_detect.v21.events import Outbox
from llm_detect.v21.remote import RemoteJob
from llm_detect.v21.repository import update
from llm_detect.v21.stage_worker import execute, read_csv, restore_checkpoints, write_csv
from .test_contract import prepared

RELEASE = SERVICE_ROOT / "vendor/v7" / DEFAULT_RELEASE


@pytest.mark.parametrize("interrupted", [True, False])
def test_native_active_resume_consumes_restored_keys(tmp_path, monkeypatch, interrupted):
    monkeypatch.syspath_prepend(str(RELEASE))
    monkeypatch.delenv("LLM_SERVICE_CONTEXT", raising=False)
    import active_gpu_recheck as active
    row = {"ip": "192.0.2.1", "port": "80", "protocol": "http", "gpu_likelihood": "中",
           "is_llm": "确认", "deploy_tool": "vllm", "model_info": "fixture"}
    assert active.is_candidate(row)
    cfg = {"task_id": 1, "run_id": 2, "source_id": 3, "stage": "ACTIVE_RECHECK",
           "run_root": str(tmp_path), "source_root": str(tmp_path)}
    if interrupted:
        atomic_json(tmp_path / "active_inflight/target.json", row)
        status = "UNKNOWN_INTERRUPTED"
    else:
        status = "probe_error"
        Outbox(tmp_path, 1, 2, 3, "ACTIVE_RECHECK").emit("RESULT", [dict(row, active_probe_status=status)])
    restore_checkpoints(cfg)
    checkpoint = json.loads((tmp_path / "active.jsonl").read_text().splitlines()[0])
    assert checkpoint["key"] == active.row_key(row)
    write_csv(tmp_path / "merged.csv", [row])
    calls = []
    monkeypatch.setattr(active, "detect_font", lambda: Path("unused-font"))
    monkeypatch.setattr(active, "run_target", lambda *a, **kw: (calls.append(a) or ({}, None)))
    monkeypatch.setattr(sys, "argv", ["active_gpu_recheck.py", "--input", str(tmp_path / "merged.csv"),
        "--output", str(tmp_path / "active.csv"), "--checkpoint", str(tmp_path / "active.jsonl"),
        "--assets", str(tmp_path / "images"), "--manifest", str(tmp_path / "manifest.json"), "--resume"])
    assert active.main() == 0
    assert calls == []
    assert read_csv(tmp_path / "active.csv")[0]["active_probe_status"] == status
    before = list((tmp_path / "outbox/3_ACTIVE_RECHECK").glob("*.json"))
    restore_checkpoints(cfg)
    assert list((tmp_path / "outbox/3_ACTIVE_RECHECK").glob("*.json")) == before


def remote_fixture(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    write_csv(root / "endpoints.csv", [{"ip": "192.0.2.1", "port": "80"}, {"ip": "192.0.2.2", "port": "80"}])
    write_csv(root / "low.csv", [{"ip": "192.0.2.1", "port": "80"}, {"ip": "192.0.2.2", "port": "80"}])
    files = {"new_ports.csv": b"ip,port\n192.0.2.1,443\n",
             "summary.json": dumps({"selected_candidates": 1, "completed": 1, "failed_or_timed_out": 0, "new_open_ports": 1}).encode(),
             "checkpoint.jsonl": (dumps({"ip": "192.0.2.1", "status": "complete", "ports": ["80", "443"]}) + "\n").encode()}
    job = RemoteJob.__new__(RemoteJob)
    job.root, job.job, job.release = root, "/synthetic", SimpleNamespace(path=RELEASE)
    job.mapping = {"ports.csv": root / "endpoints.csv", "llm.csv": root / "low.csv"}
    def download(remote, local, *_):
        Path(local).write_bytes(files[Path(remote).name])
    job.transport = SimpleNamespace(download=download,
        remote_hash=lambda remote: hashlib.sha256(files[Path(remote).name]).hexdigest() if Path(remote).name in files else None,
        optional_download=lambda *a: None)
    return job, files


@pytest.mark.parametrize("case", ["complete", "partial", "empty"])
def test_remote_accepts_only_consistent_closed_result(tmp_path, case):
    job, files = remote_fixture(tmp_path)
    summary = json.loads(files["summary.json"])
    if case == "partial":
        summary.update(selected_candidates=2, failed_or_timed_out=1)
        files["checkpoint.jsonl"] += (dumps({"ip": "192.0.2.2", "status": "timeout", "ports": []}) + "\n").encode()
    elif case == "empty":
        summary.update(selected_candidates=0, completed=0, new_open_ports=0)
        files.pop("checkpoint.jsonl")
        files["new_ports.csv"] = b"ip,port\n"
    files["summary.json"] = dumps(summary).encode()
    assert job.retrieve() == (2 if case == "partial" else 0)
    assert (job.root / "full_new.csv").read_bytes() == files["new_ports.csv"]


@pytest.mark.parametrize("case", ["truncated_csv", "wrong_ports", "duplicate_rows", "foreign_ip", "invalid_port",
    "bad_checkpoint", "missing_checkpoint", "count_mismatch", "checksum"])
def test_remote_rejects_corruption_without_publishing(tmp_path, case):
    job, files = remote_fixture(tmp_path)
    if case == "truncated_csv":
        files["new_ports.csv"] = b"ip,port\n"
    elif case == "wrong_ports":
        files["new_ports.csv"] = b"ip,port\n192.0.2.1,444\n"
    elif case == "duplicate_rows":
        files["new_ports.csv"] += b"192.0.2.1,443\n"
    elif case == "foreign_ip":
        files["new_ports.csv"] = b"ip,port\n192.0.2.99,443\n"
    elif case == "invalid_port":
        files["new_ports.csv"] = b"ip,port\n192.0.2.1,65536\n"
    elif case == "bad_checkpoint":
        files["checkpoint.jsonl"] = b'{"truncated":\n' + files["checkpoint.jsonl"]
    elif case == "missing_checkpoint":
        files.pop("checkpoint.jsonl")
    elif case == "count_mismatch":
        summary = json.loads(files["summary.json"])
        summary["completed"] = 2
        files["summary.json"] = dumps(summary).encode()
    else:
        job.transport.remote_hash = lambda _: "0" * 64
    for name in ("full_new.csv", "full_summary.json", "remote_checkpoint.jsonl"):
        (job.root / name).write_bytes(b"previous-published-result")
    with pytest.raises(ContractError, match="completeness|checksum"):
        job.retrieve()
    assert all((job.root / name).read_bytes() == b"previous-published-result"
               for name in ("full_new.csv", "full_summary.json", "remote_checkpoint.jsonl"))


@pytest.mark.parametrize("valid", [False, True])
def test_source_and_run_export_use_same_current_evidence(tmp_path, monkeypatch, valid):
    monkeypatch.syspath_prepend(str(RELEASE))
    monkeypatch.delenv("LLM_SERVICE_CONTEXT", raising=False)
    from PIL import Image
    from openpyxl import load_workbook
    import screenshot_evidence as evidence
    import finalize_llm_results as finalizer
    import llm_detect.v21.stage_worker as worker
    from llm_detect.v21.reports import build
    row = {"ip": "192.0.2.1", "port": "80", "protocol": "http", "gpu_likelihood": "高",
           "gpu_evidence": "current GPU evidence", "link": "http://192.0.2.1:80/"}
    image = tmp_path / "proof.png"
    Image.new("RGB", (20, 20), "red").save(image)
    atomic_json(tmp_path / "manifest.json", {"192.0.2.1|80|http": {"path": str(image), "url": row["link"],
        "service_result_hash": proof_hash(row if valid else dict(row, gpu_evidence="old GPU evidence"))}})
    write_csv(tmp_path / "committed.csv", [row])
    monkeypatch.setattr(evidence, "detect_font", lambda: Path("unused-font"))
    monkeypatch.setattr(evidence, "detect_chrome", lambda **kw: None)
    # Exercise the actual SOURCE stage's manifest argument and real image embedding,
    # while keeping the subprocess and all network access out of this offline test.
    def embedded(output, manifest, manifest_only=False):
        assert manifest_only
        evidence.fill_workbook(output, output, tmp_path / "assets", False, manifest_path=manifest, manifest_only=True)
        return 0
    monkeypatch.setattr(finalizer, "fill_screenshots", embedded)
    def command(argv, **kw):
        assert Path(argv[1]).name == "finalize_llm_results.py"
        output = Path(argv[argv.index("-o") + 1])
        manifest = Path(argv[argv.index("--screenshot-manifest") + 1])
        finalizer.write_result(finalizer.read_scan(Path(argv[2])), output)
        return SimpleNamespace(returncode=embedded(output, manifest, "--screenshot-manifest-only" in argv))
    monkeypatch.setattr(worker.subprocess, "run", command)
    cfg = {"release_path": str(RELEASE), "source_root": str(tmp_path), "run_root": str(tmp_path),
           "source_id": 3, "stage": "FINALIZE", "params": {}}
    assert execute(cfg) == 0
    build({"release_path": str(RELEASE), "output": str(tmp_path / "run.xlsx"),
           "sources": [{"id": 3, "file_id": 4, "source_name": "fixture", "status": "PARTIAL", "root": str(tmp_path)}]})
    for name in ("final.xlsx", "run.xlsx"):
        workbook = load_workbook(tmp_path / name)
        assert sum(len(sheet._images) for sheet in workbook.worksheets) == int(valid)
        workbook.close()


@pytest.mark.parametrize("idle", [False, True])
def test_stop_updates_source_counts_in_same_transaction(tmp_path, idle):
    db, repo, lease, sources = prepared(tmp_path, 2)
    with db.cursor() as cur:
        update(cur, "probe_task_run", lease.run_id, {"status": "PAUSED" if idle else "RUNNING",
               "requested_action": "STOP", "request_seq": 1})
    if idle:
        repo.stop_idle_requests("idle-stopper")
    else:
        repo.begin_control(lease, "STOP")
        assert repo.finish_control(lease, "STOP", 1)
    run = repo.get_run(lease.run_id)
    assert run["status"] == "STOPPED" and run["ack_seq"] == 1
    assert run["source_total"] == run["source_finished"] == 2
    assert all(s["status"] == "STOPPED" and s["finished_at"] for s in db.rows("probe_run_source"))
