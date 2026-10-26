from __future__ import annotations

import logging
import mimetypes
import os
import signal
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from .common import ContractError, LeaseLost, atomic_bytes, atomic_json, beneath, decode, digest, file_hash, proof_hash
from .events import Outbox, read_event
from .inputs import validate_inputs, validate_params
from .processes import MachineLock, ManagedProcess, ExecutionLock
from .releases import Releases, frozen_rules
from .remote import RemoteJob
from .repository import STAGES
from .stage_worker import write_csv

log = logging.getLogger(__name__)


class Runtime:
    def __init__(self, cfg, repo):
        self.cfg, self.repo = cfg, repo
        self.releases = Releases(cfg.release_root, cfg.default_release)
        self.worker = f"{socket.gethostname()[:80]}:{os.getpid()}:{uuid.uuid4().hex[:12]}"
        self.shutdown = threading.Event()
        self.lease_lost = threading.Event()
        self.heartbeat_stop = threading.Event()
        self.drained = set()
        self.remote_jobs = []
        self.child = ManagedProcess(cfg.data_root / "managed-process.json", cfg.grace_seconds, cfg.kill_seconds)

    def run(self, once=False):
        self.cfg.data_root.mkdir(parents=True, exist_ok=True)
        slot_file = self.cfg.data_root / "active-run.json"
        with MachineLock() as machine:
            self.child.machine_fd = machine.stream.fileno()
            if not machine.active() and slot_file.exists():
                machine.set_active(decode(slot_file.read_text(encoding="utf-8")))
            self.child.recover()
            self.child.recover_orphans()
            while not self.shutdown.is_set():
                self.repo.stop_idle_requests(self.worker)
                active = machine.active()
                preferred = None
                if active:
                    if active["data_root"] != str(self.cfg.data_root):
                        raise ContractError("MACHINE_BINDING", "restore the active run's original data_root before restarting")
                    prior = self.repo.get_run(active["run_id"])
                    if not prior:
                        raise ContractError("ACTIVE_RUN_MISSING", "active machine slot has lost its run record; reconcile before another scan")
                    if prior["status"] in {"SUCCESS","PARTIAL","FAILED","STOPPED","PAUSED"}:
                        machine.set_active(None)
                        slot_file.unlink(missing_ok=True)
                    else:
                        preferred = int(active["run_id"])
                lease = self.repo.claim(self.worker, preferred_id=preferred)
                if lease:
                    slot = {"data_root":str(self.cfg.data_root),"run_id":lease.run_id,"task_id":lease.task_id}
                    atomic_json(slot_file, slot)
                    machine.set_active(slot)
                    self.run_one(lease)
                    if self.repo.get_run(lease.run_id)["status"] in {"SUCCESS","PARTIAL","FAILED","STOPPED","PAUSED"}:
                        machine.set_active(None)
                        slot_file.unlink(missing_ok=True)
                if once:
                    return
                self.shutdown.wait(self.cfg.poll_seconds)

    def heartbeat(self, lease):
        while not self.heartbeat_stop.wait(self.cfg.heartbeat_seconds):
            try:
                self.repo.heartbeat(lease)
                atomic_json(self.heartbeat_file, {"monotonic": time.monotonic()})
            except Exception:
                log.exception("heartbeat unavailable; fencing scanner run=%s", lease.run_id)
                self.lease_lost.set()
                return

    def drain(self, lease, root):
        for directory in sorted((root / "outbox").glob("*")):
            for path in sorted(directory.glob("*.json")):
                if path in self.drained:
                    continue
                self.repo.commit(lease, read_event(path), path.relative_to(self.cfg.data_root).as_posix())
                self.drained.add(path)

    def control(self, lease, root):
        if self.lease_lost.is_set():
            raise LeaseLost()
        self.repo.stop_idle_requests(self.worker)
        action, seq = self.repo.command(lease)
        if action not in {"PAUSE", "STOP"} and self.shutdown.is_set():
            action = "SHUTDOWN"
        if action not in {"PAUSE", "STOP", "SHUTDOWN"}:
            return False
        if action != "SHUTDOWN":
            self.repo.begin_control(lease, action)
        atomic_json(root / "control.json", {"action": action, "seq": seq})
        # Remote stop must be confirmed, not inferred from the SSH client's exit.
        for remote in list(self.remote_jobs):
            while True:
                try:
                    if remote.rpc("stop")["state"] == "stopped":
                        previous = {}
                        for path in sorted((root / "outbox" / f"{remote.source_id}_FULL_PORT").glob("*.json")):
                            for row in read_event(path)["rows"]:
                                previous[row["ip"]] = row
                        for ip, row in remote.checkpoint().items():
                            if previous.get(ip) != row:
                                Outbox(root, lease.task_id, lease.run_id, remote.source_id, "FULL_PORT").emit("FULL_PORT_HOST", [row])
                        self.remote_jobs.remove(remote)
                        break
                except Exception:
                    log.exception("remote stop unconfirmed run=%s; retaining control pending", lease.run_id)
                if self.lease_lost.wait(self.cfg.control_seconds):
                    raise LeaseLost()
        self.child.stop()
        self.repo.fail_abandoned_artifacts(lease)
        # Deletion revokes result writes; ordinary pause/stop drains durable work.
        try:
            self.drain(lease, root)
        except LeaseLost:
            if self.repo.get_run(lease.run_id)["status"] not in {"STOPPING", "PAUSING"}:
                raise
        if action == "SHUTDOWN":
            self.repo.relinquish(lease)
            return True
        if not self.repo.finish_control(lease, action, seq):
            return self.control(lease, root)  # STOP may have superseded PAUSE.
        return True

    def run_one(self, lease):
        root = beneath(self.cfg.data_root, f"tasks/{lease.task_id}/runs/{lease.run_id}")
        root.mkdir(parents=True, exist_ok=True)
        (root / "control.json").unlink(missing_ok=True)
        self.drained.clear()
        self.remote_jobs = []
        self.lease_lost.clear()
        self.heartbeat_stop.clear()
        self.heartbeat_file = root / "leases" / f"{lease.epoch}-{digest(lease.worker.encode())[:12]}.json"
        atomic_json(self.heartbeat_file, {"monotonic": time.monotonic()})
        fence = ExecutionLock(root)
        heart = threading.Thread(target=self.heartbeat, args=(lease,), daemon=True)
        heart.start()
        reconciled = False
        run = {}
        old_descriptor = None
        try:
            fence.acquire(self.lease_lost)
            self.child.lock_fd = fence.fd
            self.repo.fail_abandoned_artifacts(lease)
            run = self.repo.get_run(lease.run_id)
            descriptor = {"executor": self.cfg.full_port_executor, "data_root": str(self.cfg.data_root),
                          "remote_config_hash": file_hash(self.cfg.remote_config) if self.cfg.remote_config else None}
            old_descriptor = decode(run["summary_json"]).get("service21_executor") if run["summary_json"] else None
            if run["started_at"] and old_descriptor != descriptor:
                raise LeaseLost("restore the original executor configuration before recovering this started run")
            if not run["started_at"] and self.control(lease, root):
                return
            release = self.releases.get(run["scanner_version"])
            if run["started_at"] and not run["scanner_version"]:
                raise ContractError("SCANNER_VERSION_MISSING", "started run cannot recreate its missing release version")
            params = validate_params(run["param_snapshot_json"], run["concurrency"])
            # Restore knowledge of a remote stage before processing an early STOP.
            for source in self.repo.sources(lease):
                stages = self.repo.stages(lease, source["id"])
                if self.cfg.full_port_executor == "remote" and any(s["stage_code"] == "FULL_PORT" and s["status"] not in {"SUCCESS","PARTIAL","SKIPPED","FAILED"} for s in stages):
                    self.remote_jobs.append(self.remote(lease, release, source, params))
            reconciled = True
            if self.control(lease, root):
                return
            run, files, resources = self.repo.input_records(lease)
            inputs = validate_inputs(run, files, resources, self.cfg.storage_roots)
            rules, checksum = frozen_rules(run, release)
            expected = f"tasks/{lease.task_id}/runs/{lease.run_id}"
            if run["workspace_relative_path"] and run["workspace_relative_path"] != expected:
                raise ContractError("WORKSPACE_MISMATCH", "explicit run directory differs from ID-derived path")
            self.repo.freeze(lease, rules, checksum, release.version)
            self.repo.bind_executor(lease, descriptor)
            atomic_bytes(root / "rules.yaml", rules["content"].encode("utf-8"))
            preflight = self.child_stage(lease, root, [sys.executable, "-m", "llm_detect.v21.preflight", str(release.path), str(root / "rules.yaml")], root)
            if preflight is None:
                return
            if preflight != 0:
                raise ContractError("PREPARATION_FAILED", "rule/environment preflight failed; see run stage.log")
            sources = self.repo.publish_sources(lease, inputs)
            if sources is None:
                self.control(lease, root)
                return
            self.drain(lease, root)
            for source in sources:
                if source["status"] in {"SUCCESS", "PARTIAL", "FAILED", "STOPPED"}:
                    continue
                source_root = beneath(self.cfg.data_root, source["workspace_relative_path"])
                source_root.mkdir(parents=True, exist_ok=True)
                for stage in STAGES:
                    if self.control(lease, root):
                        return
                    self.releases.get(release.version)
                    if not self.repo.start_stage(lease, source["id"], stage):
                        continue
                    context = {"task_id": lease.task_id, "run_id": lease.run_id, "source_id": source["id"], "stage": stage,
                        "run_root": str(root), "source_root": str(source_root), "source_snapshot": decode(source["input_snapshot_json"]),
                        "release_path": str(release.path), "rules_path": str(root / "rules.yaml"), "params": params,
                        "max_expanded_hosts": self.cfg.max_expanded_hosts, "control_file": str(root / "control.json")}
                    artifact = None
                    try:
                        if stage == "FINALIZE":
                            rows, version = self.repo.result_rows(lease, source["id"])
                            write_csv(source_root / "committed.csv", rows)
                            artifact = self.repo.reserve_artifact(lease, source["id"], "FINAL_XLSX", "final_xlsx", f"source-{source['id']}.xlsx", stage, version)
                        if stage == "FULL_PORT" and self.cfg.full_port_executor == "remote" and params["full_port"]["enabled"]:
                            code = self.remote_stage(lease, release, source, params, root)
                        else:
                            path = source_root / "context.json"
                            atomic_json(path, context)
                            code = self.child_stage(lease, root, [sys.executable, "-m", "llm_detect.v21.stage_worker", str(path)], source_root, path)
                        if code is None:
                            return
                        self.drain(lease, root)
                        if code not in {0, 2} or (code == 2 and stage != "FULL_PORT"):
                            raise ContractError("STAGE_FAILED", f"{stage} exited {code}; see isolated stage log")
                        if stage == "FINALIZE":
                            self.publish_file(lease, artifact, source_root / "final.xlsx", version)
                            self.publish_extra(lease, source, source_root, stage, version)
                        meta = {}
                        partial = code == 2
                        if stage in {"EVIDENCE", "EVIDENCE_FINAL", "ACTIVE_RECHECK"}:
                            missing = self.publish_evidence(lease, source, source_root, stage)
                            if stage in {"EVIDENCE","EVIDENCE_FINAL"} and missing:
                                partial = True
                                meta.update(error_code="EVIDENCE_INCOMPLETE",error_message=f"{missing} endpoints have no current revision-bound screenshot")
                        if stage == "ACTIVE_RECHECK":
                            from .stage_worker import read_csv
                            unresolved = sum(r.get("active_probe_status") in {"UNKNOWN_INTERRUPTED","probe_error"} for r in read_csv(source_root/"active.csv"))
                            if unresolved:
                                partial = True
                                meta.update(error_code="ACTIVE_INCOMPLETE",error_message=f"{unresolved} active probes remain incomplete; original grades retained")
                        policy_file = source_root / "port_modes/mode_summary.json"
                        if stage == "PORT_SCAN" and policy_file.exists():
                            meta["policy_summary"] = decode(policy_file.read_text(encoding="utf-8"))
                        Outbox(root, lease.task_id, lease.run_id, source["id"], stage).emit("STAGE_END", status="PARTIAL" if partial else "SUCCESS", **meta)
                        self.drain(lease, root)
                    except LeaseLost:
                        raise
                    except Exception as exc:
                        if self.control(lease, root):
                            return
                        log.exception("stage failed run=%s source=%s stage=%s", lease.run_id, source["id"], stage)
                        if artifact:
                            self.repo.artifact_failed(lease, artifact, str(exc))
                        try:
                            _, current_version = self.repo.result_rows(lease, source["id"])
                            self.publish_extra(lease, source, source_root, stage, current_version)
                        except Exception:
                            log.exception("could not publish closed failure diagnostics run=%s", lease.run_id)
                        optional = stage in {"EVIDENCE", "EVIDENCE_FINAL"}
                        Outbox(root, lease.task_id, lease.run_id, source["id"], stage).emit("STAGE_END", status="PARTIAL" if optional else "FAILED", error_code=getattr(exc, "code", "STAGE_FAILED"), error_message=str(exc)[:2000])
                        self.drain(lease, root)
                        if not optional:
                            break
            if self.control(lease, root):
                return
            self.run_report(lease, release, root)
            sources = self.repo.sources(lease)
            status = "SUCCESS" if all(s["status"] == "SUCCESS" for s in sources) else "PARTIAL" if any(s["status"] in {"SUCCESS", "PARTIAL"} for s in sources) else "FAILED"
            if not self.repo.finish(lease, status):
                self.control(lease, root)
        except LeaseLost:
            log.warning("lease fenced run=%s; no terminal state committed", lease.run_id)
            self.child.stop()
            # Remote guardian's deadline stops the worker if this lease cannot renew.
        except Exception as exc:
            log.exception("run failed run=%s", lease.run_id)
            self.child.stop()
            if not reconciled and run.get("started_at") and old_descriptor and old_descriptor.get("executor") == "remote":
                self.repo.relinquish(lease)
                return
            if not self.control(lease, root):
                self.repo.finish(lease, "FAILED", getattr(exc, "code", "RUN_FAILED"), str(exc))
        finally:
            self.heartbeat_stop.set()
            heart.join(timeout=self.cfg.heartbeat_seconds + 6)
            self.child.lock_fd = None
            fence.close()

    def child_stage(self, lease, root, argv, cwd, context=None):
        env = dict(os.environ)
        service_root = str(Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = service_root + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONUNBUFFERED"] = "1"
        env["LLM_SERVICE_HEARTBEAT_FILE"] = str(self.heartbeat_file)
        env["LLM_SERVICE_HEARTBEAT_TTL"] = str(self.cfg.lease_seconds)
        if context:
            env["LLM_SERVICE_CONTEXT"] = str(context)
        else:
            env.pop("LLM_SERVICE_CONTEXT", None)
        child = self.child.launch(argv, cwd, env, Path(cwd) / "stage.log")
        try:
            while child.poll() is None:
                self.drain(lease, root)
                if self.control(lease, root):
                    return None
                self.shutdown.wait(self.cfg.control_seconds)
        except BaseException:
            self.child.stop()
            raise
        code = child.returncode
        self.child.close()
        return code

    def remote(self, lease, release, source, params):
        return RemoteJob(self.cfg.remote_config, release, lease, source["id"], beneath(self.cfg.data_root, source["workspace_relative_path"]), params["full_port"], self.cfg.lease_seconds)

    def remote_stage(self, lease, release, source, params, root):
        remote = next((r for r in self.remote_jobs if r.root == beneath(self.cfg.data_root, source["workspace_relative_path"])), None)
        remote = remote or self.remote(lease, release, source, params)
        if remote not in self.remote_jobs:
            self.remote_jobs.append(remote)
        seen = {}
        folder = root / "outbox" / f"{source['id']}_FULL_PORT"
        for path in sorted(folder.glob("*.json")):
            event = read_event(path)
            for row in event["rows"]:
                seen[row["ip"]] = row
        prepared = False
        while True:
            if self.control(lease, root):
                return None
            try:
                state = remote.prepare() if not prepared else remote.rpc("poll")
                prepared = True
                for ip, row in remote.checkpoint().items():
                    if seen.get(ip) != row:
                        Outbox(root, lease.task_id, lease.run_id, source["id"], "FULL_PORT").emit("FULL_PORT_HOST", [row])
                        seen[ip] = row
                self.drain(lease, root)
                if state["state"] == "finished":
                    if state.get("code") not in {0, 2}:
                        raise ContractError("REMOTE_FAILED", "remote worker failed; job/checkpoints retained")
                    code = remote.retrieve()
                    self.remote_jobs.remove(remote)
                    return code
                if state["state"] in {"missing", "stopped"}:
                    prepared = False  # Same bound job only; start resumes its checkpoint.
            except ContractError as exc:
                try:
                    remote.rpc("stop")
                    if remote in self.remote_jobs:
                        self.remote_jobs.remove(remote)
                except Exception:
                    raise LeaseLost("remote failure cannot be finalized before remote stop is confirmed") from exc
                raise
            except Exception:
                log.exception("remote state unavailable run=%s; not launching a replacement", lease.run_id)
            self.shutdown.wait(self.cfg.control_seconds)

    def publish_file(self, lease, aid, source, version, metadata=None):
        if not source.is_file():
            raise ContractError("ARTIFACT_MISSING", "producer did not create the complete file")
        relative = f"tasks/{lease.task_id}/runs/{lease.run_id}/artifacts/{aid}/{source.name}"
        target = beneath(self.cfg.data_root, relative)
        if target.exists():
            raise ContractError("ARTIFACT_IMMUTABLE", "published generation path already exists")
        atomic_bytes(target, source.read_bytes())
        self.repo.artifact_ready(lease, aid, relative, target.stat().st_size, file_hash(target), mimetypes.guess_type(source.name)[0] or "application/octet-stream", version, metadata)

    def publish_extra(self, lease, source, root, stage, version):
        # Publish closed intermediates only; context files contain internal paths and are not downloads.
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.name in {"context.json", "final.xlsx", "committed.csv"} or path.suffix not in {".csv", ".jsonl", ".xml", ".log"} or "artifacts" in path.parts:
                continue
            logical = "file_" + digest(path.relative_to(root).as_posix().encode())[:24]
            kind = "FINAL_CSV" if path.name == "active.csv" else "CHECKPOINT" if path.suffix == ".jsonl" else "LOG" if path.suffix == ".log" else "INTERMEDIATE_CSV" if path.suffix == ".csv" else "NMAP_XML"
            aid = self.repo.reserve_artifact(lease, source["id"], kind, logical, path.name, stage, version)
            self.publish_file(lease, aid, path, version)

    def publish_evidence(self, lease, source, root, stage):
        from .repository import all_rows
        manifest = root / "manifest.json"
        with self.repo.db.cursor() as cur:
            run, _, _ = self.repo._locked(cur, lease)
            assets = all_rows(cur, "SELECT * FROM probe_asset_port WHERE source_group_id=%s", (source["id"],))
        records = decode(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
        missing = 0
        for asset in assets:
            raw = decode(asset["raw_result_json"])
            key = f"{raw['ip']}|{raw['port']}|{raw.get('protocol','')}"
            record = records.get(key)
            if not record or record.get("service_result_hash") != proof_hash(raw):
                if raw.get("protocol") in {"http","https"} and (asset["gpu_likelihood"] in {"HIGH","MEDIUM","LOW"} or asset["npu_likelihood"] in {"HIGH","MEDIUM"}):
                    missing += 1
                continue
            path = Path(record["path"]).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                raise ContractError("EVIDENCE_PATH", "evidence escapes its source directory")
            aid = self.repo.reserve_artifact(lease, source["id"], "SCREENSHOT", f"endpoint_{asset['endpoint_id']}_r{asset['revision_no']}", path.name,
                stage, run["result_version"], asset["endpoint_id"], asset["revision_no"])
            self.publish_file(lease, aid, path, run["result_version"], record)
        return missing

    def run_report(self, lease, release, root):
        sources = self.repo.sources(lease)
        rows, version = self.repo.result_rows(lease)
        write_csv(root / "committed.csv", rows)
        aid = self.repo.reserve_artifact(lease, None, "FINAL_CSV", "final_csv", "scan-results.csv", "RUN_FINALIZE", version)
        self.publish_file(lease, aid, root / "committed.csv", version)
        descriptions = []
        for source in sources:
            directory = beneath(self.cfg.data_root, source["workspace_relative_path"])
            directory.mkdir(parents=True, exist_ok=True)
            source_rows, _ = self.repo.result_rows(lease, source["id"])
            write_csv(directory / "committed.csv", source_rows)
            descriptions.append({**{k: source[k] for k in ("id", "file_id", "source_name", "status")}, "root": str(directory)})
        context = {"release_path": str(release.path), "output": str(root / "final.xlsx"), "sources": descriptions}
        path = root / "report-context.json"
        atomic_json(path, context)
        aid = self.repo.reserve_artifact(lease, None, "FINAL_XLSX", "final_xlsx", "scan-results.xlsx", "RUN_FINALIZE", version)
        try:
            code = self.child_stage(lease, root, [sys.executable, "-m", "llm_detect.v21.reports", str(path)], root)
            if code is None:
                return
            if code != 0:
                raise ContractError("REPORT_FAILED", f"report child exited {code}")
            self.publish_file(lease, aid, root / "final.xlsx", version)
        except Exception as exc:
            self.repo.artifact_failed(lease, aid, str(exc))
            raise
