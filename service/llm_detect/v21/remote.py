from __future__ import annotations

import base64
import csv
import importlib.util
import json
import shlex
import tempfile
from pathlib import Path

from .common import ContractError, atomic_bytes, atomic_json, digest, dumps, file_hash
from .remote_results import validate_completed_results


class RemoteJob:
    """Reuse the existing strict-host-key SSH transport, not its old job lifecycle."""
    def __init__(self, config, release, lease, source_id, source_root, params, ttl):
        spec = importlib.util.spec_from_file_location("_v7_transport", release.path / "remote_full_port_runner.py")
        transport = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(transport)
        cfg = transport.Config(config)
        self.transport = transport.Runner(cfg, release.path / "full_port_recheck.py")
        self.transport.check_credentials()
        self.release, self.lease, self.root = release, lease, Path(source_root)
        self.source_id = source_id
        self.job = f"{cfg.remote_base_dir.rstrip('/')}/service21/tasks/{lease.task_id}/runs/{lease.run_id}/sources/{source_id}/FULL_PORT"
        self.helper = self.job + "/bin/service_remote.py"
        mapping = {"ports.csv": self.root / "endpoints.csv", "llm.csv": self.root / "low.csv"}
        for name in ("full_port_recheck.py", "service_hooks.py", "service_remote.py"):
            mapping["bin/" + name] = release.path / name
        hashes = {name: file_hash(path) for name, path in mapping.items()}
        binding = digest(dumps({"version": release.version, "hashes": hashes, "params": params}).encode())
        self.request = {"epoch": lease.epoch, "binding": binding, "ttl": ttl, "params": params,
                        "python": cfg.python_bin, "nmap": cfg.nmap_bin, "file_hashes": hashes}
        self.mapping = mapping
        self.initialized = (self.root / "remote-binding.json").exists()
        if self.initialized:
            prior = json.loads((self.root / "remote-binding.json").read_text(encoding="utf-8"))
            if prior != {"binding":binding,"job":self.job}:
                raise ContractError("REMOTE_BINDING", "restore the original remote job/input binding")

    def owner_present(self):
        value = self.transport.ssh("if test -f " + shlex.quote(self.job + "/owner.json") + "; then echo present; else echo absent; fi", "verify remote ownership record").stdout.strip()
        if value not in {"present","absent"}:
            raise ContractError("REMOTE_PROTOCOL", "unconfirmed remote ownership record")
        return value == "present"

    def prepare(self):
        if self.initialized and not self.owner_present():
            raise ContractError("REMOTE_STATE_MISSING", "remote job ownership disappeared; do not launch a replacement")
        self.transport.ssh("mkdir -p " + shlex.quote(self.job + "/bin"), "prepare controlled remote directory")
        for name, path in self.mapping.items():
            remote = self.job + "/" + name
            actual = self.transport.remote_hash(remote)
            if actual and actual != self.request["file_hashes"][name]:
                raise ContractError("REMOTE_BINDING", "remote input/worker differs; existing job retained")
            if not actual:
                self.transport.upload_atomic(path, remote, "publish controlled remote file")
        self.rpc("init")
        atomic_json(self.root / "remote-binding.json", {"binding":self.request["binding"],"job":self.job})
        self.initialized = True
        return self.rpc("start")

    def rpc(self, action):
        if action == "stop":
            if getattr(self,"initialized",False) and not self.owner_present():
                raise ContractError("REMOTE_STOP_UNCONFIRMED", "remote owner record lost; cannot confirm absence of a worker")
            state = self.transport.ssh("if test -f " + shlex.quote(self.helper) + "; then echo helper; elif test -f " + shlex.quote(self.job + "/owner.json") + " -o -f " + shlex.quote(self.job + "/process.json") + "; then echo unknown; else echo absent; fi", "check remote stop ownership").stdout.strip()
            if state == "absent":
                return {"state": "stopped"}
            if state != "helper":
                raise ContractError("REMOTE_STOP_UNCONFIRMED", "remote guardian missing but ownership metadata remains")
        data = base64.urlsafe_b64encode(dumps(self.request).encode()).decode()
        command = " ".join(shlex.quote(v) for v in (self.transport.c.python_bin, self.helper, action, self.job, data))
        result = self.transport.ssh(command, "controlled remote " + action)
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ContractError("REMOTE_PROTOCOL", "invalid remote guardian response") from exc

    def checkpoint(self):
        with tempfile.TemporaryDirectory(prefix="v7-remote-checkpoint-") as temporary:
            remote = self.job + "/checkpoint.jsonl"
            exists = self.transport.ssh("if test -f " + shlex.quote(remote) + "; then echo present; else echo absent; fi", "check remote checkpoint").stdout.strip()
            if exists == "absent":
                return {}
            if exists != "present":
                raise ContractError("REMOTE_PROTOCOL", "unconfirmed remote checkpoint state")
            fetched = Path(temporary) / "checkpoint.jsonl"
            self.transport.download(remote, fetched, "retrieve remote checkpoint")
            atomic_bytes(self.root / "remote_checkpoint.jsonl", fetched.read_bytes())
        path = self.root / "remote_checkpoint.jsonl"
        rows = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                    rows[row["ip"]] = row
                except (ValueError, KeyError):
                    continue  # The currently appending final line may be incomplete.
        return rows

    def retrieve(self):
        with tempfile.TemporaryDirectory(prefix="v7-remote-result-") as temporary:
            temp = Path(temporary)
            for name in ("new_ports.csv", "summary.json", "checkpoint.jsonl"):
                remote = self.job + "/" + name
                expected = self.transport.remote_hash(remote)
                if not expected:
                    if name == "checkpoint.jsonl":
                        (temp / name).write_bytes(b"")  # Only valid when zero candidates were selected.
                        continue
                    raise ContractError("REMOTE_RESULT", f"closed remote result is missing: {name}")
                self.transport.download(remote, temp / name, "retrieve closed " + name)
                if file_hash(temp / name) != expected:
                    raise ContractError("REMOTE_RESULT", f"remote result checksum mismatch: {name}")
            spec = importlib.util.spec_from_file_location("_v7_result_validation", self.release.path / "remote_full_port_runner.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            try:
                summary = module.validate_result_files(temp / "new_ports.csv", temp / "summary.json")
                validate_completed_results(temp / "new_ports.csv", summary, temp / "checkpoint.jsonl",
                                           self.mapping["ports.csv"], self.mapping["llm.csv"])
            except (module.RemoteExecutionError, ValueError, TypeError, KeyError, csv.Error) as exc:
                raise ContractError("REMOTE_RESULT", "remote artifacts failed completeness validation") from exc
            self.transport.optional_download(self.job + "/worker.log", self.root / "remote-worker.log", temp)
            self.transport.optional_download(self.job + "/guardian.log", self.root / "remote-guardian.log", temp)
            atomic_bytes(self.root / "full_new.csv", (temp / "new_ports.csv").read_bytes())
            atomic_bytes(self.root / "full_summary.json", (temp / "summary.json").read_bytes())
            atomic_bytes(self.root / "remote_checkpoint.jsonl", (temp / "checkpoint.jsonl").read_bytes())
            return 2 if summary["failed_or_timed_out"] else 0
