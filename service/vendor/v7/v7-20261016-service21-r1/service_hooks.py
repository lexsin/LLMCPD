"""Optional service hooks. Without LLM_SERVICE_CONTEXT the original CLI is unchanged."""
import json
import os
from pathlib import Path

_writer = None

# Preserve the run fence across CLI subprocesses and nmap. No effect on legacy
# invocations, which do not carry LLM_SERVICE_LOCK_FD.
if os.name == "posix" and (os.environ.get("LLM_SERVICE_LOCK_FD") or os.environ.get("LLM_SERVICE_MACHINE_LOCK_FD")):
    import subprocess
    _fds = {int(os.environ[key]) for key in ("LLM_SERVICE_LOCK_FD","LLM_SERVICE_MACHINE_LOCK_FD") if os.environ.get(key)}
    for _fd in _fds:
        os.fstat(_fd)  # Invalid inherited ownership fails closed.
    _Popen = subprocess.Popen
    class LockedPopen(_Popen):
        def __init__(self, *args, **kwargs):
            kwargs["pass_fds"] = tuple(set(kwargs.get("pass_fds", ())) | _fds)
            super().__init__(*args, **kwargs)
    subprocess.Popen = LockedPopen


class ControlledStop(RuntimeError):
    pass


def context():
    path = os.environ.get("LLM_SERVICE_CONTEXT")
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def emit(kind, rows, **meta):
    global _writer
    cfg = context()
    if cfg is None:
        return
    if _writer is None:
        from llm_detect.v21.events import Outbox
        _writer = Outbox(cfg["run_root"], cfg["task_id"], cfg["run_id"], cfg["source_id"], cfg["stage"])
    _writer.emit(kind, rows, **meta)


def check_control():
    cfg = context()
    if cfg and Path(cfg["control_file"]).exists():
        raise ControlledStop("service requested pause/stop")


def bind_proof(row, record):
    if context():
        from llm_detect.v21.common import proof_hash
        record["service_result_hash"] = proof_hash(row)
    return record


def active_started(row):
    cfg = context()
    if cfg:
        from llm_detect.v21.common import atomic_json, digest
        key = str(row.get("ip")) + ":" + str(row.get("port"))
        path = Path(cfg["source_root"]) / "active_inflight" / (digest(key.encode()) + ".json")
        atomic_json(path, row)


def active_finished(row):
    cfg = context()
    if cfg:
        from llm_detect.v21.common import digest
        key = str(row.get("ip")) + ":" + str(row.get("port"))
        (Path(cfg["source_root"]) / "active_inflight" / (digest(key.encode()) + ".json")).unlink(missing_ok=True)
