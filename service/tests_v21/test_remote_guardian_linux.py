"""Exercise the real guardian with a sleeping fake worker; no SSH or scanning."""
import hashlib
import importlib.util
import json
import os
import sys
import time

import pytest

from llm_detect.v21.config import DEFAULT_RELEASE, SERVICE_ROOT

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux guardian requires /proc and flock")


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("synthetic guardian did not reach expected state")


@pytest.fixture
def job(tmp_path):
    path = SERVICE_ROOT / "vendor/v7" / DEFAULT_RELEASE / "service_remote.py"
    spec = importlib.util.spec_from_file_location("synthetic_guardian", path)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    folder = tmp_path / "job"
    (folder / "bin").mkdir(parents=True)
    worker = folder / "bin/full_port_recheck.py"
    worker.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    request = {"epoch": 1, "binding": "synthetic-only", "ttl": 2,
               "python": sys.executable, "nmap": "must-never-be-called",
               "file_hashes": {"bin/full_port_recheck.py": hashlib.sha256(worker.read_bytes()).hexdigest()},
               "params": {"max_targets": 1, "max_rate": 1, "min_rate": 1, "workers": 1,
                          "max_retries": 0, "host_timeout_seconds": 1, "process_timeout_seconds": 1}}
    guardians = []
    try:
        yield agent, folder, request, guardians
    finally:
        # Only synthetic processes associated with this temporary job are signalled.
        agent.rpc("stop", folder, dict(request, epoch=100))
        for pid in guardians:
            try:
                wait_for(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid)
            except ChildProcessError:
                pass


def start(job):
    agent, folder, request, guardians = job
    assert agent.rpc("start", folder, request)["state"] == "running"
    owner = json.loads((folder / "owner.json").read_text())
    guardians.append(owner["guardian"])
    return wait_for(lambda: json.loads((folder / "process.json").read_text()) if (folder / "process.json").exists() else None)


def test_guardian_expired_renewal_stops_worker_group(job):
    agent, folder, request, _ = job
    identity = start(job)
    result = wait_for(lambda: agent.load(folder / "result.json"))
    assert result["state"] == "stopped"
    assert not agent.members(identity["pgid"], identity["token"])


def test_guardian_explicit_stop_confirms_real_worker_exit(job):
    agent, folder, request, _ = job
    request["ttl"] = 30
    identity = start(job)
    assert agent.rpc("stop", folder, request)["state"] == "stopped"
    assert not agent.members(identity["pgid"], identity["token"])
