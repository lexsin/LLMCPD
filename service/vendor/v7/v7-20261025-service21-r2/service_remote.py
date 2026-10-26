#!/usr/bin/env python3
"""Self-contained SSH job guardian. Only its token-verified process group is signalled."""
import argparse
import base64
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def save(path, value):
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def flush_results(job):
    for name in ("checkpoint.jsonl","new_ports.csv","summary.json"):
        path = job / name
        if path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())


def load(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def members(pgid, token):
    result = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                pid = int(entry.name)
                if os.getpgid(pid) != pgid:
                    continue
                if (entry / "stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                    continue
                if ("LLM_SERVICE_CHILD_TOKEN=" + token).encode() not in (entry / "environ").read_bytes().split(b"\0"):
                    raise RuntimeError("unowned remote process group")
                result.append(pid)
            except (FileNotFoundError, ProcessLookupError):
                pass
    return result


def stop_group(meta, grace=30):
    if not meta.get("pgid"):
        return
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5)):
        if not members(meta["pgid"], meta["token"]):
            return
        os.killpg(meta["pgid"], sig)
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if not members(meta["pgid"], meta["token"]):
                return
            time.sleep(0.1)
    raise RuntimeError("remote stop not confirmed")


def execute(job):
    # Close the SSH-launch/PID-publish crash window: competing launches may create
    # guardians, but only one guardian can ever dispatch the actual worker.
    with (job / "execute.lock").open("a+") as execution:
        try:
            fcntl.flock(execution, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        with (job / "rpc.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            owner = load(job / "owner.json")
            owner["guardian"] = os.getpid()
            owner["guardian_start"] = (Path("/proc") / str(os.getpid()) / "stat").read_text().rsplit(")", 1)[1].split()[19]
            save(job / "owner.json", owner)
        return execute_owned(job)


def execute_owned(job):
    request = load(job / "request.json")
    env = dict(os.environ)
    env.pop("LLM_SERVICE_CONTEXT", None)  # remote worker has no service/DB dependency
    env.pop("LLM_SERVICE_LOCK_FD", None)
    env.pop("LLM_SERVICE_MACHINE_LOCK_FD", None)
    env["TZ"] = "UTC"
    meta = load(job / "owner.json")
    env["LLM_SERVICE_CHILD_TOKEN"] = meta["token"]
    args = request["params"]
    cmd = [request["python"], str(job / "bin" / "full_port_recheck.py"), "--ports-input", str(job / "ports.csv"),
           "--llm-input", str(job / "llm.csv"), "--output", str(job / "new_ports.csv"), "--checkpoint", str(job / "checkpoint.jsonl"),
           "--summary", str(job / "summary.json"), "--mode", "candidates", "--resume", "--nmap-bin", request["nmap"]]
    for key in ("max_targets", "max_rate", "min_rate", "workers", "max_retries"):
        cmd += ["--" + key.replace("_", "-"), str(args[key])]
    cmd += ["--host-timeout", str(args["host_timeout_seconds"]) + "s", "--process-timeout", str(args["process_timeout_seconds"])]
    with (job / "worker.log").open("ab") as log:
        process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                   env=env, start_new_session=True)
        # Guardian is outside the worker process group, so it can confirm cleanup.
        meta["pgid"] = process.pid
        save(job / "process.json", {"pgid": process.pid, "token": meta["token"]})
        while process.poll() is None:
            owner = load(job / "owner.json")
            if owner.get("stop") or time.time() >= owner.get("deadline", 0):
                stop_group(meta)
                process.wait()
                flush_results(job)
                save(job / "result.json", {"state": "stopped", "code": None})
                return 0
            time.sleep(0.25)
        stop_group(meta)  # also verify no detached nmap children remain
        flush_results(job)
        save(job / "result.json", {"state": "finished", "code": process.returncode})
    return 0


def rpc(action, job, request):
    import uuid
    job.mkdir(parents=True, exist_ok=True)
    with (job / "rpc.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        owner = load(job / "owner.json")
        if request["epoch"] < owner.get("epoch", 0):
            raise RuntimeError("stale remote lease epoch")
        if owner and owner["binding"] != request["binding"]:
            raise RuntimeError("remote input/release binding differs")
        owner.update(epoch=request["epoch"], binding=request["binding"], deadline=time.time() + request["ttl"])
        result = load(job / "result.json")
        identity = load(job / "process.json")
        alive = bool(identity and members(identity["pgid"], identity["token"]))
        guardian = owner.get("guardian")
        guardian_alive = False
        if guardian:
            try:
                stat = (Path("/proc") / str(guardian) / "stat").read_text().rsplit(")", 1)[1].split()
                guardian_alive = stat[0] != "Z" and stat[19] == owner.get("guardian_start")
            except OSError:
                pass
        if action == "stop":
            owner["stop"] = True
            save(job / "owner.json", owner)
            if identity:
                stop_group(identity)
            flush_results(job)
            deadline = time.monotonic() + 5
            while guardian_alive and time.monotonic() < deadline:
                time.sleep(0.1)
                if (job / "result.json").exists():
                    guardian_alive = False
            if guardian_alive:
                raise RuntimeError("guardian stop not yet confirmed")
            save(job / "result.json", {"state": "stopped", "code": None})
            return {"state": "stopped"}
        if alive and not guardian_alive:
            stop_group(identity)
            save(job / "owner.json", owner)
            save(job / "result.json", {"state":"stopped","code":None})
            return {"state":"stopped"}
        if action == "start" and not alive and not guardian_alive and result.get("state") != "finished":
            import hashlib
            for name, expected in request["file_hashes"].items():
                path = job / name
                if path.resolve().parent not in {job.resolve(), (job / "bin").resolve()} or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise RuntimeError("remote input/worker checksum mismatch")
            if owner.get("stop"):
                owner["stop"] = False
            (job / "result.json").unlink(missing_ok=True)
            save(job / "request.json", request)
            owner["token"] = uuid.uuid4().hex
            save(job / "owner.json", owner)
            with (job / "guardian.log").open("ab") as log:
                process = subprocess.Popen([request["python"], str(Path(__file__).resolve()), "execute", str(job)],
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            owner["guardian"] = process.pid
            owner["guardian_start"] = (Path("/proc") / str(process.pid) / "stat").read_text().rsplit(")", 1)[1].split()[19]
            save(job / "owner.json", owner)
            return {"state": "running"}
        save(job / "owner.json", owner)
        if alive or guardian_alive:
            return {"state": "running"}
        return result or {"state": "missing"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["init", "start", "poll", "stop", "execute"])
    parser.add_argument("job", type=Path)
    parser.add_argument("request", nargs="?")
    args = parser.parse_args()
    if args.action == "execute":
        return execute(args.job)
    request = json.loads(base64.urlsafe_b64decode(args.request.encode()).decode())
    print(json.dumps(rpc(args.action, args.job, request)), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
