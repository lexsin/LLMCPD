from __future__ import annotations

try:
    import fcntl
except ImportError:
    fcntl = None
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path

from .common import ContractError, atomic_json


class MachineLock:
    """Linux advisory lock, shared across service configurations on this machine."""
    def __init__(self, path="/run/lock/llm-detect-v7-machine.lock"):
        self.path, self.stream = Path(path), None

    def __enter__(self):
        if fcntl is None:
            raise ContractError("PLATFORM", "controlled service requires Linux flock")
        fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if os.fstat(fd).st_uid != os.geteuid():
            os.close(fd)
            raise ContractError("MACHINE_LOCK_OWNER", "machine slot file has an unexpected owner")
        self.stream = os.fdopen(fd, "r+")
        try:
            fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            raise ContractError("MACHINE_BUSY", "another controlled scanner owns this machine") from exc
        return self

    def __exit__(self, *_):
        self.stream.close()

    def active(self):
        import json
        self.stream.seek(0)
        value = self.stream.read()
        return json.loads(value) if value.strip() else None

    def set_active(self, value):
        import json
        self.stream.seek(0)
        self.stream.write(json.dumps(value) if value else "")
        self.stream.truncate()
        self.stream.flush()
        os.fsync(self.stream.fileno())


class ExecutionLock:
    """Per-run filesystem fence; scanner descendants retain the same open lock FD."""
    def __init__(self, root):
        self.stream = (Path(root) / "execution.lock").open("a+")
        self.fd = self.stream.fileno()

    def acquire(self, lost):
        if fcntl is None:
            raise ContractError("PLATFORM", "run filesystem fencing requires Linux flock")
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if lost.wait(1):
                    from .common import LeaseLost
                    raise LeaseLost("waiting for previous scanner writers to exit")

    def close(self):
        self.stream.close()


def start_lease_guard():
    """Fail-closed child watchdog; a paused/dead parent cannot leave live scanners."""
    import json
    import threading
    file = os.environ.get("LLM_SERVICE_HEARTBEAT_FILE")
    if not file:
        return
    ttl = float(os.environ["LLM_SERVICE_HEARTBEAT_TTL"])
    def guard():
        while True:
            try:
                timestamp = json.loads(Path(file).read_text(encoding="utf-8"))["monotonic"]
                alive = 0 <= time.monotonic() - timestamp < ttl
            except (OSError, ValueError, KeyError):
                alive = False
            if not alive:
                os.killpg(os.getpgrp(), signal.SIGKILL)
                return
            time.sleep(0.5)
    threading.Thread(target=guard, daemon=True).start()


def group_members(pgid, token):
    matches = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            pid = int(directory.name)
            if os.getpgid(pid) != pgid:
                continue
            status = (directory / "stat").read_text().rsplit(")", 1)[1].split()[0]
            if status == "Z":
                continue
            env = (directory / "environ").read_bytes().split(b"\0")
            if ("LLM_SERVICE_CHILD_TOKEN=" + token).encode() not in env:
                raise ContractError("PROCESS_IDENTITY", "process group contains an unowned process")
            matches.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return matches


class ManagedProcess:
    def __init__(self, registry, grace=30, kill=5):
        self.registry, self.grace, self.kill = Path(registry), grace, kill
        self.process, self.log, self.identity = None, None, None
        self.lock_fd = None
        self.machine_fd = None

    def launch(self, argv, cwd, env, log_path):
        if os.name != "posix" or not Path("/proc").is_dir():
            raise ContractError("PLATFORM", "controlled scanning requires Linux /proc and process groups")
        self.recover()
        token = uuid.uuid4().hex
        env = dict(env, LLM_SERVICE_CHILD_TOKEN=token, LLM_SERVICE_MANAGER="llm-detect-service21", TZ="UTC")
        if self.lock_fd is not None:
            env["LLM_SERVICE_LOCK_FD"] = str(self.lock_fd)
        if self.machine_fd is not None:
            env["LLM_SERVICE_MACHINE_LOCK_FD"] = str(self.machine_fd)
        self.log = Path(log_path).open("ab")
        self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True,
                                        pass_fds=tuple(fd for fd in (self.lock_fd,self.machine_fd) if fd is not None))
        self.identity = {"pgid": self.process.pid, "token": token}
        atomic_json(self.registry, self.identity)
        return self.process

    def recover_orphans(self):
        """Called only while holding MachineLock; covers a crash before PID-file publish."""
        if not Path("/proc").is_dir():
            return
        groups = {}
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            try:
                env = (path / "environ").read_bytes().split(b"\0")
                if b"LLM_SERVICE_MANAGER=llm-detect-service21" not in env:
                    continue
                token = next(v.split(b"=",1)[1].decode() for v in env if v.startswith(b"LLM_SERVICE_CHILD_TOKEN="))
                groups[os.getpgid(int(path.name))] = token
            except (FileNotFoundError, ProcessLookupError, PermissionError, StopIteration):
                continue
        for pgid, token in groups.items():
            self._stop({"pgid":pgid,"token":token})

    def _stop(self, identity):
        pgid, token = int(identity["pgid"]), identity["token"]
        for sig, timeout in ((signal.SIGTERM, self.grace), (signal.SIGKILL, self.kill)):
            if not group_members(pgid, token):
                return
            os.killpg(pgid, sig)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if self.process:
                    self.process.poll()
                if not group_members(pgid, token):
                    return
                time.sleep(0.1)
        raise ContractError("PROCESS_STOP_UNCONFIRMED", "owned process group has not exited")

    def recover(self):
        import json
        if self.registry.exists():
            identity = json.loads(self.registry.read_text(encoding="utf-8"))
            self._stop(identity)
            self.registry.unlink(missing_ok=True)

    def stop(self):
        if self.identity:
            self._stop(self.identity)
        self.close()

    def close(self):
        if self.identity and group_members(int(self.identity["pgid"]), self.identity["token"]):
            self._stop(self.identity)
        if self.log:
            self.log.close()
            self.log = None
        self.registry.unlink(missing_ok=True)
        self.identity = None
