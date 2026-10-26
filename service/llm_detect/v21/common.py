from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath


class ContractError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class LeaseLost(ContractError):
    def __init__(self, message="run lease is no longer valid"):
        super().__init__("LEASE_LOST", message)


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def proof_hash(row):
    return digest(dumps({k: str(v) for k, v in row.items() if v not in (None, "")}).encode("utf-8"))


def decode(value, name="JSON"):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError) as exc:
        raise ContractError("INVALID_JSON", f"invalid {name}") from exc


def beneath(root, relative):
    root = Path(root).resolve()
    raw = str(relative).replace("\\", "/")
    parts = PurePosixPath(raw)
    if not raw or parts.is_absolute() or ".." in parts.parts or ":" in raw:
        raise ContractError("UNSAFE_PATH", "expected a relative server-generated path")
    target = root.joinpath(*parts.parts).resolve()
    if target == root or not target.is_relative_to(root):
        raise ContractError("UNSAFE_PATH", "path escapes configured root")
    return target


def atomic_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    with tmp.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    if os.name == "posix":
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_json(path, value):
    atomic_bytes(path, (dumps(value) + "\n").encode("utf-8"))
