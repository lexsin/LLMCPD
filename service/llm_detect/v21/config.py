from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .common import ContractError

SERVICE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RELEASE = "v7-20261026-service21-r3"


@dataclass
class Config:
    database: dict = field(default_factory=dict)
    data_root: Path = field(default_factory=lambda: SERVICE_ROOT / "runtime")
    storage_roots: dict = field(default_factory=dict)
    release_root: Path = field(default_factory=lambda: SERVICE_ROOT / "vendor" / "v7")
    default_release: str = DEFAULT_RELEASE
    poll_seconds: float = 5
    heartbeat_seconds: float = 10
    control_seconds: float = 2
    lease_seconds: int = 60
    grace_seconds: float = 30
    kill_seconds: float = 5
    max_expanded_hosts: int = 1_000_000
    full_port_executor: str = "local"
    remote_config: Path | None = None
    enable_cleanup: bool = False
    log_level: str = "INFO"

    @classmethod
    def load(cls, path, secrets=True):
        path = Path(path).resolve()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if set(raw) - {"contract_version","database","runtime","storage_roots"}:
            raise ContractError("CONFIG_FIELD", "legacy/unknown top-level configuration is not supported")
        if raw.get("contract_version") != "2.1":
            raise ContractError("CONFIG_VERSION", "config must declare contract_version: '2.1'; legacy config is not accepted")
        opts = raw.get("runtime", {})
        known = set(cls.__dataclass_fields__) - {"database", "storage_roots"}
        if set(opts) - known:
            raise ContractError("CONFIG_FIELD", "unknown runtime settings: " + ", ".join(sorted(set(opts) - known)))
        cfg = cls(**opts)
        cfg.database = dict(raw.get("database", {}))
        for key, value in list(cfg.database.items()):
            if secrets and isinstance(value, str) and value.startswith("env:"):
                env = value[4:]
                if env not in os.environ:
                    raise ContractError("CONFIG_ENV", f"environment variable {env} is required")
                cfg.database[key] = os.environ[env]
        def resolve(value):
            value = Path(value)
            return value.resolve() if value.is_absolute() else (path.parent / value).resolve()
        cfg.data_root = resolve(cfg.data_root)
        cfg.release_root = resolve(cfg.release_root)
        cfg.storage_roots = {k: resolve(v) for k, v in raw.get("storage_roots", {"LOCAL": str(cfg.data_root)}).items()}
        if cfg.storage_roots.get("LOCAL") != cfg.data_root:
            raise ContractError("STORAGE_CONFIG", "LOCAL must resolve to data_root; use a separate storage_id for another upload root")
        if cfg.remote_config:
            cfg.remote_config = resolve(cfg.remote_config)
        if cfg.full_port_executor not in {"local", "remote"}:
            raise ContractError("CONFIG_EXECUTOR", "full_port_executor must be local or remote")
        if cfg.full_port_executor == "remote" and not cfg.remote_config:
            raise ContractError("CONFIG_REMOTE", "remote_config is required")
        if min(cfg.poll_seconds, cfg.heartbeat_seconds, cfg.control_seconds, cfg.grace_seconds, cfg.kill_seconds) <= 0:
            raise ContractError("CONFIG_INTERVAL", "intervals must be positive")
        if cfg.lease_seconds < 3 * cfg.heartbeat_seconds or cfg.max_expanded_hosts < 1:
            raise ContractError("CONFIG_LIMIT", "lease must allow at least three heartbeats; host limit must be positive")
        return cfg
