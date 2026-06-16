"""配置加载。仅做最小校验,字段缺失时退回到合理默认值。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


@dataclass
class DatabaseConfig:
    host: str = "127.0.0.1"
    port: int = 3306
    user: str = "root"
    password: str = ""
    database: str = "llm_detect"
    charset: str = "utf8mb4"
    pool_size: int = 8


@dataclass
class OrchestratorConfig:
    poll_interval_sec: float = 5.0
    max_concurrent_tasks: int = 1
    worker_id: str = "worker-1"
    reset_running_on_startup: bool = True


@dataclass
class Stage1Config:
    ping_workers: int = 32
    ping_timeout_sec: float = 4.0
    nmap_batch_size: int = 100
    nmap_parallel_workers: int = 1   # 透传给 ip_port_scan.run_nmap_scan
    nmap_stats_every: Optional[str] = "60s"
    nmap_min_rate: str = "5000"
    nmap_max_retries: str = "1"
    nmap_host_timeout: str = "180s"
    nmap_anomaly_threshold: int = 20  # 0=关闭;>0 时每批扫完对端口数超阈值的 IP 再做 -sV 复核
    nmap_verify_workers: int = 4      # -sV 复核的并发数(线程池)
    # ---- 低开放率确认(low-open-confirm,默认关闭)----
    # 一批 IP 扫完后,若开放率低于阈值,认为可能被防火墙整段吞 SYN,
    # 用更慢的参数 + 抽样复扫;命中再扫整批 / 扫扩展端口列表。
    low_open_enabled: bool = False
    low_open_rate_threshold: float = 0.005          # 开放 IP 占比 < 0.5% 触发
    low_open_min_open_ips: int = 5                  # 或开放 IP 数 < 5 触发
    low_open_sample_size: int = 50                  # 抽样 IP 数
    low_open_expand_rate_threshold: float = 0.01    # 抽样新发现率 ≥ 1% 时扩到全批
    low_open_extra_ports: str = ""                  # 扩展端口(逗号分隔,空=不扫扩展)
    low_open_min_rate: str = "1000"
    low_open_max_retries: str = "2"
    low_open_host_timeout: str = "300s"
    skip_ping: bool = True


@dataclass
class Stage4Config:
    batch_size: int = 2000
    concurrency_override: Optional[int] = None
    rules_yaml: Optional[str] = None  # 路径,None 表示用 vendor/llm_scan_rules.yaml


@dataclass
class HttpApiConfig:
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8088


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: Optional[str] = None


@dataclass
class Settings:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    stage1: Stage1Config = field(default_factory=Stage1Config)
    stage4: Stage4Config = field(default_factory=Stage4Config)
    http_api: HttpApiConfig = field(default_factory=HttpApiConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    config_path: Optional[Path] = None

    @classmethod
    def load(cls, path: Optional[str | os.PathLike]) -> "Settings":
        data: Dict[str, Any] = {}
        config_path: Optional[Path] = None
        if path:
            config_path = Path(path)
            with config_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        s = cls(config_path=config_path)
        if "database" in data:
            s.database = DatabaseConfig(**_pick(data["database"], DatabaseConfig))
        if "orchestrator" in data:
            s.orchestrator = OrchestratorConfig(**_pick(data["orchestrator"], OrchestratorConfig))
        stages = data.get("stages") or {}
        if "stage1_scan" in stages:
            s.stage1 = Stage1Config(**_pick(stages["stage1_scan"], Stage1Config))
        if "stage4_llm" in stages:
            s.stage4 = Stage4Config(**_pick(stages["stage4_llm"], Stage4Config))
        if "http_api" in data:
            s.http_api = HttpApiConfig(**_pick(data["http_api"], HttpApiConfig))
        if "logging" in data:
            s.logging = LoggingConfig(**_pick(data["logging"], LoggingConfig))
        return s


def _pick(raw: Dict[str, Any], cls: type) -> Dict[str, Any]:
    """只取 dataclass 已声明的字段,忽略未知键(避免 TypeError)。"""
    fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    return {k: v for k, v in raw.items() if k in fields}
