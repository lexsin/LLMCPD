"""Stage 2 — 存活检测 + 端口扫描。

输入:probe_host 中 host_phase ∈ {PENDING_SCAN, SCANNING} 的行。
处理:
    1) 可选 ping(并发线程池,沿用 vendor/ip_ping_check.ping_one)
    2) 调 nmap_runner.scan_ports_for_ips,每批结束 *立即* 写回 probe_host
       (利用 ip_port_scan.run_nmap_scan 的 on_batch_done 回调,
        中间崩溃只丢最后一批未落盘的进度)
    3) 完整跑完后再返回
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from ..adapters import bootstrap_test_path
from ..adapters.nmap_runner import LowOpenConfirmConfig, NmapOptions, scan_ports_for_ips
from ..repo import host_repo
from ..settings import Stage1Config

bootstrap_test_path()
from ip_ping_check import ping_one  # noqa: E402  vendor/

log = logging.getLogger(__name__)


def _build_low_open_config(cfg: Stage1Config) -> LowOpenConfirmConfig:
    """Stage1Config → ip_port_scan.LowOpenConfirmConfig(原脚本里的 dataclass)。"""
    return LowOpenConfirmConfig(
        enabled=cfg.low_open_enabled,
        rate_threshold=cfg.low_open_rate_threshold,
        min_open_ips=cfg.low_open_min_open_ips,
        sample_size=cfg.low_open_sample_size,
        expand_rate_threshold=cfg.low_open_expand_rate_threshold,
        extra_ports=cfg.low_open_extra_ports,
        nmap_options=NmapOptions(
            min_rate=cfg.low_open_min_rate,
            max_retries=cfg.low_open_max_retries,
            host_timeout=cfg.low_open_host_timeout,
        ),
    )


def _ping_many(ips: List[str], workers: int, timeout: float) -> Dict[str, str]:
    """并发 ping;返回 {ip: 'success'|'error'}。"""
    out: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(ping_one, ip, timeout): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                out[ip] = fut.result()
            except Exception:
                out[ip] = "error"
    return out


def run_scan(task_id: int, cfg: Stage1Config) -> Dict[str, List[int]]:
    """对该 task 还没扫的 host 做 ping + nmap。

    nmap 每批结束后立刻把结果写回 probe_host(``on_batch_done`` 回调)。
    返回汇总后的 ``{ip: open ports}``,主要用于上层日志/统计;真源是 DB。
    """
    rows = host_repo.list_hosts_to_scan(task_id)
    if not rows:
        log.info("task %s stage2: no hosts to scan", task_id)
        return {}

    ips = [r["host_ip"] for r in rows]
    log.info("task %s stage2: %d hosts to scan", task_id, len(ips))

    # 标记 SCANNING(把所有目标先标上,这样断点续跑时能识别)
    for ip in ips:
        host_repo.mark_host_scanning(task_id, ip)

    # 1) Ping
    if cfg.skip_ping:
        ping_result = {ip: "skipped" for ip in ips}
        alive_ips = list(ips)
    else:
        ping_result = _ping_many(ips, cfg.ping_workers, cfg.ping_timeout_sec)
        alive_ips = [ip for ip, r in ping_result.items() if r == "success"]
        log.info("task %s stage2: ping success=%d / total=%d",
                 task_id, len(alive_ips), len(ips))

        # 给 ping 不通的 IP 直接落 VERDICT_DONE,不进 nmap
        for ip in ips:
            if ping_result.get(ip) != "success":
                host_repo.finish_host_scan(
                    task_id, ip,
                    open_ports_json=None,
                    has_ports=False,
                    probe_info="ping=error; host unreachable",
                )

    # 2) Nmap —— 复用原脚本 run_nmap_scan,逐批回调写库
    if not alive_ips:
        return {}

    opts = NmapOptions(
        min_rate=cfg.nmap_min_rate,
        max_retries=cfg.nmap_max_retries,
        host_timeout=cfg.nmap_host_timeout,
    )

    def _on_batch(batch: Dict[str, List[int]]) -> None:
        """每批扫完 → 立即写 probe_host。"""
        for ip, ports in batch.items():
            ping_state = ping_result.get(ip, "skipped")
            if ports:
                payload = json.dumps(
                    [{"port": p, "proto": "tcp"} for p in ports],
                    ensure_ascii=False,
                )
                host_repo.finish_host_scan(
                    task_id, ip,
                    open_ports_json=payload,
                    has_ports=True,
                    probe_info=f"ping={ping_state}; open={len(ports)}",
                )
            else:
                host_repo.finish_host_scan(
                    task_id, ip,
                    open_ports_json=None,
                    has_ports=False,
                    probe_info=f"ping={ping_state}; no open ports in scan list",
                )
        log.info("task %s stage2: batch flushed (%d hosts)", task_id, len(batch))

    try:
        open_by_ip = scan_ports_for_ips(
            alive_ips,
            opts,
            batch_size=cfg.nmap_batch_size,
            parallel_workers=cfg.nmap_parallel_workers,
            stats_every=cfg.nmap_stats_every,
            anomaly_threshold=cfg.nmap_anomaly_threshold,
            verify_workers=cfg.nmap_verify_workers,
            low_open_config=_build_low_open_config(cfg),
            on_batch_done=_on_batch,
        )
    except Exception as exc:
        log.exception("task %s nmap failed: %s", task_id, exc)
        # 已扫完的批已经在 _on_batch 里落盘了,剩下未扫的留在 SCANNING 状态,
        # 下次启动 reset_orphaned_scanning_hosts 会回退到 PENDING_SCAN。
        return {}

    return open_by_ip
