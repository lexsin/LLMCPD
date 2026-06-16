"""nmap 调用薄封装。

**直接复用** ``vendor/ip_port_scan.py`` 的 ``run_nmap_scan`` / ``verify_anomalous_ports`` /
``maybe_confirm_low_open_batch`` —— 原脚本里已有的优化全保留:
  * ``-n`` 关闭 DNS 反查,``-sS`` SYN 扫描,``--open --stats-every`` 进度
  * 多批 + ProcessPoolExecutor 并行,单批失败不影响整体
  * ``on_batch_done`` 回调:每批扫完立刻可以落盘(我们在这里直接写 DB)
  * **低开放率确认**(可选):一批扫完后若开放 IP 比例过低(疑似防火墙整段吞 SYN),
    抽样复扫 → 命中再扩到全批 / 扫扩展端口
  * **异常端口复核**:每批扫完后,对开放端口数 > 阈值的 IP 用
    ``-sV --version-intensity 0`` 重扫,过滤掉 tcpwrapped 假阳性
  * 自动 IPv4 / IPv6 分流(由调用方各传一次)

low-open-confirm 与 anomaly-verify 的执行顺序与原脚本 ``make_flush_batch`` 一致:
**先 low-open-confirm,后 anomaly-verify**。
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import bootstrap_test_path

bootstrap_test_path()
import ip_port_scan as _ips  # noqa: E402  vendor/

log = logging.getLogger(__name__)

# 重新导出原脚本的 NmapOptions / LowOpenConfirmConfig,使用方不需要二次封装
NmapOptions = _ips.NmapOptions
LowOpenConfirmConfig = _ips.LowOpenConfirmConfig
SCAN_PORTS = _ips.SCAN_PORTS

# 单批扫完(并经过低开放率/异常端口复核)后的回调:`{ip: [open ports]}`,空 list 表示扫过但无开放。
BatchCallback = Callable[[Dict[str, List[int]]], None]


def split_ips_by_version(ips: List[str]) -> Tuple[List[str], List[str]]:
    v4: List[str] = []
    v6: List[str] = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        (v6 if addr.version == 6 else v4).append(ip)
    return v4, v6


def _parse_port_string(value: str) -> List[int]:
    """把 "80;443" 转回 [80, 443]。空串 / 无端口都返回 []。"""
    if not value:
        return []
    out: List[int] = []
    for piece in value.replace(",", ";").split(";"):
        piece = piece.strip()
        if not piece:
            continue
        try:
            out.append(int(piece))
        except ValueError:
            continue
    return sorted(set(out))


def scan_ports_for_ips(
    ips: List[str],
    opts: Optional[NmapOptions] = None,
    *,
    batch_size: int = 100,
    parallel_workers: int = 1,
    stats_every: Optional[str] = "60s",
    anomaly_threshold: int = 20,
    verify_workers: int = 4,
    low_open_config: Optional[LowOpenConfirmConfig] = None,
    on_batch_done: Optional[BatchCallback] = None,
) -> Dict[str, List[int]]:
    """对一组 IP 进行端口扫描,返回 ``{ip: [open ports]}``。

    完整结果会一次性返回;同时 ``on_batch_done`` 在每批扫完(且经过低开放/异常端口
    复核)后被调用一次,适合上层实现"扫一批写一批 DB"的逐步落盘语义。

    每批后处理顺序(与原脚本 ``make_flush_batch`` 一致):
      1) ``maybe_confirm_low_open_batch`` —— 若 ``low_open_config.enabled``
      2) ``verify_anomalous_ports`` —— 若 ``anomaly_threshold > 0``
      3) ``on_batch_done(decoded)`` 回调
    """
    opts = opts or NmapOptions()
    if not ips:
        return {}
    if shutil.which("nmap") is None:
        raise RuntimeError("nmap not found in PATH")

    v4, v6 = split_ips_by_version(ips)
    out: Dict[str, List[int]] = {}

    with tempfile.TemporaryDirectory(prefix="llm_detect_nmap_") as td:
        work = Path(td)

        def _make_callback(verify_dir: Path, ipv6: bool) -> Callable[[int, Dict[str, str]], None]:
            def _wrap(batch_idx: int, batch_result: Dict[str, str]) -> None:
                # 1) 低开放率确认(可选,默认关)
                if low_open_config is not None and low_open_config.enabled:
                    try:
                        _ips.maybe_confirm_low_open_batch(
                            batch_idx,
                            batch_result,
                            ipv6=ipv6,
                            tmp_dir=verify_dir,
                            stats_every=stats_every,
                            config=low_open_config,
                        )
                    except Exception:
                        log.exception(
                            "maybe_confirm_low_open_batch failed for batch %d", batch_idx,
                        )

                # 2) 异常端口 -sV 复核
                if anomaly_threshold > 0:
                    try:
                        _ips.verify_anomalous_ports(
                            batch_result,
                            anomaly_threshold,
                            verify_dir,
                            stats_every,
                            verify_workers,
                        )
                    except Exception:
                        log.exception("verify_anomalous_ports failed for batch %d", batch_idx)

                # 3) 转 List[int],累积到最终结果 + 调上层回调
                decoded = {ip: _parse_port_string(s) for ip, s in batch_result.items()}
                for ip, ports in decoded.items():
                    if ports:
                        out[ip] = ports
                    else:
                        out.setdefault(ip, [])
                if on_batch_done is not None:
                    try:
                        on_batch_done(decoded)
                    except Exception:
                        log.exception("on_batch_done failed for batch %d", batch_idx)

            return _wrap

        for ipv6, group in ((False, v4), (True, v6)):
            if not group:
                continue
            kind = "v6" if ipv6 else "v4"
            ip_list_path = work / f"ips_{kind}.txt"
            xml_path = work / f"scan_{kind}.xml"
            log.info(
                "nmap %s: %d IPs, batch_size=%d, parallel=%d, anomaly=%d, low_open=%s",
                kind, len(group), batch_size, parallel_workers, anomaly_threshold,
                "on" if (low_open_config and low_open_config.enabled) else "off",
            )

            _ips.run_nmap_scan(
                group,
                ip_list_path,
                xml_path,
                ipv6=ipv6,
                stats_every=stats_every,
                step_label="",
                batch_size=batch_size,
                keep_batch_files=False,
                on_batch_done=_make_callback(work, ipv6),
                parallel_workers=parallel_workers,
                merge_xml=False,
                nmap_options=opts,
            )

    return out
