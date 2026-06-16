"""Stage 1 — 受理:把 probe_pending_resource 展开为 probe_host 行。

支持的 resource_type:
  - IP_SEGMENT  : "起始IP-终止IP" 或 "起始IP,终止IP" 或 CIDR("192.168.1.0/24")
  - SINGLE_IP   : 单 IP
  - IP_PORT     : "ip:port" — 直接落到 probe_endpoint(此阶段也插入 probe_host)
"""

from __future__ import annotations

import ipaddress
import logging
from typing import List, Set, Tuple

from ..adapters import bootstrap_test_path

bootstrap_test_path()
from ip_ping_check import expand_range  # noqa: E402  vendor/

from ..repo import endpoint_repo, host_repo, task_repo

log = logging.getLogger(__name__)

# 单段最大展开数。超过则只保留首尾两个端点(同 ip_ping_check 的默认)
MAX_EXPAND = 4096


def _parse_segment(value: str) -> List[str]:
    """把一个 resource_value 解析为 IP 列表。"""
    v = (value or "").strip()
    if not v:
        return []

    # CIDR
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            log.warning("invalid CIDR: %s", v)
            return []
        ips = [str(ip) for ip in net.hosts()]
        if len(ips) > MAX_EXPAND:
            log.warning("CIDR %s expands to %d > %d, keep first/last only", v, len(ips), MAX_EXPAND)
            return [str(net.network_address), str(net.broadcast_address)]
        return ips

    # 起止 IP
    for sep in ("-", ","):
        if sep in v:
            start, _, end = v.partition(sep)
            try:
                ips, truncated = expand_range(start.strip(), end.strip(), MAX_EXPAND)
            except ValueError as exc:
                log.warning("invalid IP range %r: %s", v, exc)
                return []
            if truncated:
                log.warning("range %s truncated, kept first/last", v)
            return ips

    # 单 IP
    try:
        ipaddress.ip_address(v)
        return [v]
    except ValueError:
        log.warning("invalid IP value: %s", v)
        return []


def _parse_ip_port(value: str) -> Tuple[str, int]:
    v = (value or "").strip()
    # 兼容 "[ipv6]:port"
    if v.startswith("["):
        host, _, rest = v[1:].partition("]")
        port = rest.lstrip(":").strip()
    else:
        host, _, port = v.rpartition(":")
    return host.strip(), int(port)


def expand_resources(task_id: int) -> Tuple[int, int]:
    """把 probe_pending_resource 展开成 probe_host(以及 IP_PORT 类型直接喂 probe_endpoint)。

    返回 ``(host_total, endpoint_seed_total)``。
    """
    resources = task_repo.list_pending_resources(task_id)
    if not resources:
        log.warning("task %s has no pending resources", task_id)
        return 0, 0

    ip_set: Set[str] = set()
    ip_ports: List[Tuple[str, int]] = []

    for res in resources:
        rtype = (res["resource_type"] or "").strip()
        rval = res["resource_value"] or ""

        if rtype == "SINGLE_IP":
            for ip in _parse_segment(rval):
                ip_set.add(ip)
        elif rtype == "IP_SEGMENT":
            for ip in _parse_segment(rval):
                ip_set.add(ip)
        elif rtype == "IP_PORT":
            try:
                ip, port = _parse_ip_port(rval)
            except (ValueError, IndexError):
                log.warning("invalid IP_PORT: %s", rval)
                continue
            ip_set.add(ip)
            ip_ports.append((ip, port))
        else:
            log.warning("unknown resource_type=%s value=%s", rtype, rval)

    if not ip_set:
        return 0, 0

    host_count = host_repo.bulk_insert_hosts(task_id, sorted(ip_set))
    log.info("task %s stage1: %d IPs -> probe_host (total=%d)", task_id, len(ip_set), host_count)

    endpoint_seed = 0
    if ip_ports:
        endpoint_seed = endpoint_repo.bulk_insert_endpoints(task_id, ip_ports)
        log.info("task %s stage1: seeded %d endpoints from IP_PORT resources", task_id, endpoint_seed)

    return host_count, endpoint_seed
