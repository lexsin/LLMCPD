"""Stage 3 — 把 probe_host.open_ports_json 展开为 probe_endpoint 行。

JSON 形态(由 stage2 写入)::

    [{"port": 443, "proto": "tcp"}, {"port": 8080, "proto": "tcp"}]
"""

from __future__ import annotations

import json
import logging
from typing import List, Tuple

from ..repo import endpoint_repo, host_repo

log = logging.getLogger(__name__)


def _extract_ports(open_ports_json: str) -> List[int]:
    if not open_ports_json:
        return []
    try:
        data = json.loads(open_ports_json)
    except json.JSONDecodeError:
        log.warning("malformed open_ports_json: %s", open_ports_json[:200])
        return []
    ports: List[int] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "port" in item:
                try:
                    ports.append(int(item["port"]))
                except (TypeError, ValueError):
                    continue
            elif isinstance(item, (int, str)):
                try:
                    ports.append(int(item))
                except ValueError:
                    continue
    return sorted(set(ports))


def expand_endpoints(task_id: int) -> int:
    """把 PROBING 状态的主机展开为 endpoint。返回端点总数(含已存在)。"""
    rows = host_repo.list_hosts_for_endpoint_expansion(task_id)
    if not rows:
        log.info("task %s stage3: no hosts in PROBING phase", task_id)
        # 仍要返回当前 endpoint 总数(可能 stage1 由 IP_PORT 直接喂入过)
        from ..db import Database
        cnt_row = Database.get().fetchone(
            "SELECT COUNT(*) AS cnt FROM probe_endpoint WHERE task_id=%s",
            (task_id,),
        )
        return int(cnt_row["cnt"]) if cnt_row else 0

    pairs: List[Tuple[str, int]] = []
    for r in rows:
        for port in _extract_ports(r["open_ports_json"]):
            pairs.append((r["host_ip"], port))

    if not pairs:
        log.info("task %s stage3: 0 ports across %d hosts", task_id, len(rows))
        return 0

    total = endpoint_repo.bulk_insert_endpoints(task_id, pairs)
    log.info("task %s stage3: %d endpoints (from %d hosts)", task_id, total, len(rows))
    return total
