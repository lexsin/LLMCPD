"""probe_host 维护:批量插入、阶段推进、断点查询。"""

from __future__ import annotations

import logging
from typing import Iterable, List, Optional

from ..db import Database

log = logging.getLogger(__name__)


def bulk_insert_hosts(task_id: int, ips: Iterable[str]) -> int:
    """把 stage1 展开出的 IP 写入 probe_host;遇重复 (task_id, host_ip) 跳过。

    返回新增行数(估算:executemany 的 rowcount 对 IGNORE 不可靠,改用 INSERT ... ON DUPLICATE KEY)。
    """
    rows = [(task_id, ip) for ip in ips]
    if not rows:
        return 0
    Database.get().executemany(
        """
        INSERT INTO probe_host (task_id, host_ip, host_phase, insert_time)
        VALUES (%s, %s, 'PENDING_SCAN', NOW())
        ON DUPLICATE KEY UPDATE
            host_phase = IF(host_phase IN ('SCANNING','PENDING_SCAN'),
                            host_phase, host_phase)
        """,
        rows,
    )
    # 用 SELECT 拿真实计数
    row = Database.get().fetchone(
        "SELECT COUNT(*) AS cnt FROM probe_host WHERE task_id=%s",
        (task_id,),
    )
    return int(row["cnt"]) if row else 0


def list_hosts_to_scan(task_id: int) -> List[dict]:
    """阶段 1 输入:还没扫端口的主机。"""
    return Database.get().fetchall(
        """
        SELECT id, host_ip
        FROM probe_host
        WHERE task_id=%s AND host_phase IN ('PENDING_SCAN','SCANNING')
        ORDER BY id
        """,
        (task_id,),
    )


def list_hosts_for_endpoint_expansion(task_id: int) -> List[dict]:
    """阶段 2 输入:已经扫完端口、待展开端点的主机。"""
    return Database.get().fetchall(
        """
        SELECT id, host_ip, open_ports_json
        FROM probe_host
        WHERE task_id=%s AND host_phase='PROBING'
        ORDER BY id
        """,
        (task_id,),
    )


def mark_host_scanning(task_id: int, host_ip: str) -> None:
    Database.get().execute(
        """
        UPDATE probe_host
        SET host_phase='SCANNING', scan_start_time=COALESCE(scan_start_time, NOW())
        WHERE task_id=%s AND host_ip=%s AND host_phase IN ('PENDING_SCAN','SCANNING')
        """,
        (task_id, host_ip),
    )


def finish_host_scan(
    task_id: int,
    host_ip: str,
    open_ports_json: Optional[str],
    has_ports: bool,
    probe_info: Optional[str] = None,
) -> None:
    """阶段 1 落盘。无端口直接到 VERDICT_DONE,有端口推进到 PROBING。"""
    new_phase = "PROBING" if has_ports else "VERDICT_DONE"
    Database.get().execute(
        """
        UPDATE probe_host
        SET host_phase=%s,
            open_ports_json=%s,
            scan_end_time=NOW(),
            probe_info=%s
        WHERE task_id=%s AND host_ip=%s
        """,
        (new_phase, open_ports_json, probe_info, task_id, host_ip),
    )


def mark_host_verdict_done(task_id: int, host_ip: str) -> None:
    """阶段 4 完成时把 host_phase 推到 VERDICT_DONE。"""
    Database.get().execute(
        """
        UPDATE probe_host
        SET host_phase='VERDICT_DONE'
        WHERE task_id=%s AND host_ip=%s
        """,
        (task_id, host_ip),
    )


def reset_orphaned_scanning_hosts(task_id: int) -> int:
    """启动时把 SCANNING 行回退到 PENDING_SCAN。"""
    return Database.get().execute(
        """
        UPDATE probe_host
        SET host_phase='PENDING_SCAN', scan_start_time=NULL
        WHERE task_id=%s AND host_phase='SCANNING'
        """,
        (task_id,),
    )


def count_hosts_finished(task_id: int) -> int:
    row = Database.get().fetchone(
        """
        SELECT COUNT(*) AS cnt FROM probe_host
        WHERE task_id=%s AND host_phase IN ('PROBING','VERDICT_DONE')
        """,
        (task_id,),
    )
    return int(row["cnt"]) if row else 0
