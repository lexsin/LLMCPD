"""probe_endpoint 维护。"""

from __future__ import annotations

import logging
from typing import Iterable, List, Tuple

from ..db import Database

log = logging.getLogger(__name__)


def bulk_insert_endpoints(task_id: int, ip_ports: Iterable[Tuple[str, int]]) -> int:
    """阶段 2 写入端点;(task_id, host_ip, port) 唯一,重复忽略。"""
    rows = [(task_id, ip, int(port)) for ip, port in ip_ports]
    if not rows:
        return 0
    Database.get().executemany(
        """
        INSERT INTO probe_endpoint (task_id, host_ip, port, probe_shape, endpoint_status, insert_time)
        VALUES (%s, %s, %s, 'UNKNOWN', 'PENDING', NOW())
        ON DUPLICATE KEY UPDATE
            endpoint_status = IF(endpoint_status='SUCCESS', 'SUCCESS', 'PENDING')
        """,
        rows,
    )
    row = Database.get().fetchone(
        "SELECT COUNT(*) AS cnt FROM probe_endpoint WHERE task_id=%s",
        (task_id,),
    )
    return int(row["cnt"]) if row else 0


def list_pending_endpoints(task_id: int) -> List[dict]:
    return Database.get().fetchall(
        """
        SELECT id, host_ip, port
        FROM probe_endpoint
        WHERE task_id=%s AND endpoint_status IN ('PENDING','RUNNING')
        ORDER BY id
        """,
        (task_id,),
    )


def mark_endpoint_running(task_id: int, host_ip: str, port: int) -> None:
    Database.get().execute(
        """
        UPDATE probe_endpoint
        SET endpoint_status='RUNNING',
            probe_start_time=COALESCE(probe_start_time, NOW())
        WHERE task_id=%s AND host_ip=%s AND port=%s
          AND endpoint_status IN ('PENDING','RUNNING')
        """,
        (task_id, host_ip, port),
    )


def finish_endpoint(
    task_id: int,
    host_ip: str,
    port: int,
    *,
    probe_shape: str,
    success: bool,
) -> None:
    new_status = "SUCCESS" if success else "FAILED"
    Database.get().execute(
        """
        UPDATE probe_endpoint
        SET endpoint_status=%s,
            probe_shape=%s,
            probe_end_time=NOW()
        WHERE task_id=%s AND host_ip=%s AND port=%s
        """,
        (new_status, probe_shape, task_id, host_ip, port),
    )


def reset_orphaned_running_endpoints(task_id: int) -> int:
    return Database.get().execute(
        """
        UPDATE probe_endpoint
        SET endpoint_status='PENDING', probe_start_time=NULL
        WHERE task_id=%s AND endpoint_status='RUNNING'
        """,
        (task_id,),
    )


def count_endpoints_finished(task_id: int) -> int:
    row = Database.get().fetchone(
        """
        SELECT COUNT(*) AS cnt FROM probe_endpoint
        WHERE task_id=%s AND endpoint_status IN ('SUCCESS','FAILED')
        """,
        (task_id,),
    )
    return int(row["cnt"]) if row else 0
