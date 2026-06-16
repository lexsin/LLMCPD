"""probe_task 与启动期 RUNNING 行重置。"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..db import Database

log = logging.getLogger(__name__)


def claim_pending_task(worker_id: str) -> Optional[dict]:
    """抢占一个 PENDING 的任务,设为 RUNNING 并返回。无则返回 None。

    用 ``UPDATE ... WHERE id=(SELECT ...) AND status='PENDING'`` 的两段式以避免
    MySQL "can't specify target table for update in FROM clause" 限制。
    """
    db = Database.get()
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM probe_task
            WHERE status='PENDING'
            ORDER BY id
            LIMIT 1
            FOR UPDATE
            """
        )
        row = cur.fetchone()
        if not row:
            return None
        task_id = row["id"]
        cur.execute(
            """
            UPDATE probe_task
            SET status='RUNNING',
                start_time=NOW(),
                updater=NULL,
                update_date=NOW()
            WHERE id=%s AND status='PENDING'
            """,
            (task_id,),
        )
        if cur.rowcount == 0:
            return None
        cur.execute("SELECT * FROM probe_task WHERE id=%s", (task_id,))
        return cur.fetchone()


def list_pending_resources(task_id: int) -> List[dict]:
    return Database.get().fetchall(
        "SELECT * FROM probe_pending_resource WHERE task_id=%s ORDER BY id",
        (task_id,),
    )


def update_progress(
    task_id: int,
    *,
    host_total: Optional[int] = None,
    host_finished: Optional[int] = None,
    endpoint_total: Optional[int] = None,
    endpoint_finished: Optional[int] = None,
) -> None:
    fields: list[str] = []
    params: list = []
    for col, val in (
        ("host_total", host_total),
        ("host_finished", host_finished),
        ("endpoint_total", endpoint_total),
        ("endpoint_finished", endpoint_finished),
    ):
        if val is not None:
            fields.append(f"`{col}`=%s")
            params.append(val)
    if not fields:
        return
    fields.append("update_date=NOW()")
    params.append(task_id)
    Database.get().execute(
        f"UPDATE probe_task SET {', '.join(fields)} WHERE id=%s",
        params,
    )


def finalize(task_id: int, status: str) -> None:
    """把任务收尾:status ∈ {SUCCESS, PARTIAL, FAILED, STOPPED}。"""
    Database.get().execute(
        """
        UPDATE probe_task
        SET status=%s, end_time=NOW(), update_date=NOW()
        WHERE id=%s
        """,
        (status, task_id),
    )


def reset_orphaned_running_tasks() -> int:
    """启动时把 RUNNING 状态的任务重置回 PENDING(上次进程异常退出)。"""
    return Database.get().execute(
        """
        UPDATE probe_task
        SET status='PENDING', update_date=NOW()
        WHERE status='RUNNING'
        """
    )
