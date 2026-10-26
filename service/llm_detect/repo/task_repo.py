"""probe_task 与启动期 RUNNING 行重置。"""

from __future__ import annotations

import logging
from typing import List, Optional

from ..db import Database

log = logging.getLogger(__name__)


class LeaseLostError(RuntimeError):
    """Raised when a worker no longer owns a task lease."""


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
                end_time=NULL,
                worker_id=%s,
                heartbeat_time=NOW(),
                update_date=NOW()
            WHERE id=%s AND status='PENDING'
            """,
            (worker_id, task_id),
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
    worker_id: str,
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
    params.extend((task_id, worker_id))
    changed = Database.get().execute(
        f"""
        UPDATE probe_task SET {', '.join(fields)}
        WHERE id=%s AND status='RUNNING' AND worker_id=%s
        """,
        params,
    )
    if changed == 0:
        require_lease(task_id, worker_id)


def finalize(task_id: int, status: str, worker_id: str) -> None:
    """把任务收尾:status ∈ {SUCCESS, PARTIAL, FAILED, STOPPED}。"""
    changed = Database.get().execute(
        """
        UPDATE probe_task
        SET status=%s, end_time=NOW(), heartbeat_time=NOW(), update_date=NOW()
        WHERE id=%s AND status='RUNNING' AND worker_id=%s
        """,
        (status, task_id, worker_id),
    )
    if changed == 0:
        raise LeaseLostError("task %s lease lost by worker %s" % (task_id, worker_id))


def renew_lease(task_id: int, worker_id: str) -> bool:
    changed = Database.get().execute(
        """
        UPDATE probe_task
        SET heartbeat_time=NOW(), update_date=NOW()
        WHERE id=%s AND status='RUNNING' AND worker_id=%s
        """,
        (task_id, worker_id),
    )
    if changed == 1:
        return True
    try:
        require_lease(task_id, worker_id)
    except LeaseLostError:
        return False
    return True


def require_lease(task_id: int, worker_id: str) -> None:
    row = Database.get().fetchone(
        """
        SELECT id
        FROM probe_task
        WHERE id=%s AND status='RUNNING' AND worker_id=%s
        """,
        (task_id, worker_id),
    )
    if row is None:
        raise LeaseLostError("task %s lease lost by worker %s" % (task_id, worker_id))


def reset_expired_running_tasks(lease_timeout_sec: int) -> int:
    """Return only expired RUNNING tasks to PENDING."""
    return Database.get().execute(
        """
        UPDATE probe_task
        SET status='PENDING',
            worker_id=NULL,
            heartbeat_time=NULL,
            update_date=NOW()
        WHERE status='RUNNING'
          AND (
              heartbeat_time IS NULL
              OR heartbeat_time < DATE_SUB(NOW(), INTERVAL %s SECOND)
          )
        """,
        (lease_timeout_sec,),
    )
