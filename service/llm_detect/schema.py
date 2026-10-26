"""Small, idempotent schema upgrades required by the service runtime."""

from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger(__name__)

_MIGRATION_LOCK = "llm_detect_probe_task_lease_schema"


def ensure_probe_task_lease_schema(db: Optional[object] = None) -> None:
    """Add task lease columns/index when upgrading an existing database."""
    if db is None:
        from .db import Database

        db = Database.get()

    with db.cursor() as cur:  # type: ignore[attr-defined]
        cur.execute("SELECT GET_LOCK(%s, %s) AS acquired", (_MIGRATION_LOCK, 30))
        row = cur.fetchone()
        if not row or int(row["acquired"] or 0) != 1:
            raise RuntimeError("cannot acquire probe_task lease schema migration lock")

        try:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.tables
                WHERE table_schema=DATABASE() AND table_name='probe_task'
                """
            )
            table_row = cur.fetchone()
            if not table_row or int(table_row["cnt"] or 0) == 0:
                raise RuntimeError(
                    "required table probe_task does not exist; initialize the business schema first"
                )

            cur.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema=DATABASE() AND table_name='probe_task'
                """
            )
            columns = {str(r["column_name"]).lower() for r in cur.fetchall()}

            if "worker_id" not in columns:
                log.info("schema migration: adding probe_task.worker_id")
                cur.execute(
                    """
                    ALTER TABLE probe_task
                    ADD COLUMN worker_id VARCHAR(128) NULL COMMENT '任务租约所属实例'
                    """
                )
            if "heartbeat_time" not in columns:
                log.info("schema migration: adding probe_task.heartbeat_time")
                cur.execute(
                    """
                    ALTER TABLE probe_task
                    ADD COLUMN heartbeat_time DATETIME NULL COMMENT '任务租约心跳时间'
                    """
                )

            cur.execute(
                """
                SELECT DISTINCT index_name
                FROM information_schema.statistics
                WHERE table_schema=DATABASE() AND table_name='probe_task'
                """
            )
            indexes = {str(r["index_name"]).lower() for r in cur.fetchall()}
            if "idx_status_heartbeat" not in indexes:
                log.info("schema migration: adding probe_task.idx_status_heartbeat")
                cur.execute(
                    """
                    ALTER TABLE probe_task
                    ADD KEY idx_status_heartbeat (status, heartbeat_time)
                    """
                )
        finally:
            cur.execute("SELECT RELEASE_LOCK(%s) AS released", (_MIGRATION_LOCK,))
