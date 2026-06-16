"""MySQL 连接池与轻量游标包装。

使用 mysql-connector-python 的 MySQLConnectionPool —— 纯 Python 驱动,Windows 友好。
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any, Iterable, List, Optional, Sequence, Tuple

import mysql.connector
from mysql.connector import pooling

from .settings import DatabaseConfig

log = logging.getLogger(__name__)


class Database:
    """单例式连接池 wrapper。所有 repo 通过 ``Database.cursor()`` 拿连接。"""

    _instance: Optional["Database"] = None
    _lock = threading.Lock()

    def __init__(self, cfg: DatabaseConfig) -> None:
        self.cfg = cfg
        self.pool = pooling.MySQLConnectionPool(
            pool_name="llm_detect",
            pool_size=cfg.pool_size,
            host=cfg.host,
            port=cfg.port,
            user=cfg.user,
            password=cfg.password,
            database=cfg.database,
            charset=cfg.charset,
            autocommit=False,
            time_zone="+00:00",
        )
        log.info("DB pool ready: %s@%s:%s/%s pool_size=%d",
                 cfg.user, cfg.host, cfg.port, cfg.database, cfg.pool_size)

    @classmethod
    def init(cls, cfg: DatabaseConfig) -> "Database":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(cfg)
        return cls._instance

    @classmethod
    def get(cls) -> "Database":
        if cls._instance is None:
            raise RuntimeError("Database not initialized; call Database.init() first")
        return cls._instance

    @contextmanager
    def cursor(self, dictionary: bool = True):
        """从池里借一个连接,yield cursor。退出时按异常情况 commit/rollback。"""
        conn = self.pool.get_connection()
        cur = conn.cursor(dictionary=dictionary)
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    # ---- 便捷方法 -----------------------------------------------------

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> List[dict]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Optional[dict]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return row

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """执行 INSERT/UPDATE/DELETE,返回 rowcount。"""
        with self.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount

    def executemany(self, sql: str, seq_params: Iterable[Sequence[Any]]) -> int:
        with self.cursor() as cur:
            cur.executemany(sql, list(seq_params))
            return cur.rowcount

    def execute_returning_id(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return int(cur.lastrowid or 0)
