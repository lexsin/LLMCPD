from __future__ import annotations

from contextlib import contextmanager

from .common import ContractError
from .contract import CONTRACT
from .indexes import UNIQUE_INDEXES


class MySQL:
    """Explicit transactions; construction never creates or migrates a database."""
    def __init__(self, options):
        from mysql.connector.pooling import MySQLConnectionPool
        allowed = {"host", "port", "user", "password", "database", "charset", "pool_size", "ssl_ca", "ssl_cert", "ssl_key"}
        if set(options) - allowed:
            raise ContractError("DATABASE_CONFIG", "unsupported database options")
        self.schema = options.get("database")
        if not self.schema:
            raise ContractError("DATABASE_CONFIG", "database name is required")
        self.pool = MySQLConnectionPool(pool_name="v7_service21", autocommit=False,
                                       time_zone="+00:00", connection_timeout=5, **options)

    @contextmanager
    def cursor(self):
        connection = self.pool.get_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)
        try:
            yield cursor
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            cursor.close()
            connection.close()

    def now(self, cur):
        cur.execute("SELECT UTC_TIMESTAMP(6) AS now")
        return cur.fetchone()["now"]

    def validate_schema(self):
        required = [t for t in CONTRACT if t.startswith("probe_") and t != "probe_asset_review"]
        with self.cursor() as cur:
            for table in required:
                cur.execute("SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s", (self.schema, table))
                actual = {r["name"] for r in cur.fetchall()}
                missing = set(CONTRACT[table]) - actual
                if missing:
                    raise ContractError("SCHEMA_MISMATCH", f"{table}: missing columns {sorted(missing)}; apply reviewed migrations outside this service")
                cur.execute("SELECT INDEX_NAME AS name,COLUMN_NAME AS col,SEQ_IN_INDEX AS seq FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND NON_UNIQUE=0 ORDER BY INDEX_NAME,SEQ_IN_INDEX", (self.schema, table))
                indexes = {}
                for row in cur.fetchall():
                    indexes.setdefault(row["name"], []).append(row["col"])
                for name, columns in UNIQUE_INDEXES.get(table, {}).items():
                    if columns not in indexes.values():
                        raise ContractError("SCHEMA_MISMATCH", f"required unique key absent: {table}.{name}{columns}")
                for cols in indexes.values():
                    if table in {"probe_host", "probe_endpoint", "probe_asset_port"} and "host_ip" in cols and not {"run_id", "source_group_id"}.issubset(cols):
                        raise ContractError("SCHEMA_MISMATCH", f"legacy cross-run unique key on {table}: {cols}")
            cur.execute("SELECT COLUMN_NAME AS name,IS_NULLABLE AS nullable FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='probe_task_run'", (self.schema,))
            nullability = {r["name"]:r["nullable"] for r in cur.fetchall()}
            if any(nullability.get(n) != "YES" for n in ("rule_snapshot_json","rule_hash","scanner_version","workspace_relative_path")):
                raise ContractError("SCHEMA_MISMATCH", "2.1 downlink fields must permit NULL")
