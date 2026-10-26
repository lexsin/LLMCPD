from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from llm_detect.v21.common import atomic_json, dumps, file_hash
from llm_detect.v21.contract import CONTRACT
from llm_detect.v21.indexes import UNIQUE_INDEXES
from llm_detect.v21.repository import Repository, insert

sqlite3.register_adapter(datetime, lambda dt: dt.isoformat(" "))
sqlite3.register_converter("TIMESTAMP", lambda raw: datetime.fromisoformat(raw.decode()))


class Cursor:
    def __init__(self, cursor):
        self.cur = cursor

    def execute(self, sql, params=()):
        sql = re.sub(r"\s+FOR UPDATE(?: SKIP LOCKED)?", "", sql)
        self.cur.execute(sql.replace("%s", "?"), params)
        return self

    def fetchone(self):
        row = self.cur.fetchone()
        return dict(row) if row else None

    def fetchall(self):
        return [dict(r) for r in self.cur.fetchall()]

    @property
    def lastrowid(self):
        return self.cur.lastrowid


def fixture_ddl(mysql=False):
    """Test-only DDL generated from the documented contract, never imported by the service."""
    statements = []
    for name, fields in CONTRACT.items():
        columns = []
        for column, spec in fields.items():
            if column == "id":
                columns.append("id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY" if mysql else "id INTEGER PRIMARY KEY AUTOINCREMENT")
                continue
            kind = spec["type"] if mysql else "TIMESTAMP" if spec["type"].startswith("DATETIME") else "INTEGER" if any(t in spec["type"] for t in ("INT", "DECIMAL")) else "TEXT"
            col = f"`{column}` {kind}" + (" NOT NULL" if spec["required"] else "")
            default = spec.get("default")
            if default is not None and not spec["type"].endswith("TEXT"):
                col += " DEFAULT " + (default if re.fullmatch(r"\d+(?:\.\d+)?", default) else "'" + default.replace("'", "''") + "'")
            columns.append(col)
        engine = " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4" if mysql else ""
        statements.append(f"CREATE TABLE `{name}` ({','.join(columns)}){engine}")
    for table, indexes in UNIQUE_INDEXES.items():
        for name, columns in indexes.items():
            statements.append(f"CREATE UNIQUE INDEX {name} ON {table} ({','.join(columns)})")
    return statements


class SQLiteFixture:
    """Exercises real transactions/constraints; does not claim to test MySQL row locks."""
    def __init__(self):
        self.connection = sqlite3.connect(":memory:", check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        for statement in fixture_ddl():
            self.connection.execute(statement)

    @contextmanager
    def cursor(self):
        with self.lock:
            self.connection.execute("BEGIN")
            try:
                yield Cursor(self.connection.cursor())
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    def now(self, cur):
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def rows(self, table):
        with self.cursor() as cur:
            return cur.execute(f"SELECT * FROM {table}").fetchall()


def seed(db, root, file_count=1):
    defaults = json.loads((__import__("pathlib").Path(__file__).parents[1] / "llm_detect/v21/defaults.json").read_text())
    with db.cursor() as cur:
        now = db.now(cur)
        task = insert(cur, "probe_task", {"task_name": "isolated fixture", "param_json": "{}", "create_date": now})
        entries = []
        for order in range(1, file_count + 1):
            original = root / f"input-{order}.xlsx"
            original.write_bytes(b"fixture-only-no-scanning")
            fid = insert(cur, "probe_task_file", {"task_id": task, "original_name": original.name,
                "relative_path": original.name, "parse_status": "READY", "create_date": now, "row_total": 2, "valid_row_count": 2})
            rows = []
            for start, end, unit in [("192.0.2.1", "192.0.2.2", "unit-a"), ("192.0.2.2", "192.0.2.2", "unit-b")]:
                resource = {"task_id": task, "file_id": fid, "start_ip": start, "end_ip": end, "unit_name": unit,
                            "source_unit": "江苏电信", "province_name": "江苏省", "operator_name": "电信", "validation_status": "VALID", "create_date": now}
                rid = insert(cur, "probe_pending_resource", resource)
                rows.append({"resource_id": rid, **{k:resource[k] for k in ("start_ip","end_ip","unit_name","source_unit","province_name","operator_name")},
                             "resource_type": "SINGLE_IP" if start==end else "IP_SEGMENT", "enterprise_name": "江苏电信"})
            parsed = root / f"parsed-{order}.json"
            atomic_json(parsed, {"schema_version": 1, "rows": rows})
            checksum = file_hash(parsed)
            cur.execute("UPDATE probe_task_file SET parsed_relative_path=%s,parsed_hash=%s WHERE id=%s", (parsed.name, checksum, fid))
            entries.append({"file_id": str(fid), "source_order": order, "original_name": original.name, "parsed_hash": checksum, "valid_row_count":2,"invalid_row_count":0})
        rid = insert(cur, "probe_task_run", {"task_id": task, "run_no": 1, "trigger_type": "MANUAL",
            "input_snapshot_json": dumps({"schema_version":1,"allow_invalid_rows":False,"files":entries}),
            "param_snapshot_json": dumps(defaults), "create_date": now})
    return Repository(db), task, rid
