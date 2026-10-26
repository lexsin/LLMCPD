"""smoke test:不依赖 mysql / aiohttp / nmap,只做 AST + 纯函数验证。

运行::

    python -m llm_detect.tests.smoke

需要的库:仅标准库 + pyyaml(可选,加载 scan_config 时才用)。
"""

from __future__ import annotations

import ast
import datetime
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

HERE = Path(__file__).resolve()
PKG_ROOT = HERE.parents[1]                # service/llm_detect/
PROJECT_ROOT = HERE.parents[2]            # service/
sys.path.insert(0, str(PROJECT_ROOT))


def test_syntax_all_files() -> None:
    """所有 .py 必须 AST 可解析。"""
    bad = []
    for p in PKG_ROOT.rglob("*.py"):
        try:
            ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError as e:
            bad.append((p, e))
    assert not bad, f"syntax errors: {bad}"
    print("AST OK for all py files in", PKG_ROOT.name)


def test_pure_functions() -> None:
    """只测不依赖 DB 的纯函数:动态加载源码、注入到独立 module 里。"""
    # 把 stage3 的纯函数源码挑出来执行,绕开顶层 from ..repo import ...
    src = (PKG_ROOT / "stages" / "stage3_endpoint.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    # 找到 _extract_ports 函数定义,单独执行
    fn_node = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_extract_ports"),
        None,
    )
    assert fn_node is not None, "_extract_ports not found"

    ns: dict = {"json": __import__("json"), "List": list, "logging": __import__("logging"),
                "log": __import__("logging").getLogger("smoke")}
    # 单独编译这个函数定义
    mod = ast.Module(body=[fn_node], type_ignores=[])
    code = compile(mod, str(PKG_ROOT / "stages" / "stage3_endpoint.py"), "exec")
    exec(code, ns)
    extract = ns["_extract_ports"]

    assert extract('[{"port":443,"proto":"tcp"}]') == [443], "json shape"
    assert extract('[80, 443]') == [80, 443], "plain int list"
    assert extract("") == [], "empty"
    assert extract("not json") == [], "garbage"
    print("stage3 _extract_ports OK")


def test_stage1_parse_segment() -> None:
    """stage1 解析也是纯逻辑(只用 ipaddress + vendor/ip_ping_check)。"""
    src = (PKG_ROOT / "stages" / "stage1_expand.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    # 把 vendor/ 加入 path,以便 expand_range 可用
    vendor_dir = PROJECT_ROOT / "vendor"
    sys.path.insert(0, str(vendor_dir))
    from ip_ping_check import expand_range  # noqa: E402

    fn_seg = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_parse_segment")
    fn_ipp = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_parse_ip_port")

    ns = {
        "ipaddress": __import__("ipaddress"),
        "expand_range": expand_range,
        "List": list,
        "Tuple": tuple,
        "MAX_EXPAND": 4096,
        "log": __import__("logging").getLogger("smoke"),
    }
    code = compile(ast.Module(body=[fn_seg, fn_ipp], type_ignores=[]),
                   str(PKG_ROOT / "stages" / "stage1_expand.py"), "exec")
    exec(code, ns)

    assert ns["_parse_segment"]("192.168.1.1") == ["192.168.1.1"]
    rng = ns["_parse_segment"]("10.0.0.1-10.0.0.3")
    assert rng == ["10.0.0.1", "10.0.0.2", "10.0.0.3"], rng
    assert ns["_parse_segment"]("garbage") == []

    ip, port = ns["_parse_ip_port"]("1.2.3.4:8080")
    assert ip == "1.2.3.4" and port == 8080
    print("stage1 _parse_segment / _parse_ip_port OK")


class _SchemaCursor:
    def __init__(self, db) -> None:
        self.db = db
        self.result = None

    def execute(self, sql, params=()) -> None:
        normalized = " ".join(sql.split()).lower()
        if "get_lock" in normalized:
            self.result = {"acquired": 1 if self.db.lock_available else 0}
        elif "release_lock" in normalized:
            self.result = {"released": 1}
        elif "information_schema.tables" in normalized:
            self.result = {"cnt": 1 if self.db.table_exists else 0}
        elif "information_schema.columns" in normalized:
            self.result = [{"column_name": c} for c in sorted(self.db.columns)]
        elif "information_schema.statistics" in normalized:
            self.result = [{"index_name": i} for i in sorted(self.db.indexes)]
        elif "add column worker_id" in normalized:
            self.db.columns.add("worker_id")
            self.db.ddl.append("worker_id")
        elif "add column heartbeat_time" in normalized:
            self.db.columns.add("heartbeat_time")
            self.db.ddl.append("heartbeat_time")
        elif "add key idx_status_heartbeat" in normalized:
            self.db.indexes.add("idx_status_heartbeat")
            self.db.ddl.append("idx_status_heartbeat")
        else:
            raise AssertionError("unexpected schema SQL: %s" % normalized)

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class _SchemaDB:
    def __init__(self, columns=(), indexes=(), *, table_exists=True, lock_available=True):
        self.columns = set(columns)
        self.indexes = set(indexes)
        self.table_exists = table_exists
        self.lock_available = lock_available
        self.ddl = []

    @contextmanager
    def cursor(self):
        yield _SchemaCursor(self)


def test_schema_migration() -> None:
    from llm_detect.schema import ensure_probe_task_lease_schema

    db = _SchemaDB()
    ensure_probe_task_lease_schema(db)
    assert db.ddl == ["worker_id", "heartbeat_time", "idx_status_heartbeat"]
    ensure_probe_task_lease_schema(db)
    assert db.ddl == ["worker_id", "heartbeat_time", "idx_status_heartbeat"]

    one_missing = _SchemaDB(
        columns={"worker_id"},
        indexes={"idx_status_heartbeat"},
    )
    ensure_probe_task_lease_schema(one_missing)
    assert one_missing.ddl == ["heartbeat_time"]

    for bad_db, expected in (
        (_SchemaDB(table_exists=False), "does not exist"),
        (_SchemaDB(lock_available=False), "cannot acquire"),
    ):
        try:
            ensure_probe_task_lease_schema(bad_db)
        except RuntimeError as exc:
            assert expected in str(exc)
        else:
            raise AssertionError("schema migration should have failed")
    print("probe_task lease schema migration OK")


def _install_fake_mysql() -> None:
    if "mysql.connector" in sys.modules:
        return
    mysql_mod = types.ModuleType("mysql")
    connector_mod = types.ModuleType("mysql.connector")
    pooling_mod = types.ModuleType("mysql.connector.pooling")
    pooling_mod.MySQLConnectionPool = object
    connector_mod.pooling = pooling_mod
    mysql_mod.connector = connector_mod
    sys.modules["mysql"] = mysql_mod
    sys.modules["mysql.connector"] = connector_mod
    sys.modules["mysql.connector.pooling"] = pooling_mod


class _LeaseDB:
    def __init__(self) -> None:
        now = datetime.datetime.now()
        self.tasks = {
            1: {"status": "RUNNING", "worker_id": "active", "heartbeat": now},
            2: {
                "status": "RUNNING",
                "worker_id": "expired",
                "heartbeat": now - datetime.timedelta(seconds=120),
            },
            3: {"status": "RUNNING", "worker_id": "legacy", "heartbeat": None},
        }

    def fetchone(self, sql, params=()):
        task_id, worker_id = params
        task = self.tasks.get(task_id)
        if task and task["status"] == "RUNNING" and task["worker_id"] == worker_id:
            return {"id": task_id}
        return None

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if "set heartbeat_time=now()" in normalized:
            task_id, worker_id = params
            task = self.tasks.get(task_id)
            if task and task["status"] == "RUNNING" and task["worker_id"] == worker_id:
                task["heartbeat"] = datetime.datetime.now()
                return 1
            return 0
        if "set `host_total`=" in normalized:
            task_id, worker_id = params[-2:]
            task = self.tasks.get(task_id)
            return int(
                bool(task)
                and task["status"] == "RUNNING"
                and task["worker_id"] == worker_id
            )
        if "set status=%s" in normalized:
            status, task_id, worker_id = params
            task = self.tasks.get(task_id)
            if task and task["status"] == "RUNNING" and task["worker_id"] == worker_id:
                task["status"] = status
                return 1
            return 0
        if "set status='pending'" in normalized:
            timeout = int(params[0])
            cutoff = datetime.datetime.now() - datetime.timedelta(seconds=timeout)
            changed = 0
            for task in self.tasks.values():
                if task["status"] == "RUNNING" and (
                    task["heartbeat"] is None or task["heartbeat"] < cutoff
                ):
                    task.update(status="PENDING", worker_id=None, heartbeat=None)
                    changed += 1
            return changed
        raise AssertionError("unexpected lease SQL: %s" % normalized)


def test_task_lease() -> None:
    _install_fake_mysql()
    from llm_detect.repo import task_repo

    fake = _LeaseDB()
    original = task_repo.Database
    task_repo.Database = types.SimpleNamespace(
        get=lambda: fake,
    )
    try:
        assert task_repo.renew_lease(1, "active")
        assert not task_repo.renew_lease(1, "other")
        task_repo.require_lease(1, "active")
        try:
            task_repo.require_lease(1, "other")
        except task_repo.LeaseLostError:
            pass
        else:
            raise AssertionError("old worker should lose lease")

        assert task_repo.reset_expired_running_tasks(90) == 2
        assert fake.tasks[1]["status"] == "RUNNING"
        assert fake.tasks[2]["status"] == "PENDING"
        assert fake.tasks[3]["status"] == "PENDING"

        for operation in (
            lambda: task_repo.update_progress(1, "other", host_total=10),
            lambda: task_repo.finalize(1, "SUCCESS", "other"),
        ):
            try:
                operation()
            except task_repo.LeaseLostError:
                pass
            else:
                raise AssertionError("old worker write should be rejected")
        assert fake.tasks[1]["status"] == "RUNNING"
    finally:
        task_repo.Database = original
    print("task lease recovery / ownership OK")


def test_worker_identity() -> None:
    from llm_detect.orchestrator import Orchestrator
    from llm_detect.settings import Settings

    settings = Settings()
    settings.orchestrator.worker_id = "worker-" + ("x" * 200)
    first = Orchestrator(settings).worker_id
    second = Orchestrator(settings).worker_id
    assert len(first) <= 128
    assert first != second
    assert "@" in first
    print("unique bounded worker identity OK")


def test_nmap_vendor_adapter_signature() -> None:
    from llm_detect.adapters import nmap_runner

    calls = []
    original_which = nmap_runner.shutil.which
    original_run = nmap_runner._ips.run_nmap_scan
    original_verify = nmap_runner._ips.verify_anomalous_ports

    def fake_run(_ips, _list_path, _xml_path, **kwargs):
        ports = ";".join(str(p) for p in range(1, 82))
        kwargs["on_batch_done"](1, {"192.0.2.10": ports})
        return {"192.0.2.10": ports}

    def fake_verify(*args):
        calls.append(args)

    nmap_runner.shutil.which = lambda _name: "/usr/bin/nmap"
    nmap_runner._ips.run_nmap_scan = fake_run
    nmap_runner._ips.verify_anomalous_ports = fake_verify
    try:
        nmap_runner.scan_ports_for_ips(
            ["192.0.2.10"],
            anomaly_threshold=80,
            verify_workers=8,
            verify_host_timeout="15s",
            verify_max_retries="0",
            verify_proc_timeout=25,
        )
    finally:
        nmap_runner.shutil.which = original_which
        nmap_runner._ips.run_nmap_scan = original_run
        nmap_runner._ips.verify_anomalous_ports = original_verify

    assert len(calls) == 1
    assert calls[0][4:] == (8, "15s", "0", 25)
    print("nmap vendor verification parameters OK")


def test_scan_llm_auth_path_reflection() -> None:
    vendor_dir = PROJECT_ROOT / "vendor"
    sys.path.insert(0, str(vendor_dir))
    from scan_config import eval_match, get_default_config  # noqa: E402

    src_path = vendor_dir / "scan_llm.py"
    tree = ast.parse(src_path.read_text(encoding="utf-8"))
    function_names = {
        "_dedupe_keep_last", "_match_auth_suspect", "_phase1_check_confirmed"
    }
    functions = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in function_names
    ]
    assert {node.name for node in functions} == function_names

    ns = {
        "Dict": Dict,
        "List": List,
        "Optional": Optional,
        "quote": quote,
        "eval_match": eval_match,
        "ScanConfig": object,
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(src_path), "exec"), ns)

    dedupe_links = ns["_dedupe_keep_last"]
    assert dedupe_links(["root", "info", "info"]) == ["root", "info"]
    assert dedupe_links(["root", "info", "root"]) == ["info", "root"]
    assert dedupe_links(["", "root", ""]) == ["root"]

    match_auth = ns["_match_auth_suspect"]
    cfg = get_default_config()
    auth_cfg = cfg.phase1.auth_suspect
    path = "/openai/v1/models"

    assert match_auth(path, 403, '<script>window.location.href="/openai/v1/models";</script>', auth_cfg) is None
    assert match_auth(path, 403, "blocked: https://192.0.2.10:443/openai/v1/models", auth_cfg) is None
    assert match_auth(path, 403, "redirect=%2Fopenai%2Fv1%2Fmodels", auth_cfg) is None
    assert match_auth(path, 401, "OpenAI API key required", auth_cfg) == "openai"
    assert match_auth(path, 403, "<?xml version='1.0'?><Code>AccessDenied</Code> openai", auth_cfg) is None
    assert match_auth(path, 200, "OpenAI API key required", auth_cfg) is None

    confirmed = ns["_phase1_check_confirmed"](
        "/v1/models", 200, '{"object":"list","data":[]}', cfg
    )
    assert confirmed is not None
    print("scan_llm auth path reflection filtering OK")


def test_scan_llm_frontend_gpu_classification() -> None:
    """验证 vendor 的 GPU 证据分级与独立算力服务分类。"""
    vendor_dir = PROJECT_ROOT / "vendor"
    sys.path.insert(0, str(vendor_dir))
    import scan_llm as slm
    import scan_config as scfg

    cfg = scfg.get_default_config()

    frontend = slm.TargetState(
        ip="127.0.0.1", port="8000", protocol="http", is_llm="疑似",
        probes={"/": slm.ProbeResult(status=200, body="<title>Dify</title>")},
    )
    slm._apply_service_classification(frontend, cfg)
    assert frontend.service_type == "AI前端服务"
    assert frontend.gpu_likelihood == "低"

    gpu = slm.TargetState(
        ip="127.0.0.1", port="9400", protocol="http",
        probes={"/metrics": slm.ProbeResult(
            status=200,
            body='DCGM_FI_DEV_GPU_UTIL{UUID="GPU-x",modelName="RTX 5090"} 85',
        )},
    )
    slm._apply_service_classification(gpu, cfg)
    assert gpu.service_type == "GPU算力服务"
    assert gpu.gpu_likelihood == "高"
    print("scan_llm GPU classification OK")


def main() -> int:
    test_syntax_all_files()
    test_pure_functions()
    test_stage1_parse_segment()
    test_schema_migration()
    test_task_lease()
    test_worker_identity()
    test_nmap_vendor_adapter_signature()
    test_scan_llm_auth_path_reflection()
    test_scan_llm_frontend_gpu_classification()
    print("\nALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
