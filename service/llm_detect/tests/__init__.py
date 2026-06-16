"""smoke test:不依赖 mysql / aiohttp / nmap,只做 AST + 纯函数验证。

运行::

    python -m llm_detect.tests.smoke

需要的库:仅标准库 + pyyaml(可选,加载 scan_config 时才用)。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

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


def main() -> int:
    test_syntax_all_files()
    test_pure_functions()
    test_stage1_parse_segment()
    print("\nALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
