"""AST regression for unchanged classifiers; does not import/execute upstream scripts."""
import ast

from llm_detect.v21.config import DEFAULT_RELEASE, SERVICE_ROOT


def test_formal_algorithm_bodies_are_preserved():
    origin=SERVICE_ROOT.parent/"TEST/strategy_v7_active_gpu_20260916"
    packaged=SERVICE_ROOT/"vendor/v7"/DEFAULT_RELEASE
    allowed={"scan_llm.py":{"run_pipeline","run_gpu_rescan"},"ip_port_scan.py":{"main","run_nmap_scan"},
             "scan_ports_by_source_type.py":{"run_scanner"},"gpu_low_recheck.py":{"run_low_recheck"},
             "full_port_recheck.py":{"main","scan_one"},"active_gpu_recheck.py":{"main","run_target"},
             "screenshot_evidence.py":{"capture_csv_evidence"}}
    for path in packaged.glob("*.py"):
        if not (origin/path.name).exists():continue
        before=ast.parse((origin/path.name).read_text(encoding="utf-8"))
        after=ast.parse(path.read_text(encoding="utf-8"))
        before={n.name:ast.dump(n,include_attributes=False) for n in before.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
        after={n.name:ast.dump(n,include_attributes=False) for n in after.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
        for name,body in before.items():
            if name not in allowed.get(path.name,set()):
                assert after[name]==body,f"unexpected algorithm change: {path.name}:{name}"
