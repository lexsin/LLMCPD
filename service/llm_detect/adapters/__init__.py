"""Adapter 层:把 vendor/ 下脚本的核心函数包装为纯函数,从 CSV 解耦。

通过 :func:`bootstrap_test_path` 把工程根下的 ``vendor/`` 目录注入 sys.path,
然后 ``import scan_llm`` / ``import scan_config`` 等模块就能直接复用。

(历史名字 ``bootstrap_test_path`` 沿用,实际指向 ``vendor/``。)
"""

from __future__ import annotations

import sys
from pathlib import Path

_BOOTSTRAPPED = False


def bootstrap_test_path() -> Path:
    """把 ``<project>/vendor`` 目录加入 sys.path,返回该路径。重复调用幂等。

    目录布局::

        service/                     <- 工程根
        ├── vendor/                  <- 原 TEST/ 下被复用的 4 个 .py + yaml
        │   ├── ip_port_scan.py
        │   ├── scan_llm.py
        │   ├── scan_config.py
        │   ├── ip_ping_check.py
        │   └── llm_scan_rules.yaml
        └── llm_detect/          <- 当前 Python 包
            └── adapters/__init__.py <- 这个文件
                                       parents[2] = service/
    """
    global _BOOTSTRAPPED
    here = Path(__file__).resolve()
    project_root = here.parents[2]   # adapters → llm_detect → service/
    vendor_dir = project_root / "vendor"
    if vendor_dir.is_dir() and str(vendor_dir) not in sys.path:
        sys.path.insert(0, str(vendor_dir))
    _BOOTSTRAPPED = True
    return vendor_dir
