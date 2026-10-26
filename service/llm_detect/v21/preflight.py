"""Read-only environment/rule checks; never contacts a scan target or database."""
import os
import shutil
import sys
from pathlib import Path

from .processes import start_lease_guard


def main():
    start_lease_guard()
    release, rules = map(Path, sys.argv[1:3])
    sys.path.insert(0, str(release))
    import service_hooks
    import aiohttp
    import requests
    import pandas
    import openpyxl
    import PIL
    import scan_config
    import screenshot_evidence
    config = scan_config.load_config(rules)
    if not shutil.which("nmap") or not hasattr(os,"geteuid") or os.geteuid() != 0:
        raise RuntimeError("V7 SYN scanning requires Linux, root, and an installed nmap")
    # V7 capture-csv/fill already support HTTP response cards without a browser.
    screenshot_evidence.detect_chrome(required=False)
    screenshot_evidence.detect_font()
    if not config.runtime:
        raise RuntimeError("invalid rule runtime configuration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
