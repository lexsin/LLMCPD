"""Preparation must match V7's browser-optional HTTP evidence workflow."""
import sys
from pathlib import Path

import pytest

from llm_detect.v21.config import DEFAULT_RELEASE, SERVICE_ROOT
from llm_detect.v21 import preflight


def test_preflight_accepts_browserless_http_cards_and_requires_font(monkeypatch):
    release = SERVICE_ROOT / "vendor/v7" / DEFAULT_RELEASE
    monkeypatch.syspath_prepend(str(release))
    monkeypatch.delenv("LLM_SERVICE_HEARTBEAT_FILE", raising=False)
    import screenshot_evidence
    calls = []
    def no_browser(required=True):
        calls.append(required)
        if required:
            raise FileNotFoundError("browser unavailable")
        return None
    monkeypatch.setattr(screenshot_evidence, "detect_chrome", no_browser)
    monkeypatch.setattr(screenshot_evidence, "detect_font", lambda: Path("fixture-font"))
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/fixture/nmap")
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(sys, "argv", ["preflight", str(release), str(release / "llm_scan_rules.yaml")])
    assert preflight.main() == 0
    assert calls == [False]
    def missing_font():
        raise FileNotFoundError("Chinese font unavailable")
    monkeypatch.setattr(screenshot_evidence, "detect_font", missing_font)
    with pytest.raises(FileNotFoundError, match="Chinese font"):
        preflight.main()
