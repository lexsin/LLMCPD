#!/usr/bin/env python3
"""Rewrite release.json for a fixed V7 release before any run references it.

A release that a run has already frozen must never be rewritten; create a new
releaseId instead.
"""
import argparse
import hashlib
import json
from pathlib import Path

SERVICE_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_EXTRA = ("llm_detect/v21/defaults.json", "llm_detect/main.py", "llm_detect/__init__.py", "requirements.txt")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("release_id")
    args = parser.parse_args()
    release = SERVICE_ROOT / "vendor" / "v7" / args.release_id
    path = release / "release.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest["release_id"] != args.release_id:
        raise SystemExit("release_id differs from directory name")
    manifest["files"] = {p.name: sha(p) for p in sorted(release.iterdir()) if p.is_file() and p.suffix in {".py", ".yaml"}}
    adapters = sorted((SERVICE_ROOT / "llm_detect" / "v21").glob("*.py")) + [SERVICE_ROOT / name for name in ADAPTER_EXTRA]
    manifest["adapter_files"] = {p.relative_to(SERVICE_ROOT).as_posix(): sha(p) for p in sorted(adapters)}
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"files": len(manifest["files"]), "adapter_files": len(manifest["adapter_files"])}))


if __name__ == "__main__":
    main()
