"""Use the same committed-row evidence filter for SOURCE and RUN exports."""
import csv
import json
from pathlib import Path

from .common import atomic_json, proof_hash


def prepare_manifest(root):
    root = Path(root).resolve()
    with (root / "committed.csv").open(encoding="utf-8-sig", newline="") as stream:
        keys = {f"{r.get('ip')}|{r.get('port')}|{r.get('protocol', '')}": proof_hash(r)
                for r in csv.DictReader(stream)}
    try:
        records = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        records = {}
    safe = {}
    if isinstance(records, dict):
        for key, record in records.items():
            if not isinstance(record, dict) or key not in keys or record.get("service_result_hash") != keys[key]:
                continue
            path = record.get("path")
            if not isinstance(path, str) or not path:
                continue
            try:
                image = Path(path).resolve()
                if image.is_relative_to(root) and image.is_file():
                    safe[key] = record
            except (OSError, ValueError):
                continue
    target = root / "report-manifest.json"
    atomic_json(target, safe)
    return target
