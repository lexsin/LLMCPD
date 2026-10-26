from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .common import ContractError, beneath, decode, file_hash


def validate_params(value, concurrency):
    params = decode(value, "parameter snapshot")
    defaults = json.loads(Path(__file__).with_name("defaults.json").read_text(encoding="utf-8"))
    if not isinstance(params, dict) or params.get("schema_version") != 1 or set(params) != set(defaults):
        raise ContractError("PARAM_SCHEMA", "complete v1 parameter snapshot is required")
    for group, expected in defaults.items():
        if group == "schema_version":
            continue
        if not isinstance(params[group], dict) or set(params[group]) != set(expected):
            raise ContractError("PARAM_SCHEMA", f"unexpected or missing {group} fields")
        for key, sample in expected.items():
            actual = params[group][key]
            if isinstance(sample, bool):
                valid = isinstance(actual, bool)
            elif isinstance(sample, list):
                valid = isinstance(actual, list) and all(isinstance(n, (int, float)) and not isinstance(n, bool) and n >= 0 for n in actual)
            elif isinstance(sample, int):
                valid = isinstance(actual, int) and not isinstance(actual, bool) and actual >= (0 if key in {"max_retries", "min_rate"} else 1)
            else:
                valid = isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual > 0
            if not valid:
                raise ContractError("PARAM_VALUE", f"invalid {group}.{key}")
    workers = params["port_scan"]["parallel_workers"]
    if workers != concurrency or not 1 <= workers <= 20:
        raise ContractError("PARAM_MISMATCH", "run concurrency must match port_scan.parallel_workers (1..20)")
    if not 4 <= params["active_recheck"]["tokens"] <= 8:
        raise ContractError("PARAM_VALUE", "active tokens must be 4..8")
    full = params["full_port"]
    if full["min_rate"] > full["max_rate"]:
        raise ContractError("PARAM_VALUE", "full-port min_rate exceeds max_rate")
    return params


def validate_inputs(run, files, resources, storage_roots):
    snapshot = decode(run["input_snapshot_json"], "input snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1 or not isinstance(snapshot.get("allow_invalid_rows"), bool):
        raise ContractError("INPUT_SCHEMA", "unsupported input snapshot")
    entries = snapshot.get("files")
    if not isinstance(entries, list) or not entries:
        raise ContractError("INPUT_EMPTY", "complete input manifest is required")
    ids = [int(f["file_id"]) for f in entries]
    orders = [f["source_order"] for f in entries]
    if any(not isinstance(n,int) or isinstance(n,bool) for n in orders) or len(set(ids)) != len(ids) or sorted(orders) != list(range(1, len(entries) + 1)) or set(ids) != {int(f["id"]) for f in files}:
        raise ContractError("INPUT_MANIFEST", "snapshot must include all pre-registered files exactly once")
    by_file = {int(f["id"]): f for f in files}
    selected = []
    for entry in sorted(entries, key=lambda f: f["source_order"]):
        file = by_file[int(entry["file_id"])]
        if file["task_id"] != run["task_id"] or file["parse_status"] != "READY":
            raise ContractError("INPUT_NOT_READY", "all registered files must be READY")
        rows = [r for r in resources if int(r["file_id"]) == int(file["id"])]
        valid = [r for r in rows if r["validation_status"] == "VALID"]
        invalid = len(rows) - len(valid)
        if (len(valid), invalid) != (int(entry["valid_row_count"]), int(entry["invalid_row_count"])) or (len(valid), invalid) != (file["valid_row_count"], file["invalid_row_count"]):
            raise ContractError("INPUT_COUNTS", "input row counts differ from snapshot")
        if invalid and not snapshot["allow_invalid_rows"]:
            raise ContractError("INVALID_INPUT_ROWS", "invalid rows require explicit allow_invalid_rows")
        root = storage_roots.get(file["storage_id"])
        if not root:
            raise ContractError("STORAGE_UNAVAILABLE", "input storage_id is not configured")
        original = beneath(root, file["relative_path"])
        parsed = beneath(root, file["parsed_relative_path"])
        if not original.is_file() or not parsed.is_file() or not entry.get("parsed_hash") or file_hash(parsed) != entry["parsed_hash"] or file["parsed_hash"] != entry["parsed_hash"]:
            raise ContractError("INPUT_HASH", "published input is missing or differs from frozen hash")
        doc = decode(parsed.read_text(encoding="utf-8"), "parsed source")
        if not isinstance(doc, dict) or doc.get("schema_version") != 1 or not isinstance(doc.get("rows"), list):
            raise ContractError("PARSED_SCHEMA", "parsed_source.json must contain schema_version=1 and rows[]")
        parsed_rows = doc["rows"]
        db_rows = {int(r["id"]): r for r in valid}
        if len(parsed_rows) != len(db_rows) or {int(r["resource_id"]) for r in parsed_rows} != set(db_rows):
            raise ContractError("INPUT_ROWS", "parsed file and retained source IDs differ")
        checked = []
        for r in parsed_rows:
            db = db_rows[int(r["resource_id"])]
            for key in ("start_ip", "end_ip", "unit_name", "source_unit", "province_name", "operator_name"):
                if (r.get(key) or "") != (db.get(key) or ""):
                    raise ContractError("INPUT_ROWS", f"parsed source differs: resource {db['id']} {key}")
            first, last = ipaddress.ip_address(r["start_ip"]), ipaddress.ip_address(r["end_ip"])
            if first.version != last.version or int(first) > int(last) or not r.get("province_name") or not r.get("operator_name"):
                raise ContractError("INPUT_RANGE", "invalid address range or organization")
            checked.append(dict(r, resource_id=int(db["id"])))
        selected.append(dict(entry, rows=checked))
    if not any(f["rows"] for f in selected):
        raise ContractError("INPUT_EMPTY", "at least one valid target is required")
    return selected


def expand_hosts(rows, max_hosts):
    """Scan once per IP; keep every resource association, including overlapping ranges."""
    hosts = {}
    for row in rows:
        first, last = ipaddress.ip_address(row["start_ip"]), ipaddress.ip_address(row["end_ip"])
        if first.version != last.version or int(last) < int(first):
            raise ContractError("INPUT_RANGE", "invalid source range")
        if int(last) - int(first) + 1 > max_hosts:
            raise ContractError("EXPAND_CAPACITY", "source range exceeds configured scanner capacity")
        form = "SINGLE" if first == last else "RANGE"
        for number in range(int(first), int(last) + 1):
            ip = str(first.__class__(number))
            host = hosts.setdefault(ip, {"ip": ip, "ip_version": first.version, "resources": [], "source_form": form})
            host["resources"].append({"resource_id": row["resource_id"], "source_form": form})
            if host["source_form"] != form:
                host["source_form"] = "BOTH"
            if len(hosts) > max_hosts:
                raise ContractError("EXPAND_CAPACITY", "source group exceeds configured scanner capacity")
    return list(hosts.values())
