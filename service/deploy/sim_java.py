#!/usr/bin/env python3
"""Stand-in for the Java backend in isolated joint testing (Java 对接说明 §5–§7, §9.3).

Writes only what Java owns: task/file/resource rows, published inputs, QUEUED
runs and control requests. Refuses to run against anything but a loopback test
database. Never use it against a business database.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import mysql.connector
import openpyxl

SERVICE_ROOT = Path(__file__).resolve().parents[1]
UNFINISHED = ("QUEUED", "PREPARING", "RUNNING", "PAUSING", "PAUSED", "RECOVERING", "STOPPING")
OPERATORS = ("电信", "联通", "移动", "广电")
PROVINCES = {
    "北京": "北京市", "天津": "天津市", "上海": "上海市", "重庆": "重庆市", "河北": "河北省", "山西": "山西省", "辽宁": "辽宁省",
    "吉林": "吉林省", "黑龙江": "黑龙江省", "江苏": "江苏省", "浙江": "浙江省", "安徽": "安徽省", "福建": "福建省", "江西": "江西省",
    "山东": "山东省", "河南": "河南省", "湖北": "湖北省", "湖南": "湖南省", "广东": "广东省", "海南": "海南省", "四川": "四川省",
    "贵州": "贵州省", "云南": "云南省", "陕西": "陕西省", "甘肃": "甘肃省", "青海": "青海省", "台湾": "台湾省",
    "内蒙古": "内蒙古自治区", "广西": "广西壮族自治区", "西藏": "西藏自治区", "宁夏": "宁夏回族自治区", "新疆": "新疆维吾尔自治区",
}
TEMPLATE = ("起始IP", "终止IP", "使用单位信息", "来源单位")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def connect(database):
    host = os.environ.get("V7_TEST_MYSQL_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"} or not database.startswith(("llm_detect_v21_test", "test_v7_")):
        sys.exit("refusing: sim_java only targets loopback isolated test databases")
    return mysql.connector.connect(host=host, port=int(os.environ.get("V7_TEST_MYSQL_PORT", "3306")), database=database,
                                   user=os.environ["V7_TEST_MYSQL_USER"], password=os.environ["V7_TEST_MYSQL_PASSWORD"],
                                   autocommit=False, time_zone="+00:00")


def organization(source_unit):
    text = (source_unit or "").strip()
    provinces = [full for short, full in PROVINCES.items() if text.startswith(short)]
    operators = [op for op in OPERATORS if op in text]
    if len(provinces) != 1 or len(operators) != 1:
        return None
    return provinces[0], operators[0]


def insert(cur, table, values):
    cols = ", ".join(f"`{k}`" for k in values)
    cur.execute(f"INSERT INTO `{table}` ({cols}) VALUES ({', '.join(['%s'] * len(values))})", tuple(values.values()))
    return cur.lastrowid


def parse_xlsx(path):
    sheet = openpyxl.load_workbook(path, read_only=True, data_only=True).worksheets[0]
    rows = list(sheet.iter_rows(values_only=True))
    header = [str(c).strip() if c is not None else "" for c in rows[0]]
    index = {name: header.index(name) for name in TEMPLATE if name in header}
    if set(index) != set(TEMPLATE):
        raise ValueError(f"template columns missing: {set(TEMPLATE) - set(index)}")
    parsed = []
    for raw in rows[1:]:
        cells = {name: (str(raw[i]).strip() if i < len(raw) and raw[i] is not None else "") for name, i in index.items()}
        if not any(cells.values()):
            continue
        record = {"unit_name": cells["使用单位信息"] or None, "source_unit": cells["来源单位"] or None}
        try:
            first = ipaddress.ip_address(cells["起始IP"])
            last = ipaddress.ip_address(cells["终止IP"]) if cells["终止IP"] else first
            if first.version != last.version or int(last) < int(first):
                raise ValueError("IP_RANGE")
            org = organization(cells["来源单位"])
            if org is None:
                raise LookupError("ORG_UNRESOLVED")
            record.update(start_ip=str(first), end_ip=str(last), ip_version=first.version, range_size=int(last) - int(first) + 1,
                          province_name=org[0], operator_name=org[1], validation_status="VALID", validation_error=None)
        except (ValueError, LookupError) as exc:
            record.update(start_ip=None, end_ip=None, ip_version=None, range_size=None, province_name=None, operator_name=None,
                          validation_status="INVALID", validation_error=str(exc) or exc.__class__.__name__)
        parsed.append(record)
    return parsed


def create_task(args, db):
    data_root = Path(args.data_root)
    now = utcnow()
    cur = db.cursor()
    task = insert(cur, "probe_task", {"task_name": args.name, "task_type": "ONCE", "lifecycle_status": "ACTIVE", "param_json": "{}",
                                      "concurrency": args.concurrency, "schedule_enabled": 0, "last_run_no": 0,
                                      "creator": args.user, "create_date": now})
    files = []
    for path in args.xlsx:
        fid = insert(cur, "probe_task_file", {"task_id": task, "original_name": Path(path).name, "file_format": "XLSX", "storage_id": "LOCAL",
                                              "relative_path": "pending", "parse_status": "PENDING", "row_total": 0,
                                              "valid_row_count": 0, "invalid_row_count": 0, "creator": args.user, "create_date": now})
        relative = f"inputs/tasks/{task}/files/{fid}/original.xlsx"
        cur.execute("UPDATE probe_task_file SET relative_path=%s WHERE id=%s", (relative, fid))
        files.append((fid, Path(path), relative))
    db.commit()  # Task and complete file manifest commit together (§5.1).
    for fid, source, relative in files:
        publish_file(db, data_root, task, fid, source, relative, args.user)
    print(json.dumps({"task_id": task, "file_ids": [f[0] for f in files]}))


def publish_file(db, data_root, task, fid, source, relative, user):
    target = data_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".uploading")
    shutil.copyfile(source, tmp)
    os.replace(tmp, target)
    cur = db.cursor()
    cur.execute("UPDATE probe_task_file SET parse_status='PARSING', update_date=%s WHERE id=%s AND parse_status IN ('PENDING','FAILED')", (utcnow(), fid))
    db.commit()
    records = parse_xlsx(target)
    rows = []
    for record in records:
        rid = insert(cur, "probe_pending_resource", {"task_id": task, "file_id": fid, "creator": user, "create_date": utcnow(), **record})
        if record["validation_status"] == "VALID":
            rows.append({"resource_id": str(rid), "start_ip": record["start_ip"], "end_ip": record["end_ip"], "unit_name": record["unit_name"],
                         "source_unit": record["source_unit"], "province_name": record["province_name"], "operator_name": record["operator_name"],
                         "resource_type": "SINGLE_IP" if record["start_ip"] == record["end_ip"] else "IP_SEGMENT",
                         "enterprise_name": record["province_name"].removesuffix("省").removesuffix("市") + record["operator_name"]})
    parsed_relative = f"inputs/tasks/{task}/files/{fid}/parsed_source.json"
    payload = json.dumps({"schema_version": 1, "rows": rows}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    parsed = data_root / parsed_relative
    tmp = parsed.with_name(parsed.name + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, parsed)
    invalid = len(records) - len(rows)
    cur.execute("""UPDATE probe_task_file SET parse_status=%s, row_total=%s, valid_row_count=%s, invalid_row_count=%s,
                   parsed_relative_path=%s, parsed_hash=%s, parsed_at=%s, uploaded_by=%s, update_date=%s WHERE id=%s""",
                ("READY" if rows else "FAILED", len(records), len(rows), invalid, parsed_relative,
                 hashlib.sha256(payload).hexdigest(), utcnow(), user, utcnow(), fid))
    db.commit()


def start_run(args, db):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM probe_task WHERE id=%s FOR UPDATE", (args.task_id,))
    task = cur.fetchone()
    if not task or task["lifecycle_status"] != "ACTIVE":
        sys.exit("TASK_NOT_ACTIVE")
    cur.execute(f"SELECT id FROM probe_task_run WHERE task_id=%s AND status IN ({','.join(['%s'] * len(UNFINISHED))})", (args.task_id, *UNFINISHED))
    if cur.fetchone():
        db.rollback()
        sys.exit("409 TASK_BUSY")
    if args.expected_last_run_no is not None and args.expected_last_run_no != task["last_run_no"]:
        db.rollback()
        sys.exit("409 RUN_VERSION_CHANGED")
    cur.execute("SELECT * FROM probe_task_file WHERE task_id=%s ORDER BY id", (args.task_id,))
    files = cur.fetchall()
    if not files or any(f["parse_status"] != "READY" for f in files) or not any(f["valid_row_count"] for f in files):
        db.rollback()
        sys.exit("INPUT_NOT_READY")
    if any(f["invalid_row_count"] for f in files) and not args.allow_invalid_rows:
        db.rollback()
        sys.exit("INVALID_INPUT_ROWS: confirm with --allow-invalid-rows")
    entries = [{"file_id": str(f["id"]), "source_order": order, "original_name": f["original_name"], "parsed_hash": f["parsed_hash"],
                "valid_row_count": int(f["valid_row_count"]), "invalid_row_count": int(f["invalid_row_count"])}
               for order, f in enumerate(files, 1)]
    params = json.loads((SERVICE_ROOT / "llm_detect/v21/defaults.json").read_text(encoding="utf-8"))
    params["port_scan"]["parallel_workers"] = int(task["concurrency"])
    if args.full_port_disabled:
        params["full_port"]["enabled"] = False
    run_no = task["last_run_no"] + 1
    now = utcnow()
    run = insert(cur, "probe_task_run", {
        "task_id": args.task_id, "run_no": run_no, "trigger_type": "MANUAL", "status": "QUEUED",
        "input_snapshot_json": json.dumps({"schema_version": 1, "allow_invalid_rows": bool(args.allow_invalid_rows), "files": entries}, ensure_ascii=False),
        "param_snapshot_json": json.dumps(params, ensure_ascii=False), "concurrency": int(task["concurrency"]),
        "request_seq": 0, "ack_seq": 0, "creator": args.user, "create_date": now})
    cur.execute("UPDATE probe_task SET last_run_no=%s, latest_run_id=%s, updater=%s, update_date=%s WHERE id=%s",
                (run_no, run, args.user, now, args.task_id))
    db.commit()
    print(json.dumps({"task_id": args.task_id, "run_id": run, "run_no": run_no}))


def control(args, db):
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT task_id FROM probe_task_run WHERE id=%s", (args.run_id,))
    found = cur.fetchone()
    if not found:
        sys.exit("RUN_NOT_FOUND")
    cur.execute("SELECT id FROM probe_task WHERE id=%s FOR UPDATE", (found["task_id"],))
    cur.execute("SELECT * FROM probe_task_run WHERE id=%s FOR UPDATE", (args.run_id,))
    run = cur.fetchone()
    pending = run["request_seq"] > run["ack_seq"]
    allowed = {"PAUSE": {"PREPARING", "RUNNING"}, "RESUME": {"PAUSED"}, "STOP": set(UNFINISHED)}[args.action]
    if args.action == "STOP" and run["status"] == "STOPPED":
        db.rollback()
        print(json.dumps({"run_id": args.run_id, "request_seq": run["request_seq"], "result": "ALREADY_STOPPED"}))
        return
    if pending and run["requested_action"] == args.action:
        db.rollback()
        print(json.dumps({"run_id": args.run_id, "request_seq": run["request_seq"], "result": "ALREADY_PENDING"}))
        return
    if pending and args.action != "STOP":
        db.rollback()
        sys.exit("409 CONTROL_PENDING")
    if run["status"] not in allowed:
        db.rollback()
        sys.exit(f"409 INVALID_STATE {run['status']}")
    cur.execute("""UPDATE probe_task_run SET requested_action=%s, request_seq=request_seq+1, requested_at=UTC_TIMESTAMP(6),
                   updater=%s, update_date=UTC_TIMESTAMP() WHERE id=%s""", (args.action, args.user, args.run_id))
    db.commit()
    print(json.dumps({"run_id": args.run_id, "action": args.action, "request_seq": run["request_seq"] + 1}))


def status(args, db):
    cur = db.cursor(dictionary=True)
    def rows(sql, *params):
        cur.execute(sql, params)
        return cur.fetchall()
    run = rows("SELECT id,task_id,run_no,status,requested_action,request_seq,ack_seq,lease_epoch,worker_id,progress_percent,"
               "source_total,source_finished,host_total,host_finished,endpoint_total,endpoint_finished,started_at,finished_at,"
               "error_code,error_message,result_version,scanner_version,rule_hash,final_artifact_id "
               "FROM probe_task_run WHERE id=%s", args.run_id)
    report = {"run": run[0] if run else None,
              "sources": rows("SELECT id,file_id,source_order,status,current_stage,host_total,host_finished,endpoint_total,endpoint_finished,"
                              "progress_percent,started_at,finished_at,error_code FROM probe_run_source WHERE run_id=%s ORDER BY source_order", args.run_id),
              "stages": rows("SELECT source_group_id,stage_code,status,work_total,work_finished,work_success,work_failed,error_code,error_message "
                             "FROM probe_run_stage WHERE run_id=%s ORDER BY source_group_id,stage_order", args.run_id),
              "counts": rows("SELECT (SELECT COUNT(*) FROM probe_host WHERE run_id=%s) hosts,(SELECT COUNT(*) FROM probe_host_resource WHERE run_id=%s) host_resources,"
                             "(SELECT COUNT(*) FROM probe_endpoint WHERE run_id=%s) endpoints,(SELECT COUNT(*) FROM probe_asset_port WHERE run_id=%s) assets,"
                             "(SELECT COUNT(*) FROM probe_asset_port_history WHERE run_id=%s) revisions,(SELECT COUNT(*) FROM probe_scan_event WHERE run_id=%s) events",
                             *([args.run_id] * 6))[0],
              "artifacts": rows("SELECT id,scope_type,artifact_type,logical_name,generation_no,status,relative_path FROM probe_artifact WHERE run_id=%s ORDER BY id", args.run_id)}
    print(json.dumps(report, ensure_ascii=False, default=str, indent=1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="llm_detect_v21_test")
    parser.add_argument("--user", type=int, default=1001, help="simulated Java user id")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("create-task")
    p.add_argument("--name", required=True)
    p.add_argument("--data-root", required=True)
    p.add_argument("--concurrency", type=int, default=3)
    p.add_argument("--xlsx", action="append", required=True)
    p = sub.add_parser("start")
    p.add_argument("--task-id", type=int, required=True)
    p.add_argument("--expected-last-run-no", type=int)
    p.add_argument("--allow-invalid-rows", action="store_true")
    p.add_argument("--full-port-disabled", action="store_true")
    p = sub.add_parser("control")
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--action", choices=["PAUSE", "RESUME", "STOP"], required=True)
    p = sub.add_parser("status")
    p.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()
    db = connect(args.database)
    try:
        {"create-task": create_task, "start": start_run, "control": control, "status": status}[args.command](args, db)
    finally:
        db.close()


if __name__ == "__main__":
    main()
