from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .common import ContractError, LeaseLost, decode, digest, dumps
from .contract import CONTRACT

TERMINAL = {"SUCCESS", "PARTIAL", "FAILED", "STOPPED"}
STAGES = ("EXPAND", "PORT_SCAN", "IDENTIFY", "GPU_RECHECK", "EVIDENCE", "FULL_PORT",
          "FULL_IDENTIFY", "FULL_GPU_RECHECK", "MERGE", "ACTIVE_RECHECK", "EVIDENCE_FINAL", "FINALIZE")


@dataclass(frozen=True)
class Lease:
    run_id: int
    task_id: int
    worker: str
    epoch: int


def one(cur, sql, params=()):
    cur.execute(sql, params)
    return cur.fetchone()


def all_rows(cur, sql, params=()):
    cur.execute(sql, params)
    return list(cur.fetchall())


def insert(cur, table, values):
    if table not in CONTRACT or set(values) - set(CONTRACT[table]):
        raise ContractError("SQL_CONTRACT", f"unknown columns for {table}")
    columns = list(values)
    cur.execute(f"INSERT INTO `{table}` ({','.join('`'+c+'`' for c in columns)}) VALUES ({','.join(['%s']*len(columns))})", tuple(values[c] for c in columns))
    return int(cur.lastrowid)


def update(cur, table, ident, values):
    if table not in CONTRACT or set(values) - set(CONTRACT[table]):
        raise ContractError("SQL_CONTRACT", f"unknown columns for {table}")
    cur.execute(f"UPDATE `{table}` SET {','.join('`'+c+'`=%s' for c in values)} WHERE id=%s", (*values.values(), ident))


def likelihood(value):
    return {"高": "HIGH", "中": "MEDIUM", "低": "LOW", "未知": "UNKNOWN"}.get(value, value if value in {"HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN")


def json_value(value, fallback):
    if value in (None, ""):
        return dumps(fallback)
    if isinstance(value, str):
        try:
            return dumps(decode(value))
        except ContractError:
            return dumps({"raw": value})
    return dumps(value)


def normalize_result(raw, timestamp):
    row = {"host_ip": str(ipaddress.ip_address(raw["ip"])), "port": int(raw["port"]),
           "protocol": {"http": "HTTP", "https": "HTTPS", "": "NON_HTTP"}.get(raw.get("protocol", ""), raw.get("protocol")),
           "is_llm": {"确认": "CONFIRMED", "疑似": "SUSPECTED", "否": "NO"}.get(raw.get("is_llm"), "NO"),
           "gpu_likelihood": likelihood(raw.get("gpu_likelihood")), "npu_likelihood": likelihood(raw.get("npu_likelihood")),
           "raw_result_json": dumps(raw), "analysis": raw.get("分析", raw.get("analysis")), "detect_time": timestamp}
    if not 1 <= row["port"] <= 65535:
        raise ContractError("RESULT_PORT", "invalid result port")
    for key in ("service_type", "model_domain", "deploy_tool", "deploy_version", "model_info", "gpu_evidence", "npu_evidence",
                "accelerator_type", "scan_status", "scan_confidence", "selected_hostname", "evidence", "active_probe_status"):
        row[key] = raw.get(key) or None
    row["gpu_second_stage_status"] = raw.get("gpu_second_stage_status") or None
    for prefix in ("gpu_probe_detail", "protocol_probe_detail", "http_probe_detail", "verdict_rule", "fingerprint"):
        row[prefix + "_json"] = json_value(raw.get(prefix), {}) if raw.get(prefix) else None
    for key in ("certificate_names", "tested_hostnames"):
        value = raw.get(key, "")
        row[key + "_json"] = json_value(value, []) if not isinstance(value, str) else dumps([s for s in value.split("|||") if s])
    links = raw.get("link", "")
    row["links_json"] = dumps([s for s in links.split("|||") if s]) if isinstance(links, str) else dumps(links)
    for key in ("gpu_likelihood_before", "gpu_likelihood_after"):
        row[key] = likelihood(raw[key]) if raw.get(key) else None
    row["result_hash"] = digest(dumps({k: v for k, v in row.items() if k != "detect_time"}).encode("utf-8"))
    return row


class Repository:
    def __init__(self, db, lease_seconds=60):
        self.db, self.lease_seconds = db, lease_seconds

    def get_run(self, ident):
        with self.db.cursor() as cur:
            return one(cur, "SELECT * FROM probe_task_run WHERE id=%s", (ident,))

    def _locked(self, cur, lease, writable=True):
        task = one(cur, "SELECT * FROM probe_task WHERE id=%s FOR UPDATE", (lease.task_id,))
        run = one(cur, "SELECT * FROM probe_task_run WHERE id=%s FOR UPDATE", (lease.run_id,))
        now = self.db.now(cur)
        if not task or not run or run["task_id"] != lease.task_id or run["worker_id"] != lease.worker or run["lease_epoch"] != lease.epoch or not run["lease_expires_at"] or run["lease_expires_at"] <= now:
            raise LeaseLost()
        if writable and (task["lifecycle_status"] != "ACTIVE" or run["status"] in TERMINAL | {"PAUSED"}):
            raise LeaseLost("run is not writable")
        return run, now, task

    def claim(self, worker, preferred_id=None):
        with self.db.cursor() as cur:
            now = self.db.now(cur)
            candidates = all_rows(cur, """SELECT r.id,r.task_id FROM probe_task_run r JOIN probe_task t ON t.id=r.task_id
                WHERE (t.lifecycle_status='ACTIVE' OR r.requested_action='STOP') AND
                (r.status='QUEUED' OR (r.status='PAUSED' AND r.request_seq>r.ack_seq AND r.requested_action IN ('RESUME','STOP'))
                 OR (r.status IN ('PREPARING','RUNNING','PAUSING','RECOVERING','STOPPING') AND (r.lease_expires_at IS NULL OR r.lease_expires_at<=%s)))
                ORDER BY r.create_date,r.id LIMIT 32""".replace("ORDER BY r.create_date", ("AND r.id=%s " if preferred_id is not None else "") + "ORDER BY r.create_date"),
                (now, int(preferred_id)) if preferred_id is not None else (now,))
        for candidate in candidates:
            with self.db.cursor() as cur:
                task = one(cur, "SELECT * FROM probe_task WHERE id=%s FOR UPDATE SKIP LOCKED", (candidate["task_id"],))
                if not task:
                    continue
                run = one(cur, "SELECT * FROM probe_task_run WHERE id=%s FOR UPDATE", (candidate["id"],))
                now = self.db.now(cur)
                if not run or run["status"] in TERMINAL:
                    continue
                if run["status"] == "PAUSED" and not (run["request_seq"] > run["ack_seq"] and run["requested_action"] in {"RESUME", "STOP"}):
                    continue
                if run["status"] not in {"QUEUED", "PAUSED"} and run["lease_expires_at"] and run["lease_expires_at"] > now:
                    continue
                if task["lifecycle_status"] != "ACTIVE" and run["requested_action"] != "STOP":
                    continue
                epoch = run["lease_epoch"] + 1
                update(cur, "probe_task_run", run["id"], {"worker_id": worker, "lease_epoch": epoch,
                    "heartbeat_at": now, "lease_expires_at": now + timedelta(seconds=self.lease_seconds),
                    "status": "RECOVERING" if run["started_at"] else "PREPARING", "update_date": now})
                return Lease(run["id"], run["task_id"], worker, epoch)
        return None

    def heartbeat(self, lease):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease, writable=False)
            if run["status"] in TERMINAL | {"PAUSED"}:
                raise LeaseLost()
            update(cur, "probe_task_run", lease.run_id, {"heartbeat_at": now, "lease_expires_at": now + timedelta(seconds=self.lease_seconds), "update_date": now})

    def bind_executor(self, lease, descriptor):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            summary = decode(run["summary_json"]) if run["summary_json"] else {}
            old = summary.get("service21_executor")
            if (old and old != descriptor) or (run["started_at"] and not old):
                raise ContractError("EXECUTOR_MISMATCH", "cannot change the frozen remote/storage executor binding")
            summary["service21_executor"] = descriptor
            update(cur, "probe_task_run", lease.run_id, {"summary_json": dumps(summary), "update_date": now})

    def sources(self, lease):
        with self.db.cursor() as cur:
            self._locked(cur, lease, writable=False)
            return all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s ORDER BY source_order", (lease.run_id,))

    def stages(self, lease, source_id):
        with self.db.cursor() as cur:
            self._locked(cur, lease, writable=False)
            return all_rows(cur, "SELECT * FROM probe_run_stage WHERE source_group_id=%s ORDER BY stage_order", (source_id,))

    def stop_idle_requests(self, worker):
        """Queued/confirmed-paused STOP needs no execution slot and must not start a scanner."""
        with self.db.cursor() as cur:
            candidates = all_rows(cur, "SELECT id,task_id FROM probe_task_run WHERE status IN ('QUEUED','PAUSED') AND requested_action='STOP' AND request_seq>ack_seq ORDER BY id LIMIT 32")
        for item in candidates:
            with self.db.cursor() as cur:
                one(cur, "SELECT id FROM probe_task WHERE id=%s FOR UPDATE", (item["task_id"],))
                run = one(cur, "SELECT * FROM probe_task_run WHERE id=%s FOR UPDATE", (item["id"],))
                now = self.db.now(cur)
                if run["status"] in {"QUEUED", "PAUSED"} and run["requested_action"] == "STOP" and run["request_seq"] > run["ack_seq"]:
                    update(cur, "probe_task_run", run["id"], {"status": "STOPPED", "ack_seq": run["request_seq"], "finished_at": now,
                        "worker_id": worker, "lease_epoch": run["lease_epoch"] + 1, "lease_expires_at": now, "update_date": now})
                    cur.execute("UPDATE probe_run_source SET status='STOPPED',finished_at=%s WHERE run_id=%s AND status NOT IN ('SUCCESS','PARTIAL','FAILED','STOPPED')", (now, run["id"]))
                    self._counts(cur, Lease(run["id"], item["task_id"], worker, run["lease_epoch"] + 1), now)

    def relinquish(self, lease):
        with self.db.cursor() as cur:
            _, now, _ = self._locked(cur, lease, writable=False)
            update(cur, "probe_task_run", lease.run_id, {"status": "RECOVERING", "lease_expires_at": now, "update_date": now})

    def input_records(self, lease):
        with self.db.cursor() as cur:
            run, _, _ = self._locked(cur, lease)
            files = all_rows(cur, "SELECT * FROM probe_task_file WHERE task_id=%s ORDER BY id", (lease.task_id,))
            resources = all_rows(cur, "SELECT * FROM probe_pending_resource WHERE task_id=%s ORDER BY id", (lease.task_id,))
            return run, files, resources

    def freeze(self, lease, rules, rule_hash, version):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            if run["scanner_version"] and run["scanner_version"] != version:
                raise ContractError("RELEASE_MISMATCH", "cannot change a frozen scanner release")
            if run["rule_snapshot_json"] and (decode(run["rule_snapshot_json"]) != rules or run["rule_hash"] != rule_hash):
                raise ContractError("RULE_MISMATCH", "cannot change frozen rules")
            update(cur, "probe_task_run", lease.run_id, {"rule_snapshot_json": dumps(rules), "rule_hash": rule_hash, "scanner_version": version, "update_date": now})

    def publish_sources(self, lease, files):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            if not all(run.get(k) for k in ("rule_snapshot_json", "rule_hash", "scanner_version")):
                raise ContractError("PREPARATION_INCOMPLETE", "rules/hash/scanner version must be frozen before startup")
            current_files = all_rows(cur, "SELECT * FROM probe_task_file WHERE task_id=%s", (lease.task_id,))
            if {int(f["file_id"]) for f in files} != {r["id"] for r in current_files} or any(r["parse_status"] != "READY" for r in current_files):
                raise ContractError("INPUT_MANIFEST", "input readiness/manifest changed before startup")
            if run["request_seq"] > run["ack_seq"] and run["requested_action"] in {"PAUSE", "STOP"}:
                return None
            existing = all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s ORDER BY source_order", (lease.run_id,))
            if run["started_at"] and {r["file_id"] for r in existing} != {int(f["file_id"]) for f in files}:
                raise ContractError("SOURCE_INCOMPLETE", "started run has an incomplete source manifest")
            if not run["started_at"]:
                if existing and {r["file_id"] for r in existing} != {int(f["file_id"]) for f in files}:
                    raise ContractError("SOURCE_INCOMPLETE", "unexpected preexisting source manifest")
                if not existing:
                    for f in files:
                        sid = insert(cur, "probe_run_source", {"task_id": lease.task_id, "run_id": lease.run_id,
                            "file_id": int(f["file_id"]), "source_order": f["source_order"], "source_name": f["original_name"],
                            "input_snapshot_json": dumps(f), "input_hash": f["parsed_hash"], "status": "PENDING",
                            "workspace_relative_path": "pending", "creator": run["creator"], "create_date": now})
                        update(cur, "probe_run_source", sid, {"workspace_relative_path": f"tasks/{lease.task_id}/runs/{lease.run_id}/sources/{sid}"})
                update(cur, "probe_task_run", lease.run_id, {"source_total": len(files), "started_at": now})
            changes = {"status": "RUNNING", "update_date": now}
            if run["request_seq"] > run["ack_seq"] and run["requested_action"] == "RESUME":
                changes["ack_seq"] = run["request_seq"]
            update(cur, "probe_task_run", lease.run_id, changes)
            return all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s ORDER BY source_order", (lease.run_id,))

    def command(self, lease):
        with self.db.cursor() as cur:
            run, _, task = self._locked(cur, lease, writable=False)
            if task["lifecycle_status"] != "ACTIVE":
                return "STOP", run["request_seq"]
            return (run["requested_action"], run["request_seq"]) if run["request_seq"] > run["ack_seq"] else (None, run["ack_seq"])

    def begin_control(self, lease, action):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease, writable=False)
            update(cur, "probe_task_run", lease.run_id, {"status": "PAUSING" if action == "PAUSE" else "STOPPING", "update_date": now})

    def finish_control(self, lease, action, seq):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease, writable=False)
            if run["request_seq"] != seq or run["requested_action"] != action:
                return False
            status = "PAUSED" if action == "PAUSE" else "STOPPED"
            changes = {"status": status, "ack_seq": seq, "update_date": now, "lease_expires_at": now}
            if action == "STOP":
                changes["finished_at"] = now
            update(cur, "probe_task_run", lease.run_id, changes)
            for s in all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s", (lease.run_id,)):
                if s["status"] not in TERMINAL:
                    values = {"status": status, "update_date": now}
                    if action == "STOP":
                        values["finished_at"] = now
                    update(cur, "probe_run_source", s["id"], values)
            cur.execute("UPDATE probe_run_stage SET status=%s,update_date=%s WHERE run_id=%s AND status='RUNNING'", ("PAUSED" if action == "PAUSE" else "FAILED", now, lease.run_id))
            self._counts(cur, lease, now)
            return True

    def start_stage(self, lease, source_id, stage):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            source = one(cur, "SELECT * FROM probe_run_source WHERE id=%s AND run_id=%s", (source_id, lease.run_id))
            if not source:
                raise ContractError("SOURCE_MISMATCH", "source does not belong to this run")
            row = one(cur, "SELECT * FROM probe_run_stage WHERE source_group_id=%s AND stage_code=%s", (source_id, stage))
            if row and row["status"] in {"SUCCESS", "PARTIAL", "SKIPPED"}:
                return False
            if stage in {"EXPAND", "PORT_SCAN"}:
                intervals = []
                for r in decode(source["input_snapshot_json"])["rows"]:
                    first, last = ipaddress.ip_address(r["start_ip"]), ipaddress.ip_address(r["end_ip"])
                    intervals.append((first.version, int(first), int(last)))
                merged = []
                for version, first, last in sorted(intervals):
                    if merged and merged[-1][0] == version and first <= merged[-1][2] + 1:
                        merged[-1] = (version, merged[-1][1], max(last, merged[-1][2]))
                    else:
                        merged.append((version, first, last))
                total = sum(last-first+1 for _, first, last in merged)
            else:
                total = one(cur, "SELECT COUNT(*) AS n FROM probe_endpoint WHERE source_group_id=%s", (source_id,))["n"]
            if row:
                update(cur, "probe_run_stage", row["id"], {"status": "RUNNING", "attempt_no": row["attempt_no"] + 1, "update_date": now})
            else:
                insert(cur, "probe_run_stage", {"task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": source_id,
                    "stage_code": stage, "stage_order": STAGES.index(stage) + 1, "status": "RUNNING", "attempt_no": 1,
                    "work_unit": "IP" if stage in {"EXPAND","PORT_SCAN","FULL_PORT"} else "ENDPOINT", "work_total": total,
                    "started_at": now, "creator": run["creator"], "create_date": now})
            update(cur, "probe_run_source", source_id, {"status": "RUNNING", "current_stage": stage, "started_at": source["started_at"] or now, "update_date": now})
            return True

    def commit(self, lease, event, relative_path):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            if (int(event["task_id"]), int(event["run_id"])) != (lease.task_id, lease.run_id):
                raise ContractError("EVENT_OWNER", "event belongs to another run")
            previous = one(cur, "SELECT * FROM probe_scan_event WHERE event_id=%s", (event["event_id"],))
            if previous:
                if previous["payload_hash"] != event["payload_hash"] or previous["run_id"] != lease.run_id:
                    raise ContractError("EVENT_CONFLICT", "event UUID reused with another payload")
                return False
            sid, stage = event["source_group_id"], event["stage_code"]
            source = one(cur, "SELECT * FROM probe_run_source WHERE id=%s AND run_id=%s AND task_id=%s", (sid, lease.run_id, lease.task_id))
            state = one(cur, "SELECT * FROM probe_run_stage WHERE source_group_id=%s AND stage_code=%s", (sid, stage))
            if not source or not state:
                raise ContractError("EVENT_SOURCE", "event source/stage was not registered")
            if state["last_committed_seq"] + 1 != event["stage_seq"]:
                raise ContractError("EVENT_SEQUENCE", "stage event sequence has a gap or conflict")
            kind = event["event_type"]
            for row in event["rows"]:
                if kind == "HOST":
                    self._host(cur, lease, run, sid, row, now)
                elif kind in {"PORTS", "FULL_PORT_HOST"}:
                    self._ports(cur, lease, run, sid, stage, row, now)
                elif kind == "RESULT":
                    self._result(cur, lease, run, sid, stage, event, row, now)
                else:
                    raise ContractError("EVENT_TYPE", f"unsupported row event {kind}")
            total = state["work_total"]
            finished = state["work_finished"] + len(event["rows"])
            if total is not None:
                finished = min(finished, total)
            changes = {"last_committed_seq": event["stage_seq"], "work_finished": finished, "update_date": now}
            if kind == "STAGE_END":
                status = event["meta"]["status"]
                if status not in {"SUCCESS", "PARTIAL", "FAILED", "SKIPPED"}:
                    raise ContractError("EVENT_STATUS", "invalid terminal stage status")
                changes.update(status=status, finished_at=now, work_total=total if total is not None else finished,
                    work_finished=total if total is not None else finished, work_success=finished if status in {"SUCCESS","PARTIAL"} else 0,
                    summary_json=dumps(event["meta"]), error_code=event["meta"].get("error_code"), error_message=event["meta"].get("error_message"))
                if stage == "PORT_SCAN" and event["meta"].get("policy_summary"):
                    policy = event["meta"]["policy_summary"]
                    update(cur, "probe_run_source", sid, {"policy_code": str(policy["policy"])[:64], "policy_summary_json": dumps(policy), "update_date": now})
                if stage == "FINALIZE" or status == "FAILED":
                    failed = one(cur, "SELECT COUNT(*) AS n FROM probe_run_stage WHERE source_group_id=%s AND status IN ('PARTIAL','FAILED')", (sid,))["n"]
                    final = "FAILED" if status == "FAILED" else "PARTIAL" if failed or status == "PARTIAL" else "SUCCESS"
                    update(cur, "probe_run_source", sid, {"status": final, "finished_at": now, "update_date": now})
                    cur.execute("UPDATE probe_host SET host_phase='DONE',finished_at=%s WHERE source_group_id=%s", (now, sid))
                    cur.execute("UPDATE probe_endpoint SET finished_at=%s WHERE source_group_id=%s AND endpoint_status IN ('DONE','FAILED','SKIPPED')", (now, sid))
            update(cur, "probe_run_stage", state["id"], changes)
            insert(cur, "probe_scan_event", {"event_id": event["event_id"], "schema_version": 1,
                "task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": sid, "stage_code": stage,
                "stage_seq": event["stage_seq"], "event_type": kind, "lease_epoch": lease.epoch,
                "payload_hash": event["payload_hash"], "payload_relative_path": str(relative_path), "record_count": len(event["rows"]),
                "committed_at": now, "creator": run["creator"], "create_date": now})
            self._counts(cur, lease, now)
            return True

    def _host(self, cur, lease, run, sid, row, now):
        ip = str(ipaddress.ip_address(row["ip"]))
        host = one(cur, "SELECT * FROM probe_host WHERE source_group_id=%s AND host_ip=%s", (sid, ip))
        hid = host["id"] if host else insert(cur, "probe_host", {"task_id": lease.task_id, "run_id": lease.run_id,
            "source_group_id": sid, "host_ip": ip, "ip_version": ipaddress.ip_address(ip).version,
            "source_form": row["source_form"], "creator": run["creator"], "create_date": now})
        for resource in row["resources"]:
            rid = int(resource["resource_id"])
            original = one(cur, "SELECT * FROM probe_pending_resource WHERE id=%s AND task_id=%s AND file_id=%s AND validation_status='VALID'", (rid, lease.task_id, one(cur, "SELECT file_id FROM probe_run_source WHERE id=%s", (sid,))["file_id"]))
            if not original or ipaddress.ip_address(original["start_ip"]).version != ipaddress.ip_address(ip).version or not int(ipaddress.ip_address(original["start_ip"])) <= int(ipaddress.ip_address(ip)) <= int(ipaddress.ip_address(original["end_ip"])):
                raise ContractError("HOST_RESOURCE", "host/resource association is invalid")
            if not one(cur, "SELECT id FROM probe_host_resource WHERE host_id=%s AND resource_id=%s", (hid, rid)):
                insert(cur, "probe_host_resource", {"task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": sid,
                    "host_id": hid, "resource_id": rid, "source_form": resource["source_form"], "creator": run["creator"], "create_date": now})

    def _endpoint(self, cur, lease, run, sid, ip, port, stage, now):
        if not 1 <= int(port) <= 65535:
            raise ContractError("RESULT_PORT", "invalid port")
        host = one(cur, "SELECT * FROM probe_host WHERE source_group_id=%s AND host_ip=%s", (sid, ip))
        if not host:
            raise ContractError("RESULT_HOST", "port/result refers to an unregistered host")
        endpoint = one(cur, "SELECT * FROM probe_endpoint WHERE source_group_id=%s AND host_ip=%s AND port=%s", (sid, ip, int(port)))
        if not endpoint:
            ident = insert(cur, "probe_endpoint", {"task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": sid,
                "host_id": host["id"], "host_ip": ip, "port": int(port), "discovered_stage": "FULL_PORT" if stage.startswith("FULL") else "PORT_SCAN",
                "creator": run["creator"], "create_date": now})
            endpoint = one(cur, "SELECT * FROM probe_endpoint WHERE id=%s", (ident,))
        return host, endpoint

    def _ports(self, cur, lease, run, sid, stage, row, now):
        ip = str(ipaddress.ip_address(row["ip"]))
        host = one(cur, "SELECT * FROM probe_host WHERE source_group_id=%s AND host_ip=%s", (sid, ip))
        if not host:
            raise ContractError("RESULT_HOST", "scan result has an unknown host")
        ports = sorted({int(p) for p in row.get("ports", [])})
        existing = set(decode(host["open_ports_json"]) if host["open_ports_json"] else [])
        if stage == "FULL_PORT":
            update(cur, "probe_host", host["id"], {"full_port_status": row["status"], "update_date": now})
            if row["status"] != "complete":
                return
            ports = sorted(existing | set(ports))
        update(cur, "probe_host", host["id"], {"open_ports_json": dumps(ports), "host_phase": "PORTS_DONE",
            "scan_status": "open_ports_found" if ports else "scanned_no_open", "scan_mode": row.get("scan_mode", host["scan_mode"]),
            "scan_start_time": host["scan_start_time"] or now, "scan_end_time": now, "update_date": now})
        for port in ports:
            self._endpoint(cur, lease, run, sid, ip, port, stage, now)

    def _result(self, cur, lease, run, sid, stage, event, raw, now):
        observed = datetime.fromisoformat(event["observed_at"]).astimezone(timezone.utc).replace(tzinfo=None) if event.get("observed_at") else now
        detected = observed
        if event["meta"].get("reason") == "INITIAL" and raw.get("scan_time"):
            try:
                parsed = datetime.fromisoformat(raw["scan_time"])
                detected = parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
            except ValueError:
                detected = observed
        mapped = normalize_result(raw, detected)
        _, ep = self._endpoint(cur, lease, run, sid, mapped["host_ip"], mapped["port"], stage, now)
        old = one(cur, "SELECT * FROM probe_asset_port WHERE endpoint_id=%s", (ep["id"],))
        update(cur, "probe_endpoint", ep["id"], {"protocol": mapped["protocol"], "endpoint_status": "DONE",
            "probe_shape": "FRAMEWORK" if mapped.get("service_type") in {"LLM服务","AI模型服务","GPU算力服务","GPU compute"} else "WEB" if mapped.get("service_type") in {"AI前端服务","普通Web"} else "UNKNOWN",
            "current_stage": stage, "scan_status": mapped["scan_status"], "probe_start_time": ep["probe_start_time"] or detected,
            "probe_end_time": ep["probe_end_time"] or detected, "update_date": now})
        if old and old["result_hash"] == mapped["result_hash"]:
            return
        revision = old["revision_no"] + 1 if old else 1
        mapped.update(result_stage_code=stage, result_stage_seq=event["stage_seq"], revision_no=revision)
        if old:
            aid = old["id"]
            update(cur, "probe_asset_port", aid, dict(mapped, update_date=now))
        else:
            aid = insert(cur, "probe_asset_port", dict(mapped, task_id=lease.task_id, run_id=lease.run_id, source_group_id=sid,
                endpoint_id=ep["id"], creator=run["creator"], create_date=now))
        snapshot = dict(mapped, detect_time=mapped["detect_time"].isoformat(timespec="microseconds"))
        insert(cur, "probe_asset_port_history", {"task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": sid,
            "asset_port_id": aid, "revision_no": revision, "stage_code": stage, "stage_seq": event["stage_seq"],
            "event_id": event["event_id"], "change_reason": event["meta"].get("reason", "INITIAL" if not old else stage),
            "result_snapshot_json": dumps(snapshot), "result_hash": mapped["result_hash"], "detect_time": mapped["detect_time"],
            "creator": run["creator"], "create_date": now})
        cur.execute("UPDATE probe_task_run SET result_version=result_version+1 WHERE id=%s", (lease.run_id,))

    def _counts(self, cur, lease, now):
        sources = all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s", (lease.run_id,))
        for source in sources:
            sid = source["id"]
            host = one(cur, "SELECT COUNT(*) AS total,SUM(CASE WHEN host_phase<>'PENDING_SCAN' THEN 1 ELSE 0 END) AS done FROM probe_host WHERE source_group_id=%s", (sid,))
            ep = one(cur, "SELECT COUNT(*) AS total,SUM(CASE WHEN endpoint_status IN ('DONE','FAILED','SKIPPED') THEN 1 ELSE 0 END) AS done FROM probe_endpoint WHERE source_group_id=%s", (sid,))
            stages = all_rows(cur, "SELECT * FROM probe_run_stage WHERE source_group_id=%s", (sid,))
            completed = sum(1 if s["status"] in {"SUCCESS", "PARTIAL", "SKIPPED", "FAILED"} else min(0.99, s["work_finished"] / s["work_total"]) if s["work_total"] else 0 for s in stages)
            progress = 100 if source["status"] in {"SUCCESS","PARTIAL"} else min(99, 100 * completed / len(STAGES))
            update(cur, "probe_run_source", sid, {"host_total": host["total"], "host_finished": host["done"] or 0,
                "endpoint_total": ep["total"], "endpoint_finished": ep["done"] or 0, "progress_percent": progress, "update_date": now})
        sources = all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s", (lease.run_id,))
        values = {c: sum(s[c] for s in sources) for c in ("host_total", "host_finished", "endpoint_total", "endpoint_finished")}
        unique = one(cur, "SELECT COUNT(DISTINCT host_ip) AS n FROM probe_host WHERE run_id=%s", (lease.run_id,))["n"]
        values.update(source_finished=sum(s["status"] in TERMINAL for s in sources), unique_ip_count=unique,
                      progress_percent=min(99, sum(float(s["progress_percent"]) for s in sources) / max(1, len(sources))), update_date=now)
        update(cur, "probe_task_run", lease.run_id, values)

    def result_rows(self, lease, source_id=None):
        with self.db.cursor() as cur:
            run, _, _ = self._locked(cur, lease)
            clause, params = (" AND source_group_id=%s", (lease.run_id, source_id)) if source_id else ("", (lease.run_id,))
            rows = all_rows(cur, "SELECT raw_result_json,task_id,run_id,source_group_id FROM probe_asset_port WHERE run_id=%s" + clause + " ORDER BY source_group_id,id", params)
            return [decode(r["raw_result_json"]) if source_id else dict(decode(r["raw_result_json"]), task_id=r["task_id"], run_id=r["run_id"], source_group_id=r["source_group_id"]) for r in rows], run["result_version"]

    def reserve_artifact(self, lease, source_id, kind, logical, name, stage, version, endpoint=None, revision=None):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            scope, scope_id = ("SOURCE", source_id) if source_id else ("RUN", lease.run_id)
            generation = one(cur, "SELECT MAX(generation_no) AS n FROM probe_artifact WHERE run_id=%s AND scope_type=%s AND scope_id=%s AND logical_name=%s", (lease.run_id, scope, scope_id, logical))["n"] or 0
            aid = insert(cur, "probe_artifact", {"task_id": lease.task_id, "run_id": lease.run_id, "source_group_id": source_id,
                "scope_type": scope, "scope_id": scope_id, "artifact_type": kind, "logical_name": logical, "generation_no": generation + 1,
                "display_name": name, "storage_id": "LOCAL", "relative_path": "pending", "status": "WRITING", "stage_code": stage,
                "result_version": version, "endpoint_id": endpoint, "result_revision_no": revision, "creator": run["creator"], "create_date": now})
            return aid

    def artifact_ready(self, lease, aid, relative, size, checksum, mime, version, metadata=None):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            artifact = one(cur, "SELECT * FROM probe_artifact WHERE id=%s AND run_id=%s", (aid, lease.run_id))
            if not artifact or artifact["status"] != "WRITING" or run["result_version"] != version:
                raise ContractError("ARTIFACT_VERSION", "artifact generation/version changed")
            values = {"relative_path": str(relative), "file_size": size, "file_hash": checksum,
                "mime_type": mime, "status": "READY", "ready_at": now, "metadata_json": dumps(metadata or {}), "update_date": now}
            if metadata and metadata.get("url"):
                values["source_url"] = metadata["url"]
            if metadata and metadata.get("captured_at"):
                try:
                    captured = datetime.fromisoformat(metadata["captured_at"])
                    values["captured_at"] = captured.astimezone(timezone.utc).replace(tzinfo=None) if captured.tzinfo else captured
                except (ValueError,TypeError):
                    pass
            update(cur, "probe_artifact", aid, values)
            if artifact["scope_type"] == "RUN" and artifact["logical_name"] == "final_xlsx":
                update(cur, "probe_task_run", lease.run_id, {"final_artifact_id": aid, "update_date": now})

    def artifact_failed(self, lease, aid, message):
        with self.db.cursor() as cur:
            _, now, _ = self._locked(cur, lease)
            row = one(cur, "SELECT * FROM probe_artifact WHERE id=%s AND run_id=%s", (aid, lease.run_id))
            if row and row["status"] == "WRITING":
                update(cur, "probe_artifact", aid, {"status": "FAILED", "error_message": str(message)[:2000], "update_date": now})

    def fail_abandoned_artifacts(self, lease):
        with self.db.cursor() as cur:
            _, now, _ = self._locked(cur, lease, writable=False)
            cur.execute("UPDATE probe_artifact SET status='FAILED',error_message=%s,update_date=%s WHERE run_id=%s AND status='WRITING'",
                        ("producer interrupted before immutable READY publication", now, lease.run_id))

    def finish(self, lease, status, code=None, message=None):
        with self.db.cursor() as cur:
            run, now, _ = self._locked(cur, lease)
            if run["request_seq"] > run["ack_seq"]:
                return False  # Never pretend that a pending user command succeeded.
            if status == "SUCCESS" and not run["final_artifact_id"]:
                raise ContractError("REPORT_MISSING", "successful run requires its published report")
            self._counts(cur, lease, now)
            summary = decode(run["summary_json"]) if run["summary_json"] else {}
            sources = all_rows(cur, "SELECT * FROM probe_run_source WHERE run_id=%s", (lease.run_id,))
            issues = all_rows(cur, "SELECT source_group_id,stage_code,status,error_code,error_message FROM probe_run_stage WHERE run_id=%s AND status IN ('FAILED','PARTIAL')", (lease.run_id,))
            summary.update(source_total=len(sources),source_success=sum(s["status"]=="SUCCESS" for s in sources),
                           source_partial=sum(s["status"]=="PARTIAL" for s in sources),source_failed=sum(s["status"]=="FAILED" for s in sources),stage_issues=issues[:100])
            update(cur, "probe_task_run", lease.run_id, {"status": status, "finished_at": now, "lease_expires_at": now,
                "progress_percent": 100 if status in {"SUCCESS", "PARTIAL"} else run["progress_percent"],
                "error_code": code or ("SOURCES_FAILED" if status=="FAILED" else "SOURCES_PARTIAL" if status=="PARTIAL" else None),
                "error_message": str(message)[:2000] if message else None, "summary_json": dumps(summary), "update_date": now})
            return True
