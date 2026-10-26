from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .common import ContractError, atomic_json, digest, dumps


class Outbox:
    """Immutable fsynced payloads. A scan checkpoint may advance only after emit returns."""
    def __init__(self, root, task_id, run_id, source_id, stage):
        self.root = Path(root) / "outbox" / f"{int(source_id or 0)}_{stage}"
        self.root.mkdir(parents=True, exist_ok=True)
        self.task_id, self.run_id, self.source_id, self.stage = task_id, run_id, source_id, stage
        self.seq = max((int(p.name.split("-", 1)[0]) for p in self.root.glob("*.json")), default=0)
        self.lock = threading.Lock()

    def emit(self, kind, rows=None, **meta):
        with self.lock:
            self.seq += 1
            event = {"schema_version": 1, "event_id": str(uuid.uuid4()), "task_id": self.task_id,
                     "run_id": self.run_id, "source_group_id": self.source_id, "stage_code": self.stage,
                     "stage_seq": self.seq, "event_type": kind, "rows": rows or [], "meta": meta}
            event["observed_at"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
            event["payload_hash"] = digest(dumps(event).encode("utf-8"))
            path = self.root / f"{self.seq:012d}-{event['event_id']}.json"
            atomic_json(path, event)
            return path


def read_event(path):
    try:
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        expected = event.pop("payload_hash")
        if digest(dumps(event).encode("utf-8")) != expected:
            raise ValueError("checksum")
        event["payload_hash"] = expected
        if event["schema_version"] != 1 or event["stage_seq"] < 1:
            raise ValueError("version/sequence")
        return event
    except (ValueError, KeyError, TypeError) as exc:
        raise ContractError("EVENT_CORRUPT", f"invalid durable event: {Path(path).name}") from exc


def replay(root, commit):
    # Stage sequence is ordered within each source/stage directory, not by UUID.
    for directory in sorted((Path(root) / "outbox").glob("*")):
        for path in sorted(directory.glob("*.json")):
            commit(read_event(path), path)
