"""probe_asset_port 与 asset_llm UPSERT。"""

from __future__ import annotations

import json
import logging
from typing import Optional

from ..db import Database

log = logging.getLogger(__name__)


def upsert_asset_port(
    task_id: int,
    host_ip: str,
    port: int,
    *,
    probe_shape: Optional[str],
    app_type_code: Optional[int],
    asset_verdict: int,
    verdict_rule: Optional[dict],
    fingerprint: Optional[dict],
) -> None:
    """阶段 4 写每端点判定。"""
    rule_json = json.dumps(verdict_rule, ensure_ascii=False) if verdict_rule is not None else None
    fp_json = json.dumps(fingerprint, ensure_ascii=False) if fingerprint is not None else None
    Database.get().execute(
        """
        INSERT INTO probe_asset_port
            (task_id, host_ip, port, probe_shape, app_type_code,
             asset_verdict, verdict_rule_json, fingerprint_json,
             detect_time, insert_time)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            probe_shape       = VALUES(probe_shape),
            app_type_code     = VALUES(app_type_code),
            asset_verdict     = VALUES(asset_verdict),
            verdict_rule_json = VALUES(verdict_rule_json),
            fingerprint_json  = VALUES(fingerprint_json),
            detect_time       = NOW()
        """,
        (
            task_id, host_ip, port, probe_shape, app_type_code,
            asset_verdict, rule_json, fp_json,
        ),
    )


def upsert_asset_llm(
    host_ip: str,
    port: int,
    *,
    probe_shape: Optional[str],
    app_type_code: Optional[int],
    asset_verdict: int,
    verdict_rule: Optional[dict],
    fingerprint: Optional[dict],
    province: str = "",
    operator: str = "",
    house_name: Optional[str] = None,
    reported: int = 0,
) -> None:
    """全局资产表 UPSERT。``detect_source`` 与 'REPORT_DETECT' 合并为 'BOTH'。"""
    rule_json = json.dumps(verdict_rule, ensure_ascii=False) if verdict_rule is not None else None
    fp_json = json.dumps(fingerprint, ensure_ascii=False) if fingerprint is not None else None
    Database.get().execute(
        """
        INSERT INTO asset_llm
            (host_ip, port, province, operator, house_name, reported, detect_source,
             probe_shape, app_type_code, asset_verdict, alive_status,
             verdict_rule_json, fingerprint_json, detect_time, insert_time)
        VALUES (%s,%s,%s,%s,%s,%s,'IP_PROBE',%s,%s,%s,1,%s,%s,NOW(),NOW())
        ON DUPLICATE KEY UPDATE
            probe_shape       = VALUES(probe_shape),
            app_type_code     = VALUES(app_type_code),
            asset_verdict     = VALUES(asset_verdict),
            verdict_rule_json = VALUES(verdict_rule_json),
            fingerprint_json  = VALUES(fingerprint_json),
            detect_source     = IF(detect_source='REPORT_DETECT','BOTH',detect_source),
            alive_status      = 1,
            detect_time       = NOW()
        """,
        (
            host_ip, port, province, operator, house_name, reported,
            probe_shape, app_type_code, asset_verdict,
            rule_json, fp_json,
        ),
    )
