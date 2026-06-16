"""LLM 指纹探测的纯函数封装。

直接复用 ``vendor/scan_llm.py`` 的 Phase 0-3 函数与 ``_apply_service_classification``,
跳过它的 CSV-bound ``run_pipeline``。

入口:协程 :func:`probe_endpoints`,接受 ``List[(ip, port)]``,返回每个端点的判定 dict。
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import bootstrap_test_path

bootstrap_test_path()

import scan_llm as _slm  # noqa: E402
import scan_config as _scfg  # noqa: E402
from scan_config import ScanConfig, get_default_config, load_config  # noqa: E402

log = logging.getLogger(__name__)


_VERDICT_MAP = {
    "确认": 1,  # asset_verdict: 1=已确认LLM
    "疑似": 2,  # 2=疑似LLM
    "否": 0,    # 0=非LLM/不足证
}


_APP_TYPE_BY_SERVICE = {
    "LLM服务": 2,         # 2=定制化/私有化部署
    "AI模型服务": 2,
    "AI前端服务": 1,       # 1=平台化服务
    "普通Web": None,
    "非HTTP": None,
}


def _to_shape(state: "_slm.TargetState") -> str:
    """根据 service_type 推 probe_shape ∈ {FRAMEWORK, WEB, UNKNOWN}。"""
    st = (state.service_type or "").strip()
    if st in {"LLM服务", "AI模型服务"}:
        return "FRAMEWORK"
    if st in {"AI前端服务", "普通Web"}:
        return "WEB"
    return "UNKNOWN"


def load_scan_config(rules_yaml: Optional[str]) -> ScanConfig:
    """加载规则。``rules_yaml`` 为 None 时:先试 vendor/llm_scan_rules.yaml,缺失则用内置默认。"""
    if rules_yaml:
        return load_config(Path(rules_yaml))
    vendor_dir = bootstrap_test_path()
    candidate = vendor_dir / "llm_scan_rules.yaml"
    if candidate.is_file():
        log.info("loading scan rules: %s", candidate)
        return load_config(candidate)
    log.info("scan rules YAML missing, using built-in defaults")
    return get_default_config()


async def probe_endpoints(
    endpoints: List[Tuple[str, int]],
    cfg: ScanConfig,
    *,
    concurrency_override: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """对一批 (ip, port) 跑完 Phase 0-3,返回每个端点的判定 dict。

    返回字段(每个 endpoint 一行):
        ip, port, host_phase_ok(bool), probe_shape, app_type_code,
        asset_verdict(int 0/1/2), verdict_rule(dict), fingerprint(dict),
        scan_time(str)
    """
    if not endpoints:
        return []

    rt = cfg.runtime
    p0_c = concurrency_override or rt.phase0.concurrency
    p1_c = concurrency_override or rt.phase1.concurrency
    p2_c = concurrency_override or rt.phase2.concurrency
    p3_c = concurrency_override or rt.phase3.concurrency

    # scan_llm 内部都用 (ip:str, port:str) 元组
    str_targets: List[Tuple[str, str]] = [(ip, str(port)) for ip, port in endpoints]

    # Phase 0
    states = await _slm.phase0_protocol(str_targets, p0_c, cfg)
    http_alive = [s for s in states if s.protocol]
    excluded = [s for s in states if not s.protocol]

    ts = _now()
    for s in excluded:
        s.scan_time = ts

    # Phase 1
    if http_alive:
        http_alive = await _slm.phase1_fingerprint(http_alive, p1_c, cfg)

    confirmed = [s for s in http_alive if s.is_llm == "确认"]
    suspect = [s for s in http_alive if s.is_llm == "疑似"]

    # Phase 2: 已确认 + 疑似
    phase2_targets = confirmed + suspect
    if phase2_targets:
        phase2_targets = await _slm.phase2_deploy(phase2_targets, p2_c, cfg)

    # Phase 3: 已确认 LLM + 检测到 model_class 的服务
    phase3_targets = [
        s for s in phase2_targets
        if s.is_llm == "确认" or _slm._root_model_class(s)[0]
    ]
    if phase3_targets:
        phase3_targets = await _slm.phase3_model(phase3_targets, p3_c, cfg)

    ts = _now()
    for s in http_alive + excluded:
        if not s.scan_time:
            s.scan_time = ts

    state_map: Dict[str, "_slm.TargetState"] = {}
    for s in phase2_targets:
        state_map[f"{s.ip}:{s.port}"] = s
    for s in phase3_targets:
        state_map[f"{s.ip}:{s.port}"] = s

    final_states: List["_slm.TargetState"] = []
    for s in excluded:
        final_states.append(s)
    for s in http_alive:
        final_states.append(state_map.get(f"{s.ip}:{s.port}", s))

    for s in final_states:
        _slm._apply_service_classification(s, cfg)

    return [_state_to_record(s) for s in final_states]


def _state_to_record(state: "_slm.TargetState") -> Dict[str, Any]:
    verdict = _VERDICT_MAP.get(state.is_llm, 0)
    shape = _to_shape(state)
    app_type = _APP_TYPE_BY_SERVICE.get(state.service_type or "")

    fingerprint = {
        "protocol": state.protocol,
        "service_type": state.service_type,
        "model_domain": state.model_domain,
        "deploy_tool": state.deploy_tool,
        "deploy_version": state.deploy_version,
        "model_info": state.model_info,
        "gpu_likelihood": state.gpu_likelihood,
        "gpu_evidence": state.gpu_evidence,
        "scan_time": state.scan_time,
        "evidence_preview": (state.evidence_str() or "")[:1000],
    }
    verdict_rule = {
        "ruleSet": "llm_scan_rules.yaml",
        "is_llm_label": state.is_llm,
        "evidence_links": state.link_str()[:1000] if state.links else "",
    }
    return {
        "ip": state.ip,
        "port": int(state.port) if str(state.port).isdigit() else state.port,
        "probe_shape": shape,
        "app_type_code": app_type,
        "asset_verdict": verdict,
        "verdict_rule": verdict_rule,
        "fingerprint": fingerprint,
        "scan_time": state.scan_time,
        "is_http": bool(state.protocol),
    }


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
