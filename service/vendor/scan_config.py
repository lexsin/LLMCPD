#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan rules configuration loader and match engine for scan_llm.py.

Config file: llm_scan_rules.yaml (schema version 1).
Fallback: if the YAML file is not present, get_default_config() constructs
          an equivalent ScanConfig from hardcoded Python values so the scanner
          can always run standalone.

Match type reference
--------------------
Phase 0 raw-byte checks (operate on raw response bytes):
  raw_prefix              raw.startswith(value.encode())

Phase 1 / Phase 2 body checks (operate on decoded string body):
  body_substring          value in body
  body_substring_ci       value.lower() in body.lower()
  body_substring_any      any(v in body for v in values)
  body_substring_any_ci   any(v.lower() in bl for v in values)
  body_all_substrings_ci  all(v.lower() in bl for v in values)
  body_any_of             any(eval_match(c, body) for c in conditions)

JSON checks (require JSON-parseable body):
  json_has_key            key in json_dict
  json_all_keys_exist     all(k in json_dict for k in keys)
  json_field_eq           json_dict[field] == value
  json_all                all sub-rules in rules pass (op: exists | eq)
  json_nested_contains_ci dotted path "data.0.owned_by" contains value (ci)
  json_list_field         [item[item_field] for item in data[list_key]]  (extraction)
  json_field              data[field]  (extraction)

Phase 3 extraction:
  json_list_field         list extraction (see above)
  json_field              single-field extraction
  error_regex             regex on error message fields with optional filter

Misc:
  always                  always returns True (unconditional fallback)
"""

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    print("pyyaml not installed.  Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Match engine
# ---------------------------------------------------------------------------

def _get_nested(obj: Any, dotted_path: str) -> Any:
    """Traverse a dotted path like 'data.0.owned_by' through dicts and lists."""
    for key in dotted_path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        elif isinstance(obj, list):
            try:
                obj = obj[int(key)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return obj


def eval_match(spec: Dict[str, Any], body: str, raw: bytes = b"") -> bool:
    """Return True if *spec* is satisfied by the HTTP response body."""
    t = spec.get("type", "")

    # ── unconditional ──────────────────────────────────────────────────────
    if t == "always":
        return True

    # ── raw byte prefix (Phase 0) ──────────────────────────────────────────
    if t == "raw_prefix":
        v = spec.get("value", "")
        return raw.startswith(v.encode("utf-8", errors="replace"))

    # ── body substring checks ──────────────────────────────────────────────
    if t == "body_substring":
        return spec.get("value", "") in body

    if t == "body_substring_ci":
        return spec.get("value", "").lower() in body.lower()

    if t == "body_substring_any":
        return any(v in body for v in spec.get("values", []))

    if t == "body_substring_any_ci":
        bl = body.lower()
        return any(v.lower() in bl for v in spec.get("values", []))

    if t == "body_all_substrings_ci":
        bl = body.lower()
        if any(ex.lower() in bl for ex in spec.get("exclude_if_contains", [])):
            return False
        return all(v.lower() in bl for v in spec.get("values", []))

    if t == "body_any_of":
        return any(eval_match(c, body, raw) for c in spec.get("conditions", []))

    # ── JSON checks ────────────────────────────────────────────────────────
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False

    if t == "json_has_key":
        return isinstance(data, dict) and spec.get("key", "") in data

    if t == "json_all_keys_exist":
        return isinstance(data, dict) and all(
            k in data for k in spec.get("keys", [])
        )

    if t == "json_field_eq":
        return (
            isinstance(data, dict)
            and data.get(spec.get("field")) == spec.get("value")
        )

    if t == "json_nested_contains_ci":
        val = _get_nested(data, spec.get("json_path", ""))
        if val is None:
            return False
        return spec.get("value", "").lower() in str(val).lower()

    if t == "json_all":
        if not isinstance(data, dict):
            return False
        for rule in spec.get("rules", []):
            op = rule.get("op", "exists")
            f = rule.get("field", "")
            if op == "exists":
                if f not in data:
                    return False
            elif op == "eq":
                if data.get(f) != rule.get("value"):
                    return False
        return True

    return False


def extract_models(spec: Dict[str, Any], body: str) -> List[str]:
    """
    Extract model name(s) from a response body according to an extraction spec.
    Returns a (possibly empty) list of name strings.
    """
    t = spec.get("type", "")

    if t == "json_list_field":
        try:
            d = json.loads(body)
            if not isinstance(d, dict):
                return []
            items = d.get(spec["list_key"]) or []
            return [
                str(item.get(spec["item_field"], ""))
                for item in items
                if isinstance(item, dict) and item.get(spec["item_field"])
            ]
        except (json.JSONDecodeError, KeyError, AttributeError):
            return []

    if t == "json_field":
        try:
            d = json.loads(body)
            val = d.get(spec.get("field", ""), "") if isinstance(d, dict) else ""
            return [str(val)] if val else []
        except (json.JSONDecodeError, AttributeError):
            return []

    if t == "error_regex":
        regex = spec.get("regex", "")
        if not regex:
            return []
        filt = spec.get("filter", {})
        min_len = filt.get("min_len", 0)
        max_len = filt.get("max_len", 9999)
        must_chars = filt.get("must_contain_any_char", [])
        exclude_pats = [ep.lower() for ep in spec.get("exclude_patterns", [])]
        try:
            d = json.loads(body)
            msg = (
                str(d.get("message", ""))
                + str(d.get("detail", ""))
                + str(d.get("error", ""))
            )
        except (json.JSONDecodeError, AttributeError):
            msg = body

        def _passes_filter(c: str) -> bool:
            if not (min_len < len(c) < max_len):
                return False
            if must_chars and not any(ch in c for ch in must_chars):
                return False
            if exclude_pats and c.lower() in exclude_pats:
                return False
            return True

        # context_patterns: more precise regexes tried first
        context_patterns = spec.get("context_patterns", [])
        if context_patterns:
            ctx_results: List[str] = []
            for cp in context_patterns:
                try:
                    ctx_results.extend(re.findall(cp, msg))
                except re.error:
                    pass
            precise = [c for c in ctx_results if _passes_filter(c)]
            if precise:
                return precise

        # Fallback to general regex
        candidates = re.findall(regex, msg)
        return [c for c in candidates if _passes_filter(c)]

    return []


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PhaseRuntime:
    concurrency: int
    timeout: int
    retries: int = 0


@dataclass
class GpuProbeRuntime:
    concurrency: int
    timeout: int
    retries: int = 2
    retry_delays: List[float] = field(default_factory=lambda: [0.5, 1.0])


@dataclass
class Phase2Runtime:
    concurrency: int
    timeout: int
    max_extra_gets: int = 3
    retries: int = 0


@dataclass
class RuntimeConfig:
    phase0: PhaseRuntime
    phase1: PhaseRuntime
    gpu_probe: GpuProbeRuntime
    phase2: Phase2Runtime
    phase3: PhaseRuntime


@dataclass
class Phase0Config:
    non_http_prefixes: List[bytes]
    binary_threshold: float


@dataclass
class Phase1Config:
    probe_paths: List[str]
    confirm_rules: List[Dict]
    suspect_keywords: List[str]
    suspect_predicates: List[Dict]
    guards: List[Dict]
    auth_suspect: Optional[Dict] = None  # {status_codes: [...], body_keywords: [...]}
    js_bundle_suspect: Dict = field(default_factory=dict)


@dataclass
class Phase2ToolConfig:
    name: str
    scope: List[str]           # e.g. ["confirmed", "suspect"]
    match: Optional[Dict]
    supplements: List[Dict]
    version_from: Optional[Dict]
    requires_cached_ok: Optional[str]   # path that must be cached 200 to even attempt


@dataclass
class Phase2Config:
    tools: List[Phase2ToolConfig]


@dataclass
class Phase3Config:
    cache_sources: List[Dict]
    post_probes: List[Dict]
    fallback_literal: str


@dataclass
class ScanConfig:
    version: int
    runtime: RuntimeConfig
    phase0: Phase0Config
    phase1: Phase1Config
    phase2: Phase2Config
    phase3: Phase3Config
    ai_service: Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# YAML parser helpers
# ---------------------------------------------------------------------------

def _parse_runtime(d: dict) -> RuntimeConfig:
    def _pr(sd: dict, *, concurrency: int, timeout: int, retries: int = 0) -> PhaseRuntime:
        return PhaseRuntime(
            concurrency=sd.get("concurrency", concurrency),
            timeout=sd.get("timeout", timeout),
            retries=sd.get("retries", retries),
        )

    r = d.get("runtime", {})
    gpd = r.get("gpu_probe", {})
    p2d = r.get("phase2", {})
    return RuntimeConfig(
        phase0=_pr(r.get("phase0", {}), concurrency=500, timeout=3, retries=1),
        phase1=_pr(r.get("phase1", {}), concurrency=300, timeout=5),
        gpu_probe=GpuProbeRuntime(
            concurrency=int(gpd.get("concurrency", 20)),
            timeout=int(gpd.get("timeout", 10)),
            retries=int(gpd.get("retries", 2)),
            retry_delays=[
                float(v) for v in gpd.get("retry_delays", [0.5, 1.0])
            ],
        ),
        phase2=Phase2Runtime(
            concurrency=p2d.get("concurrency", 200),
            timeout=p2d.get("timeout", 5),
            max_extra_gets=p2d.get("max_extra_gets", 3),
        ),
        phase3=_pr(r.get("phase3", {}), concurrency=100, timeout=10, retries=1),
    )


def _parse_phase0(d: dict) -> Phase0Config:
    p = d.get("phase0", {})
    return Phase0Config(
        non_http_prefixes=[
            s.encode("utf-8") for s in p.get("non_http_prefixes", [])
        ],
        binary_threshold=float(p.get("binary_threshold", 0.30)),
    )


def _parse_phase1(d: dict) -> Phase1Config:
    p = d.get("phase1", {})
    suspect = p.get("suspect", {})
    return Phase1Config(
        probe_paths=p.get("probe_paths", []),
        confirm_rules=p.get("confirm_rules", []),
        suspect_keywords=suspect.get("keywords", []),
        suspect_predicates=suspect.get("extra_predicates", []),
        guards=p.get("guards", []),
        auth_suspect=p.get("auth_suspect"),
        js_bundle_suspect=p.get("js_bundle_suspect", {}),
    )


def _parse_phase2(d: dict) -> Phase2Config:
    tools = []
    for t in d.get("phase2", {}).get("tools", []):
        tools.append(Phase2ToolConfig(
            name=str(t["name"]),
            scope=t.get("scope", ["confirmed"]),
            match=t.get("match"),
            supplements=t.get("supplements", []),
            version_from=t.get("version_from"),
            requires_cached_ok=t.get("requires_cached_ok"),
        ))
    return Phase2Config(tools=tools)


def _parse_phase3(d: dict) -> Phase3Config:
    p = d.get("phase3", {})
    return Phase3Config(
        cache_sources=p.get("cache_sources", []),
        post_probes=p.get("post_probes", []),
        fallback_literal=p.get("fallback_literal", "未知"),
    )


def _parse_config_dict(raw: dict) -> ScanConfig:
    return ScanConfig(
        version=int(raw.get("version", 1)),
        runtime=_parse_runtime(raw),
        phase0=_parse_phase0(raw),
        phase1=_parse_phase1(raw),
        phase2=_parse_phase2(raw),
        phase3=_parse_phase3(raw),
        ai_service=raw.get("ai_service", {}),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(path: Path) -> ScanConfig:
    """Load and parse a YAML config file.  Raises on parse errors."""
    with path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError("Config file must be a YAML mapping: %s" % path)
    return _parse_config_dict(raw)


def get_default_config() -> ScanConfig:
    """
    Return the default ScanConfig.  Looks for llm_scan_rules.yaml next to
    this file first; falls back to hardcoded Python values if not found,
    so the scanner can always run standalone without the YAML file.
    """
    yaml_path = Path(__file__).resolve().parent / "llm_scan_rules.yaml"
    if yaml_path.is_file():
        return load_config(yaml_path)
    return _build_hardcoded_default()


def _build_hardcoded_default() -> ScanConfig:
    """Construct the default config without reading any file."""
    return ScanConfig(
        version=1,
        runtime=RuntimeConfig(
            phase0=PhaseRuntime(concurrency=500, timeout=3, retries=1),
            phase1=PhaseRuntime(concurrency=300, timeout=5),
            gpu_probe=GpuProbeRuntime(
                concurrency=20, timeout=10, retries=2,
                retry_delays=[0.5, 1.0],
            ),
            phase2=Phase2Runtime(concurrency=200, timeout=5, max_extra_gets=3),
            phase3=PhaseRuntime(concurrency=100, timeout=10, retries=1),
        ),
        phase0=Phase0Config(
            non_http_prefixes=[
                b"-ERR", b"+OK", b"+PONG",
                b"SSH-2.0",
                b"* OK", b"* BYE",
                b"220 ",
                b"RFB ",
                b"\xff\xfd",
                b"\x4a\x00\x00\x00",
                b"N\x00\x00\x00",
            ],
            binary_threshold=0.30,
        ),
        phase1=Phase1Config(
            probe_paths=[
                "/v1/models", "/api/v1/models", "/openai/v1/models",
                "/api/tags", "/api/version",
                "/info", "/health", "/docs", "/v2/models", "/",
            ],
            confirm_rules=[
                {
                    "path": "/v1/models", "when_status": 200,
                    "match": {"type": "json_all", "rules": [
                        {"field": "object", "op": "eq", "value": "list"},
                        {"field": "data",   "op": "exists"},
                    ]},
                },
                {
                    "path": "/api/v1/models", "when_status": 200,
                    "cache_also_as": "/v1/models",
                    "match": {"type": "json_all", "rules": [
                        {"field": "object", "op": "eq", "value": "list"},
                        {"field": "data",   "op": "exists"},
                    ]},
                },
                {
                    "path": "/openai/v1/models", "when_status": 200,
                    "cache_also_as": "/v1/models",
                    "match": {"type": "json_all", "rules": [
                        {"field": "object", "op": "eq", "value": "list"},
                        {"field": "data",   "op": "exists"},
                    ]},
                },
                {
                    "path": "/api/tags", "when_status": 200,
                    "match": {"type": "json_has_key", "key": "models"},
                },
                {
                    "path": "/api/version", "when_status": 200,
                    "match": {"type": "json_has_key", "key": "version"},
                },
                {
                    "path": "/info", "when_status": 200,
                    "match": {"type": "json_has_key", "key": "model_id"},
                },
                {
                    "path": "/v2/models", "when_status": 200,
                    "match": {"type": "json_has_key", "key": "models"},
                },
                {
                    "path": "/docs", "when_status": "any",
                    "match": {"type": "body_substring_any", "values": [
                        "/v1/chat/completions", "/v1/embeddings", "/api/generate",
                    ]},
                },
            ],
            suspect_keywords=[
                "gradio", "streamlit", "open-webui",
                "__gradio_mode__", "_stcore",
                "LibreChat", "New API", "new-api",
                "OpenAI 接口聚合", "模型聚合与分发网关",
                "大模型知识库", "大语言模型知识库", "智能问答知识库",
            ],
            suspect_predicates=[
                {
                    "type": "body_all_substrings_ci",
                    "values": ["chat", "model"],
                    "exclude_if_contains": [
                        "copyright", "terms of service", "privacy policy",
                    ],
                },
                {
                    "type": "json_all",
                    "rules": [
                        {"field": "model_class", "op": "exists"},
                        {"field": "status", "op": "eq", "value": "UP"},
                    ],
                },
            ],
            guards=[
                {
                    "description": "frontend UI overrides weak API signal",
                    "root_contains_any": [
                        "open webui", "open-webui", "__gradio_mode__",
                        "gradio-app", "_stcore", "streamlit",
                    ],
                    "downgrade_for_paths": ["/api/version", "/v1/models"],
                },
            ],
            auth_suspect={
                "status_codes": [401, 403],
                "body_keywords": [
                    "bearer", "api-key", "api_key", "openai", "llm",
                ],
                "exclude_body_patterns": [
                    "<?xml",
                    "<Code>AccessDenied</Code>",
                    "InvalidSecurity",
                    "SignatureDoesNotMatch",
                    "NoSuchBucket",
                    "InvalidAccessKeyId",
                ],
            },
            js_bundle_suspect={"enabled": False},
        ),
        phase2=Phase2Config(tools=[
            Phase2ToolConfig(
                name="open-webui", scope=["confirmed", "suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": ["open webui", "open-webui"]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="one-api", scope=["confirmed", "suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": [
                           "One API", "New API", "new-api",
                           "OpenAI 接口聚合", "模型聚合与分发网关",
                       ]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="librechat", scope=["suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": ["LibreChat"]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="llm-knowledge-base", scope=["suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": [
                           "大模型知识库", "大语言模型知识库", "智能问答知识库",
                       ]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="AI模型服务", scope=["suspect"],
                match={"source": "root", "type": "json_all", "rules": [
                    {"field": "model_class", "op": "exists"},
                    {"field": "status", "op": "eq", "value": "UP"},
                ]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="ollama", scope=["confirmed"],
                match={"source": "cached:/api/tags", "type": "json_has_key",
                       "key": "models"},
                supplements=[{"source": "get:/api/tags", "type": "json_has_key",
                              "key": "models"}],
                version_from={"source": "cached_or_get:/api/version",
                              "type": "json_field", "field": "version"},
                requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="tgi", scope=["confirmed"],
                match={"source": "cached:/info", "type": "json_all_keys_exist",
                       "keys": ["model_id", "max_input_length"]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="vllm", scope=["confirmed"],
                match={"source": "cached:/v1/models",
                       "type": "json_nested_contains_ci",
                       "json_path": "data.0.owned_by", "value": "vllm"},
                supplements=[{"source": "get:/metrics", "type": "body_substring",
                              "value": "vllm_"}],
                version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="TensorRT-LLM", scope=["confirmed"],
                match={"source": "cached_or_get:/metrics",
                       "type": "body_substring_any_ci",
                       "values": [
                           "tensorrt_llm", "TensorRT-LLM",
                           "nvidia_trt_llm", "triton_tensorrt_llm",
                       ]},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="llama.cpp", scope=["confirmed"],
                match={"source": "get:/props", "type": "body_substring",
                       "value": "default_generation_settings"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="sglang", scope=["confirmed"],
                match={"source": "get:/get_server_info", "type": "body_substring_ci",
                       "value": "sglang"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="litellm", scope=["confirmed"],
                match={"source": "get:/model/info", "type": "body_substring_ci",
                       "value": "litellm_params"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="fastchat", scope=["confirmed"],
                match={"source": "cached_or_get:/docs", "type": "body_substring_ci",
                       "value": "fastchat"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="xinference", scope=["confirmed"],
                match={"source": "cached_or_get:/docs", "type": "body_substring_ci",
                       "value": "xinference"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="localai", scope=["confirmed"],
                match={"source": "cached_or_get:/docs",
                       "type": "body_substring_any_ci",
                       "values": ["localai", "models/available"]},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="未知-OpenAI兼容", scope=["confirmed"],
                match={"type": "always"},
                supplements=[], version_from=None,
                requires_cached_ok="/v1/models",
            ),
            Phase2ToolConfig(
                name="triton", scope=["confirmed"],
                match={"source": "cached:/v2/models", "type": "json_has_key",
                       "key": "models"},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="langserve", scope=["confirmed"],
                match={"source": "cached_or_get:/docs", "type": "body_any_of",
                       "conditions": [
                           {"type": "body_substring_ci", "value": "langserve"},
                           {"type": "body_all_substrings_ci",
                            "values": ["invoke", "stream"]},
                       ]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="gradio", scope=["confirmed", "suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": ["__gradio_mode__", "gradio-app", "gradio"]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="streamlit", scope=["confirmed", "suspect"],
                match={"source": "root", "type": "body_substring_any_ci",
                       "values": ["_stcore", "streamlitapp", "streamlit"]},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
            Phase2ToolConfig(
                name="open-webui", scope=["confirmed"],
                match={"source": "root", "type": "body_substring_ci",
                       "value": "open-webui"},
                supplements=[], version_from=None, requires_cached_ok=None,
            ),
        ]),
        phase3=Phase3Config(
            cache_sources=[
                {"path": "/",
                 "extract": {"type": "json_field", "field": "model_class"}},
                {"path": "/v1/models",
                 "extract": {"type": "json_list_field",
                             "list_key": "data", "item_field": "id"}},
                {"path": "/api/tags",
                 "extract": {"type": "json_list_field",
                             "list_key": "models", "item_field": "name"}},
                {"path": "/info",
                 "extract": {"type": "json_field", "field": "model_id"}},
            ],
            post_probes=[
                {
                    "path": "/v1/chat/completions", "method": "POST",
                    "body": {"model": "test",
                             "messages": [{"role": "user", "content": "hi"}],
                             "max_tokens": 1},
                    "on_success": {"status": [200],
                                   "extract": {"type": "json_field",
                                               "field": "model"}},
                    "on_error": {
                        "status": [400, 404, 422],
                        "extract": {
                            "type": "error_regex",
                            "regex": '"([a-zA-Z0-9_\\-./: ]+)"',
                            "context_patterns": [
                                r'model["\s:=]+([a-zA-Z0-9_\-./]+)',
                                r"model '([a-zA-Z0-9_\-./]+)'",
                            ],
                            "exclude_patterns": [
                                "test", "your-model-id", "string", "null",
                                "none", "example",
                            ],
                            "filter": {"min_len": 3, "max_len": 80,
                                       "must_contain_any_char": ["/", ":", "-"]},
                        },
                    },
                },
                {
                    "path": "/api/generate", "method": "POST",
                    "body": {"model": "test", "prompt": "hi", "stream": False},
                    "on_error": {
                        "status": [400, 404, 422],
                        "extract": {
                            "type": "error_regex",
                            "regex": '"([a-zA-Z0-9_\\-./: ]+)"',
                            "context_patterns": [
                                r'model["\s:=]+([a-zA-Z0-9_\-./]+)',
                                r"model '([a-zA-Z0-9_\-./]+)'",
                            ],
                            "exclude_patterns": [
                                "test", "your-model-id", "string", "null",
                                "none", "example",
                            ],
                            "filter": {"min_len": 3, "max_len": 80,
                                       "must_contain_any_char": ["/", ":", "-"]},
                        },
                    },
                },
            ],
            fallback_literal="未知",
        ),
        ai_service={
            "gpu_probe_paths": ["/metrics", "/api/ps"],
            "gpu_keywords": [
                "cuda", "gpu", "nvidia", "tensorrt", "onnxruntime-gpu",
                "torch.cuda", "device: cuda", "dcgm",
            ],
            "gpu_direct_keywords": [
                "dcgm_", "DCGM_FI_DEV_", "nvidia-smi",
                "cuda_visible_devices", "gpu_uuid", "gpu_device_name",
                "gpu_device_count", "nv_gpu_", "tritonserver_gpu",
            ],
            "gpu_inference_keywords": [
                "nv_inference_", "nv_model_", "vllm_",
                "tgi_", "triton_inference",
            ],
            "tensorrt_llm_keywords": [
                "tensorrt_llm", "TensorRT-LLM", "nvidia_trt_llm",
                "triton_tensorrt_llm",
            ],
            "vision_keywords": [
                "yolo", "grounding", "detection", "segmentation",
                "visual", "vision",
            ],
            "ocr_keywords": ["ocr", "paddleocr"],
            "frontend_keywords": [
                "open-webui", "dify", "librechat", "new-api", "New API",
                "OpenAI 接口聚合", "模型聚合与分发网关",
                "大模型知识库", "大语言模型知识库", "智能问答知识库",
                "chatcomposer", "chatplaygroundpage",
                "aichat", "chat-ai-window", "jy-chat",
            ],
            "gpu_business_keywords": [
                "租GPU", "GPU租赁", "云GPU", "BitaHub", "彼塔云",
            ],
        },
    )
