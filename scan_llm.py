#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM service port scanner — Phase 0–3 async HTTP probing.

Usage:
    python3 scan_llm.py --input IPs_1_result_scan_2.csv --output IPs_1_result_llm.csv
    python3 scan_llm.py --limit 50 --output test_out.csv
    python3 scan_llm.py --resume --checkpoint llm_scan_checkpoint.jsonl
"""

import argparse
import asyncio
import csv
import json
import re
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    print("aiohttp not installed. Run: pip install aiohttp>=3.9.0", file=sys.stderr)
    sys.exit(1)

from scan_config import ScanConfig, eval_match, extract_models, get_default_config, load_config

# ---------------------------------------------------------------------------
# Fixed operational constants (not fingerprint-related, not in config)
# ---------------------------------------------------------------------------

BODY_LIMIT = 1024 * 256   # bytes read per response
EVIDENCE_BODY_MAX = 1000  # chars kept per evidence snippet
EVIDENCE_SEP = "|||"

OUTPUT_FIELDNAMES = [
    "ip", "port", "protocol", "is_llm",
    "deploy_tool", "deploy_version", "model_info", "evidence", "link", "scan_time",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    status: int = 0
    body: str = ""
    error: str = ""


@dataclass
class TargetState:
    ip: str
    port: str
    protocol: str = ""            # http / https / ""
    is_llm: str = "否"
    deploy_tool: str = ""
    deploy_version: str = ""
    model_info: str = ""
    evidence: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    probes: Dict[str, ProbeResult] = field(default_factory=dict)  # path -> ProbeResult
    scan_time: str = ""

    def add_evidence(self, method: str, path: str, status: int, body: str) -> None:
        snippet = body[:EVIDENCE_BODY_MAX]
        self.evidence.append("%s %s %d: %s" % (method, path, status, snippet))
        # Build the clickable URL for this evidence entry
        if self.protocol and self.ip and self.port:
            self.links.append("%s://%s:%s%s" % (self.protocol, self.ip, self.port, path))
        else:
            self.links.append("")

    def evidence_str(self) -> str:
        return EVIDENCE_SEP.join(self.evidence)

    def link_str(self) -> str:
        return EVIDENCE_SEP.join(self.links)

    def to_row(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "is_llm": self.is_llm,
            "deploy_tool": self.deploy_tool,
            "deploy_version": self.deploy_version,
            "model_info": self.model_info,
            "evidence": self.evidence_str(),
            "link": self.link_str(),
            "scan_time": self.scan_time,
        }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def fetch(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: int,
    json_body: Optional[dict] = None,
) -> Tuple[int, bytes, str]:
    """Return (status, raw_bytes, error_str). Never raises."""
    try:
        kwargs: dict = {
            "timeout": aiohttp.ClientTimeout(total=timeout),
            "ssl": make_ssl_ctx(),
            "allow_redirects": True,
        }
        if json_body is not None:
            kwargs["json"] = json_body
        async with session.request(method, url, **kwargs) as resp:
            raw = await resp.content.read(BODY_LIMIT)
            return resp.status, raw, ""
    except asyncio.TimeoutError:
        return 0, b"", "timeout"
    except aiohttp.ClientConnectorError as e:
        return 0, b"", "connect_error: %s" % str(e)[:120]
    except aiohttp.ClientError as e:
        return 0, b"", "client_error: %s" % str(e)[:120]
    except Exception as e:
        return 0, b"", "error: %s" % str(e)[:120]


def decode_body(raw: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def is_binary(raw: bytes, threshold: float = 0.30) -> bool:
    """Heuristic: if > threshold fraction of bytes are non-printable, treat as binary."""
    if not raw:
        return False
    sample = raw[:512]
    non_text = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20) or b == 0x7F)
    return non_text / len(sample) > threshold


def base_url(protocol: str, ip: str, port: str) -> str:
    return "%s://%s:%s" % (protocol, ip, port)


# ---------------------------------------------------------------------------
# Phase 0 — Protocol probe
# ---------------------------------------------------------------------------

async def _phase0_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    ip: str,
    port: str,
    cfg: ScanConfig,
) -> TargetState:
    state = TargetState(ip=ip, port=port)
    p0 = cfg.phase0
    rt = cfg.runtime.phase0

    async with sem:
        for proto in ("http", "https"):
            url = "%s://%s:%s/" % (proto, ip, port)
            attempts = rt.retries + 1
            status, raw, err = 0, b"", ""
            for _ in range(attempts):
                status, raw, err = await fetch(session, "GET", url, rt.timeout)
                if status != 0 or err != "timeout":
                    break

            if status == 0:
                continue

            # Got an HTTP response — check non-HTTP fingerprints
            for prefix in p0.non_http_prefixes:
                if raw.startswith(prefix):
                    state.evidence.append(
                        "Phase0: non-HTTP fingerprint (%s)"
                        % prefix.decode("utf-8", errors="replace")
                    )
                    state.scan_time = _now()
                    return state

            # Skip binary check when the response is a valid HTTP reply
            # (e.g. gzip-encoded body starts with 0x1f 0x8b which looks binary).
            if not raw.startswith(b"HTTP/") and is_binary(raw, p0.binary_threshold):
                state.evidence.append("Phase0: binary response, non-HTTP")
                state.scan_time = _now()
                return state

            # HTTP alive
            state.protocol = proto
            body = decode_body(raw)
            state.add_evidence("GET", "/", status, body)
            state.probes["/"] = ProbeResult(status=status, body=body)
            return state

        state.evidence.append("Phase0: no HTTP response (http/https both failed)")
        state.scan_time = _now()
        return state


async def phase0_protocol(
    targets: List[Tuple[str, str]], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_phase0_single(sem, session, ip, port, cfg) for ip, port in targets]
        states = await asyncio.gather(*tasks)
    return list(states)


# ---------------------------------------------------------------------------
# Phase 1 — LLM fingerprinting (config-driven)
# ---------------------------------------------------------------------------

def _phase1_check_confirmed(
    path: str, status: int, body: str, cfg: ScanConfig
) -> Optional[Dict]:
    """Return the matching confirm rule dict, or None if no rule matched."""
    for rule in cfg.phase1.confirm_rules:
        if rule.get("path") != path:
            continue
        when = rule.get("when_status", 200)
        if when != "any" and status != when:
            continue
        if eval_match(rule["match"], body):
            return rule
    return None


def _phase1_check_suspect(body: str, cfg: ScanConfig) -> bool:
    """Return True if the root-page body exhibits frontend/suspect signals."""
    bl = body.lower()
    for kw in cfg.phase1.suspect_keywords:
        if kw in bl:
            return True
    for pred in cfg.phase1.suspect_predicates:
        if eval_match(pred, body):
            return True
    return False


async def _phase1_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> TargetState:
    proto = state.protocol
    ip, port = state.ip, state.port
    rt = cfg.runtime.phase1
    has_auth_signal = False

    async with sem:
        for path in cfg.phase1.probe_paths:
            # Reuse root cached from Phase 0
            if path == "/" and "/" in state.probes:
                pr = state.probes["/"]
                status, body = pr.status, pr.body
            else:
                url = "%s://%s:%s%s" % (proto, ip, port, path)
                status, raw, err = await fetch(session, "GET", url, rt.timeout)
                if status == 0:
                    state.probes[path] = ProbeResult(error=err)
                    if path == "/":
                        break
                    continue
                body = decode_body(raw)
                state.probes[path] = ProbeResult(status=status, body=body)

            if path != "/":
                # Check for auth-gated LLM signal (401/403 with relevant keywords)
                auth_cfg = cfg.phase1.auth_suspect
                if auth_cfg and status in auth_cfg.get("status_codes", []):
                    bl = body.lower()
                    exclude_pats = auth_cfg.get("exclude_body_patterns", [])
                    if not any(ep.lower() in bl for ep in exclude_pats):
                        if any(kw in bl for kw in auth_cfg.get("body_keywords", [])):
                            has_auth_signal = True

                matched_rule = _phase1_check_confirmed(path, status, body, cfg)
                if matched_rule is not None:
                    # Store under alias path if rule specifies cache_also_as
                    alias = matched_rule.get("cache_also_as")
                    if alias and alias not in state.probes:
                        state.probes[alias] = state.probes[path]
                    # Apply guards: downgrade "确认" to "疑似" for weak paths
                    root_pr = state.probes.get("/")
                    root_body = root_pr.body.lower() if root_pr and root_pr.status > 0 else ""
                    downgraded = False
                    for guard in cfg.phase1.guards:
                        if path in guard.get("downgrade_for_paths", []):
                            if any(kw in root_body for kw in guard.get("root_contains_any", [])):
                                state.is_llm = "疑似"
                                state.add_evidence("GET", path, status, body)
                                downgraded = True
                                break
                    if not downgraded:
                        state.is_llm = "确认"
                        state.add_evidence("GET", path, status, body)
                    break
            else:
                # "/" — check suspect signals
                if _phase1_check_suspect(body, cfg):
                    state.is_llm = "疑似"
                    state.add_evidence("GET", "/", status, body)

        # Auth-gated fallback: mark 疑似 only when no stronger signal found
        if state.is_llm == "否" and has_auth_signal:
            state.is_llm = "疑似"
            state.evidence.append("Phase1: auth-gated response (401/403) with LLM keyword")

    return state


async def phase1_fingerprint(
    http_alive: List[TargetState], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_phase1_single(sem, session, s, cfg) for s in http_alive]
        states = await asyncio.gather(*tasks)
    return list(states)


# ---------------------------------------------------------------------------
# Phase 2 — Deploy tool identification
# ---------------------------------------------------------------------------

async def _extra_get(
    session: aiohttp.ClientSession,
    proto: str, ip: str, port: str,
    path: str,
    timeout: int,
) -> ProbeResult:
    url = "%s://%s:%s%s" % (proto, ip, port, path)
    status, raw, err = await fetch(session, "GET", url, timeout)
    if status == 0:
        return ProbeResult(error=err)
    return ProbeResult(status=status, body=decode_body(raw))


def _cached(state: TargetState, path: str) -> Optional[ProbeResult]:
    pr = state.probes.get(path)
    if pr and pr.status > 0:
        return pr
    return None


def _source_path(source: str) -> str:
    """Extract the URL path component from a source string like 'cached:/api/tags'."""
    if ":" in source:
        return source.split(":", 1)[1]
    return source


async def _phase2_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> TargetState:
    """
    Config-driven Phase 2 engine.

    Tools in cfg.phase2.tools are evaluated in order; first match returns.
    Suspect targets only allow root-sourced checks (cache reads, no new GETs).

    Phase 2 choice (plan Option B — full declarative pipeline):
    The tool list in the YAML defines both *what* each tool looks like and
    *in what order* tools are tried.  The Python engine is a generic evaluator
    that executes those declarations; no tool-specific if-chains remain here.
    """
    proto, ip, port = state.protocol, state.ip, state.port
    is_suspect = (state.is_llm == "疑似")
    rt = cfg.runtime.phase2

    # ── Helpers ──────────────────────────────────────────────────────────────

    extra_used = 0

    async def do_get(path: str) -> Optional[ProbeResult]:
        nonlocal extra_used
        if extra_used >= rt.max_extra_gets:
            return None
        pr = await _extra_get(session, proto, ip, port, path, rt.timeout)
        state.probes[path] = pr
        extra_used += 1
        return pr

    async def resolve_source(src: str) -> Optional[ProbeResult]:
        """Fetch or return from cache according to the source prefix."""
        if src == "root":
            return _cached(state, "/")
        if src.startswith("cached:"):
            return _cached(state, src[7:])
        if src.startswith("get:"):
            return await do_get(src[4:])
        if src.startswith("cached_or_get:"):
            path = src[14:]
            cached = _cached(state, path)
            return cached if cached else await do_get(path)
        return None

    evidenced: set = set()

    def add_ev(path: str) -> None:
        """Add evidence for a probe path at most once per target."""
        if path in evidenced:
            return
        pr = state.probes.get(path)
        if pr and pr.status > 0:
            state.add_evidence("GET", path, pr.status, pr.body)
            evidenced.add(path)

    def record_match(tool_name: str, matched_path: str, matched_pr: ProbeResult) -> None:
        """Finalize a tool match: add evidence and set deploy_tool."""
        # If the matched path differs from requires_cached_ok, record both
        req = next(
            (t.requires_cached_ok for t in cfg.phase2.tools if t.name == tool_name),
            None,
        )
        if req and req != matched_path:
            add_ev(req)
        state.add_evidence("GET", matched_path, matched_pr.status, matched_pr.body)
        state.deploy_tool = tool_name

    # ── Suspect path: only root-sourced tools, no new GETs ───────────────────
    if is_suspect:
        root = _cached(state, "/")
        if root and root.status > 0:
            for tool in cfg.phase2.tools:
                if "suspect" not in tool.scope:
                    continue
                match_spec = tool.match or {}
                if match_spec.get("source") != "root":
                    continue
                if eval_match(match_spec, root.body):
                    state.add_evidence("GET", "/", root.status, root.body)
                    state.deploy_tool = tool.name
                    return state
        return state

    # ── Confirmed path: full tool chain with possible extra GETs ─────────────
    async with sem:
        for tool in cfg.phase2.tools:
            if "confirmed" not in tool.scope:
                continue

            # Skip if a required cached path is not 200
            if tool.requires_cached_ok:
                rpr = state.probes.get(tool.requires_cached_ok)
                if not (rpr and rpr.status == 200):
                    continue

            match_spec = tool.match or {}
            mt = match_spec.get("type", "")

            # ── Unconditional fallback ──────────────────────────────────────
            if mt == "always":
                if tool.requires_cached_ok:
                    add_ev(tool.requires_cached_ok)
                state.deploy_tool = tool.name
                return state

            # ── Primary source check ────────────────────────────────────────
            src = match_spec.get("source", "")
            pr = await resolve_source(src)

            matched = False
            if pr and pr.status > 0:
                matched = eval_match(match_spec, pr.body)

            if matched:
                record_match(tool.name, _source_path(src), pr)  # type: ignore[arg-type]
                # Optionally fetch version info (e.g. Ollama /api/version)
                if tool.version_from:
                    vf = tool.version_from
                    vf_src = vf.get("source", "")
                    vpr = await resolve_source(vf_src)
                    if vpr and vpr.status == 200:
                        names = extract_models({"type": "json_field",
                                                "field": vf.get("field", "")},
                                               vpr.body)
                        if names:
                            state.deploy_version = names[0]
                            state.add_evidence("GET", _source_path(vf_src),
                                               vpr.status, vpr.body)
                return state

            # ── Supplement checks (extra GETs) ─────────────────────────────
            for sup in tool.supplements:
                sup_src = sup.get("source", "")
                sup_pr = await resolve_source(sup_src)
                if sup_pr and sup_pr.status > 0 and eval_match(sup, sup_pr.body):
                    record_match(tool.name, _source_path(sup_src), sup_pr)
                    # Also attempt version_from after a supplement match
                    if tool.version_from:
                        vf = tool.version_from
                        vf_src = vf.get("source", "")
                        vpr = await resolve_source(vf_src)
                        if vpr and vpr.status == 200:
                            names = extract_models({"type": "json_field",
                                                    "field": vf.get("field", "")},
                                                   vpr.body)
                            if names:
                                state.deploy_version = names[0]
                                state.add_evidence("GET", _source_path(vf_src),
                                                   vpr.status, vpr.body)
                    return state

    return state


async def phase2_deploy(
    confirmed: List[TargetState], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_phase2_single(sem, session, s, cfg) for s in confirmed]
        states = await asyncio.gather(*tasks)
    return list(states)


# ---------------------------------------------------------------------------
# Phase 3 — Model info extraction (config-driven)
# ---------------------------------------------------------------------------

async def _phase3_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> TargetState:
    proto, ip, port = state.protocol, state.ip, state.port
    p3 = cfg.phase3
    rt = cfg.runtime.phase3

    # Priority 1+: try each configured cache source in order
    for src_cfg in p3.cache_sources:
        path = src_cfg["path"]
        pr = state.probes.get(path)
        if pr and pr.status == 200:
            names = extract_models(src_cfg["extract"], pr.body)
            if names:
                state.model_info = ",".join(names)
                return state

    # Remaining: POST probes (need semaphore for network)
    async with sem:
        for probe in p3.post_probes:
            path = probe["path"]
            method = probe.get("method", "POST")
            url = "%s://%s:%s%s" % (proto, ip, port, path)
            retries = rt.retries + 1
            status, raw, err = 0, b"", ""
            for _ in range(retries):
                status, raw, err = await fetch(
                    session, method, url, rt.timeout,
                    json_body=probe.get("body"),
                )
                if status != 0 or err != "timeout":
                    break

            body = decode_body(raw) if raw else ""

            on_success = probe.get("on_success", {})
            if on_success and status in on_success.get("status", []):
                names = extract_models(on_success["extract"], body)
                if names:
                    state.model_info = ",".join(names)
                    state.add_evidence(method, path, status, body)
                    return state

            on_error = probe.get("on_error", {})
            if on_error and status in on_error.get("status", []):
                names = extract_models(on_error["extract"], body)
                if names:
                    state.model_info = ",".join(names)
                    state.add_evidence(method, path, status, body)
                    return state

    state.model_info = p3.fallback_literal
    return state


async def phase3_model(
    llm_targets: List[TargetState], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_phase3_single(sem, session, s, cfg) for s in llm_targets]
        states = await asyncio.gather(*tasks)
    return list(states)


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_csv_targets(path: Path) -> List[Tuple[str, str]]:
    for enc in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=enc, newline="") as f:
                rows = list(csv.DictReader(f))
            print("Input encoding: %s (%d rows)" % (enc, len(rows)))
            return [(r["ip"].strip(), r["port"].strip()) for r in rows if r.get("ip") and r.get("port")]
        except UnicodeDecodeError:
            continue
    raise ValueError("Cannot decode %s" % path)


def load_checkpoint(path: Path) -> set:
    done: set = set()
    if not path.is_file():
        return done
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                done.add("%s:%s" % (obj["ip"], obj["port"]))
            except (json.JSONDecodeError, KeyError):
                pass
    print("Checkpoint: %d completed targets loaded" % len(done))
    return done


def append_checkpoint(path: Path, states: List[TargetState]) -> None:
    with path.open("a", encoding="utf-8") as f:
        for s in states:
            f.write(json.dumps({"ip": s.ip, "port": s.port}, ensure_ascii=False) + "\n")


def write_csv_rows(path: Path, rows: List[dict], append: bool = False) -> None:
    mode = "a" if append else "w"
    need_header = not append or not path.is_file() or path.stat().st_size == 0
    with path.open(mode, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=OUTPUT_FIELDNAMES, quoting=csv.QUOTE_NONNUMERIC
        )
        if need_header:
            writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

async def run_pipeline(
    targets: List[Tuple[str, str]],
    output_path: Path,
    checkpoint_path: Path,
    resume_done: set,
    cfg: ScanConfig,
    concurrency_override: Optional[int] = None,
    batch_size: int = 2000,
) -> None:
    rt = cfg.runtime
    p0_c = concurrency_override or rt.phase0.concurrency
    p1_c = concurrency_override or rt.phase1.concurrency
    p2_c = concurrency_override or rt.phase2.concurrency
    p3_c = concurrency_override or rt.phase3.concurrency

    total = len(targets)
    print("Targets to scan: %d" % total)

    if resume_done:
        targets = [(ip, p) for ip, p in targets if "%s:%s" % (ip, p) not in resume_done]
        print("After resume filter: %d remaining" % len(targets))

    append_mode = bool(resume_done) and output_path.is_file()
    all_result_rows: List[dict] = []

    for batch_start in range(0, len(targets), batch_size):
        batch = targets[batch_start: batch_start + batch_size]
        batch_end = min(batch_start + batch_size, len(targets))
        print("\n--- Batch %d-%d / %d ---" % (batch_start + 1, batch_end, len(targets)))

        # Phase 0
        print("Phase 0: protocol probe (%d targets, concurrency=%d)..." % (len(batch), p0_c))
        states = await phase0_protocol(batch, p0_c, cfg)
        http_alive = [s for s in states if s.protocol]
        excluded = [s for s in states if not s.protocol]
        print("  HTTP alive: %d | excluded: %d" % (len(http_alive), len(excluded)))

        ts = _now()
        for s in excluded:
            s.scan_time = ts

        # Phase 1
        if http_alive:
            print("Phase 1: LLM fingerprint (%d targets, concurrency=%d)..." % (len(http_alive), p1_c))
            http_alive = await phase1_fingerprint(http_alive, p1_c, cfg)

        confirmed = [s for s in http_alive if s.is_llm == "确认"]
        suspect = [s for s in http_alive if s.is_llm == "疑似"]
        not_llm = [s for s in http_alive if s.is_llm == "否"]
        print("  LLM confirmed: %d | suspect: %d | not LLM: %d" % (
            len(confirmed), len(suspect), len(not_llm)
        ))

        # Phase 2 — confirmed + suspect
        phase2_targets = confirmed + suspect
        if phase2_targets:
            print("Phase 2: deploy tool (%d targets, concurrency=%d)..." % (len(phase2_targets), p2_c))
            phase2_targets = await phase2_deploy(phase2_targets, p2_c, cfg)

        # Phase 3 — confirmed only
        confirmed_after_p2 = [s for s in phase2_targets if s.is_llm == "确认"]
        if confirmed_after_p2:
            print("Phase 3: model info (%d targets, concurrency=%d)..." % (len(confirmed_after_p2), p3_c))
            confirmed_after_p2 = await phase3_model(confirmed_after_p2, p3_c, cfg)

        # Stamp scan_time for all processed targets
        ts = _now()
        for s in http_alive + excluded:
            if not s.scan_time:
                s.scan_time = ts

        # Merge phase2/phase3 results back
        state_map: Dict[str, TargetState] = {}
        for s in phase2_targets:
            state_map["%s:%s" % (s.ip, s.port)] = s
        for s in confirmed_after_p2:
            state_map["%s:%s" % (s.ip, s.port)] = s

        batch_states: List[TargetState] = []
        for s in excluded:
            batch_states.append(s)
        for s in http_alive:
            key = "%s:%s" % (s.ip, s.port)
            batch_states.append(state_map.get(key, s))

        rows = [s.to_row() for s in batch_states]
        write_csv_rows(output_path, rows, append=append_mode)
        append_mode = True  # subsequent batches always append
        append_checkpoint(checkpoint_path, batch_states)
        all_result_rows.extend(rows)

        llm_count = sum(1 for r in rows if r["is_llm"] == "确认")
        suspect_count = sum(1 for r in rows if r["is_llm"] == "疑似")
        print("  Batch written: %d rows (%d confirmed LLM, %d suspect)" % (
            len(rows), llm_count, suspect_count
        ))

    # Summary
    total_written = len(all_result_rows)
    total_confirmed = sum(1 for r in all_result_rows if r["is_llm"] == "确认")
    total_suspect = sum(1 for r in all_result_rows if r["is_llm"] == "疑似")
    print("\n=== Done ===")
    print("Total rows written: %d" % total_written)
    print("LLM confirmed: %d" % total_confirmed)
    print("LLM suspect:   %d" % total_suspect)
    print("Output: %s" % output_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="LLM service port scanner (Phase 0-3)"
    )
    parser.add_argument(
        "--input", default="IPs_1_result_scan_2.csv",
        help="CSV with ip and port columns (default: IPs_1_result_scan_2.csv)"
    )
    parser.add_argument(
        "--output", default="IPs_1_result_llm.csv",
        help="Output CSV (default: IPs_1_result_llm.csv)"
    )
    parser.add_argument(
        "--checkpoint", default="llm_scan_checkpoint.jsonl",
        help="Checkpoint file for resume support"
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip already-completed ip:port pairs from checkpoint"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Process only first N targets (for testing)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=2000,
        help="Rows processed per pipeline batch (default: 2000)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=None,
        help="Override concurrency for all phases"
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to YAML rules config (default: llm_scan_rules.yaml next to this script)"
    )
    args = parser.parse_args()

    # Load scan rules config
    if args.config:
        config_path = Path(args.config)
        if not config_path.is_file():
            print("Config not found: %s" % config_path, file=sys.stderr)
            return 1
        try:
            cfg = load_config(config_path)
            print("Config loaded from: %s" % config_path)
        except Exception as e:
            print("Failed to load config: %s" % e, file=sys.stderr)
            return 1
    else:
        cfg = get_default_config()

    base_dir = Path(__file__).resolve().parent
    input_path = base_dir / args.input
    output_path = base_dir / args.output
    checkpoint_path = base_dir / args.checkpoint

    if not input_path.is_file():
        print("Input not found: %s" % input_path, file=sys.stderr)
        return 1

    targets = read_csv_targets(input_path)
    if not targets:
        print("No valid ip:port rows in input", file=sys.stderr)
        return 1

    if args.limit:
        targets = targets[: args.limit]
        print("Limit: using first %d targets" % len(targets))

    resume_done: set = set()
    if args.resume:
        resume_done = load_checkpoint(checkpoint_path)

    asyncio.run(
        run_pipeline(
            targets=targets,
            output_path=output_path,
            checkpoint_path=checkpoint_path,
            resume_done=resume_done,
            cfg=cfg,
            concurrency_override=args.concurrency,
            batch_size=args.batch_size,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
