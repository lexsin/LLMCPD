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
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urljoin, urlparse

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None
    NameOID = None

try:
    import aiohttp
except ImportError:
    print("aiohttp not installed. Run: pip install aiohttp>=3.9.0", file=sys.stderr)
    sys.exit(1)

from scan_config import ScanConfig, eval_match, extract_models, get_default_config, load_config
from npu_discovery import classify as classify_npu, accelerator_type, annotate_same_ip

# ---------------------------------------------------------------------------
# Fixed operational constants (not fingerprint-related, not in config)
# ---------------------------------------------------------------------------

TLS_HINT_PORTS = {
    "443", "4443", "6443", "7443", "8443", "9443",
    "10443", "11443", "20443", "40443",
}
TLS_REQUIRED_MARKERS = (
    "plain http request was sent to https port",
    "requires tls",
    "https required",
    "ssl required",
    "use https",
    "speaking plain http to an ssl-enabled server",
)
BODY_LIMIT = 1024 * 256   # bytes read per ordinary response
GPU_METRICS_SCAN_LIMIT = 64 * 1024 * 1024
GPU_METRICS_RETAIN_LIMIT = 2 * 1024 * 1024
GPU_METRICS_PREFIX_LIMIT = 64 * 1024
EVIDENCE_BODY_MAX = 1000  # chars kept per evidence snippet
EVIDENCE_SEP = "|||"
GPU_METRIC_PATHS = (
    "/metrics", "/metrics/", "/prometheus", "/actuator/prometheus",
)
GPU_PROBE_PORTS = {"8002", "9400", "9401", "9835"}
GPU_OPENAPI_DOC_PATHS = (
    "/openapi.json", "/v3/api-docs", "/swagger.json",
    "/api/openapi.json", "/v1/openapi.json",
)
GPU_OPENAPI_MAX_DOC_PROBES = 3
GPU_OPENAPI_MAX_HARDWARE_PROBES = 3
GPU_OPENAPI_TIMEOUT = 5
GPU_OPENAPI_PATH_KEYWORDS = (
    "gpu", "device", "worker", "cluster", "resource",
    "hardware", "accelerator", "node",
)
GPU_OPENAPI_PATH_DENY = (
    "start", "stop", "launch", "terminate", "delete", "remove",
    "register", "unregister", "download", "install", "update",
    "create", "auth", "login", "token", "kill", "shutdown", "restart",
    "reset", "reboot", "scale", "allocate", "release", "enable",
    "disable", "drain", "evict", "attach", "detach", "migrate",
)
GPU_OPENAPI_PATH_READ_ONLY = (
    "gpu", "device", "worker", "cluster", "resource", "hardware",
    "accelerator", "node", "info", "status", "list", "inventory",
    "metric", "health", "summary", "detail",
)

OUTPUT_FIELDNAMES = [
    "ip", "port", "protocol", "is_llm",
    "service_type", "model_domain", "gpu_likelihood", "gpu_evidence",
    "gpu_probe_detail", "deploy_tool", "deploy_version", "model_info",
    "evidence", "link", "scan_time",
    "分析",
    "scan_status", "scan_confidence", "protocol_probe_detail",
    "http_probe_detail", "certificate_names", "tested_hostnames",
    "selected_hostname",
    "npu_likelihood", "npu_evidence", "accelerator_type",
]


def _dedupe_keep_last(values: List[str]) -> List[str]:
    """Return non-empty values once, ordered by their last occurrence."""
    seen = set()
    result_reversed: List[str] = []
    for value in reversed(values):
        if value and value not in seen:
            seen.add(value)
            result_reversed.append(value)
    return list(reversed(result_reversed))


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    status: int = 0
    body: str = ""
    error: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    body_hash: str = ""


@dataclass
class TargetState:
    ip: str
    port: str
    protocol: str = ""            # http / https / ""
    is_llm: str = "否"
    service_type: str = ""
    model_domain: str = ""
    gpu_likelihood: str = ""
    gpu_evidence: str = ""
    npu_likelihood: str = "未知"
    npu_evidence: str = ""
    accelerator_type: str = "未知"
    gpu_probe_detail: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    deploy_tool: str = ""
    deploy_version: str = ""
    model_info: str = ""
    evidence: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    probes: Dict[str, ProbeResult] = field(default_factory=dict)  # path -> ProbeResult
    scan_time: str = ""
    analysis: str = ""
    scan_status: str = ""
    scan_confidence: str = ""
    protocol_probe_detail: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    certificate_names: List[str] = field(default_factory=list)
    tested_hostnames: List[str] = field(default_factory=list)
    selected_hostname: str = ""

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
        return EVIDENCE_SEP.join(_dedupe_keep_last(self.links))

    def to_row(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "is_llm": self.is_llm,
            "service_type": self.service_type,
            "model_domain": self.model_domain,
            "gpu_likelihood": self.gpu_likelihood,
            "gpu_evidence": self.gpu_evidence,
            "npu_likelihood": self.npu_likelihood,
            "npu_evidence": self.npu_evidence,
            "accelerator_type": self.accelerator_type,
            "gpu_probe_detail": json.dumps(
                self.gpu_probe_detail, ensure_ascii=False, separators=(",", ":")
            ) if self.gpu_probe_detail else "",
            "deploy_tool": self.deploy_tool,
            "deploy_version": self.deploy_version,
            "model_info": self.model_info,
            "evidence": self.evidence_str(),
            "link": self.link_str(),
            "scan_time": self.scan_time,
            "分析": self.analysis,
            "scan_status": self.scan_status,
            "scan_confidence": self.scan_confidence,
            "protocol_probe_detail": json.dumps(
                self.protocol_probe_detail, ensure_ascii=False, separators=(",", ":")
            ) if self.protocol_probe_detail else "",
            "http_probe_detail": json.dumps(
                _http_probe_detail(self.probes), ensure_ascii=False, separators=(",", ":")
            ) if self.probes else "",
            "certificate_names": EVIDENCE_SEP.join(self.certificate_names),
            "tested_hostnames": EVIDENCE_SEP.join(self.tested_hostnames),
            "selected_hostname": self.selected_hostname,
        }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

_SSL_CTX = make_ssl_ctx()


def _selected_headers(headers: Any) -> Dict[str, str]:
    keep = {"server", "content-type", "www-authenticate", "location", "allow"}
    return {
        str(key).lower(): str(value)[:500]
        for key, value in headers.items()
        if str(key).lower() in keep
    }


def _response_body_hash(body: str, path: str = "") -> str:
    """Build a stable fingerprint, ignoring reflected paths and volatile IDs/times."""
    normalized = body.lower()
    try:
        parsed = json.loads(body)
        volatile_keys = {
            "timestamp", "time", "date", "path", "request_id", "requestid",
            "trace_id", "traceid", "correlation_id",
        }

        def scrub(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    str(key).lower(): scrub(item)
                    for key, item in value.items()
                    if str(key).lower() not in volatile_keys
                }
            if isinstance(value, list):
                return [scrub(item) for item in value]
            return value

        normalized = json.dumps(
            scrub(parsed), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).lower()
    except (json.JSONDecodeError, TypeError):
        normalized = re.sub(
            r"(?i)(timestamp|request[_-]?id|trace[_-]?id)\s*[:=]\s*[\"']?[a-z0-9_.:-]+",
            r"\1=<volatile>",
            normalized,
        )

    reflected_values = () if path == "/" else (path, quote(path, safe=""))
    for reflected in reflected_values:
        if reflected:
            normalized = normalized.replace(reflected.lower(), "")
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _make_probe_result(
    status: int, raw: bytes, error: str, headers: Optional[Dict[str, str]] = None,
    path: str = "",
) -> ProbeResult:
    body = decode_body(raw) if raw else ""
    selected = _selected_headers(headers or {})
    return ProbeResult(
        status=status,
        body=body,
        error=error,
        headers=selected,
        content_type=selected.get("content-type", ""),
        body_hash=_response_body_hash(body, path) if status else "",
    )


def _http_probe_detail(probes: Dict[str, ProbeResult]) -> Dict[str, Dict[str, Any]]:
    detail: Dict[str, Dict[str, Any]] = {}
    for path, probe in probes.items():
        if probe.status <= 0 and not probe.error:
            continue
        item: Dict[str, Any] = {
            "status": probe.status,
            "content_type": probe.content_type,
            "body_hash": probe.body_hash,
        }
        if probe.error:
            item["error"] = probe.error
        for key in ("server", "www-authenticate", "location", "allow"):
            if probe.headers.get(key):
                item[key] = probe.headers[key]
        detail[path] = item
    return detail


async def _read_limited_content(
    content: aiohttp.StreamReader, read_limit: int
) -> bytes:
    chunks: List[bytes] = []
    remaining = read_limit
    while remaining > 0:
        chunk = await content.read(min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


_METRICS_DIRECT_MARKERS = (
    b"gpu", b"nvidia", b"dcgm", b"nvml", b"cuda", b"rocm",
    b"accelerator", b"vram", b"hbm", b"cache_config_info",
)
_METRICS_ACTIVITY_MARKERS = (
    b"vllm", b"sglang", b"tgi", b"inference", b"request", b"token",
    b"generation", b"completion", b"embed", b"queue", b"worker",
)


async def _read_metrics_content(content: aiohttp.StreamReader) -> bytes:
    """Scan a large metrics response while retaining only useful lines.

    The old one-MiB prefix could miss GPU metrics near the end of a Prometheus
    response.  This consumes the response incrementally (up to 64 MiB of wire
    data), keeps a small prefix for framework detection, and separately keeps
    GPU/device lines and runtime activity lines.  Memory use remains bounded.
    """
    scanned = 0
    pending = b""
    prefix = bytearray()
    direct = bytearray()
    activity = bytearray()

    def keep_line(line: bytes) -> None:
        if len(prefix) < GPU_METRICS_PREFIX_LIMIT:
            prefix.extend(line[: GPU_METRICS_PREFIX_LIMIT - len(prefix)])
        lowered = line.lower()
        if any(marker in lowered for marker in _METRICS_DIRECT_MARKERS):
            if len(direct) < GPU_METRICS_RETAIN_LIMIT:
                direct.extend(line[: GPU_METRICS_RETAIN_LIMIT - len(direct)])
        elif any(marker in lowered for marker in _METRICS_ACTIVITY_MARKERS):
            if len(activity) < GPU_METRICS_RETAIN_LIMIT:
                activity.extend(line[: GPU_METRICS_RETAIN_LIMIT - len(activity)])

    async for chunk in content.iter_any():
        if not chunk:
            continue
        remaining = GPU_METRICS_SCAN_LIMIT - scanned
        if remaining <= 0:
            break
        chunk = chunk[:remaining]
        scanned += len(chunk)
        pending += chunk
        lines = pending.splitlines(keepends=True)
        if lines and not lines[-1].endswith((b"\n", b"\r")):
            pending = lines.pop()
        else:
            pending = b""
        for line in lines:
            keep_line(line)
    if pending:
        keep_line(pending + b"\n")
    return bytes(prefix) + b"\n# filtered_gpu_metrics\n" + bytes(direct) + bytes(activity)


async def fetch_detailed(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: int,
    json_body: Optional[dict] = None,
    allow_redirects: bool = True,
    read_limit: int = BODY_LIMIT,
    stream_mode: str = "normal",
) -> Tuple[int, bytes, str, Dict[str, str]]:
    """Return status, raw bytes, error and selected response headers."""
    try:
        kwargs: dict = {
            "timeout": aiohttp.ClientTimeout(
                total=timeout,
                connect=min(5, timeout),
                sock_connect=min(5, timeout),
                sock_read=timeout,
            ),
            "ssl": _SSL_CTX,
            "allow_redirects": allow_redirects,
            "headers": {"Accept-Encoding": "identity"},
        }
        if json_body is not None:
            kwargs["json"] = json_body
        async with session.request(method, url, **kwargs) as resp:
            if stream_mode == "metrics":
                raw = await _read_metrics_content(resp.content)
            else:
                raw = await _read_limited_content(resp.content, read_limit)
            return resp.status, raw, "", _selected_headers(resp.headers)
    except asyncio.TimeoutError:
        return 0, b"", "timeout", {}
    except aiohttp.ClientConnectorError as e:
        return 0, b"", "connect_error: %s" % str(e)[:120], {}
    except aiohttp.ClientError as e:
        return 0, b"", "client_error: %s" % str(e)[:120], {}
    except Exception as e:
        return 0, b"", "error: %s" % str(e)[:120], {}


async def fetch(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    timeout: int,
    json_body: Optional[dict] = None,
    allow_redirects: bool = True,
    read_limit: int = BODY_LIMIT,
) -> Tuple[int, bytes, str]:
    status, raw, error, _ = await fetch_detailed(
        session, method, url, timeout, json_body, allow_redirects, read_limit
    )
    return status, raw, error


async def fetch_same_host_asset(
    session: aiohttp.ClientSession,
    url: str,
    timeout: int,
    read_limit: int,
) -> Tuple[int, bytes, str]:
    """Fetch a same-host static asset, allowing http->https redirects only on the same host."""
    try:
        original = urlparse(url)
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(
                total=timeout,
                connect=min(5, timeout),
                sock_connect=min(5, timeout),
                sock_read=timeout,
            ),
            ssl=_SSL_CTX,
            allow_redirects=True,
        ) as resp:
            final = urlparse(str(resp.url))
            if final.hostname != original.hostname:
                return 0, b"", "redirected_to_external_host"
            raw = await _read_limited_content(resp.content, read_limit)
            return resp.status, raw, ""
    except asyncio.TimeoutError:
        return 0, b"", "timeout"
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


def _valid_hostname(value: str) -> Optional[str]:
    host = value.strip().rstrip(".").lower()
    if not host or host.startswith("*.") or len(host) > 253:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if host == "localhost" or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
        host,
    ):
        return None
    return host


def _certificate_names_sync(ip: str, port: str, timeout: int) -> List[str]:
    if x509 is None or NameOID is None:
        return []
    names: List[str] = []
    try:
        ctx = make_ssl_ctx()
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names.extend(san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        names.extend(
            attribute.value
            for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        )
    except Exception:
        return []
    result: List[str] = []
    for value in names:
        host = _valid_hostname(str(value))
        if host and host not in result:
            result.append(host)
    return result[:5]


def _reverse_dns_sync(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def _needs_hostname_probe(state: TargetState) -> bool:
    root = state.probes.get("/")
    if root and root.status in {400, 401, 403, 404, 421, 426}:
        return True
    return any(
        path != "/" and probe.status in {401, 403, 404}
        for path, probe in state.probes.items()
    )


async def _candidate_hostnames(state: TargetState, timeout: int) -> List[str]:
    candidates: List[str] = []
    root = state.probes.get("/")
    if root and root.headers.get("location"):
        host = _valid_hostname(urlparse(root.headers["location"]).hostname or "")
        if host:
            candidates.append(host)

    if state.protocol == "https":
        try:
            cert_names = await asyncio.wait_for(
                asyncio.to_thread(
                    _certificate_names_sync, state.ip, state.port, min(timeout, 5)
                ),
                timeout=min(timeout, 5) + 1,
            )
        except asyncio.TimeoutError:
            cert_names = []
        state.certificate_names = cert_names
        candidates.extend(cert_names)

    try:
        ptr = await asyncio.wait_for(
            asyncio.to_thread(_reverse_dns_sync, state.ip), timeout=2
        )
    except asyncio.TimeoutError:
        ptr = ""
    ptr_host = _valid_hostname(ptr)
    if ptr_host:
        candidates.append(ptr_host)

    result: List[str] = []
    for host in candidates:
        if host not in result:
            result.append(host)
    return result[:3]


def _decode_chunked(body: bytes) -> bytes:
    result = bytearray()
    pos = 0
    try:
        while pos < len(body):
            end = body.find(b"\r\n", pos)
            if end < 0:
                return body
            size = int(body[pos:end].split(b";", 1)[0], 16)
            if size == 0:
                return bytes(result)
            pos = end + 2
            result.extend(body[pos:pos + size])
            pos += size + 2
    except (ValueError, IndexError):
        return body
    return bytes(result)


async def fetch_host_override(
    ip: str, port: str, protocol: str, hostname: str, path: str, timeout: int,
) -> Tuple[int, bytes, str, Dict[str, str]]:
    """Connect to the original IP while supplying the candidate Host and TLS SNI."""
    writer = None
    try:
        ssl_ctx = _SSL_CTX if protocol == "https" else None
        server_hostname = hostname if ssl_ctx else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, int(port), ssl=ssl_ctx, server_hostname=server_hostname
            ),
            timeout=min(timeout, 5),
        )
        request = (
            "GET %s HTTP/1.1\r\nHost: %s\r\n"
            "User-Agent: llm-detect/host-probe\r\n"
            "Accept: application/json,text/html,*/*\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ) % (path, hostname)
        writer.write(request.encode("ascii"))
        await writer.drain()
        response = await asyncio.wait_for(
            reader.read(BODY_LIMIT + 65536), timeout=timeout
        )
        head, sep, body = response.partition(b"\r\n\r\n")
        if not sep:
            return 0, b"", "invalid_http_response", {}
        lines = head.split(b"\r\n")
        match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
        if not match:
            return 0, b"", "invalid_status_line", {}
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            key, colon, value = line.partition(b":")
            if colon:
                headers[key.decode("latin-1").strip().lower()] = (
                    value.decode("latin-1").strip()
                )
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = _decode_chunked(body)
        return int(match.group(1)), body[:BODY_LIMIT], "", _selected_headers(headers)
    except asyncio.TimeoutError:
        return 0, b"", "timeout", {}
    except Exception as e:
        return 0, b"", "error: %s" % str(e)[:120], {}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def base_url(protocol: str, ip: str, port: str) -> str:
    return "%s://%s:%s" % (protocol, ip, port)


def _protocol_order(port: str) -> Tuple[str, str]:
    return ("https", "http") if port in TLS_HINT_PORTS else ("http", "https")

def _tls_required_response(body: str) -> bool:
    low = body.lower()
    return any(marker in low for marker in TLS_REQUIRED_MARKERS)


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
        fallback_http: Optional[Tuple[int, str, Dict[str, str]]] = None
        tls_hint_seen = False
        for proto in _protocol_order(port):
            url = "%s://%s:%s/" % (proto, ip, port)
            attempts = rt.retries + 1
            status, raw, err, headers = 0, b"", "", {}
            for _ in range(attempts):
                status, raw, err, headers = await fetch_detailed(
                    session, "GET", url, rt.timeout
                )
                if status != 0 or err != "timeout":
                    break

            state.protocol_probe_detail[proto] = {"status": status, "error": err}
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
            body = decode_body(raw)
            if proto == "http" and _tls_required_response(body):
                tls_hint_seen = True
                continue
            if proto == "http" and status in {400, 421, 426}:
                fallback_http = (status, body, headers)
                continue
            state.protocol = proto
            state.add_evidence("GET", "/", status, body)
            state.probes["/"] = _make_probe_result(
                status, raw, err, headers, "/"
            )
            return state

        if fallback_http is not None:
            status, body, headers = fallback_http
            state.protocol = "http"
            state.add_evidence("GET", "/", status, body)
            state.probes["/"] = ProbeResult(
                status=status, body=body, headers=headers,
                content_type=headers.get("content-type", ""),
                body_hash=_response_body_hash(body, "/"),
            )
            return state

        if tls_hint_seen:
            state.evidence.append("Phase0: TLS required but HTTPS probe failed")
        else:
            state.evidence.append("Phase0: no HTTP response (http/https both failed)")
        state.scan_time = _now()
        return state


async def phase0_protocol(
    targets: List[Tuple[str, str]], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
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


def _match_auth_suspect(
    path: str, status: int, body: str, auth_cfg: Optional[Dict]
) -> Optional[str]:
    """Return an auth keyword after removing reflections of the probe path."""
    if not auth_cfg or status not in auth_cfg.get("status_codes", []):
        return None

    bl = body.lower()
    exclude_pats = auth_cfg.get("exclude_body_patterns", [])
    if any(str(pattern).lower() in bl for pattern in exclude_pats):
        return None

    # Gateways often echo the requested path in redirects or error pages.
    # Remove both literal and percent-encoded forms before matching keywords.
    sanitized = bl
    reflected_paths = {
        path.lower(),
        quote(path, safe="").lower(),
    }
    for reflected_path in reflected_paths:
        if reflected_path:
            sanitized = sanitized.replace(reflected_path, "")

    for keyword in auth_cfg.get("body_keywords", []):
        normalized = str(keyword).lower()
        if normalized and normalized in sanitized:
            return normalized
    return None


def _is_auth_specific_response(
    path: str, probe: ProbeResult, root: Optional[ProbeResult],
) -> bool:
    """Separate endpoint-specific authentication from a generic gateway denial."""
    if probe.status not in {401, 403}:
        return False
    if probe.headers.get("www-authenticate"):
        return True

    probe_hash = _response_body_hash(probe.body, path)
    root_hash = _response_body_hash(root.body, "") if root and root.status > 0 else ""
    if root_hash and probe.status == root.status and probe_hash == root_hash:
        return False

    body = probe.body.lower()
    strong_terms = (
        "unauthorized", "authentication required", "authentication failed",
        "missing api key", "invalid api key", "valid api key", "api_key",
        "bearer token", "access token", "invalid token", "token required",
    )
    if any(term in body for term in strong_terms):
        return True
    content_type = probe.content_type.lower()
    return probe.status == 401 and (
        "json" in content_type or body.lstrip().startswith(("{", "["))
    )


def _extract_script_srcs(html: str) -> List[str]:
    srcs: List[str] = []
    script_pattern = re.compile(
        r"<script\b[^>]*\bsrc\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^>\s]+))",
        re.I,
    )
    for m in script_pattern.finditer(html):
        src = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if src:
            srcs.append(src)
    link_pattern = re.compile(r"<link\b[^>]*\bhref\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^>\s]+))[^>]*>", re.I)
    for m in link_pattern.finditer(html):
        tag = m.group(0)
        low_tag = tag.lower()
        if "script" not in low_tag and "modulepreload" not in low_tag:
            continue
        src = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        if src:
            srcs.append(src)
    return srcs


def _same_origin_url(base: str, src: str) -> Optional[str]:
    joined = urljoin(base, src)
    bp = urlparse(base)
    jp = urlparse(joined)
    if jp.scheme != bp.scheme or jp.netloc != bp.netloc:
        return None
    return joined


def _js_src_allowed(src: str, cfg: Dict) -> bool:
    low = src.lower()
    patterns = cfg.get("include_src_patterns", [])
    return any(str(p).lower() in low for p in patterns)


def _match_js_bundle(body: str, cfg: Dict) -> Optional[str]:
    low = body.lower()
    if any(str(kw).lower() in low for kw in cfg.get("exclude_keywords", [])):
        return None

    for kw in cfg.get("api_path_keywords", []):
        kw_s = str(kw)
        if kw_s.lower() in low:
            return kw_s

    semantic = next(
        (str(kw) for kw in cfg.get("semantic_keywords", []) if str(kw).lower() in low),
        "",
    )
    chat = next(
        (str(kw) for kw in cfg.get("chat_keywords", []) if str(kw).lower() in low),
        "",
    )
    if semantic and chat:
        return "%s+%s" % (semantic, chat)
    return None


def _match_nextjs_deep_bundle(body: str, cfg: Dict) -> Optional[str]:
    low = body.lower()
    if any(str(kw).lower() in low for kw in cfg.get("exclude_keywords", [])):
        return None
    for kw in cfg.get("keywords", []):
        kw_s = str(kw)
        if kw_s.lower() in low:
            return kw_s
    return None


async def _phase1_check_js_bundle(
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> Optional[str]:
    js_cfg = cfg.phase1.js_bundle_suspect or {}
    if not js_cfg.get("enabled", False):
        return None

    root = state.probes.get("/")
    if not root or root.status <= 0:
        return None
    html = root.body or ""
    html_low = html.lower()
    if "<script" not in html_low and "href" not in html_low:
        return None

    base = base_url(state.protocol, state.ip, state.port) + "/"
    srcs = _extract_script_srcs(html)
    max_scripts = int(js_cfg.get("max_scripts", 3))
    max_bytes = int(js_cfg.get("max_bytes", BODY_LIMIT))
    timeout = cfg.runtime.phase1.timeout
    seen = set()
    checked = 0
    for src in srcs:
        if checked >= max_scripts:
            break
        if not _js_src_allowed(src, js_cfg):
            continue
        url = _same_origin_url(base, src)
        if not url or url in seen:
            continue
        seen.add(url)
        checked += 1
        status, raw, err = await fetch_same_host_asset(
            session, url, timeout, read_limit=max_bytes
        )
        if status != 200 or not raw:
            continue
        body = decode_body(raw[:max_bytes])
        matched = _match_js_bundle(body, js_cfg)
        if matched:
            path = urlparse(url).path or src
            return "Phase1 JS bundle suspect: %s matched=%s" % (path, matched)

    deep_cfg = js_cfg.get("nextjs_deep_scan", {}) or {}
    if not deep_cfg.get("enabled", False):
        return None
    trigger_patterns = [str(p).lower() for p in deep_cfg.get("trigger_src_patterns", [])]
    if trigger_patterns:
        haystack = "\n".join(srcs).lower() + "\n" + html.lower()
        if not any(p in haystack for p in trigger_patterns):
            return None

    deep_max_scripts = int(deep_cfg.get("max_scripts", 50))
    deep_max_bytes = int(deep_cfg.get("max_bytes", max_bytes))
    checked = 0
    for src in srcs:
        if checked >= deep_max_scripts:
            break
        if not _js_src_allowed(src, js_cfg):
            continue
        url = _same_origin_url(base, src)
        if not url or url in seen:
            continue
        seen.add(url)
        checked += 1
        status, raw, err = await fetch_same_host_asset(
            session, url, timeout, read_limit=deep_max_bytes
        )
        if status != 200 or not raw:
            continue
        body = decode_body(raw[:deep_max_bytes])
        matched = _match_nextjs_deep_bundle(body, deep_cfg)
        if matched:
            path = urlparse(url).path or src
            return "Phase1 JS bundle suspect: %s mode=nextjs_dify_deep matched=%s" % (
                path, matched
            )
    return None


async def _phase1_hostname_reprobe(
    state: TargetState, cfg: ScanConfig,
) -> None:
    """Retry high-value LLM paths on the same IP using certificate/PTR Host and SNI."""
    rt = cfg.runtime.phase1
    candidates = await _candidate_hostnames(state, rt.timeout)
    if not candidates:
        return

    high_value = [
        "/v1/models", "/api/v1/models", "/openai/v1/models",
        "/api/tags", "/api/version", "/v2/models", "/",
    ]
    paths = [path for path in high_value if path in cfg.phase1.probe_paths or path == "/"]
    original_root = state.probes.get("/")
    for hostname in candidates:
        state.tested_hostnames.append(hostname)
        hostname_worked = False
        for path in paths:
            status, raw, error, headers = await fetch_host_override(
                state.ip, state.port, state.protocol, hostname, path, rt.timeout
            )
            probe = _make_probe_result(status, raw, error, headers, path)
            state.probes["host=%s%s" % (hostname, path)] = probe
            if status == 0:
                continue
            if (
                path == "/" and status < 400
                and original_root
                and original_root.status in {400, 401, 403, 404, 421, 426}
            ):
                hostname_worked = True
            if path != "/":
                matched_rule = _phase1_check_confirmed(path, status, probe.body, cfg)
                if matched_rule is not None:
                    state.probes[path] = probe
                    state.is_llm = "确认"
                    state.selected_hostname = hostname
                    state.evidence.append(
                        "Phase1 Host/SNI %s GET %s %d: %s"
                        % (hostname, path, status, probe.body[:EVIDENCE_BODY_MAX])
                    )
                    state.links.append(
                        "%s://%s:%s%s" % (
                            state.protocol, hostname, state.port, path
                        )
                    )
                    return
            elif _phase1_check_suspect(probe.body, cfg):
                state.probes["/"] = probe
                state.is_llm = "疑似"
                state.selected_hostname = hostname
                state.evidence.append(
                    "Phase1 Host/SNI %s root suspect %d: %s"
                    % (hostname, status, probe.body[:EVIDENCE_BODY_MAX])
                )
                state.links.append(
                    "%s://%s:%s/" % (state.protocol, hostname, state.port)
                )
                return
        if hostname_worked and not state.selected_hostname:
            state.selected_hostname = hostname
            state.evidence.append(
                "Phase1: Host/SNI %s changed generic root response to a successful route"
                % hostname
            )


async def _phase1_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> TargetState:
    proto = state.protocol
    ip, port = state.ip, state.port
    rt = cfg.runtime.phase1
    auth_signal: Optional[Tuple[str, int, str]] = None

    async with sem:
        for path in cfg.phase1.probe_paths:
            # Reuse root cached from Phase 0
            if path == "/" and "/" in state.probes:
                pr = state.probes["/"]
                status, body = pr.status, pr.body
            else:
                url = "%s://%s:%s%s" % (proto, ip, port, path)
                status, raw, err, headers = await fetch_detailed(
                    session, "GET", url, rt.timeout
                )
                state.probes[path] = _make_probe_result(
                    status, raw, err, headers, path
                )
                if status == 0:
                    if path == "/":
                        break
                    continue
                body = state.probes[path].body

            if path != "/":
                # Check for auth-gated LLM signal (401/403 with relevant keywords)
                auth_keyword = _match_auth_suspect(
                    path, status, body, cfg.phase1.auth_suspect
                )
                if auth_keyword and auth_signal is None:
                    auth_signal = (path, status, auth_keyword)

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

        if state.is_llm == "否" and _needs_hostname_probe(state):
            await _phase1_hostname_reprobe(state, cfg)

        if state.is_llm == "否":
            js_evidence = await _phase1_check_js_bundle(session, state, cfg)
            if js_evidence:
                state.is_llm = "疑似"
                state.evidence.append(js_evidence)

        # Auth-gated fallback: require endpoint-specific auth, not a generic denial page.
        if state.is_llm == "否" and auth_signal is not None:
            auth_path, auth_status, auth_keyword = auth_signal
            auth_probe = state.probes.get(auth_path, ProbeResult())
            if _is_auth_specific_response(
                auth_path, auth_probe, state.probes.get("/")
            ):
                state.is_llm = "疑似"
                state.evidence.append(
                    "Phase1: auth-gated response GET %s %d with keyword %s"
                    % (auth_path, auth_status, auth_keyword)
                )

    return state


async def phase1_fingerprint(
    http_alive: List[TargetState], concurrency: int, cfg: ScanConfig
) -> List[TargetState]:
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_phase1_single(sem, session, s, cfg) for s in http_alive]
        states = await asyncio.gather(*tasks)
    return list(states)


# ---------------------------------------------------------------------------
# Independent GPU compute probe — all live HTTP/HTTPS targets
# ---------------------------------------------------------------------------

async def _gpu_probe_path(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    path: str,
    cfg: ScanConfig,
    *,
    timeout_override: Optional[int] = None,
    retries_override: Optional[int] = None,
) -> None:
    existing = state.probes.get(path)
    if existing and existing.status > 0:
        state.gpu_probe_detail[path] = {
            "status": existing.status,
            "error": existing.error,
            "attempts": 0,
            "source": "cache",
        }
        return

    rt = cfg.runtime.gpu_probe
    timeout = timeout_override if timeout_override is not None else rt.timeout
    retries = retries_override if retries_override is not None else rt.retries
    attempts = 0
    result = ProbeResult(error="not_attempted")
    async with sem:
        for attempt in range(retries + 1):
            attempts += 1
            result = await _extra_get(
                session, state.protocol, state.ip, state.port, path, timeout
            )
            retryable = result.status == 0 or result.status >= 500
            if not retryable or attempt >= retries:
                break
            delay_index = min(attempt, len(rt.retry_delays) - 1)
            delay = rt.retry_delays[delay_index] if rt.retry_delays else 0
            if delay > 0:
                await asyncio.sleep(delay)

    state.probes[path] = result
    state.gpu_probe_detail[path] = {
        "status": result.status,
        "error": result.error,
        "attempts": attempts,
        "source": "network",
    }


async def phase_gpu_probe(
    http_alive: List[TargetState], concurrency: Optional[int], cfg: ScanConfig,
    paths_override: Optional[List[str]] = None,
    timeout_override: Optional[int] = None,
    retries_override: Optional[int] = None,
) -> List[TargetState]:
    paths = list(paths_override or [])
    if not paths:
        paths = _as_list((cfg.ai_service or {}).get("gpu_probe_paths"))
    if not paths:
        paths = ["/metrics", "/api/ps"]
    # GPU probing intentionally ignores the pipeline-wide concurrency override.
    gpu_concurrency = cfg.runtime.gpu_probe.concurrency
    if concurrency is not None and concurrency != gpu_concurrency:
        gpu_concurrency = cfg.runtime.gpu_probe.concurrency
    sem = asyncio.Semaphore(gpu_concurrency)
    connector = aiohttp.TCPConnector(
        limit=gpu_concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _gpu_probe_path(
                sem, session, state, path, cfg,
                timeout_override=timeout_override,
                retries_override=retries_override,
            )
            for state in http_alive
            for path in paths
        ]
        if tasks:
            await asyncio.gather(*tasks)
    return http_alive


def _is_ai_gpu_candidate(state: TargetState) -> bool:
    return (state.is_llm in {"确认", "疑似"} or state.port in GPU_PROBE_PORTS
            or any(marker in _root_probe_text(state).lower()
                   for marker in ("mindie", "ascend", "npu-exporter")))


def _root_probe_text(state: TargetState) -> str:
    root = state.probes.get("/")
    if not root or root.status <= 0:
        return ""
    headers = " ".join("%s:%s" % item for item in root.headers.items())
    return "%s\n%s\n%s" % (root.body, root.content_type, headers)


def _select_gpu_fallback_targets(
    http_alive: List[TargetState], path: str
) -> List[TargetState]:
    selected: List[TargetState] = []
    for state in http_alive:
        root_text = _root_probe_text(state).lower()
        metrics = state.probes.get("/metrics")
        metrics_missing = not metrics or metrics.status in {0, 404, 405}
        ai_candidate = _is_ai_gpu_candidate(state)

        if path == "/metrics/":
            choose = metrics_missing and ai_candidate
        elif path == "/prometheus":
            choose = ai_candidate or "prometheus" in root_text
        elif path == "/actuator/prometheus":
            choose = ai_candidate or any(
                marker in root_text
                for marker in ("spring", "whitelabel error page", "actuator")
            )
        elif path == "/api/ps":
            choose = ai_candidate or state.port == "11434" or "ollama" in root_text
        else:
            choose = False
        if choose:
            selected.append(state)
    return selected


async def phase_gpu_discovery(
    http_alive: List[TargetState], concurrency: Optional[int], cfg: ScanConfig
) -> List[TargetState]:
    """Run one cheap GPU probe for every HTTP target, then targeted fallbacks."""
    if not http_alive:
        return http_alive

    await phase_gpu_probe(
        http_alive,
        concurrency,
        cfg,
        paths_override=["/metrics"],
        timeout_override=min(cfg.runtime.gpu_probe.timeout, 5),
        retries_override=min(cfg.runtime.gpu_probe.retries, 1),
    )
    configured = _as_list((cfg.ai_service or {}).get("gpu_probe_paths"))
    fallback_paths = [
        path for path in configured
        if path in {"/metrics/", "/prometheus", "/actuator/prometheus", "/api/ps"}
    ]
    if not fallback_paths:
        fallback_paths = ["/metrics/", "/prometheus", "/actuator/prometheus", "/api/ps"]
    for path in fallback_paths:
        selected = _select_gpu_fallback_targets(http_alive, path)
        if selected:
            await phase_gpu_probe(
                selected, concurrency, cfg, paths_override=[path]
            )
    return http_alive


def _openapi_gpu_candidate(state: TargetState) -> bool:
    if _is_ai_gpu_candidate(state):
        return True
    text = _root_probe_text(state).lower()
    return any(
        marker in text
        for marker in ("fastapi", "uvicorn", "xinference", "openapi", "swagger")
    )


def _openapi_hardware_paths(body: str) -> List[str]:
    try:
        spec = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    paths = spec.get("paths") if isinstance(spec, dict) else None
    if not isinstance(paths, dict):
        return []
    selected: List[str] = []
    for path, operations in paths.items():
        if not isinstance(path, str) or not path.startswith("/") or "{" in path:
            continue
        low = path.lower()
        npu_read_path = bool(re.fullmatch(
            r"/(?:api/|v\d+/)*(?:npu|ascend)(?:/(?:info|status|devices|inventory|metrics))?", low))
        if not npu_read_path and not any(keyword in low for keyword in GPU_OPENAPI_PATH_KEYWORDS):
            continue
        if any(keyword in low for keyword in GPU_OPENAPI_PATH_DENY):
            continue
        if not npu_read_path and not any(keyword in low for keyword in GPU_OPENAPI_PATH_READ_ONLY):
            continue
        if not isinstance(operations, dict):
            continue
        get_operation = (
            operations.get("get")
            if "get" in operations
            else operations.get("GET")
        )
        if not isinstance(get_operation, dict):
            continue
        if "requestBody" in get_operation:
            continue
        parameters = list(operations.get("parameters") or [])
        parameters.extend(get_operation.get("parameters") or [])
        if any(
            isinstance(parameter, dict)
            and str(parameter.get("in") or "").lower() == "body"
            for parameter in parameters
        ):
            continue
        selected.append(path)
    return sorted(set(selected), key=lambda value: (len(value), value))[:GPU_OPENAPI_MAX_HARDWARE_PROBES]


async def _gpu_openapi_single(
    sem: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    state: TargetState,
    cfg: ScanConfig,
) -> None:
    if not _openapi_gpu_candidate(state):
        return
    hardware_paths: List[str] = []
    for doc_path in GPU_OPENAPI_DOC_PATHS[:GPU_OPENAPI_MAX_DOC_PROBES]:
        await _gpu_probe_path(
            sem,
            session,
            state,
            doc_path,
            cfg,
            timeout_override=min(cfg.runtime.gpu_probe.timeout, GPU_OPENAPI_TIMEOUT),
            retries_override=0,
        )
        probe = state.probes.get(doc_path)
        if not probe or probe.status != 200:
            continue
        hardware_paths = _openapi_hardware_paths(probe.body)
        if hardware_paths:
            break
    for path in hardware_paths:
        await _gpu_probe_path(
            sem,
            session,
            state,
            path,
            cfg,
            timeout_override=min(cfg.runtime.gpu_probe.timeout, GPU_OPENAPI_TIMEOUT),
            retries_override=0,
        )


async def phase_gpu_openapi(
    http_alive: List[TargetState], concurrency: Optional[int], cfg: ScanConfig
) -> List[TargetState]:
    candidates = [state for state in http_alive if _openapi_gpu_candidate(state)]
    if not candidates:
        return http_alive
    gpu_concurrency = min(cfg.runtime.gpu_probe.concurrency, 8)
    sem = asyncio.Semaphore(gpu_concurrency)
    connector = aiohttp.TCPConnector(
        limit=gpu_concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[
            _gpu_openapi_single(sem, session, state, cfg)
            for state in candidates
        ])
    return http_alive


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
    is_metrics = path in GPU_METRIC_PATHS
    status, raw, err, headers = await fetch_detailed(
        session, "GET", url, timeout,
        read_limit=BODY_LIMIT,
        stream_mode="metrics" if is_metrics else "normal",
    )
    return _make_probe_result(status, raw, err, headers, path)


def _cached(state: TargetState, path: str) -> Optional[ProbeResult]:
    pr = state.probes.get(path)
    if pr and pr.status > 0:
        return pr
    return None


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _json_dict(body: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None


def _root_model_class(state: TargetState) -> Tuple[str, str]:
    root = state.probes.get("/")
    if not root or root.status != 200:
        return "", ""
    data = _json_dict(root.body)
    if not data:
        return "", ""
    model_class = str(data.get("model_class") or "")
    status = str(data.get("status") or "")
    return model_class, status


def _first_keyword_hit(text: str, keywords: List[str]) -> str:
    low = text.lower()
    for kw in keywords:
        if kw.lower() in low:
            return kw
    return ""


def _probe_text(state: TargetState) -> str:
    return "\n".join(
        pr.body for pr in state.probes.values()
        if pr and pr.status > 0 and pr.body
    )


def _gpu_hits(state: TargetState, cfg: ScanConfig) -> List[str]:
    """Return indirect GPU text/framework hints from all successful probes."""
    ai_cfg = cfg.ai_service or {}
    keywords = (
        _as_list(ai_cfg.get("gpu_keywords"))
        + _as_list(ai_cfg.get("tensorrt_llm_keywords"))
    )
    hits: List[str] = []
    for path, pr in state.probes.items():
        if not pr or pr.status <= 0 or not pr.body:
            continue
        low = pr.body.lower()
        for kw in keywords:
            if kw.lower() in low:
                item = "%s:%s" % (path, kw)
                if item not in hits:
                    hits.append(item)
    return hits[:5]


def _metric_hits(state: TargetState, keywords: List[str]) -> List[str]:
    hits: List[str] = []
    seen_keywords = set()
    for path in GPU_METRIC_PATHS:
        pr = state.probes.get(path)
        if not pr or pr.status != 200 or not pr.body:
            continue
        low = pr.body.lower()
        for kw in keywords:
            normalized = kw.lower()
            if normalized in low and normalized not in seen_keywords:
                seen_keywords.add(normalized)
                hits.append("%s:%s" % (path, kw))
    return hits[:5]


_DCGM_DEVICE_SAMPLE_RE = re.compile(
    r"^\s*(?P<metric>DCGM_FI_DEV_[A-Za-z0-9_:]+)"
    r"(?:\{(?P<labels>[^}]*)\})?\s+"
    r"(?P<value>(?:[-+]?(?:\d+(?:\.\d*)?|\.\d+)"
    r"(?:[eE][-+]?\d+)?|NaN|[-+]?Inf))"
    r"(?:\s+\d+)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _dcgm_device_metric_hits(state: TargetState) -> List[str]:
    """Return actual DCGM device samples; HELP/TYPE comments are not evidence."""
    hits: List[str] = []
    seen = set()
    for path in GPU_METRIC_PATHS:
        probe = state.probes.get(path)
        if not probe or probe.status != 200 or not probe.body:
            continue
        for match in _DCGM_DEVICE_SAMPLE_RE.finditer(probe.body):
            metric = match.group("metric")
            labels = {
                key.lower(): value
                for key, value in re.findall(
                    r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"',
                    match.group("labels") or "",
                )
            }
            identity = tuple(
                labels.get(key, "")
                for key in ("gpu", "uuid", "device", "modelname", "instance")
            )
            dedupe_key = (path, metric.lower(), identity)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            details = ["value=%s" % match.group("value")]
            for key in ("gpu", "uuid", "device", "modelname", "hostname", "instance"):
                if labels.get(key):
                    details.append("%s=%s" % (key, labels[key]))
            hits.append("%s:%s %s" % (path, metric, " ".join(details)))
    return hits[:5]


def _ollama_vram_hits(state: TargetState) -> List[str]:
    pr = state.probes.get("/api/ps")
    if not pr or pr.status != 200:
        return []
    data = _json_dict(pr.body)
    if not data:
        return []
    hits: List[str] = []
    for model in data.get("models") or []:
        if not isinstance(model, dict):
            continue
        try:
            size_vram = int(model.get("size_vram") or 0)
        except (TypeError, ValueError):
            size_vram = 0
        if size_vram > 0:
            name = str(model.get("name") or model.get("model") or "model")
            hits.append("/api/ps:size_vram=%d model=%s" % (size_vram, name))
    return hits[:5]


def _vllm_gpu_allocation_hits(state: TargetState) -> List[str]:
    """Return direct GPU evidence from an active vLLM KV-cache allocation."""
    hits: List[str] = []
    for path in GPU_METRIC_PATHS:
        pr = state.probes.get(path)
        if not pr or pr.status != 200 or not pr.body:
            continue
        for labels in re.findall(r"^vllm:cache_config_info\{([^}]*)\}\s+\S+", pr.body, re.MULTILINE):
            values = dict(re.findall(r"(\w+)=\"([^\"]*)\"", labels))
            try:
                gpu_blocks = int(values.get("num_gpu_blocks") or 0)
                gpu_memory = float(values.get("gpu_memory_utilization") or 0)
            except ValueError:
                continue
            if gpu_blocks > 0 and gpu_memory > 0:
                hits.append(
                    "%s:vllm_gpu_blocks=%d gpu_memory_utilization=%s"
                    % (path, gpu_blocks, values["gpu_memory_utilization"])
                )
    return _dedupe_keep_last(hits)[:5]


def _prometheus_metric_values(body: str, metric: str) -> List[float]:
    values: List[float] = []
    pattern = re.compile(
        r"^(?!#)(?:vllm[:_])?%s(?:\{[^}]*\})?\s+([-+0-9.eE]+)(?:\s|$)"
        % re.escape(metric),
        re.MULTILINE,
    )
    for match in pattern.finditer(body):
        try:
            values.append(float(match.group(1)))
        except ValueError:
            continue
    return values


def _has_positive_vllm_gpu_config(body: str) -> bool:
    for labels in re.findall(
        r"^vllm:cache_config_info\{([^}]*)\}\s+\S+", body, re.MULTILINE
    ):
        values = dict(re.findall(r"(\w+)=\"([^\"]*)\"", labels))
        try:
            gpu_blocks = int(values.get("num_gpu_blocks") or 0)
            gpu_memory = float(values.get("gpu_memory_utilization") or 0)
        except ValueError:
            continue
        if gpu_blocks > 0 or gpu_memory > 0:
            return True
    return False


def _vllm_gpu_runtime_hits(state: TargetState) -> List[str]:
    """Return active vLLM GPU-cache or GPU-backed request evidence."""
    hits: List[str] = []
    for path in GPU_METRIC_PATHS:
        pr = state.probes.get(path)
        if not pr or pr.status != 200 or not pr.body:
            continue
        cache_values = _prometheus_metric_values(
            pr.body, "gpu_cache_usage_perc"
        )
        if any(value > 0 for value in cache_values):
            hits.append(
                "%s:vllm_gpu_cache_usage=%s"
                % (path, max(cache_values))
            )

        running_values = _prometheus_metric_values(
            pr.body, "num_requests_running"
        )
        if (
            _has_positive_vllm_gpu_config(pr.body)
            and any(value > 0 for value in running_values)
        ):
            hits.append(
                "%s:vllm_gpu_requests_running=%s"
                % (path, max(running_values))
            )
    return _dedupe_keep_last(hits)[:5]


def _cluster_gpu_inventory(state: TargetState) -> Tuple[int, int, bool]:
    gpu_count = 0
    gpu_vram_total = 0
    inventory_seen = False
    for path, pr in state.probes.items():
        if not path.endswith("/v1/cluster/info") or pr.status != 200:
            continue
        try:
            data = json.loads(pr.body)
        except (json.JSONDecodeError, TypeError):
            continue
        nodes = data if isinstance(data, list) else [data]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if "gpu_count" in node or "gpu_vram_total" in node:
                inventory_seen = True
            try:
                gpu_count += int(node.get("gpu_count") or 0)
                gpu_vram_total += int(node.get("gpu_vram_total") or 0)
            except (TypeError, ValueError):
                continue
    return gpu_count, gpu_vram_total, inventory_seen


def _openapi_gpu_inventory_tiers(
    state: TargetState,
) -> Tuple[List[str], List[str]]:
    direct_hits: List[str] = []
    inference_hits: List[str] = []
    count_keys = {"gpu_count", "gpu_num", "num_gpus"}
    vram_keys = {"gpu_vram_total", "gpu_memory_total", "vram_total"}
    activity_keys = {
        "gpu_utilization", "gpu_util", "gpu_memory_used", "gpu_memory_usage",
    }

    def walk(
        value: Any,
        counters: Dict[str, float],
        models: List[str],
        device_ids: List[str],
    ) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                low_key = str(key).lower()
                if low_key in count_keys | vram_keys | activity_keys:
                    try:
                        numeric = float(item or 0)
                    except (TypeError, ValueError):
                        numeric = 0
                    if numeric > 0:
                        counters[low_key] = counters.get(low_key, 0) + numeric
                if low_key in {
                    "modelname", "gpu_name", "device_name",
                    "product_name", "model",
                }:
                    text = str(item or "")
                    if re.search(r"\b(?:nvidia|amd instinct|radeon)\b", text, re.I):
                        models.append(text)
                if low_key in {"gpu_uuid", "device_uuid"} and str(item or ""):
                    device_ids.append(str(item))
                walk(item, counters, models, device_ids)
        elif isinstance(value, list):
            for item in value:
                walk(item, counters, models, device_ids)

    for path, probe in state.probes.items():
        if path in GPU_OPENAPI_DOC_PATHS or probe.status != 200:
            continue
        low_path = path.lower()
        if not any(keyword in low_path for keyword in GPU_OPENAPI_PATH_KEYWORDS):
            continue
        try:
            data = json.loads(probe.body)
        except (json.JSONDecodeError, TypeError):
            continue
        counters: Dict[str, float] = {}
        models: List[str] = []
        device_ids: List[str] = []
        walk(data, counters, models, device_ids)
        if not counters and not models and not device_ids:
            continue
        detail = [
            "%s=%g" % item for item in sorted(counters.items())
        ]
        if models:
            detail.append("models=%s" % ",".join(_dedupe_keep_last(models)[:4]))
        if device_ids:
            detail.append(
                "device_ids=%s" % ",".join(_dedupe_keep_last(device_ids)[:4])
            )
        evidence = "%s:%s" % (path, " ".join(detail))
        has_direct_device = (
            any(key in vram_keys | activity_keys for key in counters)
            or bool(models)
            or bool(device_ids)
        )
        if has_direct_device:
            direct_hits.append(evidence)
        elif any(key in count_keys for key in counters):
            inference_hits.append(evidence)
    return (
        _dedupe_keep_last(direct_hits)[:5],
        _dedupe_keep_last(inference_hits)[:5],
    )


def _model_accelerator_assignments(
    state: TargetState,
) -> List[Tuple[str, List[str]]]:
    pr = state.probes.get("/v1/models")
    if not pr or pr.status != 200:
        return []
    data = _json_dict(pr.body)
    items = data.get("data") if data else None
    if not isinstance(items, list):
        return []
    assignments: List[Tuple[str, List[str]]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        accelerators = item.get("accelerators")
        if accelerators in (None, "", []):
            continue
        if isinstance(accelerators, list):
            values = [str(value) for value in accelerators if str(value)]
        else:
            values = [str(accelerators)]
        if values:
            model = str(item.get("id") or item.get("model_name") or "model")
            assignments.append((model, values))
    return assignments


def _model_accelerator_conflict(state: TargetState) -> bool:
    if not _model_accelerator_assignments(state):
        return False
    gpu_count, gpu_vram_total, inventory_seen = _cluster_gpu_inventory(state)
    return inventory_seen and gpu_count <= 0 and gpu_vram_total <= 0


def _model_accelerator_hits(state: TargetState) -> List[str]:
    """Return accelerator assignments unless inventory explicitly reports no GPU."""
    assignments = _model_accelerator_assignments(state)
    if not assignments or _model_accelerator_conflict(state):
        return []
    return [
        "/v1/models:accelerators=%s model=%s"
        % (",".join(values[:8]), model)
        for model, values in assignments[:5]
    ]


def _model_gpu_inventory_hits(state: TargetState) -> List[str]:
    """Return service-declared GPU configuration, never device-runtime evidence."""
    pr = state.probes.get("/v1/models")
    if not pr or pr.status != 200:
        return []
    data = _json_dict(pr.body)
    items = data.get("data") if data else None
    if not isinstance(items, list):
        return []
    hits: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            count = float(item.get("num_gpus") or 0)
        except (TypeError, ValueError):
            count = 0
        if count <= 0:
            continue
        model = str(item.get("id") or item.get("model_name") or "model")
        task = str(item.get("task_type") or "")
        detail = "/v1/models:num_gpus=%g model=%s" % (count, model)
        if task:
            detail += " task_type=%s" % task
        hits.append(detail)
    return _dedupe_keep_last(hits)[:5]

def _gpu_evidence_tiers(
    state: TargetState, cfg: ScanConfig
) -> Tuple[List[str], List[str]]:
    ai_cfg = cfg.ai_service or {}
    openapi_direct, openapi_inference = _openapi_gpu_inventory_tiers(state)
    direct_keywords = [
        keyword
        for keyword in _as_list(ai_cfg.get("gpu_direct_keywords"))
        if not keyword.lower().startswith("dcgm")
    ]
    direct = _metric_hits(state, direct_keywords)
    direct.extend(_dcgm_device_metric_hits(state))
    direct.extend(_ollama_vram_hits(state))
    direct.extend(_vllm_gpu_allocation_hits(state))
    direct.extend(_vllm_gpu_runtime_hits(state))
    direct.extend(openapi_direct)
    inference = _metric_hits(
        state, _as_list(ai_cfg.get("gpu_inference_keywords"))
    )
    inference.extend(_model_accelerator_hits(state))
    # ``num_gpus`` is supplied by the service's own inventory/configuration.
    # It is useful corroboration, but unlike DCGM, VRAM bytes, or GPU UUIDs it
    # does not prove a GPU is presently attached or being used.
    inference.extend(_model_gpu_inventory_hits(state))
    inference.extend(openapi_inference)
    return _dedupe_keep_last(direct)[:5], _dedupe_keep_last(inference)[:5]

@dataclass(frozen=True)
class ModelProfile:
    """A model-level input to the no-metric GPU likelihood fallback."""

    name: str
    origin: str  # local / cloud / unknown
    kind: str  # generative / embedding / reranker / ocr / vision / multimodal / unknown
    parameter_b: Optional[float]


_CLOUD_OWNER_MARKERS = (
    "openai", "anthropic", "google", "gemini", "azure", "volcengine",
    "doubao", "dashscope", "alibaba", "qianfan", "baidu", "zhipu",
    "minimax", "moonshot", "tencent", "hunyuan",
)
_EMBEDDING_MODEL_MARKERS = (
    "embedding", "embed", "e5", "bge", "m3e", "gte", "text2vec",
    "jina-embeddings", "nomic-embed",
)
_RERANKER_MODEL_MARKERS = (
    "reranker", "rerank", "cross-encoder", "cross_encoder", "colbert",
)


def _parse_parameter_billions(value: Any) -> Optional[float]:
    """Parse model sizes such as ``7B`` or ``558.84M`` into billions."""
    if value is None:
        return None
    match = re.search(r"(?<![a-z0-9])(\d+(?:\.\d+)?)\s*([bm])\b", str(value).lower())
    if not match:
        return None
    amount = float(match.group(1))
    return amount if match.group(2) == "b" else amount / 1000.0


def _model_kind(name: str) -> str:
    low = name.lower()
    if any(marker in low for marker in _EMBEDDING_MODEL_MARKERS):
        return "embedding"
    if any(marker in low for marker in _RERANKER_MODEL_MARKERS):
        return "reranker"
    if "ocr" in low:
        return "ocr"
    if any(marker in low for marker in ("yolo", "vision", "visual", "detection", "segmentation")):
        return "vision"
    if any(marker in low for marker in ("multimodal", "qwen-vl", "vision-language", "vl-")):
        return "multimodal"
    return "generative" if name else "unknown"


def _is_explicit_cloud_owner(owner: Any) -> bool:
    low = str(owner or "").lower()
    return bool(low) and any(marker in low for marker in _CLOUD_OWNER_MARKERS)


def _is_explicit_cloud_model(name: Any, item: Dict[str, Any]) -> bool:
    """Recognize an API entry that explicitly denotes a remote cloud model."""
    model_name = str(name or "").strip().lower()
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    remote_host = str(item.get("remote_host") or details.get("remote_host") or "").strip()
    return bool(remote_host) or model_name.endswith(":cloud")


def _local_model_profiles(
    state: TargetState, framework_signal: str
) -> List[ModelProfile]:
    """Extract local/cloud/unknown model profiles from model APIs."""
    profiles: Dict[str, ModelProfile] = {}

    def add(name: Any, origin: str, parameter_size: Any = None) -> None:
        name_s = str(name or "").strip()
        if not name_s:
            return
        key = name_s.lower()
        parameter_b = _parse_parameter_billions(parameter_size)
        if parameter_b is None:
            parameter_b = _parse_parameter_billions(name_s)
        incoming = ModelProfile(name_s, origin, _model_kind(name_s), parameter_b)
        existing = profiles.get(key)
        if existing is None:
            profiles[key] = incoming
            return
        preferred_origin = "local" if "local" in {existing.origin, origin} else existing.origin
        profiles[key] = ModelProfile(
            existing.name,
            preferred_origin,
            existing.kind if existing.kind != "unknown" else incoming.kind,
            existing.parameter_b if existing.parameter_b is not None else incoming.parameter_b,
        )

    tags = state.probes.get("/api/tags")
    tags_data = _json_dict(tags.body) if tags and tags.status == 200 else None
    for item in (tags_data or {}).get("models") or []:
        if isinstance(item, dict):
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            name = item.get("name") or item.get("model")
            origin = "cloud" if _is_explicit_cloud_model(name, item) else "local"
            add(name, origin, details.get("parameter_size"))

    for path in ("/v1/models", "/api/v1/models", "/openai/v1/models", "/v2/models"):
        probe = state.probes.get(path)
        data = _json_dict(probe.body) if probe and probe.status == 200 else None
        for item in (data or {}).get("data") or []:
            if not isinstance(item, dict):
                continue
            owner = item.get("owned_by")
            name = item.get("id") or item.get("model_name") or item.get("name")
            origin = (
                "cloud" if _is_explicit_cloud_model(name, item) or _is_explicit_cloud_owner(owner)
                else "local" if framework_signal else "unknown"
            )
            add(name, origin,
                item.get("parameter_size") or item.get("parameters"))
    return list(profiles.values())


def _model_candidate_decision(
    state: TargetState, framework_signal: str
) -> Optional[Tuple[bool, str]]:
    """Return whether model evidence retains medium likelihood without metrics."""
    profiles = _local_model_profiles(state, framework_signal)
    if not profiles:
        return None
    unknown = [profile for profile in profiles if profile.origin == "unknown"]
    if unknown:
        names = ", ".join(profile.name for profile in unknown[:4])
        return True, "模型来源或规模无法确认，保留中等候选：%s" % names

    local = [profile for profile in profiles if profile.origin == "local"]
    cloud = [profile for profile in profiles if profile.origin == "cloud"]
    cloud_note = (
        "已排除cloud模型：%s" % ", ".join(profile.name for profile in cloud[:4])
        if cloud else ""
    )
    if not local:
        return False, cloud_note or "模型均为明确cloud来源，已从本地GPU候选中排除"

    retained: List[ModelProfile] = []
    excluded: List[str] = []
    for profile in local:
        if profile.kind in {"embedding", "reranker"}:
            excluded.append("%s(%s)" % (profile.name, profile.kind))
        elif profile.kind == "generative" and profile.parameter_b is not None and profile.parameter_b < 10:
            excluded.append("%s(%.3gB<10B)" % (profile.name, profile.parameter_b))
        else:
            retained.append(profile)

    if retained:
        names = ", ".join(profile.name for profile in retained[:4])
        details = [cloud_note] if cloud_note else []
        if excluded:
            details.append("已排除 " + ", ".join(excluded[:4]))
        suffix = ("；" + "；".join(details)) if details else ""
        return True, "保留本地GPU候选：%s%s" % (names, suffix)
    details = [cloud_note] if cloud_note else []
    details.append("本地模型均已排除：%s" % ", ".join(excluded[:6]))
    return False, "；".join(details)


def _set_gpu_classification(
    state: TargetState,
    *,
    ai_service: bool,
    gpu_hits: List[str],
    direct_gpu_hits: List[str],
    inference_hits: List[str],
    framework_signal: str = "",
) -> None:
    """Apply tiers: device/VRAM=high, inference=medium, then model fallback."""
    if direct_gpu_hits:
        state.gpu_likelihood = "高"
        state.gpu_evidence = "; ".join(direct_gpu_hits)
    elif _model_accelerator_conflict(state):
        state.gpu_likelihood = "低"
        state.gpu_evidence = "accelerators reported but cluster_gpu_count=0"
    elif inference_hits:
        state.gpu_likelihood = "中"
        state.gpu_evidence = "; ".join(inference_hits)
    elif ai_service:
        model_decision = _model_candidate_decision(state, framework_signal)
        if model_decision is not None and not model_decision[0]:
            state.gpu_likelihood = "低"
            state.gpu_evidence = model_decision[1]
        elif gpu_hits or framework_signal or model_decision is not None:
            state.gpu_likelihood = "中"
            evidence = list(gpu_hits)
            if framework_signal:
                evidence.append("framework=%s" % framework_signal)
            if model_decision is not None:
                evidence.append(model_decision[1])
            state.gpu_evidence = "; ".join(_dedupe_keep_last(evidence))
        else:
            state.gpu_likelihood = "低"
            state.gpu_evidence = "仅检测到AI/LLM服务，未发现当前端口的GPU证据"
    else:
        state.gpu_likelihood = "未知"
        state.gpu_evidence = ""


def _add_gpu_probe_evidence(state: TargetState, hits: List[str]) -> None:
    for hit in hits:
        path = hit.split(":", 1)[0]
        pr = state.probes.get(path)
        if not pr or pr.status <= 0:
            continue
        prefix = "GET %s " % path
        if not any(item.startswith(prefix) for item in state.evidence):
            state.add_evidence("GET", path, pr.status, pr.body)


def _llm_analysis_reason(state: TargetState) -> str:
    if state.is_llm == "否":
        return ""
    if state.deploy_tool == "librechat":
        return "页面标题命中 LibreChat，判为疑似 LLM 前端"
    if state.deploy_tool == "one-api":
        return "页面命中 New API/模型 API 网关特征，判为疑似 LLM 前端"
    if state.deploy_tool == "llm-knowledge-base":
        return "页面标题命中大模型知识库，判为疑似 LLM 应用"
    evidence = state.evidence_str()
    js_match = re.search(r"JS bundle suspect: ([^\s]+) matched=([^|\s]+)", evidence)
    if js_match:
        keyword = js_match.group(2).split("+", 1)[0]
        return "页面脚本命中AI聊天关键词“%s”，判为疑似LLM前端" % keyword
    if state.is_llm == "确认":
        if state.deploy_tool and state.deploy_tool not in {"unknown", "未知-OpenAI兼容"}:
            return "识别到%s模型服务，确认已部署AI模型" % state.deploy_tool
        return "模型接口返回有效模型信息，确认已部署AI模型"
    return "响应命中LLM前端或接口特征，判为疑似LLM"


def _apply_scan_outcome(state: TargetState) -> None:
    """Classify whether a negative result is conclusive or probe-limited."""
    if state.is_llm == "确认":
        state.scan_status = "llm_confirmed"
        state.scan_confidence = "高"
        return
    if state.is_llm == "疑似":
        state.scan_status = "llm_suspect"
        state.scan_confidence = "中"
        return
    if state.gpu_likelihood == "高":
        state.scan_status = "gpu_confirmed"
        state.scan_confidence = "高"
        return
    if not state.protocol:
        evidence = state.evidence_str().lower()
        if "tls required" in evidence:
            state.scan_status = "protocol_unknown"
        elif "no http response" in evidence:
            state.scan_status = "network_unreachable"
        else:
            state.scan_status = "protocol_unknown"
        state.scan_confidence = "低"
        return

    model_paths = {
        "/v1/models", "/api/v1/models", "/openai/v1/models",
        "/api/tags", "/api/version", "/v2/models",
    }
    root_probe = state.probes.get("/", ProbeResult())
    auth_restricted = any(
        path in model_paths
        and _is_auth_specific_response(path, probe, root_probe)
        for path, probe in state.probes.items()
    )
    generic_restricted = any(
        path in model_paths
        and probe.status in {401, 403}
        and not _is_auth_specific_response(path, probe, root_probe)
        for path, probe in state.probes.items()
    )
    if auth_restricted:
        state.scan_status = "auth_restricted"
        state.scan_confidence = "中"
    elif root_probe.status in {400, 403, 421, 426}:
        state.scan_status = "virtual_host_or_policy_restricted"
        state.scan_confidence = "中"
    elif generic_restricted:
        state.scan_status = "generic_policy_restricted"
        state.scan_confidence = "中"
    elif state.selected_hostname:
        state.scan_status = "hostname_route_completed_no_llm"
        state.scan_confidence = "高"
    else:
        state.scan_status = "completed_no_llm"
        state.scan_confidence = "高"


def _analysis_text(state: TargetState) -> str:
    parts: List[str] = []
    llm_reason = _llm_analysis_reason(state)
    if llm_reason:
        parts.append(llm_reason)
    if state.gpu_likelihood == "高":
        parts.append(
            "当前端口%s，确认存在GPU算力"
            % state.gpu_evidence.replace(";", "、")
        )
    elif state.gpu_likelihood == "中":
        if "业务页面包含GPU租赁/云GPU/BitaHub线索" in state.gpu_evidence:
            parts.append("页面命中租GPU/BitaHub业务线索，属于 GPU 算力业务平台；未发现设备级指标，GPU 判中")
        else:
            parts.append(
                "当前端口%s，GPU算力可能性中"
                % state.gpu_evidence.replace(";", "、")
            )
    elif state.gpu_likelihood == "低":
        if state.gpu_evidence:
            parts.append(
                "当前端口未发现GPU设备或推理指标，%s，GPU算力可能性低"
                % state.gpu_evidence.replace(";", "、")
            )
        else:
            parts.append("未发现当前端口GPU设备或推理指标，GPU算力可能性低")
    return "；".join(parts) + ("。" if parts else "")


def _model_domain(text: str, cfg: ScanConfig) -> str:
    ai_cfg = cfg.ai_service or {}
    low = text.lower()
    if _first_keyword_hit(low, _as_list(ai_cfg.get("ocr_keywords"))):
        return "ocr"
    if _first_keyword_hit(low, _as_list(ai_cfg.get("vision_keywords"))):
        return "vision"
    if "embedding" in low or "bge-m3" in low or "m3e" in low:
        return "embedding"
    if "reranker" in low:
        return "reranker"
    if any(x in low for x in ["qwen-vl", "vl-", "vision-language", "multimodal"]):
        return "multimodal"
    if any(x in low for x in ["qwen", "deepseek", "llama", "chatglm", "vllm", "ollama"]):
        return "llm"
    return "unknown"


def _frontend_signal(state: TargetState, cfg: ScanConfig) -> str:
    """Return a normalized AI frontend signal from full bodies or JS evidence."""
    ai_cfg = cfg.ai_service or {}
    body_hit = _first_keyword_hit(
        _probe_text(state), _as_list(ai_cfg.get("frontend_keywords"))
    )
    if body_hit:
        return body_hit

    for evidence in state.evidence:
        if "JS bundle suspect" not in evidence:
            continue
        match = re.search(r"\bmatched=([^\s]+)", evidence)
        return match.group(1) if match else "js-bundle"
    return ""


def _gpu_business_signal(state: TargetState, cfg: ScanConfig) -> str:
    """Return a GPU business-page signal such as BitaHub/GPU rental."""
    ai_cfg = cfg.ai_service or {}
    return _first_keyword_hit(
        _probe_text(state), _as_list(ai_cfg.get("gpu_business_keywords"))
    )


def _inferred_framework_signal(state: TargetState) -> str:
    root = state.probes.get("/")
    if root and root.status > 0 and "ollama is running" in root.body.lower():
        return "ollama"
    if root and root.status > 0 and "xinference" in root.body.lower():
        return "xinference"

    tags = state.probes.get("/api/tags")
    tags_data = _json_dict(tags.body) if tags and tags.status == 200 else None
    if tags_data is not None and isinstance(tags_data.get("models"), list):
        return "ollama"

    models = state.probes.get("/v1/models")
    models_data = _json_dict(models.body) if models and models.status == 200 else None
    items = models_data.get("data") if models_data else None
    if isinstance(items, list):
        owners = {
            str(item.get("owned_by") or "").lower()
            for item in items
            if isinstance(item, dict)
        }
        for framework in ("vllm", "sglang", "xinference", "ollama", "tgi"):
            if any(framework in owner for owner in owners):
                return framework
    return ""


def _apply_service_classification(state: TargetState, cfg: ScanConfig) -> None:
    _apply_gpu_service_classification(state, cfg)
    state.npu_likelihood, state.npu_evidence, backend = classify_npu(state.probes, state.ip)
    if backend:
        # Re-evaluate independent evidence without backend-agnostic vLLM fields.
        hardware_state = TargetState(ip=state.ip, port=state.port, protocol=state.protocol)
        for path, probe in state.probes.items():
            if "metrics" in path or "prometheus" in path:
                body = "\n".join(line for line in probe.body.splitlines()
                                 if not line.lstrip().lower().startswith(("vllm", "#")))
                hardware_state.probes[path] = ProbeResult(status=probe.status, body=body, error=probe.error)
            elif path != "/v1/models":
                hardware_state.probes[path] = probe
        direct, _ = _gpu_evidence_tiers(hardware_state, cfg)
        if not direct:
            state.gpu_likelihood = "未知"
            state.gpu_evidence = "明确昇腾后端；通用推理框架不作为GPU证据，未见独立GPU硬件证据"
            if state.service_type == "GPU算力服务":
                state.service_type = "NPU算力资源"
    if state.npu_likelihood in {"高", "中"} and state.service_type == "普通Web":
        state.service_type = "NPU算力资源"
    state.accelerator_type = accelerator_type(state.gpu_likelihood, state.npu_likelihood)


def _apply_gpu_service_classification(state: TargetState, cfg: ScanConfig) -> None:
    model_class, model_status = _root_model_class(state)
    body_text = _probe_text(state)
    combined = " ".join([
        state.deploy_tool or "",
        state.model_info or "",
        model_class,
        body_text[:2000],
    ])
    gpu_hits = _gpu_hits(state, cfg)
    direct_gpu_hits, inference_hits = _gpu_evidence_tiers(state, cfg)
    _add_gpu_probe_evidence(state, direct_gpu_hits + inference_hits)
    frontend_signal = _frontend_signal(state, cfg)
    gpu_business_signal = _gpu_business_signal(state, cfg)

    if not state.protocol:
        state.service_type = "非HTTP"
        state.model_domain = "unknown"
        state.gpu_likelihood = "未知"
        state.gpu_evidence = ""
        return

    if model_class and model_status.upper() == "UP":
        state.is_llm = "否"
        state.service_type = "AI模型服务"
        state.deploy_tool = state.deploy_tool or "AI模型服务"
        state.model_info = state.model_info or model_class
        state.model_domain = _model_domain(model_class, cfg)
        _set_gpu_classification(
            state,
            ai_service=True,
            gpu_hits=gpu_hits,
            direct_gpu_hits=direct_gpu_hits,
            inference_hits=inference_hits,
        )
        evidence = ["model_class=%s" % model_class, "status=%s" % model_status]
        if state.gpu_evidence:
            evidence.append(state.gpu_evidence)
        state.gpu_evidence = "; ".join(evidence)
        return

    if state.is_llm == "确认":
        state.service_type = "LLM服务"
        state.model_domain = _model_domain(combined, cfg)
        gpu_frameworks = {
            "vllm", "tgi", "sglang", "xinference", "triton", "TensorRT-LLM",
            "ollama", "llama.cpp", "localai", "fastchat",
        }
        framework_signal = (
            state.deploy_tool if state.deploy_tool in gpu_frameworks
            else _inferred_framework_signal(state)
        )
        if framework_signal and state.deploy_tool in {
            "", "unknown", "未知-OpenAI兼容"
        }:
            state.deploy_tool = framework_signal
        _set_gpu_classification(
            state,
            ai_service=True,
            gpu_hits=gpu_hits,
            direct_gpu_hits=direct_gpu_hits,
            inference_hits=inference_hits,
            framework_signal=framework_signal,
        )
        if state.deploy_tool == "未知-OpenAI兼容":
            suffix = "OpenAI-compatible API; may be proxy"
            state.gpu_evidence = (
                "%s; %s" % (state.gpu_evidence, suffix)
                if state.gpu_evidence else suffix
            )
        return

    if state.is_llm == "疑似":
        frontend_tools = {
            "open-webui", "one-api", "gradio", "streamlit",
            "librechat", "llm-knowledge-base",
        }
        is_frontend = state.deploy_tool in frontend_tools or bool(frontend_signal)
        if is_frontend:
            state.service_type = "AI前端服务"
            state.model_domain = _model_domain(combined, cfg)
        # A Gradio or AI frontend can relay requests to an external model API.
        # Page/framework keywords alone do not establish a local model or GPU.
        if is_frontend and not direct_gpu_hits and not inference_hits:
            state.gpu_likelihood = "低"
            state.gpu_evidence = "AI前端服务未返回本机GPU设备、显存或推理运行指标"
            return
        _set_gpu_classification(
            state,
            ai_service=True,
            gpu_hits=gpu_hits,
            direct_gpu_hits=direct_gpu_hits,
            inference_hits=inference_hits,
        )
        return

    if gpu_business_signal:
        state.is_llm = "否"
        state.service_type = "GPU算力服务"
        state.model_domain = "unknown"
        if direct_gpu_hits or inference_hits:
            _set_gpu_classification(
                state,
                ai_service=True,
                gpu_hits=gpu_hits,
                direct_gpu_hits=direct_gpu_hits,
                inference_hits=inference_hits,
            )
        else:
            state.gpu_likelihood = "中"
            state.gpu_evidence = "业务页面包含GPU租赁/云GPU/BitaHub线索"
        root_probe = state.probes.get("/")
        if root_probe and root_probe.status > 0:
            state.add_evidence("GET", "/", root_probe.status, root_probe.body)
        return

    state.model_domain = "unknown"
    _set_gpu_classification(
        state,
        ai_service=False,
        gpu_hits=[],
        direct_gpu_hits=direct_gpu_hits,
        inference_hits=inference_hits,
    )
    state.service_type = (
        "GPU算力服务"
        if state.gpu_likelihood in {"高", "中"}
        else "普通Web"
    )


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
        existing = state.probes.get(path)
        if existing and existing.status > 0:
            return existing
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
    connector = aiohttp.TCPConnector(
        limit=concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
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
    connector = aiohttp.TCPConnector(
        limit=concurrency, ssl=False,
        enable_cleanup_closed=True, keepalive_timeout=30,
    )
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


def _strip_surrogates(value: Any) -> Any:
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass").decode("utf-8", "ignore")
    return value


def _sanitize_csv_rows(rows: List[dict]) -> List[dict]:
    return [
        {key: _strip_surrogates(value) for key, value in row.items()}
        for row in rows
    ]

def write_csv_rows(path: Path, rows: List[dict], append: bool = False) -> None:
    if append and path.is_file() and path.stat().st_size:
        fields, existing = read_csv_rows_preserve(path)
        if fields != OUTPUT_FIELDNAMES:
            fields = list(dict.fromkeys(fields + OUTPUT_FIELDNAMES))
            write_csv_atomic(path, fields, existing + rows)
            return
    mode = "a" if append else "w"
    need_header = not append or not path.is_file() or path.stat().st_size == 0
    with path.open(mode, encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=OUTPUT_FIELDNAMES, quoting=csv.QUOTE_NONNUMERIC
        )
        if need_header:
            writer.writeheader()
        writer.writerows(_sanitize_csv_rows(rows))



def read_csv_rows_preserve(path: Path) -> Tuple[List[str], List[dict]]:
    for enc in ("utf-8-sig", "gbk", "utf-8"):
        try:
            with path.open(encoding=enc, newline="") as source:
                reader = csv.DictReader(line.replace("\0", "") for line in source)
                rows = list(reader)
                return list(reader.fieldnames or []), rows
        except UnicodeDecodeError:
            continue
    raise ValueError("Cannot decode %s" % path)


def _parse_probe_detail(value: str) -> Dict[str, Dict[str, Any]]:
    if not value:
        return {}
    try:
        data = json.loads(value)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _row_to_state(row: dict) -> TargetState:
    evidence = [
        item for item in (row.get("evidence") or "").split(EVIDENCE_SEP) if item
    ]
    links = [
        item for item in (row.get("link") or "").split(EVIDENCE_SEP) if item
    ]
    return TargetState(
        ip=(row.get("ip") or "").strip(),
        port=(row.get("port") or "").strip(),
        protocol=(row.get("protocol") or "").strip(),
        is_llm=(row.get("is_llm") or "否").strip(),
        service_type=(row.get("service_type") or "").strip(),
        model_domain=(row.get("model_domain") or "").strip(),
        gpu_likelihood=(row.get("gpu_likelihood") or "").strip(),
        gpu_evidence=(row.get("gpu_evidence") or "").strip(),
        npu_likelihood=(row.get("npu_likelihood") or "未知").strip(),
        npu_evidence=(row.get("npu_evidence") or "").strip(),
        accelerator_type=(row.get("accelerator_type") or "未知").strip(),
        gpu_probe_detail=_parse_probe_detail(row.get("gpu_probe_detail") or ""),
        deploy_tool=(row.get("deploy_tool") or "").strip(),
        deploy_version=(row.get("deploy_version") or "").strip(),
        model_info=(row.get("model_info") or "").strip(),
        evidence=evidence,
        links=links,
        scan_time=(row.get("scan_time") or "").strip(),
        analysis=(row.get("分析") or "").strip(),
        scan_status=(row.get("scan_status") or "").strip(),
        scan_confidence=(row.get("scan_confidence") or "").strip(),
        protocol_probe_detail=_parse_probe_detail(
            row.get("protocol_probe_detail") or ""
        ),
        certificate_names=[
            item for item in (row.get("certificate_names") or "").split(EVIDENCE_SEP)
            if item
        ],
        tested_hostnames=[
            item for item in (row.get("tested_hostnames") or "").split(EVIDENCE_SEP)
            if item
        ],
        selected_hostname=(row.get("selected_hostname") or "").strip(),
    )


def load_gpu_rescan_updates(path: Path) -> Dict[str, dict]:
    updates: Dict[str, dict] = {}
    if not path.is_file():
        return updates
    with path.open(encoding="utf-8") as source:
        for line in source:
            try:
                obj = json.loads(line)
                row = obj["row"]
                updates["%s:%s" % (row["ip"], row["port"])] = row
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    print("GPU rescan checkpoint: %d completed HTTP targets" % len(updates))
    return updates


def append_gpu_rescan_updates(path: Path, rows: List[dict]) -> None:
    with path.open("a", encoding="utf-8") as target:
        for row in rows:
            target.write(json.dumps({"row": row}, ensure_ascii=False) + "\n")
        target.flush()


def write_csv_atomic(path: Path, fieldnames: List[str], rows: List[dict]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(
            target, fieldnames=fieldnames, quoting=csv.QUOTE_NONNUMERIC,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(_sanitize_csv_rows(rows))
    temp.replace(path)


def _has_direct_gpu_evidence(value: str) -> bool:
    lower = (value or "").lower()
    return any(token in lower for token in (
        "size_vram=", "dcgm_", "dcgm_fi_dev_", "nvidia-smi",
        "gpu_uuid", "gpu_device", "gpu_memory", "gpu_utilization",
        "nv_gpu_", "tritonserver_gpu", "rocm_smi", "amd_smi", "amdgpu",
    ))


def apply_same_ip_gpu_correlation(rows: List[dict]) -> int:
    """Propagate direct GPU evidence to confirmed LLM ports on the same IP."""
    sources_by_ip: Dict[str, List[dict]] = {}
    for row in rows:
        evidence = (row.get("gpu_evidence") or "").strip()
        if row.get("gpu_likelihood") != "高" or not _has_direct_gpu_evidence(evidence):
            continue
        sources_by_ip.setdefault((row.get("ip") or "").strip(), []).append(row)

    changed = 0
    for row in rows:
        if row.get("is_llm") != "确认" or row.get("gpu_likelihood") == "高":
            continue
        ip = (row.get("ip") or "").strip()
        target_port = str(row.get("port") or "").strip()
        sources = [
            source for source in sources_by_ip.get(ip, [])
            if str(source.get("port") or "").strip() != target_port
        ]
        if not sources:
            continue
        source_ports = []
        source_evidence = []
        for source in sources:
            port = str(source.get("port") or "").strip()
            if port and port not in source_ports:
                source_ports.append(port)
            evidence = (source.get("gpu_evidence") or "").strip()
            if evidence and evidence not in source_evidence:
                source_evidence.append(evidence)
        row["gpu_likelihood"] = "高"
        row["gpu_evidence"] = (
            "same_ip_gpu_port=%s; %s"
            % (",".join(source_ports[:5]), "; ".join(source_evidence[:5]))
        ).strip("; ")
        state = _row_to_state(row)
        row["分析"] = _analysis_text(state)
        changed += 1
    return changed

async def run_gpu_rescan(
    input_path: Path,
    output_path: Path,
    checkpoint_path: Path,
    cfg: ScanConfig,
    batch_size: int,
    resume: bool,
) -> None:
    fieldnames, original_rows = read_csv_rows_preserve(input_path)
    for name in OUTPUT_FIELDNAMES:
        if name not in fieldnames:
            fieldnames.append(name)

    original_llm = {
        label: sum(1 for row in original_rows if row.get("is_llm") == label)
        for label in ("确认", "疑似")
    }
    updates = load_gpu_rescan_updates(checkpoint_path) if resume else {}
    # Old checkpoints did not examine NPUs; do not silently skip those targets.
    updates = {key: row for key, row in updates.items() if "npu_likelihood" in row}
    http_rows = [
        row for row in original_rows
        if (row.get("protocol") or "").strip() in {"http", "https"}
    ]
    pending = [
        row for row in http_rows
        if "%s:%s" % (row.get("ip"), row.get("port")) not in updates
    ]
    print(
        "GPU rescan: %d total rows, %d HTTP targets, %d pending"
        % (len(original_rows), len(http_rows), len(pending))
    )

    for start in range(0, len(pending), batch_size):
        batch_rows = pending[start:start + batch_size]
        states = [_row_to_state(row) for row in batch_rows]
        await phase_gpu_discovery(states, None, cfg)
        await phase_gpu_openapi(states, None, cfg)
        completed: List[dict] = []
        for original, state in zip(batch_rows, states):
            _apply_service_classification(state, cfg)
            state.scan_time = _now()
            state.analysis = _analysis_text(state)
            updated = dict(original)
            updated.update(state.to_row())
            completed.append(updated)
            updates["%s:%s" % (state.ip, state.port)] = updated
        append_gpu_rescan_updates(checkpoint_path, completed)
        print(
            "GPU rescan progress: %d/%d HTTP targets"
            % (min(start + len(completed) + (len(http_rows) - len(pending)),
                     len(http_rows)), len(http_rows))
        )

    final_rows = []
    for row in original_rows:
        key = "%s:%s" % (row.get("ip"), row.get("port"))
        final_rows.append(updates.get(key, row))
    correlated = apply_same_ip_gpu_correlation(final_rows)
    annotate_same_ip(final_rows)
    print("NPU likelihood: %s" % {
        label: sum(row.get("npu_likelihood") == label for row in final_rows)
        for label in ("高", "中", "低", "未知")})
    print("Same-IP GPU correlation: %d confirmed LLM ports promoted" % correlated)
    final_llm = {
        label: sum(1 for row in final_rows if row.get("is_llm") == label)
        for label in ("确认", "疑似")
    }
    if final_llm != original_llm:
        raise RuntimeError(
            "GPU rescan changed LLM counts: %s -> %s"
            % (original_llm, final_llm)
        )
    write_csv_atomic(output_path, fieldnames, final_rows)
    gpu_counts = {
        label: sum(1 for row in final_rows if row.get("gpu_likelihood") == label)
        for label in ("高", "中", "低", "未知")
    }
    print("GPU rescan complete: %s" % gpu_counts)
    print("Output: %s" % output_path)


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
    gpu_c = rt.gpu_probe.concurrency
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

        # GPU discovery is independent from LLM fingerprinting. Every live
        # HTTP target gets one cheap /metrics request; only candidates receive
        # framework-specific fallback probes.
        if http_alive:
            print(
                "GPU discovery: %d HTTP targets, adaptive paths (concurrency=%d)..."
                % (len(http_alive), gpu_c)
            )
            await phase_gpu_discovery(http_alive, gpu_c, cfg)

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

        # Phase 3 — confirmed LLM plus root model_class services
        phase3_targets = [
            s for s in phase2_targets
            if s.is_llm == "确认" or _root_model_class(s)[0]
        ]
        if phase3_targets:
            print("Phase 3: model info (%d targets, concurrency=%d)..." % (len(phase3_targets), p3_c))
            phase3_targets = await phase3_model(phase3_targets, p3_c, cfg)

        # OpenAPI probing is read-only and limited to AI/API candidates.
        if http_alive:
            await phase_gpu_openapi(http_alive, gpu_c, cfg)

        # Stamp scan_time for all processed targets
        ts = _now()
        for s in http_alive + excluded:
            if not s.scan_time:
                s.scan_time = ts

        # Merge phase2/phase3 results back
        state_map: Dict[str, TargetState] = {}
        for s in phase2_targets:
            state_map["%s:%s" % (s.ip, s.port)] = s
        for s in phase3_targets:
            state_map["%s:%s" % (s.ip, s.port)] = s

        batch_states: List[TargetState] = []
        for s in excluded:
            batch_states.append(s)
        for s in http_alive:
            key = "%s:%s" % (s.ip, s.port)
            batch_states.append(state_map.get(key, s))

        for s in batch_states:
            _apply_service_classification(s, cfg)
            _apply_scan_outcome(s)
            s.analysis = _analysis_text(s)

        rows = [s.to_row() for s in batch_states]
        write_csv_rows(output_path, rows, append=append_mode)
        append_mode = True  # subsequent batches always append
        append_checkpoint(checkpoint_path, batch_states)
        all_result_rows.extend(rows)

        llm_count = sum(1 for r in rows if r["is_llm"] == "确认")
        suspect_count = sum(1 for r in rows if r["is_llm"] == "疑似")
        ai_model_count = sum(1 for r in rows if r["service_type"] == "AI模型服务")
        ai_frontend_count = sum(1 for r in rows if r["service_type"] == "AI前端服务")
        gpu_compute_count = sum(1 for r in rows if r["service_type"] == "GPU算力服务")
        gpu_high_count = sum(1 for r in rows if r["gpu_likelihood"] == "高")
        print("  Batch written: %d rows (%d confirmed LLM, %d suspect, %d AI model, %d AI frontend, %d GPU compute, %d GPU high)" % (
            len(rows), llm_count, suspect_count, ai_model_count,
            ai_frontend_count, gpu_compute_count, gpu_high_count
        ))

    # Apply same-IP evidence after all batches so GPU metrics and LLM ports can
    # be correlated even when they were processed in different batches.
    if output_path.is_file():
        fieldnames, final_rows = read_csv_rows_preserve(output_path)
        correlated = apply_same_ip_gpu_correlation(final_rows)
        npu_changed = annotate_same_ip(final_rows)
        fieldnames = list(dict.fromkeys(fieldnames + OUTPUT_FIELDNAMES))
        if correlated or npu_changed:
            write_csv_atomic(output_path, fieldnames, final_rows)
        all_result_rows = final_rows
        print("Same-IP GPU correlation: %d confirmed LLM ports promoted" % correlated)

    # Summary
    total_written = len(all_result_rows)
    total_confirmed = sum(1 for r in all_result_rows if r["is_llm"] == "确认")
    total_suspect = sum(1 for r in all_result_rows if r["is_llm"] == "疑似")
    total_ai_model = sum(1 for r in all_result_rows if r["service_type"] == "AI模型服务")
    total_ai_frontend = sum(1 for r in all_result_rows if r["service_type"] == "AI前端服务")
    total_gpu_compute = sum(1 for r in all_result_rows if r["service_type"] == "GPU算力服务")
    gpu_counts = {
        label: sum(1 for r in all_result_rows if r["gpu_likelihood"] == label)
        for label in ("高", "中", "低", "未知")
    }
    print("\n=== Done ===")
    print("NPU likelihood: %s" % {
        label: sum(row.get("npu_likelihood") == label for row in all_result_rows)
        for label in ("高", "中", "低", "未知")})
    print("Total rows written: %d" % total_written)
    print("LLM confirmed: %d" % total_confirmed)
    print("LLM suspect:   %d" % total_suspect)
    print("AI model services:    %d" % total_ai_model)
    print("AI frontend services: %d" % total_ai_frontend)
    print("GPU compute services: %d" % total_gpu_compute)
    print("GPU likelihood: high=%d medium=%d low=%d unknown=%d" % (
        gpu_counts["高"], gpu_counts["中"], gpu_counts["低"], gpu_counts["未知"]
    ))
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
        "--gpu-rescan", action="store_true",
        help="Only re-probe GPU URIs in an existing result CSV; preserve LLM fields"
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

    if args.gpu_rescan:
        asyncio.run(
            run_gpu_rescan(
                input_path=input_path,
                output_path=output_path,
                checkpoint_path=checkpoint_path,
                cfg=cfg,
                batch_size=args.batch_size,
                resume=args.resume,
            )
        )
        return 0

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
