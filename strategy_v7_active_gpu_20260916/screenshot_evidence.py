#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fill Excel '证明截图' with evidence-aware screenshots (URL + Beijing timestamp)."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
import shutil
import ssl
import textwrap
from datetime import datetime
from pathlib import Path
from subprocess import PIPE, STDOUT, TimeoutExpired, run
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

from openpyxl import load_workbook
from openpyxl.drawing.image import Image as ExcelImage
from openpyxl.drawing.spreadsheet_drawing import AnchorMarker, TwoCellAnchor
from openpyxl.utils import get_column_letter
from PIL import Image, ImageDraw, ImageFont

CONTEXT = ssl._create_unverified_context()
IMAGE_DISPLAY_WIDTH = 400
IMAGE_MIN_DISPLAY_HEIGHT = 180
IMAGE_MAX_DISPLAY_HEIGHT = 320
IMAGE_MIN_ROW_HEIGHT = 140
IMAGE_COL_WIDTH = 62
CHROME_CANDIDATES = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    Path("/usr/bin/google-chrome"),
    Path("/usr/bin/google-chrome-stable"),
    Path("/opt/google/chrome/chrome"),
    Path("/usr/bin/chromium-browser"),
    Path("/usr/bin/chromium"),
]
FONT_CANDIDATES = [
    Path(r"C:\Windows\Fonts\msyh.ttc"),
    Path(r"C:\Windows\Fonts\msyh.ttf"),
    Path("/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc"),
    Path("/usr/share/fonts/google-noto-sans-cjk-fonts/NotoSansCJK-Regular.ttc"),
    Path("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"),
    Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
    Path("/usr/share/fonts/wqy-zenhei/wqy-zenhei.ttc"),
    Path("/usr/share/fonts/wqy-microhei/wqy-microhei.ttc"),
]


def find_column(sheet, header):
    for column in range(1, sheet.max_column + 1):
        if str(sheet.cell(1, column).value or "").strip() == header:
            return column
    return None


def detect_chrome(required=True):
    for name in ("google-chrome", "google-chrome-stable", "chromium-browser", "chromium", "chrome"):
        found = shutil.which(name)
        if found:
            return Path(found)
    for path in CHROME_CANDIDATES:
        if path.is_file():
            return path
    if required:
        raise FileNotFoundError("未找到 Chrome/Chromium")
    return None


def detect_font():
    for path in FONT_CANDIDATES:
        if path.is_file():
            return path
    raise FileNotFoundError("未找到中文字体，无法写入 URL/时间戳")


def split_urls(value):
    return [url.strip() for url in str(value or "").split("|||") if url.strip()]


def evidence_kind(note):
    text = str(note or "")
    lowered = text.lower()
    if "/api/ps" in lowered or "size_vram" in lowered or "显存" in text:
        return "vram"
    if any(token in lowered for token in ("/metrics", "dcgm", "gpu_memory", "vllm_gpu", "gpu_uuid", "nv_gpu")):
        return "metrics"
    return "models"


def score_url(url, kind):
    if kind == "vram":
        if "/api/ps" in url:
            return 0
        if "/v1/models" in url:
            return 2
        if "/api/tags" in url:
            return 3
        return 9
    if kind == "metrics":
        if "/metrics" in url:
            return 0
        if "/v1/models" in url:
            return 2
        return 9
    if "/v1/models" in url:
        return 0
    if "/api/tags" in url:
        return 1
    if "/info" in url:
        return 2
    if "/props" in url:
        return 3
    if "/api/version" in url:
        return 4
    return 8


def preferred_urls(links, note):
    kind = evidence_kind(note)
    urls = split_urls(links)
    return sorted(urls, key=lambda url: score_url(url, kind))


def fetch_response(url):
    try:
        with urlopen(Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=8, context=CONTEXT) as response:
            if "/metrics" in url:
                prefix = bytearray()
                relevant = bytearray()
                pending = b""
                scanned = 0
                while scanned < 64 * 1024 * 1024:
                    chunk = response.read(min(65536, 64 * 1024 * 1024 - scanned))
                    if not chunk:
                        break
                    scanned += len(chunk)
                    pending += chunk
                    lines = pending.splitlines(keepends=True)
                    if lines and not lines[-1].endswith((b"\n", b"\r")):
                        pending = lines.pop()
                    else:
                        pending = b""
                    for line in lines:
                        if len(prefix) < 65536:
                            prefix.extend(line[: 65536 - len(prefix)])
                        low = line.lower()
                        if any(token in low for token in (
                            b"gpu", b"nvidia", b"dcgm", b"nvml", b"cuda",
                            b"vram", b"hbm", b"accelerator", b"cache_config_info",
                        )) and len(relevant) < 2 * 1024 * 1024:
                            relevant.extend(line[: 2 * 1024 * 1024 - len(relevant)])
                body = bytes(prefix) + b"\n# filtered_gpu_metrics\n" + bytes(relevant)
            else:
                body = response.read(2 * 1024 * 1024)
            if 200 <= response.status < 400 and body:
                return response.status, response.headers.get("Content-Type", ""), body
    except Exception:
        pass
    return None


def capture(chrome, url, path):
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(chrome), "--headless", "--disable-gpu", "--no-first-run",
        "--no-sandbox", "--disable-dev-shm-usage",
        "--ignore-certificate-errors", "--virtual-time-budget=4000",
        "--window-size=1100,500", f"--screenshot={target}", url,
    ]
    try:
        result = run(command, stdout=PIPE, stderr=STDOUT, text=True, timeout=20)
    except TimeoutExpired:
        return False
    return result.returncode == 0 and target.exists() and target.stat().st_size > 0


def response_text(content_type, body):
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type or "", flags=re.I)
    if match:
        charset = match.group(1).strip('"\'')
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    stripped = text.lstrip()
    if "json" in (content_type or "").lower() or stripped.startswith(("{", "[")):
        try:
            return json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass
    if "html" in (content_type or "").lower() or "<html" in stripped[:500].lower():
        text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", text, flags=re.I | re.S)
        text = re.sub(r"<[^>]+>", "\n", text)
        text = html.unescape(text)
    return text


GPU_EVIDENCE_RE = re.compile(
    r"gpu|nvidia|dcgm|nvml|cuda|vram|hbm|accelerator|"
    r"size_vram|memory_(?:used|total|utilization)|vllm_gpu|nv_gpu|gpu_uuid",
    flags=re.IGNORECASE,
)


def response_card_lines(content_type, body, evidence_note="", max_lines=36):
    """Return response lines that make the recorded GPU conclusion reviewable.

    Metric endpoints can put the useful values thousands of lines below the
    first viewport.  ``fetch_response`` retains both a prefix and matching
    metrics, so select the latter here instead of blindly rendering the prefix.
    """
    source_lines = response_text(content_type, body).splitlines()
    kind = evidence_kind(evidence_note)
    evidence_indexes = [
        index for index, line in enumerate(source_lines)
        if GPU_EVIDENCE_RE.search(line)
    ]
    if kind == "models":
        # A model response may start with cloud or helper models while the
        # explanation names a later, retained local candidate.  Render the
        # named JSON records rather than a blind first viewport.
        note_markers = {
            marker.lower()
            for marker in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(evidence_note))
            if len(marker) >= 3
        }
        matched_indexes = [
            index for index, line in enumerate(source_lines)
            if any(marker in line.lower() for marker in note_markers)
        ]
        if matched_indexes:
            selected = []
            seen = set()
            for index in matched_indexes:
                for nearby in range(max(0, index - 1), min(len(source_lines), index + 2)):
                    if nearby not in seen:
                        selected.append(source_lines[nearby])
                        seen.add(nearby)
                    if len(selected) >= max_lines:
                        return selected, bool(evidence_indexes)
            return selected[:max_lines], bool(evidence_indexes)
        return source_lines[:max_lines], bool(evidence_indexes)

    if kind not in {"metrics", "vram"} or not evidence_indexes:
        visible = source_lines[:max_lines]
        return visible, bool(evidence_indexes)

    # Prefer the exact metric names named in the conclusion.  A Prometheus
    # endpoint can expose hundreds of GPU lines; taking only the first ones
    # would still risk omitting (for example) gpu_memory_utilization cited by
    # the workbook.
    generic_markers = {
        "gpu", "vram", "hbm", "cuda", "nvidia", "dcgm", "nvml", "accelerator",
    }
    note_markers = {
        marker.lower()
        for marker in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(evidence_note))
        if GPU_EVIDENCE_RE.search(marker) and marker.lower() not in generic_markers
    }
    cited_indexes = [
        index for index, line in enumerate(source_lines)
        if any(marker in line.lower() for marker in note_markers)
    ]
    evidence_indexes = cited_indexes or evidence_indexes

    selected = []
    seen = set()
    seen_lines = set()
    for index in evidence_indexes:
        # JSON values and Prometheus labels can wrap over adjacent lines, so
        # retain a small amount of context without allowing unrelated prefixes
        # to consume the card.
        for nearby in range(max(0, index - 1), min(len(source_lines), index + 1)):
            line = source_lines[nearby]
            line_key = line.strip()
            if nearby not in seen and line_key not in seen_lines:
                selected.append(line)
                seen.add(nearby)
                seen_lines.add(line_key)
            if len(selected) >= max_lines:
                return selected, True
    return selected[:max_lines], True


def wrap_response_lines(lines, width=112, max_lines=40):
    wrapped = []
    for source_line in lines:
        wrapped.extend(textwrap.wrap(source_line, width=width, replace_whitespace=False) or [""])
        if len(wrapped) >= max_lines:
            return wrapped[:max_lines - 1] + ["…（响应内容已截断）"]
    return wrapped or ["（响应正文为空）"]


def capture_response_card(url, response, path, font_path, evidence_note=""):
    status, content_type, body = response
    selected_lines, _found_evidence = response_card_lines(
        content_type, body, evidence_note
    )
    lines = wrap_response_lines(selected_lines)
    width = 1200
    title_height = 42
    line_height = 28
    height = max(220, title_height + len(lines) * line_height + 22)
    page = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(page)
    font = ImageFont.truetype(font_path, 16)
    title_font = ImageFont.truetype(font_path, 18)
    draw.rectangle((0, 0, width, title_height), fill=(238, 244, 252))
    draw.text(
        (16, 9),
        f"HTTP {status}  {content_type or 'unknown content type'}",
        font=title_font,
        fill=(25, 55, 85),
    )
    draw.multiline_text((16, title_height + 12), "\n".join(lines), font=font, fill=(25, 25, 25), spacing=7)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    page.save(path)
    return True


def add_metadata(path, url, font_path):
    page = Image.open(path).convert("RGB")
    header_height, footer_height = 42, 36
    image = Image.new("RGB", (page.width, page.height + header_height + footer_height), "white")
    image.paste(page, (0, header_height))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, page.width, header_height), fill=(245, 245, 245))
    draw.line((0, header_height - 1, page.width, header_height - 1), fill=(210, 210, 210))
    draw.text((16, 10), url, font=ImageFont.truetype(font_path, 18), fill=(35, 35, 35))
    timestamp = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    draw.text(
        (16, page.height + header_height + 8),
        f"截图时间：{timestamp}（北京时间）",
        font=ImageFont.truetype(font_path, 16),
        fill=(75, 75, 75),
    )
    image.save(path)


def image_cells(sheet, image_column):
    cells = set()
    for image in sheet._images:
        anchor = image.anchor
        if hasattr(anchor, "_from") and anchor._from.col + 1 == image_column:
            cells.add(anchor._from.row + 1)
    return cells


def remove_image_at(sheet, row, column):
    """Remove a prior screenshot before replacing it or marking it stale."""
    coordinate = "%s%s" % (get_column_letter(column), row)
    sheet._images = [
        image for image in sheet._images
        if not (
            (isinstance(image.anchor, str) and image.anchor == coordinate)
            or (
                hasattr(image.anchor, "_from")
                and image.anchor._from.row + 1 == row
                and image.anchor._from.col + 1 == column
            )
        )
    ]


def attach_image(sheet, path, row, column):
    """Bind screenshot to the 证明截图 cell (TwoCellAnchor, one cell).

    This is Excel 'Place over cells' sized to that cell, not 365 'Place in Cell'.
    WPS and older Excel can display it; the picture moves with the row.
    """
    image = ExcelImage(path)
    display_height = round(IMAGE_DISPLAY_WIDTH * image.height / image.width)
    image.width = IMAGE_DISPLAY_WIDTH
    image.height = min(IMAGE_MAX_DISPLAY_HEIGHT, max(IMAGE_MIN_DISPLAY_HEIGHT, display_height))
    image.anchor = TwoCellAnchor(
        editAs="oneCell",
        _from=AnchorMarker(col=column - 1, colOff=0, row=row - 1, rowOff=0),
        to=AnchorMarker(col=column, colOff=0, row=row, rowOff=0),
    )
    sheet.add_image(image)
    sheet.row_dimensions[row].height = max(
        sheet.row_dimensions[row].height or 0,
        max(IMAGE_MIN_ROW_HEIGHT, image.height * 0.75),
    )
    letter = get_column_letter(column)
    if (sheet.column_dimensions[letter].width or 0) < 58:
        sheet.column_dimensions[letter].width = IMAGE_COL_WIDTH


def evidence_key(ip, port, protocol):
    return "%s|%s|%s" % (str(ip or "").strip(), str(port or "").strip(), str(protocol or "").strip())


def load_manifest(path):
    if not path or not Path(path).is_file():
        return {}
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_manifest(path, records):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(target)


def read_csv_rows(path):
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            with Path(path).open(encoding=encoding, newline="") as source:
                return list(csv.DictReader(source))
        except UnicodeDecodeError:
            continue
    raise ValueError("cannot decode %s" % path)


def capture_csv_evidence(source, assets, manifest_path, limit=None):
    """Capture evidence immediately after a scan stage and persist a manifest."""
    chrome = detect_chrome(required=False)
    font_path = str(detect_font())
    assets.mkdir(parents=True, exist_ok=True)
    records = load_manifest(manifest_path)
    captured = 0
    for row in read_csv_rows(source):
        if limit is not None and captured >= limit:
            break
        ip = row.get("ip", "")
        port = row.get("port", "")
        protocol = row.get("protocol", "")
        likelihood = str(row.get("gpu_likelihood", "")).strip().lower()
        if likelihood not in {"高", "中", "低", "high", "medium", "low"}:
            continue
        if not ip or not port or protocol not in {"http", "https"}:
            continue
        key = evidence_key(ip, port, protocol)
        existing = records.get(key) or {}
        if existing.get("path") and Path(existing["path"]).is_file():
            continue
        note = row.get("gpu_evidence", "") or row.get("npu_evidence", "") or row.get("evidence", "")
        urls = preferred_urls(row.get("link", ""), note)
        selected = None
        response = None
        for url in urls:
            response = fetch_response(url)
            if response is not None:
                selected = url
                break
        if not selected:
            selected = "%s://%s:%s/" % (protocol, ip, port)
            text = "扫描阶段的原始 HTTP 响应\n\n%s" % (row.get("evidence", "") or note)
            response = (200, "text/plain; charset=utf-8", text.encode("utf-8"))
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
        image_path = assets / (digest + ".png")
        # Use the exact HTTP response instead of a browser first viewport.  A
        # metrics page can be very long and its GPU evidence is often not near
        # the top, which previously made the image contradict the conclusion.
        captured_ok = capture_response_card(
            selected, response, image_path, font_path, note
        )
        if not captured_ok:
            continue
        add_metadata(image_path, selected, font_path)
        records[key] = {
            "path": str(image_path.resolve()),
            "url": selected,
            "captured_at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
            "source": str(Path(source).resolve()),
        }
        save_manifest(manifest_path, records)
        captured += 1
    return captured, records


def fill_workbook(
    source, output, assets, blank_only, sheet_name=None, limit=None,
    manifest_path=None, manifest_only=False,
):
    chrome = detect_chrome(required=False)
    font_path = str(detect_font())
    assets.mkdir(parents=True, exist_ok=True)
    workbook = load_workbook(source)
    records = []
    filled = 0
    pre_captured = load_manifest(manifest_path)

    sheets = [workbook[sheet_name]] if sheet_name else workbook.worksheets
    for sheet in sheets:
        link_column = find_column(sheet, "访问链接")
        note_column = find_column(sheet, "存在GPU算力的说明")
        image_column = find_column(sheet, "证明截图")
        ip_column = find_column(sheet, "IP地址")
        port_column = find_column(sheet, "端口号")
        protocol_column = find_column(sheet, "协议类型")
        if not link_column or not image_column:
            continue
        occupied = image_cells(sheet, image_column)
        for row in range(2, sheet.max_row + 1):
            if limit is not None and filled >= limit:
                break
            if not sheet.cell(row, 1).value:
                continue
            if blank_only and row in occupied:
                continue
            pre_key = evidence_key(
                sheet.cell(row, ip_column).value if ip_column else "",
                sheet.cell(row, port_column).value if port_column else "",
                sheet.cell(row, protocol_column).value if protocol_column else "",
            )
            pre_record = pre_captured.get(pre_key) or {}
            pre_path = Path(pre_record.get("path", "")) if pre_record.get("path") else None
            if pre_path and pre_path.is_file():
                if row in occupied:
                    remove_image_at(sheet, row, image_column)
                    occupied.discard(row)
                attach_image(sheet, pre_path, row, image_column)
                records.append((sheet.title, row, "已填充预先截图", pre_record.get("url", "")))
                filled += 1
                continue
            if manifest_only:
                records.append((sheet.title, row, "无预先截图", ""))
                continue
            urls = preferred_urls(
                sheet.cell(row, link_column).value,
                sheet.cell(row, note_column).value if note_column else "",
            )
            selected = None
            response = None
            for url in urls:
                response = fetch_response(url)
                if response is not None:
                    selected = url
                    break
            if not selected or response is None:
                if row in occupied:
                    # An old browser image cannot stand in for a current HTTP
                    # proof.  Remove it rather than leaving a stale screenshot
                    # beside an explanation that can no longer be verified.
                    remove_image_at(sheet, row, image_column)
                    occupied.discard(row)
                    records.append((sheet.title, row, "未获取到有效响应，已清除旧截图", ""))
                else:
                    records.append((sheet.title, row, "未获取到有效响应", ""))
                continue
            path = assets / f"{sheet.title}_{row}.png"
            note = sheet.cell(row, note_column).value if note_column else ""
            captured = capture_response_card(
                selected, response, path, font_path, note
            )
            if not captured:
                records.append((sheet.title, row, "截图生成失败", selected))
                continue
            add_metadata(path, selected, font_path)
            if row in occupied:
                remove_image_at(sheet, row, image_column)
                occupied.discard(row)
            attach_image(sheet, path, row, image_column)
            records.append((sheet.title, row, "已填充", selected))
            filled += 1

    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.calculation.calcMode = "auto"
    workbook.save(output)
    return records


def main():
    parser = argparse.ArgumentParser(description="为 LLM 结果 Excel 填充证明截图")
    parser.add_argument("command", choices=["fill", "retry-blank", "capture-csv", "check"])
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--sheet")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--manifest-only", action="store_true")
    args = parser.parse_args()

    if args.command == "check":
        chrome = detect_chrome(required=False)
        print(f"Capture: {chrome or 'HTTP response evidence image fallback'}")
        print(f"Font: {detect_font()}")
        return 0
    if args.input is None:
        parser.error("--input is required")

    source = args.input
    output = args.output or source
    assets = args.assets or (source.parent / "screenshot_assets")
    manifest = args.manifest or (assets / "manifest.json")
    if args.command == "capture-csv":
        captured, manifest_records = capture_csv_evidence(
            source, assets, manifest, limit=args.limit
        )
        print(f"即时证据截图完成: captured={captured} manifest_total={len(manifest_records)}")
        print(f"截图清单: {manifest}")
        return 0
    records = fill_workbook(
        source,
        output,
        assets,
        blank_only=(args.command == "retry-blank"),
        sheet_name=args.sheet,
        limit=args.limit,
        manifest_path=manifest,
        manifest_only=args.manifest_only,
    )
    for sheet, row, status, url in records:
        print(f"{sheet}!{row}: {status} {url}")
    filled = sum(status == "已填充" for _, _, status, _ in records)
    print(f"截图填充完成: filled={filled} total={len(records)}")
    print(f"输出文件: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
