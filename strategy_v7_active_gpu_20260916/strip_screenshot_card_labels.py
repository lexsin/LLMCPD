#!/usr/bin/env python3
"""Remove the retired GPU-evidence status strip from existing response cards."""
from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from PIL import Image


# Full cards comprise a 42px URL strip followed by a 78px HTTP-status panel.
# The retired status message fills the lower 36px of that panel.
KEEP_THROUGH_Y = 84
RESUME_FROM_Y = 120


def remove_status_strip(payload: bytes) -> bytes:
    image = Image.open(BytesIO(payload)).convert("RGB")
    if image.height <= RESUME_FROM_Y:
        return payload
    cleaned = Image.new("RGB", (image.width, image.height - (RESUME_FROM_Y - KEEP_THROUGH_Y)), "white")
    cleaned.paste(image.crop((0, 0, image.width, KEEP_THROUGH_Y)), (0, 0))
    cleaned.paste(
        image.crop((0, RESUME_FROM_Y, image.width, image.height)),
        (0, KEEP_THROUGH_Y),
    )
    output = BytesIO()
    cleaned.save(output, format="PNG")
    return output.getvalue()


def compact_footer_gap(payload: bytes) -> bytes:
    """Remove the blank area between response text and the timestamp footer."""
    image = Image.open(BytesIO(payload)).convert("RGB")
    footer_height = 36
    footer_start = image.height - footer_height
    if footer_start <= RESUME_FROM_Y:
        return payload

    content_bottom = None
    for y in range(footer_start - 1, RESUME_FROM_Y - 1, -1):
        if any(sum(pixel) < 720 for pixel in image.crop((0, y, image.width, y + 1)).getdata()):
            content_bottom = y
            break
    if content_bottom is None or footer_start - content_bottom <= 18:
        return payload

    body_end = min(footer_start, content_bottom + 14)
    cleaned = Image.new("RGB", (image.width, body_end + footer_height), "white")
    cleaned.paste(image.crop((0, 0, image.width, body_end)), (0, 0))
    cleaned.paste(image.crop((0, footer_start, image.width, image.height)), (0, body_end))
    output = BytesIO()
    cleaned.save(output, format="PNG")
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description="清理证据截图中的状态提示文字")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--compact-blank", action="store_true")
    args = parser.parse_args()

    with ZipFile(args.input) as source, ZipFile(args.output, "w", ZIP_DEFLATED) as target:
        for member in source.infolist():
            payload = source.read(member.filename)
            if member.filename.startswith("xl/media/") and member.filename.endswith(".png"):
                payload = compact_footer_gap(payload) if args.compact_blank else remove_status_strip(payload)
            target.writestr(member, payload)


if __name__ == "__main__":
    main()
