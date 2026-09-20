#!/usr/bin/env python3
"""Regression coverage for removing the old response-card status strip."""
from io import BytesIO

from PIL import Image, ImageDraw

from strip_screenshot_card_labels import compact_footer_gap, remove_status_strip


source = Image.new("RGB", (200, 180), "white")
draw = ImageDraw.Draw(source)
draw.rectangle((0, 42, 200, 120), fill=(238, 244, 252))
draw.rectangle((0, 84, 200, 120), fill=(150, 40, 20))
raw = BytesIO()
source.save(raw, format="PNG")

cleaned = Image.open(BytesIO(remove_status_strip(raw.getvalue()))).convert("RGB")
assert cleaned.height == 144
assert cleaned.getpixel((10, 90)) != (150, 40, 20)

spacious = Image.new("RGB", (200, 300), "white")
ImageDraw.Draw(spacious).text((10, 130), "evidence", fill="black")
ImageDraw.Draw(spacious).text((10, 272), "timestamp", fill="black")
raw = BytesIO()
spacious.save(raw, format="PNG")
compacted = Image.open(BytesIO(compact_footer_gap(raw.getvalue()))).convert("RGB")
assert compacted.height < spacious.height
print("strip_screenshot_card_labels_tests=passed")
