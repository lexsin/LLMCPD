#!/usr/bin/env python3
"""Regression coverage for removing unverified screenshots."""
from pathlib import Path
import tempfile

from openpyxl import Workbook
from openpyxl.drawing.image import Image as ExcelImage
from PIL import Image

from screenshot_evidence import remove_image_at


with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "proof.png"
    Image.new("RGB", (20, 20), "white").save(path)
    book = Workbook()
    sheet = book.active
    image = ExcelImage(path)
    image.anchor = "F2"
    sheet.add_image(image)
    remove_image_at(sheet, 2, 6)
    assert not sheet._images

print("screenshot_evidence_remove_stale_tests=passed")
