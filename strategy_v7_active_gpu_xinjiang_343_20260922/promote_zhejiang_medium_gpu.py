#!/usr/bin/env python3
"""Promote the verified Zhejiang GPU record while preserving workbook drawings."""
from __future__ import annotations

import argparse
from pathlib import Path

from openpyxl import load_workbook


NOTE = (
    "/metrics响应中显示vllm:gpu_cache_usage_perc=0.0、"
    "vllm:gpu_prefix_cache_hit_rate=-1.0、gpu_memory_utilization=0.1；"
    "这些字段属于本机GPU指标证据，因此GPU算力可能性高。"
)


def header_columns(sheet):
    return {str(cell.value or "").strip(): index for index, cell in enumerate(sheet[1], start=1)}


def main():
    parser = argparse.ArgumentParser(description="提升已验证GPU记录为高风险")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    workbook = load_workbook(args.input)
    sheet = workbook["浙江电信"]
    columns = header_columns(sheet)
    probability = columns["存在GPU算力概率"]
    note = columns["存在GPU算力的说明"]
    image = columns["证明截图"]
    row = 4

    if str(sheet.cell(row, 1).value or "").strip() != "202.107.219.40":
        raise RuntimeError("target IP changed; refusing to update a different row")
    if not any(
        hasattr(item.anchor, "_from")
        and item.anchor._from.row + 1 == row
        and item.anchor._from.col + 1 == image
        for item in sheet._images
    ):
        raise RuntimeError("target evidence screenshot is missing")

    sheet.cell(row, probability).value = "GPU算力可能性高"
    sheet.cell(row, note).value = NOTE
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.calculation.calcMode = "auto"
    workbook.save(args.output)
    print("updated=浙江电信!4")


if __name__ == "__main__":
    main()
