#!/usr/bin/env python3
"""Idempotently merge incremental LLM scan rows into a base result CSV."""

import argparse
import csv
from pathlib import Path


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        return list(reader), list(reader.fieldnames or [])


def row_key(row):
    return (
        str(row.get("ip") or "").strip(),
        str(row.get("port") or "").strip(),
    )


def merge_rows(base, extra):
    merged = {row_key(row): row for row in base if all(row_key(row))}
    order = [row_key(row) for row in base if all(row_key(row))]
    for row in extra:
        key = row_key(row)
        if not all(key):
            continue
        if key not in merged:
            order.append(key)
        merged[key] = row
    return [merged[key] for key in order]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--incremental", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    base, fields = read_csv(args.base)
    extra, extra_fields = read_csv(args.incremental)
    fields += [field for field in extra_fields if field not in fields]
    rows = merge_rows(base, extra)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temp = args.output.with_suffix(args.output.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(
            target, fieldnames=fields, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(args.output)
    print(
        "Merged LLM results: base=%d incremental=%d output=%d"
        % (len(base), len(extra), len(rows))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
