#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import csv
import hashlib
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from openpyxl import load_workbook


ROOT = Path("/home/lixiao/llm-detect/TEST")
DATA = ROOT / "data"
BASE_DATA = DATA / "base_0715"
DATABASE = DATA / "llm_detect.sqlite3"
LOCATION_ALIASES = {
    "2联通北京": "联通北京",
    "2联通河南": "联通河南",
    "4电信广东": "电信广东",
    "4电信甘肃": "电信甘肃",
    "4联通吉林": "联通吉林",
}


def normalize(value):
    return str(value or "").replace("\n", "").replace(" ", "").strip()


def ip_value(value):
    try:
        return int(ipaddress.IPv4Address(str(value).strip()))
    except Exception:
        return None


def used_rows(sheet):
    rows = []
    blanks = 0
    for row in sheet.iter_rows():
        if any(cell.value is not None for cell in row):
            rows.append(row)
            blanks = 0
        elif rows:
            blanks += 1
            if blanks >= 50:
                break
    return rows


def find_columns(headers):
    start = end = unit = None
    for index, value in enumerate(headers):
        value = normalize(value)
        if "起始IP" in value:
            start = index
        elif "终止IP" in value:
            end = index
        elif "使用单位" in value or value == "企业名称":
            unit = index
    return start, end, unit


def file_fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_manifest():
    if not BASE_DATA.is_dir():
        raise FileNotFoundError(f"基础数据目录不存在: {BASE_DATA}")
    return [
        (LOCATION_ALIASES.get(path.stem, path.stem), path)
        for path in sorted(BASE_DATA.glob("*.xlsx"))
    ]


def read_xlsx(path):
    workbook = load_workbook(path, read_only=True, data_only=True)
    for sheet in workbook.worksheets:
        rows = used_rows(sheet)
        header_index = None
        columns = (None, None, None)
        for index, row in enumerate(rows):
            candidate = find_columns([cell.value for cell in row])
            if candidate[0] is not None and candidate[1] is not None:
                header_index, columns = index, candidate
                break
        if header_index is None:
            continue
        start_column, end_column, unit_column = columns
        for source_row, row in enumerate(rows[header_index + 1:], header_index + 2):
            values = [cell.value for cell in row]
            yield sheet.title, source_row, values, start_column, end_column, unit_column
    workbook.close()


def read_csv(path):
    for encoding in ("utf-8-sig", "gb18030", "utf-8"):
        try:
            with path.open("r", encoding=encoding, newline="") as stream:
                reader = csv.reader(stream)
                rows = list(reader)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"无法解码: {path}")

    headers = rows[0] if rows else []
    start_column, end_column, unit_column = find_columns(headers)
    if start_column is None or end_column is None:
        return
    for source_row, values in enumerate(rows[1:], 2):
        yield "CSV", source_row, values, start_column, end_column, unit_column


def schema(connection):
    connection.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS import_runs (
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            source_count INTEGER NOT NULL,
            valid_count INTEGER NOT NULL DEFAULT 0,
            invalid_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS source_ip_ranges (
            id INTEGER PRIMARY KEY,
            location TEXT NOT NULL,
            source_path TEXT NOT NULL,
            source_hash TEXT NOT NULL,
            sheet_name TEXT NOT NULL,
            source_row INTEGER NOT NULL,
            unit_name TEXT,
            start_ip TEXT NOT NULL,
            end_ip TEXT NOT NULL,
            start_ip_int INTEGER NOT NULL,
            end_ip_int INTEGER NOT NULL,
            imported_at TEXT NOT NULL,
            UNIQUE(source_path, source_hash, sheet_name, source_row, start_ip, end_ip)
        );
        CREATE INDEX IF NOT EXISTS idx_ranges_location ON source_ip_ranges(location);
        CREATE INDEX IF NOT EXISTS idx_ranges_bounds ON source_ip_ranges(start_ip_int, end_ip_int);
        """
    )


def import_sources(connection, sources, replace_all):
    started = datetime.now(timezone.utc).isoformat()
    cursor = connection.execute(
        "INSERT INTO import_runs(started_at, source_count) VALUES (?, ?)",
        (started, len(sources)),
    )
    run_id = cursor.lastrowid
    valid = invalid = 0
    summary = []

    if replace_all:
        connection.execute("DELETE FROM source_ip_ranges")

    for location, path in sources:
        if not path.is_file():
            raise FileNotFoundError(path)
        fingerprint = file_fingerprint(path)
        connection.execute(
            "DELETE FROM source_ip_ranges WHERE source_path = ?",
            (str(path),),
        )
        reader = read_csv(path) if path.suffix.lower() == ".csv" else read_xlsx(path)
        source_valid = source_invalid = 0
        for sheet, source_row, values, start_column, end_column, unit_column in reader:
            start_text = values[start_column] if start_column < len(values) else None
            end_text = values[end_column] if end_column < len(values) else None
            start = ip_value(start_text)
            end = ip_value(end_text)
            if start is None or end is None:
                if start_text not in (None, "") or end_text not in (None, ""):
                    source_invalid += 1
                continue
            unit_name = values[unit_column] if unit_column is not None and unit_column < len(values) else None
            connection.execute(
                """
                INSERT OR IGNORE INTO source_ip_ranges (
                    location, source_path, source_hash, sheet_name, source_row, unit_name,
                    start_ip, end_ip, start_ip_int, end_ip_int, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    location, str(path), fingerprint, sheet, source_row, str(unit_name or ""),
                    str(start_text).strip(), str(end_text).strip(), min(start, end), max(start, end),
                    started,
                ),
            )
            source_valid += 1
        valid += source_valid
        invalid += source_invalid
        summary.append((location, source_valid, source_invalid))

    connection.execute(
        "UPDATE import_runs SET completed_at = ?, valid_count = ?, invalid_count = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), valid, invalid, run_id),
    )
    return summary, valid, invalid


def export_location(connection, location, output):
    rows = connection.execute(
        """
        SELECT start_ip, end_ip, unit_name
        FROM source_ip_ranges
        WHERE location = ?
        ORDER BY start_ip_int, end_ip_int, id
        """,
        (location,),
    ).fetchall()
    if not rows:
        raise ValueError(f"未找到地区: {location}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["起始IP", "终止IP", "使用单位信息"])
        writer.writerows(rows)
    print(f"{location}: 导出 {len(rows)} 条到 {output}")


def show_summary(connection):
    rows = connection.execute(
        """
        SELECT location, COUNT(*) AS range_count,
               SUM(end_ip_int - start_ip_int + 1) AS address_count
        FROM source_ip_ranges
        GROUP BY location
        ORDER BY location
        """
    ).fetchall()
    for location, ranges, addresses in rows:
        print(f"{location}\t范围={ranges}\t地址={addresses}")
    print(f"地区数: {len(rows)}")
    print(f"入库记录数: {sum(ranges for _, ranges, _ in rows)}")


def main():
    parser = argparse.ArgumentParser(description="扫描原始 IP SQLite 管理工具")
    parser.add_argument("--db", type=Path, default=DATABASE)
    subparsers = parser.add_subparsers(dest="command", required=True)
    importer = subparsers.add_parser("import")
    importer.add_argument("--replace-all", action="store_true")
    subparsers.add_parser("summary")
    export = subparsers.add_parser("export")
    export.add_argument("--location", required=True)
    export.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(args.db) as connection:
        schema(connection)
        if args.command == "import":
            sources = source_manifest()
            summary, valid, invalid = import_sources(connection, sources, args.replace_all)
            for location, source_valid, source_invalid in summary:
                print(f"{location}\t有效={source_valid}\t异常={source_invalid}")
            print(f"总计: 地区={len(summary)} 有效={valid} 异常={invalid}")
        elif args.command == "summary":
            show_summary(connection)
        else:
            export_location(connection, args.location, args.output)


if __name__ == "__main__":
    main()
