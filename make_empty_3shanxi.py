import csv
from pathlib import Path

from scan_llm import OUTPUT_FIELDNAMES


scan_ports_fields = ["\u63a5\u5165\u5355\u4f4d", "\u8d77\u59cbIP", "\u7ec8\u6b62IP", "ip", "port", "ping"]
targets = [
    (Path("data/3\u79fb\u52a8\u5c71\u897f_scan_ports.csv"), scan_ports_fields),
    (Path("data/3\u79fb\u52a8\u5c71\u897f_llm.csv"), OUTPUT_FIELDNAMES),
]

for path, fields in targets:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        csv.DictWriter(handle, fieldnames=fields, quoting=csv.QUOTE_NONNUMERIC).writeheader()

print("wrote empty 3shanxi scan_ports and llm csv")
