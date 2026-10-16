# Recommended batch scan parameters (2026-09-10)

Scope: carrier GPU/NPU resource discovery baseline used by the active 3.43 rerun.

## Source-aware -Pn policy

1. Expand source ranges with max-expand 2048.
2. Deduplicate expanded targets and skip separate ping precheck.
3. If an enterprise has fewer than 50,000 unique expanded IPs, scan all targets with -Pn.
4. If it has 50,000 or more, scan targets explicitly present as single-IP source records with -Pn.
5. Scan targets present only through source ranges with normal nmap host discovery.
6. If one IP has both source forms, prefer the single-IP rule and use -Pn.
7. Keep each group cache/checkpoint separate, then merge results by IP.

## Expansion

- --skip-ping
- --dedup-ip
- --max-expand 2048
- --expand-all

## Port scan

- ports: 490 LLM/inference/GPU/NPU-related ports
- mode: -sS -n -T4 --open
- batch size: 500
- --parallel-workers 12
- --verify-workers 12
- --min-rate 3000
- --max-retries 1
- --host-timeout 120s
- --resume

## Low-open confirmation

- disabled for this baseline
- do not pass --low-open-confirm
- the scanner default is disabled; its historical confirmation defaults, when deliberately enabled, are rate threshold 0.005, fewer than 5 open IPs, sample 50, min rate 1000, retries 2, host timeout 300s.

## Current runner

run_rerun_237_on_343_source_policy_20260909.sh

The active result directory is:
 /home/lixiao/llm-detect/TEST/data/rescan_237_on_343_source_policy_20260909
