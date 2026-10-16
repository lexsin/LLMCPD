# Source-aware port scan policy (2026-09-09)

This policy is part of the isolated v4 NPU/GPU discovery strategy.

## Decision order

1. Count unique expanded IPs for the enterprise.
2. If the count is below 50,000, scan every target with nmap -Pn.
3. Otherwise, targets explicitly present as a single-IP source record (start IP equals end IP) use -Pn.
4. Targets present only through an IP range use nmap host discovery.
5. If the same IP is present both as a single-IP record and inside a range, the single-IP rule wins and the target uses -Pn.
6. Run the two groups sequentially with separate caches/checkpoints, then merge by IP before model/GPU/NPU detection.

## Operational parameters

- batch size: 500
- port scan workers: 12
- verification workers: 12
- min rate: 3000
- max retries: 1
- host timeout: 120s
- max expand: 2048
- resume: enabled

## Files

- scan_ports_by_source_type.py: policy implementation and result merge
- run_rerun_237_on_343_source_policy_20260909.sh: 3.43 background runner
- test_source_type_scan_policy.py: threshold and precedence regression tests

The source CSV is used for precedence decisions because the expanded CSV is deduplicated and may no longer retain both source records.
