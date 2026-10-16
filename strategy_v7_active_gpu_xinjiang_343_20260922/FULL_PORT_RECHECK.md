# Candidate full-port recheck

The v5 pipeline keeps the 490-port first-stage scan unchanged. Full-port
recheck is enabled by default and runs after the first LLM/GPU/NPU classification and the
low-GPU second-stage probe, so every IP already promoted to GPU high is skipped.

## Default policy

- Enabled by default; set `FULL_PORT_SCAN=0` only for an explicitly requested partial run.
- Candidate mode only; generic 80/443/8080 exposure does not qualify.
- Any IP with at least one `gpu_likelihood=高` row is excluded before ranking.
- Candidates are ranked by GPU medium, confirmed/suspected LLM, known serving
  products, accelerator evidence, strong AI ports, and verified Kubernetes.
- At most 50 IPs per enterprise.
- Six nmap workers, `-Pn -sS -n -T3 -p-`, `--max-rate 200`,
  `--min-rate 100`, `--max-retries 0`, `--host-timeout 40m`,
  `--process-timeout 2700`. Host timeout is per IP; process timeout
  prevents a hung nmap from blocking the batch.
- Only newly found ports are sent to `scan_llm.py`; results are merged by
  `(ip, port)`. Port-level GPU grades are not inherited across the IP.
- `finalize_llm_results.py` runs after the merge and fills the final workbook's
  evidence screenshots. `COMPLETE` is written only after that workbook succeeds.

## Run a batch

```bash
FULL_PORT_SCAN=1 \
FULL_PORT_MODE=candidates \
FULL_PORT_MAX_TARGETS=50 \
FULL_PORT_MAX_RATE=200 \
FULL_PORT_MIN_RATE=100 \
FULL_PORT_WORKERS=6 \
FULL_PORT_MAX_RETRIES=0 \
FULL_PORT_HOST_TIMEOUT=40m \
FULL_PORT_PROCESS_TIMEOUT=2700 \
bash run_batch2_source_policy_20260910.sh
```

Each enterprise writes `full_port_checkpoint.jsonl`,
`full_port_summary.json`, `full_port_new_ports.csv`, and the incremental
LLM result files in its stage directory. It also writes
`<enterprise>_llm_最终版.xlsx` with embedded screenshots. Re-running with the
same run directory uses the checkpoint and does not rescan completed candidate
IPs. Before scanning, the runner checks the screenshot backend and a Chinese
font. Chrome/Chromium is used when available; otherwise the screenshot module
renders the live HTTP status and response content into a timestamped evidence
image, so the final workbook remains self-contained on aarch64 servers.
