"""Stage 4 — LLM 指纹探测,UPSERT 到 probe_asset_port + asset_llm。"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Dict, List, Tuple

from ..adapters.llm_prober import load_scan_config, probe_endpoints
from ..repo import asset_repo, endpoint_repo, host_repo, task_repo
from ..settings import Stage4Config

log = logging.getLogger(__name__)


def _summarize_batch(results: List[Dict]) -> Dict[str, int]:
    """统计一批结果的关键分布,用于运维日志。"""
    summary: Counter = Counter()
    summary["total"] = len(results)
    summary["http_alive"] = sum(1 for r in results if r.get("is_http"))
    for r in results:
        label = (r.get("verdict_rule") or {}).get("is_llm_label", "")
        if label == "确认":
            summary["llm_confirmed"] += 1
        elif label == "疑似":
            summary["llm_suspect"] += 1
        else:
            summary["not_llm"] += 1

        st = (r.get("fingerprint") or {}).get("service_type", "")
        if st == "LLM服务":
            summary["svc_llm"] += 1
        elif st == "AI模型服务":
            summary["svc_ai_model"] += 1
        elif st == "AI前端服务":
            summary["svc_ai_frontend"] += 1
        elif st == "普通Web":
            summary["svc_plain_web"] += 1
        elif st == "非HTTP":
            summary["svc_non_http"] += 1
    return dict(summary)


async def run_llm_probe(task_id: int, cfg: Stage4Config) -> int:
    """对 PENDING/RUNNING 的 endpoint 做指纹探测,返回处理总数。

    每批 cfg.batch_size 个 endpoint。处理流程:
      1) 标记 RUNNING
      2) 调 probe_endpoints(异步)
      3) 把每条结果 UPSERT 到 probe_asset_port + asset_llm
      4) 标记 SUCCESS / FAILED
    然后把对应主机推到 VERDICT_DONE。
    """
    pending = endpoint_repo.list_pending_endpoints(task_id)
    if not pending:
        log.info("task %s stage4: no pending endpoints", task_id)
        return 0

    rules = load_scan_config(cfg.rules_yaml)
    log.info("task %s stage4: %d endpoints to probe", task_id, len(pending))

    processed = 0
    affected_hosts: set[str] = set()
    cumulative: Counter = Counter()
    total_batches = (len(pending) + cfg.batch_size - 1) // cfg.batch_size

    for batch_start in range(0, len(pending), cfg.batch_size):
        batch_idx = batch_start // cfg.batch_size + 1
        batch = pending[batch_start: batch_start + cfg.batch_size]
        targets: List[Tuple[str, int]] = [(r["host_ip"], int(r["port"])) for r in batch]

        log.info("task %s stage4: --- batch %d/%d (%d targets) ---",
                 task_id, batch_idx, total_batches, len(targets))

        # 标记 RUNNING
        for ip, port in targets:
            endpoint_repo.mark_endpoint_running(task_id, ip, port)

        try:
            results = await probe_endpoints(
                targets, rules, concurrency_override=cfg.concurrency_override,
            )
        except Exception as exc:
            log.exception("task %s stage4 batch %d failed: %s", task_id, batch_idx, exc)
            for ip, port in targets:
                endpoint_repo.finish_endpoint(
                    task_id, ip, port, probe_shape="UNKNOWN", success=False,
                )
            continue

        # 索引,方便逐 endpoint 标记
        result_by_key = {f"{r['ip']}:{r['port']}": r for r in results}

        # phase 级统计(覆盖该批 result)
        summary = _summarize_batch(results)
        log.info(
            "task %s stage4 batch %d: total=%d http_alive=%d "
            "| LLM confirmed=%d suspect=%d not_llm=%d "
            "| svc llm=%d ai_model=%d ai_frontend=%d plain_web=%d non_http=%d",
            task_id, batch_idx,
            summary.get("total", 0), summary.get("http_alive", 0),
            summary.get("llm_confirmed", 0), summary.get("llm_suspect", 0), summary.get("not_llm", 0),
            summary.get("svc_llm", 0), summary.get("svc_ai_model", 0),
            summary.get("svc_ai_frontend", 0), summary.get("svc_plain_web", 0),
            summary.get("svc_non_http", 0),
        )
        for k, v in summary.items():
            cumulative[k] += v

        for ip, port in targets:
            key = f"{ip}:{port}"
            r = result_by_key.get(key)
            if r is None:
                endpoint_repo.finish_endpoint(
                    task_id, ip, port, probe_shape="UNKNOWN", success=False,
                )
                continue

            shape = r.get("probe_shape") or "UNKNOWN"
            verdict = int(r.get("asset_verdict", 0))
            app_type = r.get("app_type_code")

            asset_repo.upsert_asset_port(
                task_id, ip, port,
                probe_shape=shape,
                app_type_code=app_type,
                asset_verdict=verdict,
                verdict_rule=r.get("verdict_rule"),
                fingerprint=r.get("fingerprint"),
            )
            asset_repo.upsert_asset_llm(
                ip, port,
                probe_shape=shape,
                app_type_code=app_type,
                asset_verdict=verdict,
                verdict_rule=r.get("verdict_rule"),
                fingerprint=r.get("fingerprint"),
            )
            endpoint_repo.finish_endpoint(
                task_id, ip, port, probe_shape=shape, success=True,
            )
            affected_hosts.add(ip)
            processed += 1

        # 进度回写
        finished = endpoint_repo.count_endpoints_finished(task_id)
        task_repo.update_progress(task_id, endpoint_finished=finished)

    # 把所有涉及到的 host 推进到 VERDICT_DONE
    for ip in affected_hosts:
        host_repo.mark_host_verdict_done(task_id, ip)

    log.info(
        "task %s stage4: done. probed=%d hosts=%d "
        "| LLM confirmed=%d suspect=%d not_llm=%d "
        "| svc llm=%d ai_model=%d ai_frontend=%d plain_web=%d non_http=%d",
        task_id, processed, len(affected_hosts),
        cumulative.get("llm_confirmed", 0), cumulative.get("llm_suspect", 0), cumulative.get("not_llm", 0),
        cumulative.get("svc_llm", 0), cumulative.get("svc_ai_model", 0),
        cumulative.get("svc_ai_frontend", 0), cumulative.get("svc_plain_web", 0),
        cumulative.get("svc_non_http", 0),
    )
    return processed
