"""任务编排:轮询 probe_task → 抢占 → 串跑 4 阶段 → 收尾。"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from typing import Optional

from .repo import endpoint_repo, host_repo, task_repo
from .settings import Settings
from .stages import stage1_expand, stage2_scan, stage3_endpoint, stage4_llm

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        cfg = settings.orchestrator
        if cfg.heartbeat_interval_sec <= 0:
            raise ValueError("heartbeat_interval_sec must be > 0")
        if cfg.lease_timeout_sec <= cfg.heartbeat_interval_sec:
            raise ValueError("lease_timeout_sec must exceed heartbeat_interval_sec")
        suffix = "%s:%s:%s" % (
            socket.gethostname(),
            os.getpid(),
            uuid.uuid4().hex[:12],
        )
        prefix_limit = max(0, 127 - len(suffix))
        self.worker_id = "%s@%s" % (str(cfg.worker_id)[:prefix_limit], suffix)

    def request_stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def wake(self) -> None:
        """供 HTTP wake 端点调用。"""
        self._wake.set()

    async def run(self) -> None:
        cfg = self.settings.orchestrator

        if cfg.reset_running_on_startup:
            n = task_repo.reset_expired_running_tasks(cfg.lease_timeout_sec)
            if n:
                log.warning("startup: recovered %d expired RUNNING tasks", n)

        log.info("orchestrator started; poll=%ss max_concurrent=%d worker=%s",
                 cfg.poll_interval_sec, cfg.max_concurrent_tasks, self.worker_id)

        # 这里目前实现的是 max_concurrent_tasks=1 的串行抢占;> 1 时仍然顺序抢占,
        # 但每次抢到一个就启一个 task 协程,通过 Semaphore 限制总数。
        sem = asyncio.Semaphore(max(1, cfg.max_concurrent_tasks))
        running: list[asyncio.Task] = []

        while not self._stop.is_set():
            if cfg.reset_running_on_startup:
                recovered = task_repo.reset_expired_running_tasks(
                    cfg.lease_timeout_sec
                )
                if recovered:
                    log.warning(
                        "runtime: recovered %d expired RUNNING tasks", recovered,
                    )

            # 清理已完成
            running = [t for t in running if not t.done()]

            # 拿任务直到达到上限
            while not self._stop.is_set() and len(running) < cfg.max_concurrent_tasks:
                task_row = task_repo.claim_pending_task(self.worker_id)
                if not task_row:
                    break
                log.info("claimed task #%s name=%s", task_row["id"], task_row.get("task_name"))
                running.append(asyncio.create_task(self._run_one(task_row, sem)))

            # 等待 wake 或下次轮询
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=cfg.poll_interval_sec)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

        # 优雅停止:等所有 task 完成
        if running:
            log.info("stopping; waiting for %d running task(s)", len(running))
            await asyncio.gather(*running, return_exceptions=True)
        log.info("orchestrator stopped")

    async def _run_one(self, task_row: dict, sem: asyncio.Semaphore) -> None:
        async with sem:
            task_id = int(task_row["id"])
            heartbeat_stop = asyncio.Event()
            lease_lost = asyncio.Event()
            heartbeat = asyncio.create_task(
                self._heartbeat_loop(task_id, heartbeat_stop, lease_lost)
            )
            try:
                final_status = await self._run_stages(task_id, lease_lost)
            except task_repo.LeaseLostError:
                log.warning("task %s stopped because lease ownership was lost", task_id)
            except Exception as exc:
                log.exception("task %s failed: %s", task_id, exc)
                heartbeat_stop.set()
                await heartbeat
                try:
                    task_repo.finalize(task_id, "FAILED", self.worker_id)
                except task_repo.LeaseLostError:
                    log.warning("task %s failure not finalized because lease was lost", task_id)
                except Exception:
                    log.exception("task %s: finalize FAILED also failed", task_id)
            else:
                heartbeat_stop.set()
                await heartbeat
                try:
                    task_repo.finalize(task_id, final_status, self.worker_id)
                except task_repo.LeaseLostError:
                    log.warning(
                        "task %s result %s not finalized because lease was lost",
                        task_id, final_status,
                    )
                except Exception:
                    log.exception(
                        "task %s result %s could not be finalized",
                        task_id, final_status,
                    )
            finally:
                heartbeat_stop.set()
                if not heartbeat.done():
                    await heartbeat

    async def _heartbeat_loop(
        self,
        task_id: int,
        stop: asyncio.Event,
        lease_lost: asyncio.Event,
    ) -> None:
        interval = self.settings.orchestrator.heartbeat_interval_sec
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
                return
            except asyncio.TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    task_repo.renew_lease, task_id, self.worker_id,
                )
            except Exception:
                log.exception("task %s heartbeat failed", task_id)
                continue
            if not renewed:
                lease_lost.set()
                log.warning("task %s heartbeat rejected; lease lost", task_id)
                return

    async def _require_lease(
        self, task_id: int, lease_lost: asyncio.Event,
    ) -> None:
        if lease_lost.is_set():
            raise task_repo.LeaseLostError("task %s lease lost" % task_id)
        await asyncio.to_thread(task_repo.require_lease, task_id, self.worker_id)

    async def _run_stages(
        self, task_id: int, lease_lost: asyncio.Event,
    ) -> str:
        st = self.settings

        await self._require_lease(task_id, lease_lost)
        # 重启续跑:把上次留下的 SCANNING/RUNNING 行还原
        n_h = host_repo.reset_orphaned_scanning_hosts(task_id)
        n_e = endpoint_repo.reset_orphaned_running_endpoints(task_id)
        if n_h or n_e:
            log.info("task %s: resumed (hosts=%d, endpoints=%d reset)", task_id, n_h, n_e)

        loop = asyncio.get_running_loop()

        # ---- Stage 1: 展开 IP ----
        host_total, _seed_endpoints = await loop.run_in_executor(
            None, stage1_expand.expand_resources, task_id,
        )
        task_repo.update_progress(
            task_id, self.worker_id, host_total=host_total,
        )

        # ---- Stage 2: ping + nmap ----
        # 在 executor 里跑,避免阻塞 event loop(ping / nmap 都是子进程)
        await self._require_lease(task_id, lease_lost)
        await loop.run_in_executor(
            None, stage2_scan.run_scan, task_id, st.stage1, self.worker_id,
        )
        await self._require_lease(task_id, lease_lost)
        host_finished = host_repo.count_hosts_finished(task_id)
        task_repo.update_progress(
            task_id, self.worker_id, host_finished=host_finished,
        )

        # ---- Stage 3: 端点展开 ----
        await self._require_lease(task_id, lease_lost)
        endpoint_total = await loop.run_in_executor(
            None, stage3_endpoint.expand_endpoints, task_id,
        )
        task_repo.update_progress(
            task_id, self.worker_id, endpoint_total=endpoint_total,
        )

        # ---- Stage 4: LLM 指纹(原生 async)----
        await self._require_lease(task_id, lease_lost)
        await stage4_llm.run_llm_probe(task_id, st.stage4, self.worker_id)
        await self._require_lease(task_id, lease_lost)

        # ---- 收尾 ----
        ep_finished = endpoint_repo.count_endpoints_finished(task_id)
        host_finished = host_repo.count_hosts_finished(task_id)
        task_repo.update_progress(
            task_id,
            self.worker_id,
            host_finished=host_finished,
            endpoint_finished=ep_finished,
        )

        # 判定最终状态:全部 host 完成 + 全部 endpoint 完成 → SUCCESS;否则 PARTIAL
        if host_finished >= host_total and ep_finished >= endpoint_total:
            final_status = "SUCCESS"
        elif host_finished == 0 and endpoint_total == 0:
            final_status = "FAILED"
        else:
            final_status = "PARTIAL"
        log.info("task %s done: hosts=%d/%d endpoints=%d/%d",
                 task_id, host_finished, host_total, ep_finished, endpoint_total)
        return final_status


def install_signal_handlers(orch: Orchestrator) -> None:
    """SIGINT / SIGTERM 触发优雅停止。Windows 下只 SIGINT 有效。"""
    loop = asyncio.get_event_loop()

    def _handler(signum: int) -> None:
        log.warning("signal %d received, shutting down", signum)
        orch.request_stop()

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except NotImplementedError:
            # Windows: signal.signal() 仍然有效
            signal.signal(sig, lambda s, _f: _handler(s))
