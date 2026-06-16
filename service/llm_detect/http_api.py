"""可选 HTTP 端点:/health 与 /tasks/{id}/wake。

只有 ``http_api.enabled: true`` 时才启动。依赖 fastapi + uvicorn(非默认必需)。
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .orchestrator import Orchestrator
    from .settings import HttpApiConfig

log = logging.getLogger(__name__)


def build_app(orch: "Orchestrator"):
    from fastapi import FastAPI, HTTPException

    app = FastAPI(title="llm_detect wake API", version="0.1.0")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/tasks/{task_id}/wake")
    def wake(task_id: int) -> dict:
        # 仅作通知,真正抢占由 orchestrator 完成
        orch.wake()
        return {"task_id": task_id, "wake": True}

    return app


async def serve(orch: "Orchestrator", cfg: "HttpApiConfig") -> None:
    import uvicorn
    app = build_app(orch)
    config = uvicorn.Config(app, host=cfg.host, port=cfg.port, log_level="info")
    server = uvicorn.Server(config)
    log.info("HTTP API: http://%s:%d", cfg.host, cfg.port)
    await server.serve()
