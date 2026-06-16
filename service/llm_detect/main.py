"""llm_detect 主入口。

用法::

    python -m llm_detect.main --config config.yaml
    python -m llm_detect.main --config config.yaml --http     # 启 wake API
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .db import Database
from .orchestrator import Orchestrator, install_signal_handlers
from .settings import Settings


def _setup_logging(level: str, file: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if file:
        handlers.append(logging.FileHandler(file, encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


async def _run(settings: Settings, with_http: bool) -> None:
    Database.init(settings.database)
    orch = Orchestrator(settings)
    install_signal_handlers(orch)

    coros = [orch.run()]
    if with_http or settings.http_api.enabled:
        from . import http_api
        coros.append(http_api.serve(orch, settings.http_api))

    await asyncio.gather(*coros, return_exceptions=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="llm_detect — DB-driven LLM detection orchestrator")
    parser.add_argument("--config", required=True, help="path to config.yaml")
    parser.add_argument("--http", action="store_true", help="enable HTTP wake API regardless of config")
    args = parser.parse_args()

    settings = Settings.load(Path(args.config))
    _setup_logging(settings.logging.level, settings.logging.file)
    logging.getLogger(__name__).info("starting llm_detect with config=%s", args.config)

    try:
        asyncio.run(_run(settings, args.http))
    except KeyboardInterrupt:
        logging.getLogger(__name__).warning("interrupted by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())
