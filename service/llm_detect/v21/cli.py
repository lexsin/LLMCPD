from __future__ import annotations

import argparse
import json
import logging
import signal

from .common import ContractError
from .config import Config
from .releases import Releases


def main(argv=None):
    parser = argparse.ArgumentParser(description="V7 service, MySQL run/source contract 2.1")
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true", help="validate configuration/release offline; never connect to MySQL or scan")
    parser.add_argument("--once", action="store_true", help="process at most one available run (connects to configured queue)")
    args = parser.parse_args(argv)
    try:
        cfg = Config.load(args.config, secrets=not args.check)
        release = Releases(cfg.release_root, cfg.default_release).get()
        logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        if args.check:
            print(json.dumps({"contract_version": "2.1", "scanner_version": release.version,
                              "release_files": len(release.manifest["files"]), "database_connected": False, "scanner_started": False}))
            return 0
        if cfg.enable_cleanup:
            raise ContractError("CLEANUP_BARRIER_REQUIRED", "automatic WAIT_STOP cleanup remains disabled until Java in-flight writer coordination is agreed")
        from .database import MySQL
        from .repository import Repository
        from .runtime import Runtime
        from .processes import MachineLock
        db = MySQL(cfg.database)
        db.validate_schema()  # Read-only checks; never ALTER/CREATE.
        runtime = Runtime(cfg, Repository(db, cfg.lease_seconds))
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda *_: runtime.shutdown.set())
        runtime.run(once=args.once)
        return 0
    except ContractError as exc:
        logging.error("%s: %s", exc.code, exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
