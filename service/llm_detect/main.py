"""Supported service entrypoint: MySQL run/source contract 2.1."""
from .v21.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
