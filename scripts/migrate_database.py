"""Apply Alembic migrations for the configured SOC database."""

from __future__ import annotations

import os

from alembic import command
from alembic.config import Config


def main() -> None:
    if not os.getenv("DATABASE_URL"):
        raise SystemExit("DATABASE_URL is required")
    config = Config("alembic.ini")
    command.upgrade(config, "head")


if __name__ == "__main__":
    main()
