"""
HISN — Database Configuration
==============================
SQLModel engine + session management for the HISN API.

For development we use SQLite (zero-config, single file). In production
(Week 7), this will swap to Postgres via DATABASE_URL environment variable.

Author: Sohaila Taher Shaker
License: MIT
"""

import os
from typing import Generator

from sqlmodel import SQLModel, Session, create_engine


# Default: local SQLite file in repo root. Override with DATABASE_URL env var.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hisn.db")

# SQLite + multi-threading: FastAPI handlers run in threads, so we relax the
# default same-thread check. Not needed for Postgres later.
connect_args = (
    {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)


def create_db_and_tables() -> None:
    """Create all tables defined in SQLModel metadata. Idempotent.

    Imports the models module internally as a side-effect so model
    classes register with SQLModel.metadata before create_all runs.
    Without this, callers who haven't already imported models would
    end up with an empty database file.
    """
    from hisn.api import models  # noqa: F401  -- side-effect import
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a DB session that auto-closes after request."""
    with Session(engine) as session:
        yield session