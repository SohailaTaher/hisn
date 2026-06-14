"""
HISN — Celery Worker Configuration
====================================
Celery application config: connects to Redis as broker + result backend.

Run the worker (from repo root, venv active):
    celery -A hisn.api.worker worker --loglevel=info

Author: Sohaila Taher Shaker
License: MIT
"""

import os

from celery import Celery


REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

celery_app = Celery(
    "hisn",
    broker=f"{REDIS_URL}/0",            # broker uses Redis DB 0
    backend=f"{REDIS_URL}/1",           # result backend uses Redis DB 1
    include=["hisn.api.tasks"],         # tells Celery where to find tasks
)

# Defaults tuned for scan workloads — long-running tasks, not high-volume.
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=900,                # hard kill after 15 min (Nuclei can take 10+)
    task_soft_time_limit=840,           # soft warning at 14 min
)