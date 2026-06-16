"""
HISN — FastAPI Application Entry Point
========================================
Initializes the FastAPI app, creates DB tables on startup,
will mount scan routers (Day 3).

Run locally:
    uvicorn hisn.api.main:app --reload

Interactive API docs:
    http://localhost:8000/docs

Author: Sohaila Taher Shaker
License: MIT
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI

from hisn.api.db import create_db_and_tables
from hisn.api.routers import scans
from fastapi.middleware.cors import CORSMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create DB tables if they don't exist. Shutdown: nothing yet."""
    create_db_and_tables()
    yield


app = FastAPI(
    title="HISN API",
    description="External Attack Surface Management for SMBs in MENA",
    version="0.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],   # Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)

@app.get("/health", tags=["meta"])
def health() -> dict:
    """Liveness probe — used for deployment health checks and uptime monitoring."""
    return {"status": "ok", "service": "hisn-api"}