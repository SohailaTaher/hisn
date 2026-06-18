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
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI

from hisn.api.db import create_db_and_tables
from hisn.api.routers import auth, scans
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

# Comma-separated list of allowed origins from CORS_ORIGINS env var,
# falling back to localhost for dev
_default_origins = "http://localhost:5173,http://127.0.0.1:5173"
allowed_origins = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", _default_origins).split(",") if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(auth.router)
@app.get("/health", tags=["meta"])
def health() -> dict:
    """Liveness probe — used for deployment health checks and uptime monitoring."""
    return {"status": "ok", "service": "hisn-api"}