"""
HISN — Database Models
=======================
SQLModel tables backing the HISN API:
  - Target:  An external asset (domain) being monitored
  - Scan:    A single scan run against a Target
  - Finding: An individual issue surfaced by a scanner module during a Scan

Design notes:
  - target → scans is 1:N (scan history over time)
  - scan → findings is 1:N
  - Each Finding carries its scanner_name so we can group them in the UI
    without needing a separate per-scanner-result table (defer until Week 6+)
  - raw_data on Finding stores the full scanner output for that finding,
    so the UI can render remediation text without re-running anything

Author: Sohaila Taher Shaker
License: MIT
"""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import SQLModel, Field, Relationship, Column, JSON


def _utcnow() -> datetime:
    """UTC-aware current time (avoids naive-datetime deprecation warnings)."""
    return datetime.now(timezone.utc)


class Target(SQLModel, table=True):
    """An external asset (domain) being monitored."""
    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True, unique=True)
    name: Optional[str] = None  # Display name, e.g. "Acme Corp"
    created_at: datetime = Field(default_factory=_utcnow)

    scans: list["Scan"] = Relationship(back_populates="target")


class Scan(SQLModel, table=True):
    """A single scan run against a Target."""
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id", index=True)

    # Lifecycle: pending → running → done | failed
    status: str = Field(default="pending", index=True)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: Optional[datetime] = None

    # Results (populated on completion)
    overall_score: Optional[int] = None
    overall_grade: Optional[str] = None        # A-F
    error_message: Optional[str] = None        # set if status == "failed"

    target: Optional[Target] = Relationship(back_populates="scans")
    findings: list["Finding"] = Relationship(back_populates="scan")


class Finding(SQLModel, table=True):
    """An individual issue surfaced by a scanner module."""
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)

    # Which scanner produced it: recon | email_security | port_scanner | tls_audit | vuln_scanner
    scanner_name: str = Field(index=True)
    # Standardized severity: critical | high | medium | low | info | unknown
    severity: str = Field(index=True)

    title: str
    description: Optional[str] = None

    # Original scanner output for this finding (kept as JSON blob for flexibility)
    raw_data: Optional[dict] = Field(default=None, sa_column=Column(JSON))

    scan: Optional[Scan] = Relationship(back_populates="findings")