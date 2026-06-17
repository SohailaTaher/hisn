"""
HISN — API Request/Response Schemas
=====================================
Pydantic models for HTTP I/O. Separate from the SQLModel tables in models.py
so the DB shape and the API shape can evolve independently.

Author: Sohaila Taher Shaker
License: MIT
"""

from datetime import datetime
from typing import Optional
from pydantic import EmailStr
from pydantic import BaseModel, ConfigDict, Field


# ---- Request shapes ----

class ScanCreate(BaseModel):
    """Body of POST /scans — triggers a new scan against a domain."""
    domain: str = Field(..., min_length=3, max_length=253,
                        description="Domain to scan (e.g. 'example.com')")
    name: Optional[str] = Field(None, max_length=100,
                                description="Optional display name for the target")


# ---- Response shapes ----

class TargetRead(BaseModel):
    id: int
    domain: str
    name: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingRead(BaseModel):
    id: int
    scanner_name: str
    severity: str
    title: str
    description: Optional[str] = None
    raw_data: Optional[dict] = None

    model_config = ConfigDict(from_attributes=True)


class ScanRead(BaseModel):
    """Compact scan view — used in lists and POST responses."""
    id: int
    target_id: int
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    overall_score: Optional[int] = None
    overall_grade: Optional[str] = None
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanWithFindings(ScanRead):
    """Full scan detail — used by GET /scans/{id}."""
    target: TargetRead
    findings: list[FindingRead] = []


class ScanList(BaseModel):
    """Paginated list of scans."""
    total: int
    scans: list[ScanRead]


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str | None = None


class UserRead(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"