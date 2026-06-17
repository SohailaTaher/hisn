"""
HISN — Scans Router
=====================
HTTP endpoints for triggering and inspecting scans.

Author: Sohaila Taher Shaker
License: MIT
"""
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlmodel import Session, select

from hisn.api.db import get_session
from hisn.api.models import Target, Scan, Finding
from hisn.api.schemas import (
    ScanCreate, ScanRead, ScanWithFindings, ScanList, FindingRead,
)
from hisn.api.tasks import run_scan

from typing import Optional

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger a new scan",
)
def create_scan(
    payload: ScanCreate,
    session: Session = Depends(get_session),
):
    """Create or reuse a Target for the domain, create a new Scan record,
    enqueue the Celery task, return the new scan immediately (status=pending).

    The actual scan runs in the background. Poll GET /scans/{id} for status.
    """
    # Find-or-create Target
    target = session.exec(
        select(Target).where(Target.domain == payload.domain)
    ).first()
    if target is None:
        target = Target(domain=payload.domain, name=payload.name)
        session.add(target)
        session.commit()
        session.refresh(target)

    # Create Scan
    scan = Scan(target_id=target.id)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Enqueue task — fires async, doesn't block the response
    run_scan.delay(scan.id)

    return scan


@router.get(
    "",
    response_model=ScanList,
    summary="List scans (newest first)",
)
def list_scans(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
):
    """Paginated list. Default page size 50, max 100."""
    total = session.scalar(select(func.count()).select_from(Scan)) or 0
    scans = session.exec(
        select(Scan).order_by(Scan.started_at.desc()).limit(limit).offset(offset)
    ).all()
    return ScanList(total=total, scans=scans)


@router.get(
    "/{scan_id}",
    response_model=ScanWithFindings,
    summary="Get scan detail with findings",
)
def get_scan(
    scan_id: int,
    session: Session = Depends(get_session),
):
    """Returns the full scan: status, score, grade, target info, all findings."""
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Trigger lazy loading of relationships while session is still active
    _ = scan.target
    _ = scan.findings
    return scan



# Set up Jinja2 once at module load (cheap, reusable)
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html"]),
)


@router.get("/{scan_id}/report.pdf")
def get_scan_pdf(scan_id: int, session: Session = Depends(get_session)):
    """Generate and return a PDF report for a scan."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Force lazy-load relationships
    _ = scan.target
    _ = scan.findings

    # Group findings by severity for the template
    findings_by_severity = {}
    for f in scan.findings:
        findings_by_severity.setdefault(f.severity, []).append(f)

    # Render template → HTML string
    template = _jinja_env.get_template("report.html")
    html_content = template.render(
        scan=scan,
        findings_by_severity=findings_by_severity,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    # Render HTML → PDF bytes
    pdf_bytes = HTML(string=html_content).write_pdf()

    # Return as a downloadable PDF
    filename = f"hisn-report-{scan.target.domain}-{scan.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
    )




@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingRead],
    summary="Get findings for a scan",
)
def get_scan_findings(
    scan_id: int,
    severity: Optional[str] = Query(
        None,
        description="Filter by severity: critical|high|medium|low|info|unknown",
    ),
    session: Session = Depends(get_session),
):
    """Findings list — optionally filtered by severity."""
    if session.get(Scan, scan_id) is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity.lower())

    return session.exec(query).all()


# Need Optional in imports — add at top of file: