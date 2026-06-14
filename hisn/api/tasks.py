"""
HISN — Celery Tasks
=====================
Background tasks executed by Celery workers.

Tasks:
  - hisn.ping     : trivial liveness task (validates the worker is alive)
  - hisn.run_scan : runs all configured scanners against a target, writes
                    Finding rows + updates Scan status / score / grade.

Author: Sohaila Taher Shaker
License: MIT
"""

from datetime import datetime, timezone

from sqlmodel import Session

from hisn.api.worker import celery_app
from hisn.api.db import engine
from hisn.api.models import Scan, Finding
from hisn.core.orchestrator import run_all_scanners


@celery_app.task(name="hisn.ping")
def ping(message: str = "hello") -> dict:
    """Trivial task — proves the worker is alive and Redis is reachable."""
    return {"reply": f"pong: {message}"}


@celery_app.task(name="hisn.run_scan", bind=True)
def run_scan(self, scan_id: int) -> dict:
    """Run ALL scanners against the target of `scan_id`."""
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return {"error": f"Scan id={scan_id} not found"}

        target = scan.target
        if target is None:
            scan.status = "failed"
            scan.error_message = "Scan has no associated target"
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan); session.commit()
            return {"error": "no_target", "scan_id": scan_id}

        domain = target.domain

        scan.status = "running"
        session.add(scan); session.commit()

        try:
            result = run_all_scanners(domain)

            for f in result["findings"]:
                session.add(Finding(
                    scan_id=scan.id,
                    scanner_name=f["scanner_name"],
                    severity=f["severity"],
                    title=f["title"],
                    description=f.get("description"),
                    raw_data=f.get("raw_data"),
                ))

            scan.overall_score = result["score"]
            scan.overall_grade = result["grade"]
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan); session.commit()

            return {
                "scan_id": scan_id,
                "domain": domain,
                "status": "done",
                "overall_score": result["score"],
                "overall_grade": result["grade"],
                "findings_count": len(result["findings"]),
                "per_scanner": result["per_scanner"],
            }

        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.finished_at = datetime.now(timezone.utc)
            session.add(scan); session.commit()
            raise