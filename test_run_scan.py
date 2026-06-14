"""One-off Phase 2 smoke test — create a target+scan, trigger the task, verify DB."""

from sqlmodel import Session, select

from hisn.api.db import engine, create_db_and_tables
from hisn.api.models import Target, Scan, Finding
from hisn.api.tasks import run_scan


# Ensure tables exist (idempotent — safe to run every time)
create_db_and_tables()


# 1. Find-or-create test target, always create a new scan
with Session(engine) as session:
    existing = session.exec(
        select(Target).where(Target.domain == "github.com")
    ).first()
    if existing:
        target = existing
        print(f"✅ Reusing Target id={target.id} domain={target.domain}")
    else:
        target = Target(domain="github.com", name="GitHub (test)")
        session.add(target)
        session.commit()
        session.refresh(target)
        print(f"✅ Created Target id={target.id} domain={target.domain}")

    scan = Scan(target_id=target.id)
    session.add(scan)
    session.commit()
    session.refresh(scan)
    scan_id = scan.id
    print(f"✅ Created Scan id={scan_id} status={scan.status}")

# 2. Trigger the task
print(f"\n→ Dispatching run_scan({scan_id})...")
result = run_scan.delay(scan_id)
print(f"   Task id: {result.id}")
print(f"   Waiting up to 30s for result...")
task_result = result.get(timeout=900)
print(f"\n✅ Task returned: {task_result}")

# 3. Verify DB
print(f"\n→ Verifying DB state for scan {scan_id}...")
with Session(engine) as session:
    scan = session.get(Scan, scan_id)
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
    ).all()
    print(f"   Scan status:  {scan.status}")
    print(f"   Score:        {scan.overall_score}/100")
    print(f"   Grade:        {scan.overall_grade}")
    print(f"   Findings:     {len(findings)}")
    for f in findings:
        print(f"     [{f.severity:8s}] {f.scanner_name}: {f.title}")