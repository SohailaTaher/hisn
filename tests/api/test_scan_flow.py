"""
HISN — API integration tests
==============================
Tests the HTTP contracts of the scans router. Requires Redis to be running
because POST /scans enqueues a Celery task — the dispatch itself is what's
tested, not whether a worker picks it up.

Run:
    pytest tests/api/test_scan_flow.py -v
"""

import pytest
from fastapi.testclient import TestClient

from hisn.api.main import app
from hisn.api.db import create_db_and_tables


@pytest.fixture(scope="module")
def client():
    """FastAPI test client. Triggers lifespan (table creation) on entry."""
    create_db_and_tables()
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    """/health should return ok."""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "hisn-api"}


def test_create_scan_returns_201(client):
    """POST /scans creates Target+Scan, returns 201 with pending status."""
    r = client.post(
        "/scans",
        json={"domain": "example.com", "name": "Test domain"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["target_id"] > 0
    assert body["status"] == "pending"
    assert "id" in body


def test_create_scan_validates_domain(client):
    """Missing domain → 422."""
    r = client.post("/scans", json={})
    assert r.status_code == 422


def test_list_scans(client):
    """GET /scans returns paginated list."""
    r = client.get("/scans?limit=10")
    assert r.status_code == 200
    body = r.json()
    assert "total" in body
    assert isinstance(body["scans"], list)
    assert body["total"] >= 1   # at least the one we created above


def test_get_scan_detail(client):
    """GET /scans/{id} returns target + findings."""
    # Create a scan first
    create = client.post("/scans", json={"domain": "test.example.com"})
    scan_id = create.json()["id"]

    detail = client.get(f"/scans/{scan_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["id"] == scan_id
    assert body["target"]["domain"] == "test.example.com"
    assert isinstance(body["findings"], list)


def test_get_scan_returns_404_for_missing(client):
    """Missing scan → 404."""
    r = client.get("/scans/99999")
    assert r.status_code == 404


def test_filter_findings_by_severity(client):
    """Severity filter parameter accepted (even if no findings match)."""
    create = client.post("/scans", json={"domain": "filter-test.example.com"})
    scan_id = create.json()["id"]
    r = client.get(f"/scans/{scan_id}/findings?severity=critical")
    assert r.status_code == 200
    assert isinstance(r.json(), list)