import os
import tempfile

import pytest

os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mkdtemp().replace("\\", "/") + "/test.db"
os.environ["STORAGE_ROOT"] = tempfile.mkdtemp()
os.environ["SECRET_KEY"] = "test-secret-for-ci-only"
os.environ["EVIDENCE_ENCRYPTION_KEY"] = "629N15khwM2Q9Abj2eZx0sY7wBjwVDM7bb5VmkpGMhs="
os.environ["SEED_ADMIN_USERNAME"] = "admin"
os.environ["SEED_ADMIN_PASSWORD"] = "AdminPass123!"

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _auth_headers(client, username="admin", password="AdminPass123!"):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_login_failure_and_success(client):
    bad = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert bad.status_code == 401
    good = client.post("/api/auth/login", json={"username": "admin", "password": "AdminPass123!"})
    assert good.status_code == 200
    assert good.json()["access_token"]


def test_unauthorized_access_blocked(client):
    assert client.get("/api/dashboard/overview").status_code == 401


def test_forensics_flow(client):
    h = _auth_headers(client)
    # create a case
    r = client.post("/api/cases", json={"name": "Incident 2026-001", "description": "test"},
                    headers=h)
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]

    # upload a sample evtx (treated as generic file for filesystem module)
    files = {"file": ("sample.log", b"timestamp=2024-01-01 10:00:00 src=10.0.0.5 dst=192.168.1.10 dport=4444", "text/plain")}
    data = {"case_id": str(case_id), "category": "log", "evidence_type": "network"}
    r = client.post("/api/evidence", data=data, files=files, headers=h)
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["integrity_status"] == "verified"
    assert ev["sha256_original"]

    # verify endpoint
    r = client.post(f"/api/evidence/{ev['id']}/verify", headers=h)
    assert r.status_code == 200
    assert r.json()["integrity_status"] == "verified"

    # run a module
    r = client.post(f"/api/evidence/{ev['id']}/run/filesystem", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "completed"

    # run network module
    r = client.post(f"/api/evidence/{ev['id']}/run/network", headers=h)
    assert r.status_code == 200
    assert r.json()["status"] == "completed"

    # custody records exist
    r = client.get(f"/api/evidence/{ev['id']}/custody", headers=h)
    assert r.status_code == 200
    assert len(r.json()) >= 2

    # timeline events present
    r = client.get(f"/api/timeline/{case_id}/events", headers=h)
    assert r.status_code == 200
    assert len(r.json()["events"]) >= 1

    # assistant summarize
    r = client.post(f"/api/assistant/{case_id}/ask", json={"query": "summarize this case"},
                    headers=h)
    assert r.status_code == 200
    assert r.json()["is_hypothesis"] is True

    # report generation
    r = client.get(f"/api/reports/{case_id}/generate", headers=h)
    assert r.status_code == 200
    assert "evidence_inventory" in r.json()
    assert "analysis_methodology" in r.json()