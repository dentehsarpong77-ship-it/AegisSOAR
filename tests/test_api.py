from fastapi.testclient import TestClient
import pytest
from aegissoar.db import init_db
from aegissoar.main import app


@pytest.fixture
def client():
    init_db()
    with TestClient(app) as client:
        yield client


def test_api_metrics(client):
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "active_incidents" in data
    assert "blocked_ips" in data


def test_api_ingest_raw_log(client):
    payload = {
        "log": '198.51.100.42 - - [08/Nov/2026:16:35:20 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
    }
    response = client.post("/api/v1/logs/ingest", json=payload)
    assert response.status_code == 200
    assert response.json()["processed_events"] == 1


def test_api_threat_intel_lookup(client):
    response = client.get("/api/v1/threat-intel/185.220.101.5")
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "185.220.101.5"
    assert data["country"] == "Germany"
    assert data["verdict"] == "MALICIOUS"
    assert data["reputation_score"] >= 80


def test_api_simulator_trigger(client):
    response = client.post("/api/v1/simulator/trigger", json={"scenario": "recon_fuzzing"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["result"]["scenario"] == "recon_fuzzing"


def test_api_firewall_list(client):
    response = client.get("/api/v1/firewall/blocklist")
    assert response.status_code == 200
    assert "blocklist" in response.json()
