import pytest
from fastapi.testclient import TestClient
from aegissoar.main import app

client = TestClient(app)


def test_ai_analyst_endpoint():
    response = client.post("/api/v1/ai/analyze", json={"query": "Test SOC query"})
    assert response.status_code == 200
    data = response.json()
    assert "ai_summary" in data


def test_ai_insights_endpoint():
    response = client.get("/api/v1/ai/insights")
    assert response.status_code == 200
    data = response.json()
    assert "insights_summary" in data


def test_auth_login():
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "adminpassword"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["role"] in ["Administrator", "owner"]



def test_endpoints_list():
    response = client.get("/api/v1/endpoints")
    assert response.status_code == 200
    data = response.json()
    assert "endpoints" in data
    assert data["total_count"] >= 1


def test_reports_summary():
    response = client.get("/api/v1/reports/summary")
    assert response.status_code == 200
    data = response.json()
    assert "report_title" in data


def test_reports_csv_export():
    response = client.get("/api/v1/reports/export/csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "ID,Title,Severity" in response.text
