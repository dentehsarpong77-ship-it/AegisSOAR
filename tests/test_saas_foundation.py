import uuid
import pytest
from fastapi.testclient import TestClient
from aegissoar.main import app

client = TestClient(app)


def test_customer_registration_and_org_creation():
    uid = str(uuid.uuid4())[:8]
    payload = {
        "organization_name": f"Accra Cyber Defense {uid}",
        "full_name": "Kwame Mensah",
        "email": f"kwame_{uid}@accracyber.gh",
        "username": f"kwame_{uid}",
        "password": "SecurePassword123!"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert "organization_id" in data

    # Test login with registered user
    login_res = client.post("/api/v1/auth/login", json={
        "username": f"kwame_{uid}",
        "password": "SecurePassword123!"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data
    assert login_data["user"]["username"] == f"kwame_{uid}"
    assert login_data["user"]["role"] == "owner"


def test_existing_demo_user_authentication():
    response = client.post("/api/v1/auth/login", json={
        "username": "admin",
        "password": "adminpassword"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["username"] == "admin"


def test_duplicate_registration_fails():
    uid = str(uuid.uuid4())[:8]
    payload = {
        "organization_name": f"Kumasi Security Hub {uid}",
        "full_name": "Akua Boateng",
        "email": f"akua_{uid}@kumasisec.gh",
        "username": f"akua_{uid}",
        "password": "Password123!"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 200

    # Registering again with same email/username should fail
    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
