import uuid
import pytest
from fastapi.testclient import TestClient
from aegissoar.main import app
from aegissoar.core.auth import hash_password, verify_password, needs_rehash
from aegissoar.core.security import clear_rate_limit_store

client = TestClient(app)


def test_pen_brute_force_rate_limiting():
    """Simulate a brute-force login attack and verify rate limiting protection (429)."""
    print("\n[PenTest] Simulating Brute-Force Login Attack...")

    # Send requests to trigger rate limit (MAX 60 per minute)
    responses = []
    for _ in range(65):
        responses.append(client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "wrongpassword"
        }))

    # Check if we got at least one 429
    assert any(r.status_code == 429 for r in responses), "Rate limiter failed to block rapid brute-force requests!"
    # Clear rate limit store so subsequent unit tests are not affected
    clear_rate_limit_store()


def test_pen_argon2_hashing():
    """Verify password hashing uses Argon2 and verification works."""
    password = "MySecurePassword123"
    hashed = hash_password(password)

    # Verify hash is argon2
    assert hashed.startswith("$argon2")
    # Verify successful match
    assert verify_password(password, hashed) is True
    # Verify failed match
    assert verify_password("wrong", hashed) is False


def test_pen_legacy_password_migration():
    """Simulate migration of SHA-256 legacy password to Argon2."""
    import hashlib
    legacy_pwd = "legacy_password"
    legacy_hash = hashlib.sha256(legacy_pwd.encode()).hexdigest()

    # Verify it verifies as legacy
    assert verify_password(legacy_pwd, legacy_hash) is True
    assert needs_rehash(legacy_hash) is True


def test_pen_tenant_isolation():
    """Verify tenant isolation across organizations."""
    print("\n[PenTest] Verifying Cross-Tenant Data Access...")
    clear_rate_limit_store()

    # 1. Register Org A
    uid_a = str(uuid.uuid4())[:8]
    res_a = client.post("/api/v1/auth/register", json={
        "organization_name": f"Org A {uid_a}",
        "full_name": "User A",
        "email": f"usera_{uid_a}@org.gh",
        "username": f"usera_{uid_a}",
        "password": "Password123!"
    })
    assert res_a.status_code == 200, f"Failed to register Org A: {res_a.text}"
    token_a = res_a.json()["access_token"]
    org_id_a = res_a.json()["organization_id"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # 2. Register Org B
    uid_b = str(uuid.uuid4())[:8]
    res_b = client.post("/api/v1/auth/register", json={
        "organization_name": f"Org B {uid_b}",
        "full_name": "User B",
        "email": f"userb_{uid_b}@org.gh",
        "username": f"userb_{uid_b}",
        "password": "Password123!"
    })
    assert res_b.status_code == 200, f"Failed to register Org B: {res_b.text}"
    token_b = res_b.json()["access_token"]
    org_id_b = res_b.json()["organization_id"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    assert org_id_a != org_id_b

    # 3. Try to access Org B incident using Org A token (should fail with 403 Forbidden)
    res_incidents_b_with_token_a = client.get(f"/api/v1/incidents?organization_id={org_id_b}", headers=headers_a)
    assert res_incidents_b_with_token_a.status_code == 403, "Tenant isolation failure! Cross-organization access allowed."
    clear_rate_limit_store()
