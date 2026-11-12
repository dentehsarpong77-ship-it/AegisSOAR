import uuid
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional
from aegissoar.db import (
    create_user_db, create_organization_db, create_membership_db,
    get_user_by_email_db, get_user_by_username_db, log_audit,
    get_user_memberships_db, update_user_password_hash_db
)
from aegissoar.core.security import create_access_token, get_current_user, check_rate_limit
from aegissoar.core.auth import hash_password, verify_password, needs_rehash

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class UserRegisterRequest(BaseModel):
    organization_name: str
    full_name: str
    email: str
    username: str
    password: str


class UserProfile(BaseModel):
    username: str
    role: str
    email: str
    full_name: str
    organization_id: Optional[str] = None
    organization_name: Optional[str] = None


# Pre-defined SOC accounts for RBAC (with Argon2 hashed passwords or fallback verification)
DEMO_USERS = {
    "admin": {"password_hash": hash_password("adminpassword"), "role": "owner", "full_name": "Lead SOC Administrator", "email": "admin@aegissoar.io"},
    "analyst": {"password_hash": hash_password("analystpassword"), "role": "analyst", "full_name": "Tier 2 SOC Analyst", "email": "analyst@aegissoar.io"},
    "viewer": {"password_hash": hash_password("viewerpassword"), "role": "viewer", "full_name": "Audit Auditor", "email": "viewer@aegissoar.io"}
}


@router.post("/register")
async def register(req: UserRegisterRequest, request: Request):
    check_rate_limit(request)
    if get_user_by_email_db(req.email) or get_user_by_username_db(req.username):
        log_audit(action="USER_REGISTER_FAIL", username=req.username, endpoint=request.url.path, ip_address=request.client.host if request.client else None, status="duplicate")
        raise HTTPException(status_code=400, detail="User already exists")

    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    membership_id = str(uuid.uuid4())
    org_slug = req.organization_name.lower().replace(" ", "-")

    hashed_pwd = hash_password(req.password)
    create_user_db(user_id, req.username, req.email, hashed_pwd, req.full_name, "owner")
    create_organization_db(org_id, req.organization_name, org_slug, user_id)
    create_membership_db(membership_id, org_id, user_id, "owner")

    log_audit(
        action="USER_REGISTER_SUCCESS",
        user_id=user_id,
        username=req.username,
        organization_id=org_id,
        endpoint=request.url.path,
        ip_address=request.client.host if request.client else None,
        status="success"
    )

    token = create_access_token({"sub": req.username, "organization_id": org_id, "role": "owner"})

    return {
        "message": "User and organization registered successfully",
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_id,
        "organization_id": org_id
    }


@router.post("/login")
async def login(credentials: LoginRequest, request: Request):
    # Enforce rate limiting on public login endpoint
    check_rate_limit(request)

    db_user = get_user_by_username_db(credentials.username)
    if db_user and verify_password(credentials.password, db_user["password_hash"]):
        # Lazy rehash migration if legacy hash
        if needs_rehash(db_user["password_hash"]):
            new_h = hash_password(credentials.password)
            update_user_password_hash_db(db_user["id"], new_h)

        memberships = get_user_memberships_db(db_user["id"])
        org_id = memberships[0]["organization_id"] if memberships else "org_default"
        role = memberships[0]["role"] if memberships else db_user.get("role", "analyst")

        token = create_access_token({"sub": db_user["username"], "organization_id": org_id, "role": role})
        log_audit(
            action="USER_LOGIN_SUCCESS",
            user_id=db_user["id"],
            username=db_user["username"],
            organization_id=org_id,
            endpoint=request.url.path,
            ip_address=request.client.host if request.client else None,
            status="success"
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": db_user["id"],
                "username": db_user["username"],
                "role": role,
                "full_name": db_user["full_name"],
                "email": db_user["email"],
                "organization_id": org_id
            }
        }

    # Demo user fallback
    demo = DEMO_USERS.get(credentials.username.lower())
    if demo and verify_password(credentials.password, demo["password_hash"]):
        token = create_access_token({"sub": credentials.username, "organization_id": "org_default", "role": demo["role"]})
        log_audit(
            action="DEMO_LOGIN_SUCCESS",
            username=credentials.username,
            organization_id="org_default",
            endpoint=request.url.path,
            ip_address=request.client.host if request.client else None,
            status="success"
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": f"demo_{credentials.username}",
                "username": credentials.username,
                "role": demo["role"],
                "full_name": demo["full_name"],
                "email": demo["email"],
                "organization_id": org_id if 'org_id' in locals() else "org_default"
            }
        }

    log_audit(
        action="USER_LOGIN_FAIL",
        username=credentials.username,
        endpoint=request.url.path,
        ip_address=request.client.host if request.client else None,
        status="unauthorized"
    )
    # Generic error message to avoid exposing whether user exists
    raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/me")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user.get("id"),
        "username": current_user["username"],
        "role": current_user["role"],
        "full_name": current_user.get("full_name"),
        "email": current_user.get("email"),
        "organization_id": current_user.get("organization_id")
    }
