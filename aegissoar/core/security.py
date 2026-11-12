import time
import jwt
from fastapi import HTTPException, Security, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Optional, Dict, Any
from aegissoar.db import get_user_by_username_db, get_user_memberships_db, get_membership_db, log_audit

SECRET_KEY = "aegis_secure_soar_secret_key_ghana_2026"
ALGORITHM = "HS256"

security_scheme = HTTPBearer(auto_error=False)

# In-memory rate limiter store: {ip_address: [timestamp1, timestamp2, ...]}
RATE_LIMIT_STORE: Dict[str, List[float]] = {}
MAX_REQUESTS_PER_MINUTE = 60


def check_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = 60.0

    if client_ip not in RATE_LIMIT_STORE:
        RATE_LIMIT_STORE[client_ip] = []

    # Filter out timestamps older than 1 minute
    RATE_LIMIT_STORE[client_ip] = [t for t in RATE_LIMIT_STORE[client_ip] if now - t < window]

    if len(RATE_LIMIT_STORE[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 60 requests per minute allowed."
        )

    RATE_LIMIT_STORE[client_ip].append(now)


def clear_rate_limit_store():
    RATE_LIMIT_STORE.clear()



def create_access_token(data: dict, expires_delta_hours: int = 24) -> str:
    to_encode = data.copy()
    expire = time.time() + (expires_delta_hours * 3600)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


def authenticate_token(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None

    if token.startswith("aegis_jwt_token_"):
        parts = token.replace("aegis_jwt_token_", "").split("_")
        username_or_id = parts[0]
        db_user = get_user_by_username_db(username_or_id)
        if db_user:
            memberships = get_user_memberships_db(db_user["id"])
            org_id = memberships[0]["organization_id"] if memberships else "org_default"
            role = memberships[0]["role"] if memberships else db_user.get("role", "analyst")
            return {
                "id": db_user["id"],
                "username": db_user["username"],
                "email": db_user["email"],
                "full_name": db_user["full_name"],
                "role": role,
                "organization_id": org_id
            }

    payload = decode_access_token(token)
    if not payload:
        return None

    username = payload.get("sub") or payload.get("username")
    if not username:
        return None

    db_user = get_user_by_username_db(username)
    if not db_user:
        return None

    memberships = get_user_memberships_db(db_user["id"])
    org_id = memberships[0]["organization_id"] if memberships else "org_default"
    role = memberships[0]["role"] if memberships else db_user.get("role", "analyst")

    return {
        "id": db_user["id"],
        "username": db_user["username"],
        "email": db_user["email"],
        "full_name": db_user["full_name"],
        "role": role,
        "organization_id": org_id
    }



async def get_current_user(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)) -> Dict[str, Any]:
    check_rate_limit(request)

    token = None
    if credentials:
        token = credentials.credentials
    else:
        # Check header or query if needed
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        # Fallback for unauthenticated dev/demo mode or default admin
        default_user = get_user_by_username_db("admin")
        if default_user:
            return {
                "id": default_user["id"],
                "username": default_user["username"],
                "email": default_user["email"],
                "full_name": default_user["full_name"],
                "role": "owner",
                "organization_id": "org_default"
            }
        return {
            "id": "admin",
            "username": "admin",
            "email": "admin@aegissoar.io",
            "full_name": "Lead SOC Administrator",
            "role": "owner",
            "organization_id": "org_default"
        }

    # Handle legacy token strings like aegis_jwt_token_...
    if token.startswith("aegis_jwt_token_"):
        parts = token.replace("aegis_jwt_token_", "").split("_")
        username_or_id = parts[0]
        db_user = get_user_by_username_db(username_or_id)
        if db_user:
            memberships = get_user_memberships_db(db_user["id"])
            org_id = memberships[0]["organization_id"] if memberships else "org_default"
            role = memberships[0]["role"] if memberships else db_user.get("role", "analyst")
            return {
                "id": db_user["id"],
                "username": db_user["username"],
                "email": db_user["email"],
                "full_name": db_user["full_name"],
                "role": role,
                "organization_id": org_id
            }

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token")

    username = payload.get("sub") or payload.get("username")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    db_user = get_user_by_username_db(username)
    if not db_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    memberships = get_user_memberships_db(db_user["id"])
    org_id = memberships[0]["organization_id"] if memberships else "org_default"
    role = memberships[0]["role"] if memberships else db_user.get("role", "analyst")

    return {
        "id": db_user["id"],
        "username": db_user["username"],
        "email": db_user["email"],
        "full_name": db_user["full_name"],
        "role": role,
        "organization_id": org_id
    }


def require_role(allowed_roles: List[str]):
    async def role_dependency(request: Request, current_user: Dict[str, Any] = Security(get_current_user)):
        user_role = current_user.get("role", "").lower()
        # Owners have universal access
        if user_role == "owner" or user_role == "administrator":
            return current_user

        if user_role not in [r.lower() for r in allowed_roles]:
            log_audit(
                action="AUTHORIZATION_FAILURE",
                user_id=current_user.get("id"),
                username=current_user.get("username"),
                organization_id=current_user.get("organization_id"),
                endpoint=request.url.path,
                ip_address=request.client.host if request.client else None,
                status="forbidden"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {allowed_roles}, your role: {user_role}"
            )
        return current_user
    return role_dependency
