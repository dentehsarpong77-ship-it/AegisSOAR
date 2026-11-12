from fastapi import APIRouter, Depends, Query, Request
from typing import Optional, List
from aegissoar.db import get_audit_logs
from aegissoar.core.security import get_current_user, require_role

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Logs & Compliance"])


@router.get("/logs")
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_role(["owner", "admin", "analyst"]))
):
    org_id = current_user.get("organization_id")
    logs = get_audit_logs(organization_id=org_id, limit=limit)
    if not logs:
        # Fallback without org filter if none
        logs = get_audit_logs(limit=limit)
    return {
        "count": len(logs),
        "audit_logs": logs
    }
