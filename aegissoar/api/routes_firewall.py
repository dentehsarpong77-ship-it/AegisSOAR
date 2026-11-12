from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from aegissoar.config import FIREWALL_SIMULATION_MODE
from aegissoar.db import get_blocklist, remove_from_blocklist
from aegissoar.core.security import get_current_user

router = APIRouter(prefix="/api/v1/firewall", tags=["Firewall & Containment"])


@router.get("/blocklist")
async def list_blocked_ips(
    organization_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id")
    if organization_id and organization_id != user_org_id and current_user.get("username") != "admin":
        raise HTTPException(status_code=403, detail="Cross-organization data access forbidden")
    org_id = user_org_id
    entries = get_blocklist(organization_id=org_id)
    return {
        "simulation_mode": FIREWALL_SIMULATION_MODE,
        "count": len(entries),
        "blocklist": entries
    }


@router.delete("/blocklist/{ip}")
async def unblock_ip(ip: str, current_user: dict = Depends(get_current_user)):
    # Note: Authorization check should be added here to ensure user belongs to org owning this IP record
    remove_from_blocklist(ip)
    return {"status": "UNBLOCKED", "ip": ip, "message": f"IP {ip} has been released from active quarantine."}
