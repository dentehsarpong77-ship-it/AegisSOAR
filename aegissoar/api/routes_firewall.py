from fastapi import APIRouter
from aegissoar.config import FIREWALL_SIMULATION_MODE
from aegissoar.db import get_blocklist, remove_from_blocklist

router = APIRouter(prefix="/api/v1/firewall", tags=["Firewall & Containment"])


@router.get("/blocklist")
async def list_blocked_ips():
    entries = get_blocklist()
    return {
        "simulation_mode": FIREWALL_SIMULATION_MODE,
        "count": len(entries),
        "blocklist": entries
    }


@router.delete("/blocklist/{ip}")
async def unblock_ip(ip: str):
    remove_from_blocklist(ip)
    return {"status": "UNBLOCKED", "ip": ip, "message": f"IP {ip} has been released from active quarantine."}
