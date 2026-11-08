from fastapi import APIRouter
from aegissoar.core.threat_intel import lookup_ip_reputation

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])


@router.get("/{ip}")
async def query_ip_intel(ip: str):
    intel = await lookup_ip_reputation(ip)
    return intel
