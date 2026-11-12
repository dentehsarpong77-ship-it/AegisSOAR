from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import time

router = APIRouter(prefix="/api/v1/endpoints", tags=["endpoints"])


class EndpointRegister(BaseModel):
    hostname: str
    os_type: str
    ip_address: str


# Simulated SOC Managed Endpoints
REGISTERED_ENDPOINTS = [
    {
        "id": "EP-001",
        "hostname": "workstation-corp-01",
        "os_type": "Windows 11 Pro",
        "ip_address": "192.168.1.105",
        "status": "ONLINE",
        "agent_version": "v2.4.1",
        "last_heartbeat": "Just now",
        "risk_score": 12
    },
    {
        "id": "EP-002",
        "hostname": "prod-db-cluster-01",
        "os_type": "Ubuntu 22.04 LTS",
        "ip_address": "10.0.4.12",
        "status": "ONLINE",
        "agent_version": "v2.4.1",
        "last_heartbeat": "Just now",
        "risk_score": 5
    },
    {
        "id": "EP-003",
        "hostname": "k8s-node-worker-03",
        "os_type": "Debian 12",
        "ip_address": "10.0.8.44",
        "status": "ONLINE",
        "agent_version": "v2.4.0",
        "last_heartbeat": "2m ago",
        "risk_score": 0
    }
]


@router.get("")
async def list_endpoints():
    return {
        "total_count": len(REGISTERED_ENDPOINTS),
        "online_count": sum(1 for e in REGISTERED_ENDPOINTS if e["status"] == "ONLINE"),
        "endpoints": REGISTERED_ENDPOINTS
    }


@router.post("/register")
async def register_endpoint(ep: EndpointRegister):
    new_id = f"EP-{len(REGISTERED_ENDPOINTS) + 1:03d}"
    record = {
        "id": new_id,
        "hostname": ep.hostname,
        "os_type": ep.os_type,
        "ip_address": ep.ip_address,
        "status": "ONLINE",
        "agent_version": "v2.4.1",
        "last_heartbeat": "Just now",
        "risk_score": 0
    }
    REGISTERED_ENDPOINTS.append(record)
    return {"message": "Endpoint successfully registered", "endpoint": record}
