from fastapi import APIRouter, Depends, HTTPException
from aegissoar.core.simulator import simulator
from aegissoar.db import get_dashboard_metrics, get_playbook_executions
from aegissoar.models import SimulationRequest
from aegissoar.core.security import get_current_user

router = APIRouter(prefix="/api/v1", tags=["Simulation & Telemetry"])


@router.post("/simulator/trigger")
async def trigger_attack_simulation(request: SimulationRequest):
    try:
        res = await simulator.run_scenario(request.scenario, request.attacker_ip)
        return {"status": "SUCCESS", "result": res}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/metrics")
async def get_metrics(current_user: dict = Depends(get_current_user)):
    organization_id = current_user.get("organization_id")
    return get_dashboard_metrics(organization_id=organization_id)


@router.get("/playbooks/executions")
async def list_playbook_runs(limit: int = 20):
    runs = get_playbook_executions(limit=limit)
    return {"count": len(runs), "executions": runs}
