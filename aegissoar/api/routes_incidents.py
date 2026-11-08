from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from aegissoar.core.playbooks import playbook_engine
from aegissoar.db import get_incident_by_id, get_incidents, get_recent_events, update_incident
from aegissoar.models import Incident, IncidentUpdateRequest

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents & Case Management"])


@router.get("")
async def list_incidents(
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200)
):
    incidents = get_incidents(status=status, limit=limit)
    return {"count": len(incidents), "incidents": incidents}


@router.get("/{incident_id}")
async def get_incident(incident_id: str):
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    evidence_events = get_recent_events(limit=25, ip=incident["source_ip"])
    return {
        "incident": incident,
        "evidence_events": evidence_events
    }


@router.patch("/{incident_id}")
async def patch_incident(incident_id: str, update: IncidentUpdateRequest):
    updated = update_incident(
        incident_id=incident_id,
        status=update.status,
        severity=update.severity,
        note=update.note
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "UPDATED", "incident": updated}


@router.post("/{incident_id}/playbook")
async def trigger_playbook_on_incident(incident_id: str, playbook_id: str = Query(...)):
    incident_data = get_incident_by_id(incident_id)
    if not incident_data:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident_obj = Incident(**incident_data)
    result = await playbook_engine.execute_playbook(playbook_id, incident_obj)

    update_incident(incident_id, note=f"Manual execution of playbook '{result.playbook_name}' ({playbook_id})")
    return {"status": "EXECUTED", "execution": result}
