from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from aegissoar.core.detector import detection_engine
from aegissoar.core.parser import parse_raw_log
from aegissoar.db import get_recent_events
from aegissoar.models import LogIngestRequest, SecurityEvent
from aegissoar.core.security import get_current_user

router = APIRouter(prefix="/api/v1/logs", tags=["Logs & Ingestion"])


@router.post("/ingest")
async def ingest_logs(payload: LogIngestRequest, current_user: dict = Depends(get_current_user)):
    org_id = current_user.get("organization_id", "org_default")
    processed_count = 0
    incidents_raised = []

    events_to_process = []
    if payload.event:
        events_to_process.append(payload.event)
    if payload.events:
        events_to_process.extend(payload.events)
    if payload.log:
        events_to_process.append(parse_raw_log(payload.log))
    if payload.logs:
        for line in payload.logs:
            events_to_process.append(parse_raw_log(line))

    if not events_to_process:
        raise HTTPException(status_code=400, detail="No log data provided in request body.")

    for evt in events_to_process:
        evt.organization_id = org_id
        inc = await detection_engine.process_event(evt)
        if inc:
            incidents_raised.append(inc.id)
        processed_count += 1

    return {
        "status": "SUCCESS",
        "processed_events": processed_count,
        "incidents_raised": incidents_raised
    }


@router.get("/recent")
async def fetch_recent_logs(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = None,
    ip: Optional[str] = None,
    organization_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    org_id = organization_id or current_user.get("organization_id")
    events = get_recent_events(limit=limit, event_type=event_type, ip=ip, organization_id=org_id)
    return {"count": len(events), "events": events}
