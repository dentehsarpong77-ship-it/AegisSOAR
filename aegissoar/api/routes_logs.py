from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from aegissoar.core.detector import detection_engine
from aegissoar.core.parser import parse_raw_log
from aegissoar.db import get_recent_events
from aegissoar.models import LogIngestRequest, SecurityEvent

router = APIRouter(prefix="/api/v1/logs", tags=["Logs & Ingestion"])


@router.post("/ingest")
async def ingest_logs(payload: LogIngestRequest):
    processed_count = 0
    incidents_raised = []

    if payload.event:
        inc = await detection_engine.process_event(payload.event)
        if inc:
            incidents_raised.append(inc.id)
        processed_count += 1
    elif payload.events:
        for evt in payload.events:
            inc = await detection_engine.process_event(evt)
            if inc:
                incidents_raised.append(inc.id)
            processed_count += 1
    elif payload.log:
        evt = parse_raw_log(payload.log)
        inc = await detection_engine.process_event(evt)
        if inc:
            incidents_raised.append(inc.id)
        processed_count += 1
    elif payload.logs:
        for line in payload.logs:
            evt = parse_raw_log(line)
            inc = await detection_engine.process_event(evt)
            if inc:
                incidents_raised.append(inc.id)
            processed_count += 1
    else:
        raise HTTPException(status_code=400, detail="No log data provided in request body.")

    return {
        "status": "SUCCESS",
        "processed_events": processed_count,
        "incidents_raised": incidents_raised
    }


@router.get("/recent")
async def fetch_recent_logs(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = None,
    ip: Optional[str] = None
):
    events = get_recent_events(limit=limit, event_type=event_type, ip=ip)
    return {"count": len(events), "events": events}
