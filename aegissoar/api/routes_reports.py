from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from aegissoar.db import get_dashboard_metrics, get_incidents
from aegissoar.core.security import get_current_user

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("/summary")
async def get_security_summary(
    organization_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id")
    if organization_id and organization_id != user_org_id and current_user.get("username") != "admin":
        raise HTTPException(status_code=403, detail="Cross-organization data access forbidden")
    org_id = user_org_id
    metrics = get_dashboard_metrics(organization_id=org_id)
    incidents = get_incidents(limit=100, organization_id=org_id)

    return {
        "report_title": "AegisSOAR Executive Security Summary",
        "generated_at": "Real-time automated export",
        "metrics": metrics,
        "total_incidents_analyzed": len(incidents),
        "posture": "SECURE // Automated Defense Active",
        "compliance": ["ISO 27001", "SOC 2 Type II", "NIST CSF"]
    }


@router.get("/export/csv")
async def export_incidents_csv(
    organization_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_org_id = current_user.get("organization_id")
    if organization_id and organization_id != user_org_id and current_user.get("username") != "admin":
        raise HTTPException(status_code=403, detail="Cross-organization data access forbidden")
    org_id = user_org_id
    incidents = get_incidents(limit=500, organization_id=org_id)
    csv_lines = ["ID,Title,Severity,Source IP,MITRE,Status,Threat Score,Timestamp"]
    for inc in incidents:
        csv_lines.append(
            f"\"{inc.get('id')}\",\"{inc.get('title')}\",\"{inc.get('severity')}\","
            f"\"{inc.get('source_ip')}\",\"{inc.get('mitre_technique')}\",\"{inc.get('status')}\","
            f"\"{inc.get('threat_score')}\",\"{inc.get('created_at')}\""
        )
    csv_data = "\n".join(csv_lines)
    return Response(content=csv_data, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=aegissoar_incident_export.csv"})
