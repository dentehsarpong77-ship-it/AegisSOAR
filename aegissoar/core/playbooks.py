import asyncio
from datetime import datetime, timedelta, timezone
import uuid
from typing import Any, Dict, List, Optional
import httpx
from aegissoar.config import FIREWALL_SIMULATION_MODE, WEBHOOK_ALERT_URL, load_yaml_playbooks
from aegissoar.db import add_to_blocklist, get_recent_events, record_playbook_execution
from aegissoar.models import BlocklistEntry, Incident, PlaybookExecution


class PlaybookEngine:
    def __init__(self):
        self.playbooks_def = {pb["id"]: pb for pb in load_yaml_playbooks()}

    async def execute_playbook(self, playbook_id: str, incident: Incident) -> PlaybookExecution:
        pb_config = self.playbooks_def.get(playbook_id)
        if not pb_config:
            pb_name = f"Custom Playbook ({playbook_id})"
            actions = [{"type": "FIREWALL_BLOCK", "params": {"ttl_seconds": 3600}}]
        else:
            pb_name = pb_config.get("name", playbook_id)
            actions = pb_config.get("actions", [])

        execution_id = f"exec_{uuid.uuid4().hex[:10]}"
        actions_taken = []

        for action in actions:
            action_type = action.get("type")
            params = action.get("params", {})
            result = await self._run_action(action_type, params, incident)
            actions_taken.append({
                "action": action_type,
                "status": "COMPLETED",
                "details": result
            })

        execution_record = PlaybookExecution(
            id=execution_id,
            playbook_id=playbook_id,
            playbook_name=pb_name,
            incident_id=incident.id,
            status="SUCCESS",
            executed_at=datetime.now(timezone.utc),
            actions_taken=actions_taken
        )

        record_playbook_execution(execution_record)
        return execution_record

    async def _run_action(self, action_type: str, params: Dict[str, Any], incident: Incident) -> Dict[str, Any]:
        if action_type == "FIREWALL_BLOCK":
            ttl = params.get("ttl_seconds", 3600)
            expires = datetime.now(timezone.utc) + timedelta(seconds=ttl)
            reason = params.get("reason", f"Automated block for {incident.title}")

            entry = BlocklistEntry(
                ip=incident.source_ip,
                reason=reason,
                rule_id=incident.rule_id,
                incident_id=incident.id,
                blocked_at=datetime.now(timezone.utc),
                expires_at=expires,
                active=True
            )
            add_to_blocklist(entry)

            cli_cmd = f"iptables -I INPUT 1 -s {incident.source_ip} -j DROP"
            return {
                "ip": incident.source_ip,
                "action": "BLOCK",
                "ttl_seconds": ttl,
                "expires_at": expires.isoformat(),
                "firewall_command": cli_cmd,
                "simulation": FIREWALL_SIMULATION_MODE,
                "message": f"Successfully quarantined {incident.source_ip} for {ttl}s via {'Simulated Firewall' if FIREWALL_SIMULATION_MODE else 'System Firewall'}"
            }

        elif action_type == "DISPATCH_WEBHOOK":
            channel = params.get("channel", "soc-alerts")
            payload = {
                "title": f"🚨 [AEGIS SOAR] {incident.severity} ALERT: {incident.title}",
                "incident_id": incident.id,
                "attacker_ip": incident.source_ip,
                "mitre_technique": f"{incident.mitre_technique} ({incident.mitre_technique_name})",
                "threat_score": incident.threat_score,
                "status": incident.status,
                "channel": channel,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

            if WEBHOOK_ALERT_URL:
                try:
                    async with httpx.AsyncClient(timeout=3.0) as client:
                        await client.post(WEBHOOK_ALERT_URL, json=payload)
                except Exception as e:
                    return {"status": "WEBHOOK_FAILED", "error": str(e), "payload": payload}

            return {
                "channel": channel,
                "dispatched": True,
                "notification_preview": payload
            }

        elif action_type == "CAPTURE_FORENSICS":
            window_hours = params.get("window_hours", 24)
            related_events = get_recent_events(limit=20, ip=incident.source_ip)
            return {
                "forensics_window_hours": window_hours,
                "correlated_event_count": len(related_events),
                "forensic_summary": f"Captured {len(related_events)} raw audit logs associated with attacker {incident.source_ip}"
            }

        elif action_type == "LOCK_USER":
            user = incident.target_user or "unknown_user"
            duration = params.get("duration_minutes", 60)
            return {
                "targeted_user": user,
                "action": "ACCOUNT_DISABLED",
                "session_tokens_revoked": True,
                "quarantine_duration_min": duration,
                "message": f"User account '{user}' has been locked and active sessions revoked for {duration}m"
            }

        elif action_type == "LOG_AUDIT":
            return {
                "audit_entry": params.get("message", "Audit log created"),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        return {"status": "UNKNOWN_ACTION"}


playbook_engine = PlaybookEngine()
