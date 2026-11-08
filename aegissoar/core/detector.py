import asyncio
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable, Dict, List, Optional
import uuid
from aegissoar.config import load_yaml_rules
from aegissoar.core.playbooks import playbook_engine
from aegissoar.core.threat_intel import lookup_ip_reputation
from aegissoar.db import get_incident_by_id, insert_event, save_incident
from aegissoar.models import Incident, SecurityEvent


class DetectionEngine:
    def __init__(self):
        self.rules = load_yaml_rules()
        self._compiled_patterns = {}
        self._window_history = defaultdict(lambda: defaultdict(list))
        self._active_incidents = {}
        self.broadcast_callback: Optional[Callable] = None
        self._compile_regexes()

    def _compile_regexes(self):
        for rule in self.rules:
            patterns = rule.get("patterns", [])
            if patterns:
                self._compiled_patterns[rule["id"]] = [re.compile(p, re.IGNORECASE) for p in patterns]

    async def process_event(self, event: SecurityEvent) -> Optional[Incident]:
        if not event.id:
            event.id = f"evt_{uuid.uuid4().hex[:12]}"

        insert_event(event)

        if self.broadcast_callback:
            await self.broadcast_callback("RAW_LOG", event.model_dump(mode="json"))

        triggered_incident = None

        for rule in self.rules:
            if self._matches_rule(rule, event):
                incident = await self._handle_rule_trigger(rule, event)
                if incident:
                    triggered_incident = incident

        return triggered_incident

    def _matches_rule(self, rule: Dict[str, Any], event: SecurityEvent) -> bool:
        if rule.get("event_type") and rule["event_type"] != event.event_type:
            return False

        match_criteria = rule.get("match", {})
        for field, expected_val in match_criteria.items():
            actual_val = getattr(event, field, None)
            if actual_val is None and field in event.metadata:
                actual_val = event.metadata[field]
            if actual_val != expected_val:
                return False

        if rule["id"] in self._compiled_patterns:
            patterns = self._compiled_patterns[rule["id"]]
            content_to_check = f"{event.message} {event.raw_payload or ''}"
            matched = any(p.search(content_to_check) for p in patterns)
            if not matched:
                return False

        threshold_conf = rule.get("threshold", {})
        required_count = threshold_conf.get("count", 1)
        window_seconds = threshold_conf.get("window_seconds", 60)
        group_by = threshold_conf.get("group_by", "source_ip")

        group_val = getattr(event, group_by, None) or event.metadata.get(group_by, event.source_ip)
        now = datetime.now(timezone.utc)

        history = self._window_history[rule["id"]][group_val]
        cutoff = now - timedelta(seconds=window_seconds)
        history = [ts for ts in history if ts > cutoff]
        history.append(now)
        self._window_history[rule["id"]][group_val] = history

        return len(history) >= required_count

    async def _handle_rule_trigger(self, rule: Dict[str, Any], event: SecurityEvent) -> Incident:
        rule_id = rule["id"]
        group_by = rule.get("threshold", {}).get("group_by", "source_ip")
        group_val = getattr(event, group_by, None) or event.source_ip

        incident_key = f"{rule_id}:{group_val}"
        existing_id = self._active_incidents.get(incident_key)

        now = datetime.now(timezone.utc)
        mitre = rule.get("mitre_attack", {})

        intel = await lookup_ip_reputation(event.source_ip)

        if existing_id:
            existing_data = get_incident_by_id(existing_id)
            if existing_data and existing_data["status"] not in ["RESOLVED", "FALSE_POSITIVE"]:
                incident = Incident(
                    id=existing_id,
                    title=rule["name"],
                    description=rule["description"],
                    severity=rule.get("severity", "HIGH"),
                    status=existing_data["status"],
                    source_ip=event.source_ip,
                    target_user=event.username,
                    mitre_tactic=mitre.get("tactic", "Unknown"),
                    mitre_technique=mitre.get("technique", "Unknown"),
                    mitre_technique_name=mitre.get("name", "Unknown"),
                    rule_id=rule_id,
                    evidence_count=existing_data.get("evidence_count", 1) + 1,
                    threat_score=intel.reputation_score,
                    threat_intel=intel,
                    created_at=datetime.fromisoformat(existing_data["created_at"]),
                    updated_at=now,
                    notes=existing_data.get("notes", []),
                    playbook_executions=existing_data.get("playbook_executions", [])
                )
                save_incident(incident)
                if self.broadcast_callback:
                    await self.broadcast_callback("INCIDENT_UPDATED", incident.model_dump(mode="json"))
                return incident

        incident_id = f"inc_{uuid.uuid4().hex[:8]}"
        self._active_incidents[incident_key] = incident_id

        base_sev = rule.get("severity", "MEDIUM")
        if intel.reputation_score >= 90:
            base_sev = "CRITICAL"
        elif intel.reputation_score >= 70 and base_sev == "LOW":
            base_sev = "HIGH"

        incident = Incident(
            id=incident_id,
            title=rule["name"],
            description=rule["description"],
            severity=base_sev,
            status="OPEN",
            source_ip=event.source_ip,
            target_user=event.username,
            mitre_tactic=mitre.get("tactic", "Initial Access"),
            mitre_technique=mitre.get("technique", "T0000"),
            mitre_technique_name=mitre.get("name", "Unknown"),
            rule_id=rule_id,
            evidence_count=1,
            threat_score=intel.reputation_score,
            threat_intel=intel,
            created_at=now,
            updated_at=now,
            notes=[f"Incident automatically raised by rule {rule_id}"]
        )

        save_incident(incident)

        auto_pb = rule.get("auto_playbook")
        if auto_pb:
            exec_record = await playbook_engine.execute_playbook(auto_pb, incident)
            incident.playbook_executions.append(exec_record.id)
            incident.status = "CONTAINED"
            save_incident(incident)

        if self.broadcast_callback:
            await self.broadcast_callback("INCIDENT_CREATED", incident.model_dump(mode="json"))

        return incident


detection_engine = DetectionEngine()
