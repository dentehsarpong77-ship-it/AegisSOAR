from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def utc_now():
    return datetime.now(timezone.utc)


class SecurityEvent(BaseModel):
    id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: str = "generic"  # "auth", "http", "network", "system"
    source_ip: str
    destination_ip: Optional[str] = "192.168.1.1"
    service: Optional[str] = "generic"
    username: Optional[str] = None
    status: str = "INFO"  # "SUCCESS", "FAILURE", "INFO"
    status_code: Optional[int] = None
    message: str
    raw_payload: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    organization_id: Optional[str] = "org_default"


class LogIngestRequest(BaseModel):
    source: str = "api"
    format: str = "auto"
    log: Optional[str] = None
    logs: Optional[List[str]] = None
    event: Optional[SecurityEvent] = None
    events: Optional[List[SecurityEvent]] = None


class ThreatIntelResult(BaseModel):
    ip: str
    reputation_score: int
    verdict: str
    country: str = "Unknown"
    country_code: str = "XX"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = "Unknown"
    asn: str = "Unknown"
    threat_types: List[str] = Field(default_factory=list)
    source: str = "AegisThreatDB"
    is_tor_node: bool = False
    is_known_scanner: bool = False


class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    status: str = "OPEN"
    source_ip: str
    target_user: Optional[str] = None
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_name: str
    rule_id: str
    evidence_count: int = 1
    threat_score: int = 0
    threat_intel: Optional[ThreatIntelResult] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    notes: List[str] = Field(default_factory=list)
    playbook_executions: List[str] = Field(default_factory=list)
    organization_id: Optional[str] = "org_default"


class IncidentUpdateRequest(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    note: Optional[str] = None


class BlocklistEntry(BaseModel):
    ip: str
    reason: str
    rule_id: Optional[str] = None
    incident_id: Optional[str] = None
    blocked_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = None
    active: bool = True


class PlaybookExecution(BaseModel):
    id: str
    playbook_id: str
    playbook_name: str
    incident_id: Optional[str] = None
    status: str = "SUCCESS"
    executed_at: datetime = Field(default_factory=utc_now)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)


class SimulationRequest(BaseModel):
    scenario: str
    attacker_ip: Optional[str] = None
    intensity: int = 5


class UserRegisterRequest(BaseModel):
    organization_name: str
    full_name: str
    email: str
    username: str
    password: str


class OrganizationModel(BaseModel):
    id: str
    name: str
    slug: str
    owner_user_id: str
    status: str = "active"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class MembershipModel(BaseModel):
    id: str
    organization_id: str
    user_id: str
    role: str  # owner, security_admin, analyst, viewer
    status: str = "active"
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class InvitationCreateModel(BaseModel):
    email: str
    role: str = "analyst"

