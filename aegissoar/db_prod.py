import os
from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime, JSON, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from aegissoar.config import DATABASE_URL

Base = declarative_base()

class Event(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    event_type = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String)
    service = Column(String)
    username = Column(String)
    status = Column(String)
    status_code = Column(Integer)
    message = Column(Text)
    raw_payload = Column(Text)
    metadata = Column(JSON)
    organization_id = Column(String, default='org_default')

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    target_user = Column(String)
    mitre_tactic = Column(String)
    mitre_technique = Column(String)
    mitre_technique_name = Column(String)
    rule_id = Column(String)
    evidence_count = Column(Integer, default=1)
    threat_score = Column(Integer, default=0)
    threat_intel = Column(JSON)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)
    notes = Column(JSON)
    playbook_executions = Column(JSON)
    organization_id = Column(String, default='org_default')

class Blocklist(Base):
    __tablename__ = "blocklist"
    ip = Column(String, primary_key=True)
    reason = Column(Text)
    rule_id = Column(String)
    incident_id = Column(String)
    blocked_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime)
    active = Column(Boolean, default=True)
    organization_id = Column(String, default='org_default')

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    id = Column(String, primary_key=True)
    playbook_id = Column(String, nullable=False)
    playbook_name = Column(String, nullable=False)
    incident_id = Column(String)
    status = Column(String, nullable=False)
    executed_at = Column(DateTime, nullable=False)
    actions_taken = Column(JSON)
    organization_id = Column(String, default='org_default')

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String)
    created_at = Column(DateTime, nullable=False)

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, unique=True, nullable=False)
    owner_user_id = Column(String, nullable=False)
    status = Column(String, default='active')
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

class Membership(Base):
    __tablename__ = "memberships"
    id = Column(String, primary_key=True)
    organization_id = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    role = Column(String, nullable=False)
    status = Column(String, default='active')
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

class Invitation(Base):
    __tablename__ = "invitations"
    id = Column(String, primary_key=True)
    organization_id = Column(String, nullable=False)
    invited_email = Column(String, nullable=False)
    role = Column(String, nullable=False)
    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, default='pending')
    created_by_user_id = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    user_id = Column(String)
    username = Column(String)
    organization_id = Column(String)
    action = Column(String, nullable=False)
    endpoint = Column(String)
    ip_address = Column(String)
    status = Column(String)


def get_prod_engine(url=None):
    db_url = url or DATABASE_URL
    if not db_url:
        db_url = "postgresql://aegis_user:aegis_password@localhost:5432/aegis_db"
    return create_engine(db_url)

def init_db_prod(url=None):
    eng = get_prod_engine(url)
    Base.metadata.create_all(bind=eng)


