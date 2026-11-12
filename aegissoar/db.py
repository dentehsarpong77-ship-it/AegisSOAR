import json
import sqlite3
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from aegissoar.config import DB_PATH
from aegissoar.models import BlocklistEntry, Incident, PlaybookExecution, SecurityEvent, ThreatIntelResult


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        role TEXT,
        created_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        owner_user_id TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS memberships (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(organization_id, user_id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        invited_email TEXT NOT NULL,
        role TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_by_user_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        user_id TEXT,
        username TEXT,
        organization_id TEXT,
        action TEXT NOT NULL,
        endpoint TEXT,
        ip_address TEXT,
        status TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs (organization_id)")


    # --- Backfilling/Ensuring Default Org & Admin User ---
    cursor.execute("INSERT OR IGNORE INTO organizations (id, name, slug, owner_user_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ('org_default', 'Aegis Default Org', 'default-org', 'admin', 'active', datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))

    cursor.execute("INSERT OR IGNORE INTO users (id, username, email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ('user_admin', 'admin', 'admin@aegissoar.io', hashlib.sha256('adminpassword'.encode()).hexdigest(), 'Lead SOC Administrator', 'owner', datetime.now(timezone.utc).isoformat()))

    cursor.execute("INSERT OR IGNORE INTO memberships (id, organization_id, user_id, role, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ('mem_admin', 'org_default', 'user_admin', 'owner', 'active', datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))

    # --- Alter Tables for Multi-tenancy ---
    try:
        cursor.execute("ALTER TABLE events ADD COLUMN organization_id TEXT DEFAULT 'org_default'")
    except: pass
    try:
        cursor.execute("ALTER TABLE incidents ADD COLUMN organization_id TEXT DEFAULT 'org_default'")
    except: pass
    try:
        cursor.execute("ALTER TABLE blocklist ADD COLUMN organization_id TEXT DEFAULT 'org_default'")
    except: pass
    try:
        cursor.execute("ALTER TABLE playbook_executions ADD COLUMN organization_id TEXT DEFAULT 'org_default'")
    except: pass

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_org ON events (organization_id)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        target_user TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        mitre_technique_name TEXT,
        rule_id TEXT,
        evidence_count INTEGER DEFAULT 1,
        threat_score INTEGER DEFAULT 0,
        threat_intel TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        notes TEXT,
        playbook_executions TEXT,
        organization_id TEXT DEFAULT 'org_default'
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents (source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents (organization_id)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocklist (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        rule_id TEXT,
        incident_id TEXT,
        blocked_at TEXT NOT NULL,
        expires_at TEXT,
        active INTEGER DEFAULT 1,
        organization_id TEXT DEFAULT 'org_default'
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_org ON blocklist (organization_id)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS playbook_executions (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        playbook_name TEXT NOT NULL,
        incident_id TEXT,
        status TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        actions_taken TEXT,
        organization_id TEXT DEFAULT 'org_default'
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_playbook_executions_org ON playbook_executions (organization_id)")


    conn.commit()
    conn.close()


def insert_event(event: SecurityEvent, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    org_id = organization_id or getattr(event, 'organization_id', None) or 'org_default'
    cursor.execute("""
    INSERT INTO events (
        id, timestamp, event_type, source_ip, destination_ip, service,
        username, status, status_code, message, raw_payload, metadata, organization_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.id,
        event.timestamp.isoformat(),
        event.event_type,
        event.source_ip,
        event.destination_ip,
        event.service,
        event.username,
        event.status,
        event.status_code,
        event.message,
        event.raw_payload,
        json.dumps(event.metadata),
        org_id
    ))
    conn.commit()
    conn.close()


def get_recent_events(limit: int = 100, event_type: Optional[str] = None, ip: Optional[str] = None, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM events"
    params = []
    clauses = []

    if organization_id:
        clauses.append("organization_id = ?")
        params.append(organization_id)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if ip:
        clauses.append("source_ip = ?")
        params.append(ip)

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d["metadata"]) if d.get("metadata") else {}
        results.append(d)
    conn.close()
    return results


def save_incident(incident: Incident, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    threat_intel_json = incident.threat_intel.model_dump_json() if incident.threat_intel else "{}"
    notes_json = json.dumps(incident.notes)
    executions_json = json.dumps(incident.playbook_executions)
    org_id = organization_id or getattr(incident, 'organization_id', None) or 'org_default'

    cursor.execute("""
    INSERT INTO incidents (
        id, title, description, severity, status, source_ip, target_user,
        mitre_tactic, mitre_technique, mitre_technique_name, rule_id,
        evidence_count, threat_score, threat_intel, created_at, updated_at,
        notes, playbook_executions, organization_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        evidence_count = excluded.evidence_count,
        updated_at = excluded.updated_at,
        severity = excluded.severity,
        threat_score = excluded.threat_score,
        threat_intel = excluded.threat_intel,
        notes = excluded.notes,
        playbook_executions = excluded.playbook_executions
    """, (
        incident.id,
        incident.title,
        incident.description,
        incident.severity,
        incident.status,
        incident.source_ip,
        incident.target_user,
        incident.mitre_tactic,
        incident.mitre_technique,
        incident.mitre_technique_name,
        incident.rule_id,
        incident.evidence_count,
        incident.threat_score,
        threat_intel_json,
        incident.created_at.isoformat(),
        incident.updated_at.isoformat(),
        notes_json,
        executions_json,
        org_id
    ))
    conn.commit()
    conn.close()


def get_incidents(status: Optional[str] = None, limit: int = 50, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM incidents"
    params = []
    clauses = []

    if organization_id:
        clauses.append("organization_id = ?")
        params.append(organization_id)
    if status:
        clauses.append("status = ?")
        params.append(status)

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["threat_intel"] = json.loads(d["threat_intel"]) if d.get("threat_intel") else {}
        d["notes"] = json.loads(d["notes"]) if d.get("notes") else []
        d["playbook_executions"] = json.loads(d["playbook_executions"]) if d.get("playbook_executions") else []
        results.append(d)
    conn.close()
    return results


def get_incident_by_id(incident_id: str, organization_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, organization_id))
    else:
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["threat_intel"] = json.loads(d["threat_intel"]) if d.get("threat_intel") else {}
    d["notes"] = json.loads(d["notes"]) if d.get("notes") else []
    d["playbook_executions"] = json.loads(d["playbook_executions"]) if d.get("playbook_executions") else []
    return d


def update_incident(incident_id: str, status: Optional[str] = None, severity: Optional[str] = None, note: Optional[str] = None, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT notes FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, organization_id))
    else:
        cursor.execute("SELECT notes FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    notes_list = json.loads(row["notes"]) if row["notes"] else []
    if note:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        notes_list.append(f"[{timestamp_str}] {note}")

    updates = ["updated_at = ?"]
    params = [datetime.now(timezone.utc).isoformat()]

    if status:
        updates.append("status = ?")
        params.append(status)
    if severity:
        updates.append("severity = ?")
        params.append(severity)
    if note:
        updates.append("notes = ?")
        params.append(json.dumps(notes_list))

    params.append(incident_id)
    query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
    if organization_id:
        query += " AND organization_id = ?"
        params.append(organization_id)
    cursor.execute(query, params)
    conn.commit()
    conn.close()
    return get_incident_by_id(incident_id, organization_id)


def add_to_blocklist(entry: BlocklistEntry, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    org_id = organization_id or getattr(entry, 'organization_id', None) or 'org_default'
    cursor.execute("""
    INSERT INTO blocklist (ip, reason, rule_id, incident_id, blocked_at, expires_at, active, organization_id)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    ON CONFLICT(ip) DO UPDATE SET
        reason = excluded.reason,
        rule_id = excluded.rule_id,
        incident_id = excluded.incident_id,
        blocked_at = excluded.blocked_at,
        expires_at = excluded.expires_at,
        active = 1,
        organization_id = excluded.organization_id
    """, (
        entry.ip,
        entry.reason,
        entry.rule_id,
        entry.incident_id,
        entry.blocked_at.isoformat(),
        entry.expires_at.isoformat() if entry.expires_at else None,
        org_id
    ))
    conn.commit()
    conn.close()


def get_blocklist(organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT * FROM blocklist WHERE active = 1 AND organization_id = ? ORDER BY blocked_at DESC", (organization_id,))
    else:
        cursor.execute("SELECT * FROM blocklist WHERE active = 1 ORDER BY blocked_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def remove_from_blocklist(ip: str, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("UPDATE blocklist SET active = 0 WHERE ip = ? AND organization_id = ?", (ip, organization_id))
    else:
        cursor.execute("UPDATE blocklist SET active = 0 WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


def record_playbook_execution(exec_data: PlaybookExecution, organization_id: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    org_id = organization_id or getattr(exec_data, 'organization_id', None) or 'org_default'
    cursor.execute("""
    INSERT INTO playbook_executions (id, playbook_id, playbook_name, incident_id, status, executed_at, actions_taken, organization_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        exec_data.id,
        exec_data.playbook_id,
        exec_data.playbook_name,
        exec_data.incident_id,
        exec_data.status,
        exec_data.executed_at.isoformat(),
        json.dumps(exec_data.actions_taken),
        org_id
    ))
    conn.commit()
    conn.close()


def get_playbook_executions(limit: int = 50, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT * FROM playbook_executions WHERE organization_id = ? ORDER BY executed_at DESC LIMIT ?", (organization_id, limit))
    else:
        cursor.execute("SELECT * FROM playbook_executions ORDER BY executed_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["actions_taken"] = json.loads(d["actions_taken"]) if d.get("actions_taken") else []
        results.append(d)
    conn.close()
    return results


def get_dashboard_metrics(organization_id: Optional[str] = None) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    org_filter = " AND organization_id = ?" if organization_id else ""
    org_params = (organization_id,) if organization_id else ()

    cursor.execute(
        f"""
        SELECT UPPER(severity), COUNT(*)
        FROM incidents
        WHERE UPPER(status) NOT IN ('RESOLVED', 'FALSE_POSITIVE'){org_filter}
        GROUP BY UPPER(severity)
        """,
        org_params
    )
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "OTHER": 0
    }
    for severity, count in cursor.fetchall():
        key = severity if severity in severity_counts and severity != "OTHER" else "OTHER"
        severity_counts[key] += count

    if organization_id:
        cursor.execute("SELECT COUNT(*) FROM events WHERE organization_id = ?", (organization_id,))
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE UPPER(status) NOT IN ('RESOLVED', 'FALSE_POSITIVE') AND organization_id = ?", (organization_id,))
        active_incidents = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM blocklist WHERE active = 1 AND organization_id = ?", (organization_id,))
        blocked_ips = cursor.fetchone()[0]

        critical_incidents = severity_counts["CRITICAL"]

        cursor.execute("""
        SELECT mitre_tactic, COUNT(*) as count
        FROM incidents
        WHERE organization_id = ?
        GROUP BY mitre_tactic
        ORDER BY count DESC
        LIMIT 6
        """, (organization_id,))
        mitre_tactics = [{"tactic": r[0], "count": r[1]} for r in cursor.fetchall() if r[0]]

        cursor.execute("""
        SELECT source_ip, COUNT(*) as event_count
        FROM events
        WHERE (status = 'FAILURE' OR event_type IN ('auth', 'http')) AND organization_id = ?
        GROUP BY source_ip
        ORDER BY event_count DESC
        LIMIT 5
        """, (organization_id,))
        top_attackers = [{"ip": r[0], "count": r[1]} for r in cursor.fetchall()]
    else:
        cursor.execute("SELECT COUNT(*) FROM events")
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM incidents WHERE UPPER(status) NOT IN ('RESOLVED', 'FALSE_POSITIVE')")
        active_incidents = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM blocklist WHERE active = 1")
        blocked_ips = cursor.fetchone()[0]

        critical_incidents = severity_counts["CRITICAL"]

        cursor.execute("""
        SELECT mitre_tactic, COUNT(*) as count
        FROM incidents
        GROUP BY mitre_tactic
        ORDER BY count DESC
        LIMIT 6
        """)
        mitre_tactics = [{"tactic": r[0], "count": r[1]} for r in cursor.fetchall() if r[0]]

        cursor.execute("""
        SELECT source_ip, COUNT(*) as event_count
        FROM events
        WHERE status = 'FAILURE' OR event_type IN ('auth', 'http')
        GROUP BY source_ip
        ORDER BY event_count DESC
        LIMIT 5
        """)
        top_attackers = [{"ip": r[0], "count": r[1]} for r in cursor.fetchall()]

    conn.close()

    return {
        "total_events": total_events,
        "active_incidents": active_incidents,
        "blocked_ips": blocked_ips,
        "critical_incidents": critical_incidents,
        "severity_counts": severity_counts,
        "mitre_tactics": mitre_tactics,
        "top_attackers": top_attackers
    }



# --- SaaS Database Operations ---

def create_user_db(user_id: str, username: str, email: str, password_hash: str, full_name: str, role: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO users (id, username, email, password_hash, full_name, role, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, email, password_hash, full_name, role, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


def update_user_password_hash_db(user_id: str, new_hash: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
    conn.commit()
    conn.close()



def get_user_by_username_db(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email_db(email: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_organization_db(org_id: str, name: str, slug: str, owner_user_id: str, status: str = "active"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO organizations (id, name, slug, owner_user_id, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (org_id, name, slug, owner_user_id, status, now_str, now_str))
    conn.commit()
    conn.close()


def get_organization_by_id_db(org_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_organization_by_slug_db(slug: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM organizations WHERE LOWER(slug) = LOWER(?)", (slug,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def create_membership_db(membership_id: str, organization_id: str, user_id: str, role: str, status: str = "active"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT OR REPLACE INTO memberships (id, organization_id, user_id, role, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (membership_id, organization_id, user_id, role, status, now_str, now_str))
    conn.commit()
    conn.close()


def get_user_memberships_db(user_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT m.*, o.name as org_name, o.slug as org_slug, o.status as org_status
    FROM memberships m
    JOIN organizations o ON m.organization_id = o.id
    WHERE m.user_id = ? AND m.status = 'active'
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_membership_db(organization_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM memberships WHERE organization_id = ? AND user_id = ? AND status = 'active'
    """, (organization_id, user_id))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def log_audit(action: str, user_id: Optional[str] = None, username: Optional[str] = None, organization_id: Optional[str] = None, endpoint: Optional[str] = None, ip_address: Optional[str] = None, status: str = "success"):
    conn = get_db_connection()
    cursor = conn.cursor()
    log_id = str(uuid.uuid4()) if 'uuid' in globals() or __import__('uuid') else str(__import__('uuid').uuid4())
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO audit_logs (id, timestamp, user_id, username, organization_id, action, endpoint, ip_address, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (log_id, now_str, user_id, username, organization_id, action, endpoint, ip_address, status))
    conn.commit()
    conn.close()


def get_audit_logs(organization_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    if organization_id:
        cursor.execute("SELECT * FROM audit_logs WHERE organization_id = ? ORDER BY timestamp DESC LIMIT ?", (organization_id, limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# Auto-initialize database tables on first import
init_db()
