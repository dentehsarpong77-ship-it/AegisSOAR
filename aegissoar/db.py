import json
import sqlite3
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
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT,
        service TEXT,
        username TEXT,
        status TEXT,
        status_code INTEGER,
        message TEXT,
        raw_payload TEXT,
        metadata TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp)")

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
        playbook_executions TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents (source_ip)")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocklist (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        rule_id TEXT,
        incident_id TEXT,
        blocked_at TEXT NOT NULL,
        expires_at TEXT,
        active INTEGER DEFAULT 1
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS playbook_executions (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        playbook_name TEXT NOT NULL,
        incident_id TEXT,
        status TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        actions_taken TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_event(event: SecurityEvent):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO events (
        id, timestamp, event_type, source_ip, destination_ip, service,
        username, status, status_code, message, raw_payload, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        json.dumps(event.metadata)
    ))
    conn.commit()
    conn.close()


def get_recent_events(limit: int = 100, event_type: Optional[str] = None, ip: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM events"
    params = []
    clauses = []

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


def save_incident(incident: Incident):
    conn = get_db_connection()
    cursor = conn.cursor()

    threat_intel_json = incident.threat_intel.model_dump_json() if incident.threat_intel else "{}"
    notes_json = json.dumps(incident.notes)
    executions_json = json.dumps(incident.playbook_executions)

    cursor.execute("""
    INSERT INTO incidents (
        id, title, description, severity, status, source_ip, target_user,
        mitre_tactic, mitre_technique, mitre_technique_name, rule_id,
        evidence_count, threat_score, threat_intel, created_at, updated_at,
        notes, playbook_executions
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        executions_json
    ))
    conn.commit()
    conn.close()


def get_incidents(status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM incidents"
    params = []

    if status:
        query += " WHERE status = ?"
        params.append(status)

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


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
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


def update_incident(incident_id: str, status: Optional[str] = None, severity: Optional[str] = None, note: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
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
    cursor.execute(query, params)
    conn.commit()
    conn.close()
    return get_incident_by_id(incident_id)


def add_to_blocklist(entry: BlocklistEntry):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO blocklist (ip, reason, rule_id, incident_id, blocked_at, expires_at, active)
    VALUES (?, ?, ?, ?, ?, ?, 1)
    ON CONFLICT(ip) DO UPDATE SET
        reason = excluded.reason,
        rule_id = excluded.rule_id,
        incident_id = excluded.incident_id,
        blocked_at = excluded.blocked_at,
        expires_at = excluded.expires_at,
        active = 1
    """, (
        entry.ip,
        entry.reason,
        entry.rule_id,
        entry.incident_id,
        entry.blocked_at.isoformat(),
        entry.expires_at.isoformat() if entry.expires_at else None
    ))
    conn.commit()
    conn.close()


def get_blocklist() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocklist WHERE active = 1 ORDER BY blocked_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def remove_from_blocklist(ip: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocklist SET active = 0 WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


def record_playbook_execution(exec_data: PlaybookExecution):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO playbook_executions (id, playbook_id, playbook_name, incident_id, status, executed_at, actions_taken)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        exec_data.id,
        exec_data.playbook_id,
        exec_data.playbook_name,
        exec_data.incident_id,
        exec_data.status,
        exec_data.executed_at.isoformat(),
        json.dumps(exec_data.actions_taken)
    ))
    conn.commit()
    conn.close()


def get_playbook_executions(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM playbook_executions ORDER BY executed_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["actions_taken"] = json.loads(d["actions_taken"]) if d.get("actions_taken") else []
        results.append(d)
    conn.close()
    return results


def get_dashboard_metrics() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE status != 'RESOLVED' AND status != 'FALSE_POSITIVE'")
    active_incidents = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM blocklist WHERE active = 1")
    blocked_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'CRITICAL'")
    critical_incidents = cursor.fetchone()[0]

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
        "mitre_tactics": mitre_tactics,
        "top_attackers": top_attackers
    }


# Auto-initialize database tables on first import
init_db()
