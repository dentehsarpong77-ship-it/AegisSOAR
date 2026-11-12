import uuid
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, HTTPException, Query, Header, Depends
from typing import Optional, List
from aegissoar.models import InvitationCreateModel
from aegissoar.db import (
    get_user_memberships_db,
    get_organization_by_id_db,
    get_db_connection,
    create_membership_db,
    get_user_by_email_db
)

router = APIRouter(prefix="/api/v1/orgs", tags=["organizations"])


@router.get("/my")
async def get_my_organizations(username: str = "admin"):
    # Return user's organization memberships
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT o.id, o.name, o.slug, o.owner_user_id, m.role, m.status as member_status
    FROM memberships m
    JOIN organizations o ON m.organization_id = o.id
    JOIN users u ON m.user_id = u.id
    WHERE LOWER(u.username) = LOWER(?)
    """, (username,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        # Fallback to default organization for demo users
        default_org = get_organization_by_id_db("org_default")
        return [{
            "id": default_org["id"] if default_org else "org_default",
            "name": default_org["name"] if default_org else "Aegis Default Org",
            "slug": default_org["slug"] if default_org else "default-org",
            "role": "owner" if username == "admin" else "analyst",
            "member_status": "active"
        }]

    return [dict(r) for r in rows]


@router.get("/members")
async def get_org_members(organization_id: str = "org_default"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT m.id as membership_id, m.role, m.status, u.username, u.email, u.full_name
    FROM memberships m
    JOIN users u ON m.user_id = u.id
    WHERE m.organization_id = ?
    """, (organization_id,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        # Return default demo members if query is empty
        return [
            {"membership_id": "mem_1", "role": "owner", "status": "active", "username": "admin", "email": "admin@aegissoar.io", "full_name": "Lead SOC Administrator"},
            {"membership_id": "mem_2", "role": "analyst", "status": "active", "username": "analyst", "email": "analyst@aegissoar.io", "full_name": "Tier 2 SOC Analyst"}
        ]

    return [dict(r) for r in rows]


@router.post("/invite")
async def invite_team_member(req: InvitationCreateModel, organization_id: str = "org_default"):
    invitation_id = str(uuid.uuid4())
    token_hash = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO invitations (id, organization_id, invited_email, role, token_hash, expires_at, status, created_by_user_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'pending', 'system', ?)
    """, (invitation_id, organization_id, req.email, req.role, token_hash, expires_at, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

    return {
        "message": f"Invitation created for {req.email}",
        "invitation_id": invitation_id,
        "role": req.role,
        "expires_at": expires_at
    }
