"""Orgs routes (8 routes)."""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request

from db import get_db
from helpers import get_user_id
from models import (
    OrgCreateRequest, OrgInviteRequest, OrgRoleUpdateRequest,
    OrgCreateResponse, OrgListResponse, OrgDetailResponse,
    OrgInviteResponse, OrgMembersResponse, OrgRemoveResponse,
    OrgRoleChangeResponse, OrgSwitchResponse,
)

from rate_limit import limiter, make_tier_limit

router = APIRouter()

@router.post("/v1/orgs", response_model=OrgCreateResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def create_org(request: Request, req: OrgCreateRequest, user_id: str = Depends(get_user_id)):
    org_id = f"org_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    slug = req.slug
    with get_db() as db:
        if slug:
            existing_slug = db.execute(
                "SELECT org_id FROM organizations WHERE slug = ?", (slug,)
            ).fetchone()
            if existing_slug:
                raise HTTPException(409, "Slug already taken")
        db.execute(
            "INSERT INTO organizations (org_id, name, slug, owner_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (org_id, req.name, slug, user_id, now),
        )
        db.execute(
            "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (org_id, user_id, "owner", now),
        )
    return {"org_id": org_id, "name": req.name, "slug": slug, "owner_user_id": user_id, "created_at": now, "role": "owner"}


@router.get("/v1/orgs", response_model=OrgListResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def list_orgs(request: Request, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        rows = db.execute(
            """SELECT o.org_id, o.name, o.slug, o.owner_user_id, o.created_at, m.role
               FROM organizations o
               JOIN org_members m ON m.org_id = o.org_id
               WHERE m.user_id = ?""",
            (user_id,),
        ).fetchall()
    return {"orgs": [dict(r) for r in rows]}


@router.get("/v1/orgs/{org_id}", response_model=OrgDetailResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def get_org(request: Request, org_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute(
            "SELECT org_id, name, slug, owner_user_id, created_at FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
        members = db.execute(
            "SELECT user_id, role, joined_at FROM org_members WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return {
        **dict(org),
        "members": [dict(m) for m in members],
    }


@router.post("/v1/orgs/{org_id}/members", response_model=OrgInviteResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def invite_member(request: Request, org_id: str, req: OrgInviteRequest, user_id: str = Depends(get_user_id)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        org = db.execute("SELECT org_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Only owners and admins can invite members")
        # Validate target user exists
        target_user = db.execute(
            "SELECT user_id FROM users WHERE user_id = ?", (req.user_id,)
        ).fetchone()
        if not target_user:
            raise HTTPException(404, "User not found")
        existing = db.execute(
            "SELECT user_id FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, req.user_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, "Already a member")
        db.execute(
            "INSERT INTO org_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
            (org_id, req.user_id, req.role, now),
        )
    return {"org_id": org_id, "user_id": req.user_id, "role": req.role, "joined_at": now}


@router.get("/v1/orgs/{org_id}/members", response_model=OrgMembersResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def list_org_members(request: Request, org_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute("SELECT org_id FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
        members = db.execute(
            "SELECT user_id, role, joined_at FROM org_members WHERE org_id = ?",
            (org_id,),
        ).fetchall()
    return {"org_id": org_id, "members": [dict(m) for m in members]}


@router.delete("/v1/orgs/{org_id}/members/{target_user_id}", response_model=OrgRemoveResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def remove_member(request: Request, org_id: str, target_user_id: str, user_id: str = Depends(get_user_id)):
    with get_db() as db:
        org = db.execute(
            "SELECT owner_user_id FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] not in ("owner", "admin"):
            raise HTTPException(403, "Only owners and admins can remove members")
        if org["owner_user_id"] == target_user_id:
            raise HTTPException(400, "Cannot remove the org owner")
        db.execute(
            "DELETE FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, target_user_id),
        )
    return {"removed": True}


@router.patch("/v1/orgs/{org_id}/members/{target_user_id}", response_model=OrgRoleChangeResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def change_member_role(request: Request, 
    org_id: str,
    target_user_id: str,
    req: OrgRoleUpdateRequest,
    user_id: str = Depends(get_user_id),
):
    with get_db() as db:
        org = db.execute(
            "SELECT owner_user_id FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        caller = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not caller or caller["role"] != "owner":
            raise HTTPException(403, "Only the owner can change member roles")
        if org["owner_user_id"] == target_user_id and req.role != "owner":
            raise HTTPException(400, "Cannot demote the org owner away from owner role")
        db.execute(
            "UPDATE org_members SET role = ? WHERE org_id = ? AND user_id = ?",
            (req.role, org_id, target_user_id),
        )
    return {"org_id": org_id, "user_id": target_user_id, "role": req.role}


@router.post("/v1/orgs/{org_id}/switch", response_model=OrgSwitchResponse, tags=["Orgs"])
@limiter.limit(make_tier_limit("admin"))
def switch_org_context(request: Request, org_id: str, user_id: str = Depends(get_user_id)):
    """Switch the user's active org context."""
    with get_db() as db:
        org = db.execute(
            "SELECT org_id, name FROM organizations WHERE org_id = ?",
            (org_id,),
        ).fetchone()
        if not org:
            raise HTTPException(404, "Org not found")
        member = db.execute(
            "SELECT role FROM org_members WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        ).fetchone()
        if not member:
            raise HTTPException(403, "Not a member of this org")
    return {"active_org_id": org_id, "org_name": org["name"]}
