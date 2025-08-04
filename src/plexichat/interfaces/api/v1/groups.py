"""
Groups and channels management endpoints for PlexiChat v1 API.
Provides group creation, management, and collaboration features.
"""

import time
from typing import Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .auth import get_current_user

# Router setup
router = APIRouter(prefix="/groups", tags=["Groups & Channels"])

# In-memory storage (replace with database in production)
groups_db: Dict[str, Dict] = {}
group_members_db: Dict[str, List[str]] = {}  # group_id -> list of user_ids
group_messages_db: Dict[str, List[Dict]] = {}  # group_id -> list of messages

# Models
class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    type: str = "group"  # group, channel, private
    is_public: bool = True
    max_members: Optional[int] = 100

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None
    max_members: Optional[int] = None

class GroupMessage(BaseModel):
    content: str
    message_type: str = "text"  # text, image, file, system
    reply_to: Optional[str] = None

class MemberRole(BaseModel):
    user_id: str
    role: str = "member"  # owner, admin, moderator, member

class GroupInvite(BaseModel):
    user_ids: List[str]
    message: Optional[str] = None

# Group management endpoints
@router.post("/create")
async def create_group(
    group_data: GroupCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new group or channel."""
    group_id = str(uuid4())
    
    group = {
        "id": group_id,
        "name": group_data.name,
        "description": group_data.description,
        "type": group_data.type,
        "is_public": group_data.is_public,
        "max_members": group_data.max_members,
        "owner_id": current_user["user_id"],
        "created_at": time.time(),
        "updated_at": time.time(),
        "member_count": 1,
        "message_count": 0,
        "settings": {
            "allow_invites": True,
            "allow_file_sharing": True,
            "moderation_enabled": False,
            "read_only": False
        }
    }
    
    groups_db[group_id] = group
    group_members_db[group_id] = [current_user["user_id"]]
    group_messages_db[group_id] = []
    
    return {}}
        "status": "Group created successfully",
        "group": group
    }

@router.get("/")
async def list_groups(
    type: Optional[str] = Query(None, description="Filter by group type"),
    public_only: bool = Query(False, description="Show only public groups"),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """List available groups and channels."""
    groups = []
    
    for group_id, group in groups_db.items():
        # Apply filters
        if type and group["type"] != type:
            continue
        if public_only and not group["is_public"]:
            continue
        
        # Check if user is member or if group is public
        is_member = current_user["user_id"] in group_members_db.get(group_id, [])
        if not group["is_public"] and not is_member:
            continue
        
        group_info = group.copy()
        group_info["is_member"] = is_member
        groups.append(group_info)
    
    # Apply pagination
    total = len(groups)
    groups = groups[offset:offset + limit]
    
    return {}}
        "groups": groups,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@router.get("/stats")
async def get_groups_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get groups statistics."""
    total_groups = len(groups_db)
    public_groups = sum(1 for g in groups_db.values() if g["is_public"])
    private_groups = total_groups - public_groups

    total_members = sum(len(members) for members in group_members_db.values())
    avg_members = total_members / total_groups if total_groups > 0 else 0

    return {}}
        "total_groups": total_groups,
        "public_groups": public_groups,
        "private_groups": private_groups,
        "total_members": total_members,
        "average_members_per_group": round(avg_members, 2),
        "user_groups": len([
            g for g_id, members in group_members_db.items()
            if current_user["user_id"] in members
        ])
    }

@router.get("/{group_id}")
async def get_group(
    group_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed information about a specific group."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    group = groups_db[group_id]
    is_member = current_user["user_id"] in group_members_db.get(group_id, [])
    
    # Check access permissions
    if not group["is_public"] and not is_member:
        raise HTTPException(status_code=403, detail="Access denied")
    
    group_info = group.copy()
    group_info["is_member"] = is_member
    group_info["members"] = group_members_db.get(group_id, [])
    
    return group_info

@router.put("/{group_id}")
async def update_group(
    group_id: str,
    group_data: GroupUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update group information."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    group = groups_db[group_id]
    
    # Check if user is owner or admin
    if group["owner_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Only group owner can update group")
    
    # Update fields
    if group_data.name is not None:
        group["name"] = group_data.name
    if group_data.description is not None:
        group["description"] = group_data.description
    if group_data.is_public is not None:
        group["is_public"] = group_data.is_public
    if group_data.max_members is not None:
        group["max_members"] = group_data.max_members
    
    group["updated_at"] = time.time()
    
    return {}}
        "status": "Group updated successfully",
        "group": group
    }

@router.delete("/{group_id}")
async def delete_group(
    group_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a group."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    group = groups_db[group_id]
    
    # Check if user is owner
    if group["owner_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Only group owner can delete group")
    
    # Delete group and related data
    del groups_db[group_id]
    if group_id in group_members_db:
        del group_members_db[group_id]
    if group_id in group_messages_db:
        del group_messages_db[group_id]
    
    return {}}"status": "Group deleted successfully"}

# Member management endpoints
@router.post("/{group_id}/join")
async def join_group(
    group_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Join a public group."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    group = groups_db[group_id]
    
    # Check if group is public
    if not group["is_public"]:
        raise HTTPException(status_code=403, detail="Group is private")
    
    # Check if already a member
    if current_user["user_id"] in group_members_db.get(group_id, []):
        raise HTTPException(status_code=400, detail="Already a member")
    
    # Check member limit
    current_members = len(group_members_db.get(group_id, []))
    if group["max_members"] and current_members >= group["max_members"]:
        raise HTTPException(status_code=400, detail="Group is full")
    
    # Add user to group
    if group_id not in group_members_db:
        group_members_db[group_id] = []
    group_members_db[group_id].append(current_user["user_id"])
    
    # Update member count
    groups_db[group_id]["member_count"] = len(group_members_db[group_id])
    
    return {}}"status": "Successfully joined group"}

@router.post("/{group_id}/leave")
async def leave_group(
    group_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Leave a group."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if user is a member
    if current_user["user_id"] not in group_members_db.get(group_id, []):
        raise HTTPException(status_code=400, detail="Not a member of this group")
    
    # Remove user from group
    group_members_db[group_id].remove(current_user["user_id"])
    
    # Update member count
    groups_db[group_id]["member_count"] = len(group_members_db[group_id])
    
    return {}}"status": "Successfully left group"}

@router.post("/{group_id}/invite")
async def invite_users(
    group_id: str,
    invite_data: GroupInvite,
    current_user: dict = Depends(get_current_user)
):
    """Invite users to a group."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    group = groups_db[group_id]
    
    # Check if user is a member and can invite
    if current_user["user_id"] not in group_members_db.get(group_id, []):
        raise HTTPException(status_code=403, detail="Must be a member to invite others")
    
    if not group["settings"]["allow_invites"]:
        raise HTTPException(status_code=403, detail="Invites are disabled for this group")
    
    invited_users = []
    for user_id in invite_data.user_ids:
        # Check if user is already a member
        if user_id not in group_members_db.get(group_id, []):
            # Check member limit
            current_members = len(group_members_db.get(group_id, []))
            if group["max_members"] and current_members >= group["max_members"]:
                continue
            
            group_members_db[group_id].append(user_id)
            invited_users.append(user_id)
    
    # Update member count
    groups_db[group_id]["member_count"] = len(group_members_db[group_id])
    
    return {}}
        "status": "Invitations sent",
        "invited_users": invited_users,
        "total_invited": len(invited_users)
    }

@router.get("/{group_id}/members")
async def get_group_members(
    group_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get list of group members."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if user is a member or group is public
    group = groups_db[group_id]
    is_member = current_user["user_id"] in group_members_db.get(group_id, [])
    
    if not group["is_public"] and not is_member:
        raise HTTPException(status_code=403, detail="Access denied")
    
    members = group_members_db.get(group_id, [])
    
    return {}}
        "group_id": group_id,
        "members": members,
        "member_count": len(members)
    }

@router.get("/my/groups")
async def get_my_groups(
    current_user: dict = Depends(get_current_user)
):
    """Get groups that the current user is a member of."""
    user_groups = []
    
    for group_id, members in group_members_db.items():
        if current_user["user_id"] in members:
            group = groups_db.get(group_id)
            if group:
                group_info = group.copy()
                group_info["is_member"] = True
                group_info["is_owner"] = group["owner_id"] == current_user["user_id"]
                user_groups.append(group_info)
    
    return {}}
        "groups": user_groups,
        "total": len(user_groups)
    }


