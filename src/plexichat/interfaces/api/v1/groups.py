import time
from typing import Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

# Mock user dependency
def get_current_user():
    return {"user_id": "mock_user"}

router = APIRouter(prefix="/groups", tags=["Groups & Channels"])

# In-memory storage for demonstration
groups_db: Dict[str, Dict] = {}
group_members_db: Dict[str, List[str]] = {}

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_public: bool = True

class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

@router.post("/create")
async def create_group(group_data: GroupCreate, current_user: dict = Depends(get_current_user)):
    """Create a new group."""
    group_id = str(uuid4())
    group = {
        "id": group_id,
        "owner_id": current_user["user_id"],
        "created_at": time.time(),
        **group_data.dict()
    }
    groups_db[group_id] = group
    group_members_db[group_id] = [current_user["user_id"]]
    return {"status": "Group created", "group": group}

@router.get("/")
async def list_groups(current_user: dict = Depends(get_current_user)):
    """List available groups."""
    return [
        g for g in groups_db.values()
        if g["is_public"] or current_user["user_id"] in group_members_db.get(g["id"], [])
    ]

@router.get("/{group_id}")
async def get_group(group_id: str, current_user: dict = Depends(get_current_user)):
    """Get information about a specific group."""
    group = groups_db.get(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    is_member = current_user["user_id"] in group_members_db.get(group_id, [])
    if not group["is_public"] and not is_member:
        raise HTTPException(status_code=403, detail="Access denied")

    return group

@router.put("/{group_id}")
async def update_group(group_id: str, group_data: GroupUpdate, current_user: dict = Depends(get_current_user)):
    """Update a group's information."""
    group = groups_db.get(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Only the owner can update the group")
    
    update_data = group_data.dict(exclude_unset=True)
    group.update(update_data)
    return {"status": "Group updated", "group": group}

@router.delete("/{group_id}")
async def delete_group(group_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a group."""
    group = groups_db.get(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group["owner_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Only the owner can delete the group")

    del groups_db[group_id]
    if group_id in group_members_db:
        del group_members_db[group_id]

    return {"status": "Group deleted"}

@router.post("/{group_id}/join")
async def join_group(group_id: str, current_user: dict = Depends(get_current_user)):
    """Join a public group."""
    group = groups_db.get(group_id)
    if not group or not group["is_public"]:
        raise HTTPException(status_code=404, detail="Public group not found")
    
    if current_user["user_id"] not in group_members_db.get(group_id, []):
        group_members_db.setdefault(group_id, []).append(current_user["user_id"])
    
    return {"status": "Joined group"}

@router.post("/{group_id}/leave")
async def leave_group(group_id: str, current_user: dict = Depends(get_current_user)):
    """Leave a group."""
    if group_id in group_members_db and current_user["user_id"] in group_members_db[group_id]:
        group_members_db[group_id].remove(current_user["user_id"])
        return {"status": "Left group"}
    raise HTTPException(status_code=400, detail="Not a member of this group")

@router.get("/{group_id}/members")
async def get_group_members(group_id: str):
    """Get a list of group members."""
    if group_id not in groups_db:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"members": group_members_db.get(group_id, [])}

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
