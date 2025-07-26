"""
PlexiChat API v1 - User Management Endpoints

Simple user management with:
- User profiles
- User search
- User updates
- User preferences
"""

from typing import Dict, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, EmailStr
import logging

from .auth import get_current_user, users_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["Users"])

# Models
class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: datetime
    is_active: bool

class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None

class UserSearch(BaseModel):
    id: str
    username: str
    display_name: str
    is_online: bool = False

# Endpoints
@router.get("/me", response_model=UserProfile)
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    """Get current user's profile."""
    return UserProfile(
        id=current_user['id'],
        username=current_user['username'],
        email=current_user['email'],
        display_name=current_user['display_name'],
        created_at=current_user['created_at'],
        is_active=current_user['is_active']
    )

@router.put("/me")
async def update_my_profile(
    update_data: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update current user's profile."""
    try:
        user_id = current_user['id']
        user = users_db[user_id]
        
        if update_data.display_name is not None:
            user['display_name'] = update_data.display_name
        
        if update_data.email is not None:
            # Check if email is already taken
            for other_user in users_db.values():
                if other_user['id'] != user_id and other_user['email'] == update_data.email:
                    raise HTTPException(status_code=400, detail="Email already taken")
            user['email'] = update_data.email
        
        user['updated_at'] = datetime.now()
        
        logger.info(f"User profile updated: {current_user['username']}")
        
        return {
            "success": True,
            "message": "Profile updated successfully",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email'],
                "display_name": user['display_name']
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        raise HTTPException(status_code=500, detail="Profile update failed")

@router.get("/search")
async def search_users(
    query: str = Query(..., min_length=1),
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    """Search for users."""
    try:
        results = []
        query_lower = query.lower()
        
        for user in users_db.values():
            if user['id'] == current_user['id']:
                continue
                
            if (query_lower in user['username'].lower() or 
                query_lower in user['display_name'].lower() or
                query_lower in user['email'].lower()):
                
                results.append(UserSearch(
                    id=user['id'],
                    username=user['username'],
                    display_name=user['display_name'],
                    is_online=False  # Would check session status in real app
                ))
                
                if len(results) >= limit:
                    break
        
        return {
            "users": results,
            "count": len(results),
            "query": query
        }
        
    except Exception as e:
        logger.error(f"User search error: {e}")
        raise HTTPException(status_code=500, detail="Search failed")

@router.get("/{user_id}", response_model=UserProfile)
async def get_user_profile(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a user's public profile."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users_db[user_id]
        
        return UserProfile(
            id=user['id'],
            username=user['username'],
            email=user['email'],  # In real app, might hide email for privacy
            display_name=user['display_name'],
            created_at=user['created_at'],
            is_active=user['is_active']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get user profile error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user profile")

@router.get("/")
async def list_users(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """List all users (paginated)."""
    try:
        all_users = list(users_db.values())
        total = len(all_users)
        
        # Apply pagination
        paginated_users = all_users[offset:offset + limit]
        
        users_list = []
        for user in paginated_users:
            users_list.append({
                "id": user['id'],
                "username": user['username'],
                "display_name": user['display_name'],
                "created_at": user['created_at'],
                "is_active": user['is_active']
            })
        
        return {
            "users": users_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }
        
    except Exception as e:
        logger.error(f"List users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")

@router.delete("/me")
async def delete_my_account(current_user: dict = Depends(get_current_user)):
    """Delete current user's account."""
    try:
        user_id = current_user['id']
        
        # Remove user from database
        if user_id in users_db:
            del users_db[user_id]
        
        # Remove all sessions for this user
        from .auth import sessions_db
        sessions_to_remove = [
            sid for sid, session in sessions_db.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        logger.info(f"User account deleted: {current_user['username']}")
        
        return {
            "success": True,
            "message": "Account deleted successfully"
        }
        
    except Exception as e:
        logger.error(f"Delete account error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete account")

@router.get("/stats/summary")
async def get_user_stats(current_user: dict = Depends(get_current_user)):
    """Get user statistics summary."""
    return {
        "total_users": len(users_db),
        "active_users": sum(1 for u in users_db.values() if u.get('is_active', False)),
        "timestamp": datetime.now()
    }
