"""
PlexiChat API v1 - Admin Endpoints

Simple admin functionality with:
- System statistics
- User management
- Message moderation
- File management
- System health
"""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
import logging

from .auth import get_current_user, users_db, sessions_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["Admin"])

# Admin user IDs (in production, use proper role system)
ADMIN_USERS = set()

# Models
class SystemStats(BaseModel):
    total_users: int
    active_sessions: int
    total_messages: int
    total_files: int
    system_uptime: str
    timestamp: datetime

class UserAdmin(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: datetime
    is_active: bool
    last_login: Optional[datetime] = None

# Utility functions
async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Require admin privileges."""
    if current_user['id'] not in ADMIN_USERS and current_user['username'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

def make_user_admin(user_id: str):
    """Make a user an admin."""
    ADMIN_USERS.add(user_id)

# Endpoints
@router.get("/stats", response_model=SystemStats)
async def get_system_stats(admin_user: dict = Depends(require_admin)):
    """Get system statistics."""
    try:
        from .messages import messages_db
        from .files import files_db
        
        # Calculate stats
        active_messages = len([m for m in messages_db.values() if not m.get('deleted')])
        
        return SystemStats(
            total_users=len(users_db),
            active_sessions=len(sessions_db),
            total_messages=active_messages,
            total_files=len(files_db),
            system_uptime="N/A",  # Would calculate actual uptime in production
            timestamp=datetime.now()
        )
        
    except Exception as e:
        logger.error(f"Get system stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")

@router.get("/users")
async def list_all_users(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: Optional[str] = None,
    admin_user: dict = Depends(require_admin)
):
    """List all users with admin details."""
    try:
        all_users = list(users_db.values())
        
        # Apply search filter
        if search:
            search_lower = search.lower()
            all_users = [
                user for user in all_users
                if (search_lower in user['username'].lower() or
                    search_lower in user['email'].lower() or
                    search_lower in user.get('display_name', '').lower())
            ]
        
        # Sort by creation date (newest first)
        all_users.sort(key=lambda x: x['created_at'], reverse=True)
        
        # Apply pagination
        total = len(all_users)
        paginated_users = all_users[offset:offset + limit]
        
        # Format response
        users_list = []
        for user in paginated_users:
            # Find last login from sessions
            last_login = None
            for session in sessions_db.values():
                if session['user_id'] == user['id']:
                    session_time = datetime.fromtimestamp(session['created_at'])
                    if last_login is None or session_time > last_login:
                        last_login = session_time
            
            users_list.append(UserAdmin(
                id=user['id'],
                username=user['username'],
                email=user['email'],
                display_name=user['display_name'],
                created_at=user['created_at'],
                is_active=user['is_active'],
                last_login=last_login
            ))
        
        return {
            "users": users_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }
        
    except Exception as e:
        logger.error(f"List all users error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")

@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: str,
    admin_user: dict = Depends(require_admin)
):
    """Deactivate a user account."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        if user_id == admin_user['id']:
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        
        user = users_db[user_id]
        user['is_active'] = False
        user['deactivated_at'] = datetime.now()
        user['deactivated_by'] = admin_user['id']
        
        # Remove all sessions for this user
        sessions_to_remove = [
            sid for sid, session in sessions_db.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        logger.info(f"User deactivated: {user['username']} by admin {admin_user['username']}")
        
        return {
            "success": True,
            "message": f"User {user['username']} deactivated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Deactivate user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to deactivate user")

@router.post("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    admin_user: dict = Depends(require_admin)
):
    """Activate a user account."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        user = users_db[user_id]
        user['is_active'] = True
        user['reactivated_at'] = datetime.now()
        user['reactivated_by'] = admin_user['id']
        
        logger.info(f"User activated: {user['username']} by admin {admin_user['username']}")
        
        return {
            "success": True,
            "message": f"User {user['username']} activated successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Activate user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to activate user")

@router.delete("/users/{user_id}")
async def delete_user_admin(
    user_id: str,
    admin_user: dict = Depends(require_admin)
):
    """Delete a user account (admin only)."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        if user_id == admin_user['id']:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        user = users_db[user_id]
        username = user['username']
        
        # Remove user
        del users_db[user_id]
        
        # Remove all sessions
        sessions_to_remove = [
            sid for sid, session in sessions_db.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del sessions_db[session_id]
        
        # Mark user's messages as deleted
        from .messages import messages_db
        for message in messages_db.values():
            if message['sender_id'] == user_id or message['recipient_id'] == user_id:
                message['deleted'] = True
                message['deleted_by_admin'] = admin_user['id']
                message['admin_deleted_at'] = datetime.now()
        
        logger.info(f"User deleted by admin: {username} by {admin_user['username']}")
        
        return {
            "success": True,
            "message": f"User {username} deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete user admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user")

@router.get("/messages/recent")
async def get_recent_messages(
    limit: int = Query(50, ge=1, le=200),
    admin_user: dict = Depends(require_admin)
):
    """Get recent messages for moderation."""
    try:
        from .messages import messages_db
        
        # Get non-deleted messages
        active_messages = [
            m for m in messages_db.values()
            if not m.get('deleted') and not m.get('deleted_by_admin')
        ]
        
        # Sort by timestamp (newest first)
        active_messages.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Apply limit
        recent_messages = active_messages[:limit]
        
        # Format response with user info
        messages_list = []
        for message in recent_messages:
            sender = users_db.get(message['sender_id'], {})
            recipient = users_db.get(message['recipient_id'], {})
            
            messages_list.append({
                "id": message['id'],
                "content": message['original_content'][:200],  # Truncate for moderation view
                "sender": {
                    "id": message['sender_id'],
                    "username": sender.get('username', 'Unknown')
                },
                "recipient": {
                    "id": message['recipient_id'],
                    "username": recipient.get('username', 'Unknown')
                },
                "timestamp": message['timestamp'],
                "message_type": message['message_type'],
                "encrypted": message['encrypted']
            })
        
        return {
            "messages": messages_list,
            "count": len(messages_list),
            "total_active_messages": len(active_messages)
        }
        
    except Exception as e:
        logger.error(f"Get recent messages error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get recent messages")

@router.delete("/messages/{message_id}")
async def delete_message_admin(
    message_id: str,
    reason: str = Query(..., min_length=1),
    admin_user: dict = Depends(require_admin)
):
    """Delete a message (admin moderation)."""
    try:
        from .messages import messages_db
        
        if message_id not in messages_db:
            raise HTTPException(status_code=404, detail="Message not found")
        
        message = messages_db[message_id]
        message['deleted'] = True
        message['deleted_by_admin'] = admin_user['id']
        message['admin_deleted_at'] = datetime.now()
        message['deletion_reason'] = reason
        
        logger.info(f"Message deleted by admin: {message_id} by {admin_user['username']} - {reason}")
        
        return {
            "success": True,
            "message": "Message deleted successfully",
            "reason": reason
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete message admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete message")

@router.post("/make-admin/{user_id}")
async def make_admin(
    user_id: str,
    admin_user: dict = Depends(require_admin)
):
    """Make a user an admin."""
    try:
        if user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        make_user_admin(user_id)
        user = users_db[user_id]
        
        logger.info(f"User made admin: {user['username']} by {admin_user['username']}")
        
        return {
            "success": True,
            "message": f"User {user['username']} is now an admin"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Make admin error: {e}")
        raise HTTPException(status_code=500, detail="Failed to make user admin")

@router.get("/health")
async def admin_health_check(admin_user: dict = Depends(require_admin)):
    """Admin health check with detailed system info."""
    try:
        from .messages import messages_db
        from .files import files_db
        
        return {
            "status": "healthy",
            "timestamp": datetime.now(),
            "system": {
                "users": len(users_db),
                "active_sessions": len(sessions_db),
                "messages": len([m for m in messages_db.values() if not m.get('deleted')]),
                "files": len(files_db),
                "admins": len(ADMIN_USERS)
            },
            "admin_user": admin_user['username']
        }
        
    except Exception as e:
        logger.error(f"Admin health check error: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")
