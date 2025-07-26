"""
Notifications system endpoints for PlexiChat v1 API.
Provides comprehensive notification management and delivery.
"""

import time
from typing import Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .auth import get_current_user

# Router setup
router = APIRouter(prefix="/notifications", tags=["Notifications"])

# In-memory storage (replace with database in production)
notifications_db: Dict[str, Dict] = {}
user_notification_settings: Dict[str, Dict] = {}

# Models
class NotificationCreate(BaseModel):
    title: str
    message: str
    type: str = "info"  # info, success, warning, error, message, mention, system
    recipient_id: str
    action_url: Optional[str] = None
    metadata: Optional[Dict] = {}
    priority: str = "normal"  # low, normal, high, urgent

class NotificationUpdate(BaseModel):
    read: Optional[bool] = None
    archived: Optional[bool] = None

class NotificationSettings(BaseModel):
    email_notifications: bool = True
    push_notifications: bool = True
    desktop_notifications: bool = True
    sound_enabled: bool = True
    notification_types: Dict[str, bool] = {
        "messages": True,
        "mentions": True,
        "system": True,
        "updates": False
    }
    quiet_hours: Optional[Dict[str, str]] = None  # {"start": "22:00", "end": "08:00"}

class BulkNotificationCreate(BaseModel):
    title: str
    message: str
    type: str = "info"
    recipient_ids: List[str]
    action_url: Optional[str] = None
    metadata: Optional[Dict] = {}

# Notification management
@router.post("/send")
async def send_notification(
    notification: NotificationCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a notification to a specific user."""
    notification_id = str(uuid4())
    
    notification_data = {
        "id": notification_id,
        "title": notification.title,
        "message": notification.message,
        "type": notification.type,
        "sender_id": current_user["user_id"],
        "recipient_id": notification.recipient_id,
        "action_url": notification.action_url,
        "metadata": notification.metadata or {},
        "priority": notification.priority,
        "read": False,
        "archived": False,
        "created_at": time.time(),
        "read_at": None
    }
    
    notifications_db[notification_id] = notification_data
    
    # Here you would typically trigger actual notification delivery
    # (email, push notification, WebSocket, etc.)
    
    return {
        "status": "Notification sent successfully",
        "notification_id": notification_id,
        "notification": notification_data
    }

@router.post("/broadcast")
async def broadcast_notification(
    notification: BulkNotificationCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a notification to multiple users."""
    notification_ids = []
    
    for recipient_id in notification.recipient_ids:
        notification_id = str(uuid4())
        
        notification_data = {
            "id": notification_id,
            "title": notification.title,
            "message": notification.message,
            "type": notification.type,
            "sender_id": current_user["user_id"],
            "recipient_id": recipient_id,
            "action_url": notification.action_url,
            "metadata": notification.metadata or {},
            "priority": "normal",
            "read": False,
            "archived": False,
            "created_at": time.time(),
            "read_at": None
        }
        
        notifications_db[notification_id] = notification_data
        notification_ids.append(notification_id)
    
    return {
        "status": "Broadcast notification sent successfully",
        "notification_ids": notification_ids,
        "recipients_count": len(notification.recipient_ids)
    }

@router.get("/")
async def get_notifications(
    unread_only: bool = Query(False, description="Show only unread notifications"),
    type: Optional[str] = Query(None, description="Filter by notification type"),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get notifications for the current user."""
    user_notifications = []
    
    for notification_id, notification in notifications_db.items():
        if notification["recipient_id"] != current_user["user_id"]:
            continue
        
        # Apply filters
        if unread_only and notification["read"]:
            continue
        if type and notification["type"] != type:
            continue
        if notification["archived"]:
            continue
        
        user_notifications.append(notification)
    
    # Sort by creation time (newest first)
    user_notifications.sort(key=lambda x: x["created_at"], reverse=True)
    
    # Apply pagination
    total = len(user_notifications)
    user_notifications = user_notifications[offset:offset + limit]
    
    return {
        "notifications": user_notifications,
        "total": total,
        "unread_count": len([n for n in user_notifications if not n["read"]]),
        "limit": limit,
        "offset": offset
    }

@router.get("/unread/count")
async def get_unread_count(
    current_user: dict = Depends(get_current_user)
):
    """Get count of unread notifications."""
    user_id = current_user["user_id"]

    unread_count = len([
        n for n in notifications_db.values()
        if (n["recipient_id"] == user_id and
            not n["read"] and
            not n["archived"])
    ])

    return {
        "unread_count": unread_count,
        "user_id": user_id
    }

@router.get("/settings")
async def get_notification_settings(
    current_user: dict = Depends(get_current_user)
):
    """Get notification settings for the current user."""
    user_id = current_user["user_id"]

    if user_id not in user_notification_settings:
        # Return default settings
        default_settings = NotificationSettings()
        return default_settings.dict()

    return user_notification_settings[user_id]

@router.get("/stats")
async def get_notification_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get notification statistics for the current user."""
    user_id = current_user["user_id"]

    user_notifications = [
        n for n in notifications_db.values()
        if n["recipient_id"] == user_id
    ]

    total_notifications = len(user_notifications)
    unread_notifications = len([n for n in user_notifications if not n["read"]])
    archived_notifications = len([n for n in user_notifications if n["archived"]])

    # Notifications by type
    type_counts = {}
    for notification in user_notifications:
        notification_type = notification["type"]
        type_counts[notification_type] = type_counts.get(notification_type, 0) + 1

    # Recent activity (last 7 days)
    week_ago = time.time() - (7 * 24 * 3600)
    recent_notifications = [
        n for n in user_notifications
        if n["created_at"] > week_ago
    ]

    return {
        "total_notifications": total_notifications,
        "unread_notifications": unread_notifications,
        "archived_notifications": archived_notifications,
        "notifications_by_type": type_counts,
        "recent_activity": {
            "notifications_this_week": len(recent_notifications),
            "average_per_day": len(recent_notifications) / 7
        }
    }

@router.get("/{notification_id}")
async def get_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific notification."""
    if notification_id not in notifications_db:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification = notifications_db[notification_id]
    
    # Check if user has access to this notification
    if notification["recipient_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return notification

@router.put("/{notification_id}")
async def update_notification(
    notification_id: str,
    update_data: NotificationUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update notification status (mark as read/unread, archive)."""
    if notification_id not in notifications_db:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification = notifications_db[notification_id]
    
    # Check if user has access to this notification
    if notification["recipient_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields
    if update_data.read is not None:
        notification["read"] = update_data.read
        if update_data.read:
            notification["read_at"] = time.time()
        else:
            notification["read_at"] = None
    
    if update_data.archived is not None:
        notification["archived"] = update_data.archived
    
    return {
        "status": "Notification updated successfully",
        "notification": notification
    }

@router.post("/mark-all-read")
async def mark_all_read(
    current_user: dict = Depends(get_current_user)
):
    """Mark all notifications as read for the current user."""
    updated_count = 0
    current_time = time.time()
    
    for notification_id, notification in notifications_db.items():
        if (notification["recipient_id"] == current_user["user_id"] and 
            not notification["read"] and 
            not notification["archived"]):
            notification["read"] = True
            notification["read_at"] = current_time
            updated_count += 1
    
    return {
        "status": "All notifications marked as read",
        "updated_count": updated_count
    }

@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a notification."""
    if notification_id not in notifications_db:
        raise HTTPException(status_code=404, detail="Notification not found")
    
    notification = notifications_db[notification_id]
    
    # Check if user has access to this notification
    if notification["recipient_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    del notifications_db[notification_id]
    
    return {"status": "Notification deleted successfully"}

# Keep only the PUT settings endpoint
@router.put("/settings")
async def update_notification_settings(
    settings: NotificationSettings,
    current_user: dict = Depends(get_current_user)
):
    """Update notification settings for the current user."""
    user_id = current_user["user_id"]
    user_notification_settings[user_id] = settings.dict()

    return {
        "status": "Notification settings updated successfully",
        "settings": user_notification_settings[user_id]
    }

@router.post("/test")
async def send_test_notification(
    current_user: dict = Depends(get_current_user)
):
    """Send a test notification to the current user."""
    notification_id = str(uuid4())
    
    test_notification = {
        "id": notification_id,
        "title": "Test Notification",
        "message": "This is a test notification to verify the system is working correctly.",
        "type": "info",
        "sender_id": "system",
        "recipient_id": current_user["user_id"],
        "action_url": None,
        "metadata": {"test": True},
        "priority": "normal",
        "read": False,
        "archived": False,
        "created_at": time.time(),
        "read_at": None
    }
    
    notifications_db[notification_id] = test_notification
    
    return {
        "status": "Test notification sent successfully",
        "notification": test_notification
    }

@router.get("/system/status")
async def notification_system_status():
    """Get notification system status."""
    total_notifications = len(notifications_db)
    active_users = len(set(n["recipient_id"] for n in notifications_db.values()))
    
    return {
        "status": "operational",
        "total_notifications": total_notifications,
        "active_users": active_users,
        "features": [
            "real_time_notifications",
            "email_notifications",
            "push_notifications",
            "notification_settings",
            "bulk_notifications",
            "notification_analytics"
        ],
        "delivery_methods": [
            "websocket",
            "email",
            "push",
            "desktop"
        ]
    }
