import time
from typing import Dict, List, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

# Mock user dependency
def get_current_user():
    return {"user_id": "mock_user"}

router = APIRouter(prefix="/notifications", tags=["Notifications"])

# In-memory storage for demonstration
notifications_db: Dict[str, Dict] = {}

class NotificationCreate(BaseModel):
    title: str
    message: str
    recipient_id: str

@router.post("/send")
async def send_notification(
    notification: NotificationCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a notification to a specific user."""
    notification_id = str(uuid4())
    notification_data = {
        "id": notification_id,
        "sender_id": current_user["user_id"],
        "created_at": time.time(),
        "read": False,
        **notification.dict()
    }
    notifications_db[notification_id] = notification_data
    return {"status": "Notification sent", "notification_id": notification_id}

@router.get("/")
async def get_notifications(
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get notifications for the current user."""
    user_notifications = [
        n for n in notifications_db.values()
        if n["recipient_id"] == current_user["user_id"]
    ]
    user_notifications.sort(key=lambda x: x["created_at"], reverse=True)
    return {
        "notifications": user_notifications[offset : offset + limit],
        "total": len(user_notifications)
    }

@router.get("/unread/count")
async def get_unread_count(current_user: dict = Depends(get_current_user)):
    """Get the count of unread notifications."""
    count = sum(
        1 for n in notifications_db.values()
        if n["recipient_id"] == current_user["user_id"] and not n["read"]
    )
    return {"unread_count": count}

@router.post("/{notification_id}/mark-read")
async def mark_as_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a notification as read."""
    if notification_id in notifications_db and notifications_db[notification_id]["recipient_id"] == current_user["user_id"]:
        notifications_db[notification_id]["read"] = True
        return {"status": "marked as read"}
    return {"status": "not found or not authorized"}, 404

@router.post("/mark-all-read")
async def mark_all_as_read(current_user: dict = Depends(get_current_user)):
    """Mark all of the user's notifications as read."""
    count = 0
    for nid, notification in notifications_db.items():
        if notification["recipient_id"] == current_user["user_id"] and not notification["read"]:
            notification["read"] = True
            count += 1
    return {"status": f"{count} notifications marked as read"}
