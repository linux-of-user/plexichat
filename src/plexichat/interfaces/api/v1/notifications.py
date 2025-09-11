"""
Notification API Router

Provides REST API endpoints for notification management including:
- Getting user notifications
- Marking notifications as read
- Managing notification preferences
- Sending notifications
- Notification analytics
"""

from datetime import datetime
import logging
from typing import Any

try:
    from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
    from pydantic import BaseModel, Field
except ImportError:
    APIRouter = None
    HTTPException = Exception
    Depends = None
    Query = None
    BackgroundTasks = None
    BaseModel = object
    Field = lambda **kwargs: None

from plexichat.core.notifications import notification_manager
from plexichat.interfaces.api.auth_utils import get_current_user

logger = logging.getLogger(__name__)

# Create router
if APIRouter:
    router = APIRouter(prefix="/notifications", tags=["notifications"])
else:
    router = None

# Pydantic models for request/response
class NotificationResponse(BaseModel):
    """Response model for notification data."""
    id: str
    type: str
    title: str
    message: str
    priority: str
    created_at: str
    read_at: str | None
    data: dict[str, Any]

class NotificationListResponse(BaseModel):
    """Response model for notification list."""
    notifications: list[NotificationResponse]
    total_count: int
    unread_count: int

class SendNotificationRequest(BaseModel):
    """Request model for sending notifications."""
    user_id: int = Field(..., description="Target user ID")
    notification_type: str = Field(..., description="Notification type", examples=["message", "mention", "system"])
    title: str = Field(..., description="Notification title")
    message: str = Field(..., description="Notification message")
    priority: str | None = Field("normal", description="Notification priority", examples=["low", "normal", "high", "urgent"])
    data: dict[str, Any] | None = Field(None, description="Additional notification data")
    expires_in_hours: int | None = Field(None, description="Expiration time in hours")

class MarkReadRequest(BaseModel):
    """Request model for marking notifications as read."""
    notification_ids: list[str] = Field(..., description="List of notification IDs to mark as read")

class NotificationPreferencesRequest(BaseModel):
    """Request model for updating notification preferences."""
    notifications_enabled: bool | None = Field(None, description="Enable/disable all notifications")
    message_notifications: bool | None = Field(None, description="Enable message notifications")
    mention_notifications: bool | None = Field(None, description="Enable mention notifications")
    friend_request_notifications: bool | None = Field(None, description="Enable friend request notifications")
    system_notifications: bool | None = Field(None, description="Enable system notifications")
    push_notifications: bool | None = Field(None, description="Enable push notifications")
    email_notifications: bool | None = Field(None, description="Enable email notifications")
    min_priority: str | None = Field(None, description="Minimum priority level", examples=["low", "normal", "high", "urgent"])
    quiet_hours: dict[str, Any] | None = Field(None, description="Quiet hours configuration")

class NotificationPreferencesResponse(BaseModel):
    """Response model for notification preferences."""
    notifications_enabled: bool
    message_notifications: bool
    mention_notifications: bool
    friend_request_notifications: bool
    system_notifications: bool
    push_notifications: bool
    email_notifications: bool
    min_priority: str
    quiet_hours: dict[str, Any]

class NotificationStatsResponse(BaseModel):
    """Response model for notification statistics."""
    total_sent: int
    total_read: int
    total_expired: int
    unread_count: int
    queue_size: int
    processing_active: bool

# API Endpoints
if router:

    @router.get("/me", response_model=NotificationListResponse)
    async def get_my_notifications(
        limit: int = Query(50, ge=1, le=100, description="Maximum number of notifications to return"),
        unread_only: bool = Query(False, description="Return only unread notifications"),
        current_user: dict[str, Any] = Depends(get_current_user)
    ):
        """Get current user's notifications."""
        try:
            user_id = current_user["id"]

            # Get notifications
            notifications = await notification_manager.get_user_notifications(
                user_id=user_id,
                limit=limit,
                unread_only=unread_only
            )

            # Get unread count
            unread_count = await notification_manager.get_unread_count(user_id)

            # Convert to response format
            notification_responses = []
            for notification in notifications:
                notification_responses.append(NotificationResponse(
                    id=notification["id"],
                    type=notification["type"],
                    title=notification["title"],
                    message=notification["message"],
                    priority=notification["priority"],
                    created_at=notification["created_at"],
                    read_at=notification["read_at"],
                    data=notification["data"]
                ))

            return NotificationListResponse(
                notifications=notification_responses,
                total_count=len(notification_responses),
                unread_count=unread_count
            )

        except Exception as e:
            logger.error(f"Error getting user notifications: {e}")
            raise HTTPException(status_code=500, detail="Failed to get notifications")

    @router.put("/read")
    async def mark_notifications_read(
        request: MarkReadRequest,
        current_user: dict[str, Any] = Depends(get_current_user)
    ):
        """Mark notifications as read."""
        try:
            user_id = current_user["id"]
            results = []

            for notification_id in request.notification_ids:
                success = await notification_manager.mark_as_read(notification_id, user_id)
                results.append({"notification_id": notification_id, "success": success})

            return {"results": results}

        except Exception as e:
            logger.error(f"Error marking notifications as read: {e}")
            raise HTTPException(status_code=500, detail="Failed to mark notifications as read")

    @router.post("/send")
    async def send_notification(
        request: SendNotificationRequest,
        background_tasks: BackgroundTasks,
        current_user: dict[str, Any] = Depends(get_current_user)
    ):
        """Send a notification to a user."""
        try:
            # Validate notification type
            valid_types = ["message", "mention", "friend_request", "system", "warning", "error", "info"]
            if request.notification_type not in valid_types:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid notification type. Valid types: {', '.join(valid_types)}"
                )

            # Validate priority
            valid_priorities = ["low", "normal", "high", "urgent"]
            priority = request.priority or "normal"
            if priority not in valid_priorities:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid priority. Valid priorities: {', '.join(valid_priorities)}"
                )

            # Send notification in background
            background_tasks.add_task(
                notification_manager.create_notification,
                user_id=request.user_id,
                notification_type=getattr(notification_manager.NotificationType, request.notification_type.upper()),
                title=request.title,
                message=request.message,
                priority=getattr(notification_manager.NotificationPriority, priority.upper()),
                data=request.data,
                expires_in_hours=request.expires_in_hours
            )

            return {"message": "Notification queued for sending", "user_id": request.user_id}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            raise HTTPException(status_code=500, detail="Failed to send notification")

    @router.get("/preferences", response_model=NotificationPreferencesResponse)
    async def get_notification_preferences(current_user: dict[str, Any] = Depends(get_current_user)):
        """Get current user's notification preferences."""
        try:
            user_id = current_user["id"]
            preferences = await notification_manager._get_user_preferences(user_id)

            return NotificationPreferencesResponse(**preferences)

        except Exception as e:
            logger.error(f"Error getting notification preferences: {e}")
            raise HTTPException(status_code=500, detail="Failed to get notification preferences")

    @router.put("/preferences", response_model=NotificationPreferencesResponse)
    async def update_notification_preferences(
        request: NotificationPreferencesRequest,
        current_user: dict[str, Any] = Depends(get_current_user)
    ):
        """Update current user's notification preferences."""
        try:
            user_id = current_user["id"]

            # Get current preferences
            current_prefs = await notification_manager._get_user_preferences(user_id)

            # Update with provided values
            updated_prefs = current_prefs.copy()
            for field, value in request.dict(exclude_unset=True).items():
                if value is not None:
                    updated_prefs[field] = value

            # Validate preferences
            if updated_prefs.get("min_priority") not in ["low", "normal", "high", "urgent"]:
                raise HTTPException(status_code=400, detail="Invalid minimum priority")

            # Save preferences (this would need database implementation)
            # For now, we'll just return the updated preferences
            logger.info(f"Updated notification preferences for user {user_id}")

            return NotificationPreferencesResponse(**updated_prefs)

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating notification preferences: {e}")
            raise HTTPException(status_code=500, detail="Failed to update notification preferences")

    @router.delete("/{notification_id}")
    async def delete_notification(
        notification_id: str,
        current_user: dict[str, Any] = Depends(get_current_user)
    ):
        """Delete a notification."""
        try:
            user_id = current_user["id"]

            # This would need database implementation
            # For now, we'll just mark as read (soft delete)
            success = await notification_manager.mark_as_read(notification_id, user_id)

            if success:
                return {"message": "Notification deleted", "notification_id": notification_id}
            else:
                raise HTTPException(status_code=404, detail="Notification not found")

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deleting notification: {e}")
            raise HTTPException(status_code=500, detail="Failed to delete notification")

    @router.get("/unread/count")
    async def get_unread_count(current_user: dict[str, Any] = Depends(get_current_user)):
        """Get count of unread notifications."""
        try:
            user_id = current_user["id"]
            count = await notification_manager.get_unread_count(user_id)

            return {"unread_count": count}

        except Exception as e:
            logger.error(f"Error getting unread count: {e}")
            raise HTTPException(status_code=500, detail="Failed to get unread count")

    @router.post("/mark-all-read")
    async def mark_all_notifications_read(current_user: dict[str, Any] = Depends(get_current_user)):
        """Mark all notifications as read."""
        try:
            user_id = current_user["id"]

            # Get all unread notifications
            unread_notifications = await notification_manager.get_user_notifications(
                user_id=user_id,
                limit=1000,  # Large limit to get all
                unread_only=True
            )

            # Mark each as read
            marked_count = 0
            for notification in unread_notifications:
                success = await notification_manager.mark_as_read(notification["id"], user_id)
                if success:
                    marked_count += 1

            return {"message": f"Marked {marked_count} notifications as read"}

        except Exception as e:
            logger.error(f"Error marking all notifications as read: {e}")
            raise HTTPException(status_code=500, detail="Failed to mark all notifications as read")

    @router.get("/stats", response_model=NotificationStatsResponse)
    async def get_notification_stats(current_user: dict[str, Any] = Depends(get_current_user)):
        """Get notification statistics for current user."""
        try:
            user_id = current_user["id"]

            # Get user-specific stats
            unread_count = await notification_manager.get_unread_count(user_id)

            # Get global stats
            global_stats = notification_manager.get_stats()

            return NotificationStatsResponse(
                total_sent=global_stats["notifications_sent"],
                total_read=global_stats["notifications_read"],
                total_expired=global_stats["notifications_expired"],
                unread_count=unread_count,
                queue_size=global_stats["queue_size"],
                processing_active=global_stats["processing"]
            )

        except Exception as e:
            logger.error(f"Error getting notification stats: {e}")
            raise HTTPException(status_code=500, detail="Failed to get notification stats")

    @router.post("/test")
    async def send_test_notification(current_user: dict[str, Any] = Depends(get_current_user)):
        """Send a test notification to current user."""
        try:
            user_id = current_user["id"]

            notification_id = await notification_manager.create_notification(
                user_id=user_id,
                notification_type=notification_manager.NotificationType.INFO,
                title="Test Notification",
                message="This is a test notification to verify your notification settings are working correctly.",
                priority=notification_manager.NotificationPriority.NORMAL,
                data={"test": True, "timestamp": str(datetime.now())}
            )

            return {"message": "Test notification sent", "notification_id": notification_id}

        except Exception as e:
            logger.error(f"Error sending test notification: {e}")
            raise HTTPException(status_code=500, detail="Failed to send test notification")

    @router.get("/types")
    async def get_notification_types():
        """Get list of available notification types."""
        return {
            "types": ["message", "mention", "friend_request", "system", "warning", "error", "info"],
            "priorities": ["low", "normal", "high", "urgent"]
        }
