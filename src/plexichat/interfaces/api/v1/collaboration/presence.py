# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


from ....core.auth.dependencies import ()
from ....core.logging import get_logger
from ....core.security.rate_limiting import rate_limiter


from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

    from plexichat.infrastructure.utils.auth import get_current_user,
import socket
import time

    from,
    import,
    plexichat.infrastructure.utils.auth,
)
"""
Presence and activity tracking endpoints.
Handles user presence, typing indicators, and activity status.
"""

logger = get_logger(__name__)

router = APIRouter(tags=["Presence & Activity"])


class PresenceStatus(str, Enum):
    """User presence status."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"
    OFFLINE = "offline"


class ActivityType(str, Enum):
    """User activity type."""
    TYPING = "typing"
    VIEWING = "viewing"
    EDITING = "editing"
    IDLE = "idle"


class PresenceUpdate(BaseModel):
    """Presence update model."""
    status: PresenceStatus
    custom_message: Optional[str] = Field(None, max_length=100)
    activity: Optional[Dict[str, Any]] = None


class TypingIndicator(BaseModel):
    """Typing indicator model."""
    channel_id: Optional[str] = None
    conversation_id: Optional[str] = None
    is_typing: bool


class UserPresence(BaseModel):
    """User presence information."""
    user_id: int
    username: str
    status: PresenceStatus
    custom_message: Optional[str] = None
    last_seen: datetime
    activity: Optional[Dict[str, Any]] = None
    is_mobile: bool = False


# In-memory presence store (in production, use Redis or similar)
presence_store: Dict[int, UserPresence] = {}
typing_indicators: Dict[str, Dict[int, datetime]] = {}
websocket_connections: Dict[int, List[WebSocket]] = {}


@router.post()
    "/status",
    summary="Update presence status",
    description="Update user's presence status and activity"
)
async def update_presence()
    presence_data: PresenceUpdate,
    current_user=Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
):
    """Update user presence status."""
    try:
        # Rate limiting
        if not await rate_limiter.check_rate_limit()
            f"presence:{current_user.id}",
            max_requests=30,
            window_seconds=60
        ):
            raise HTTPException()
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many presence updates"
            )

        # Update presence
        presence = UserPresence()
            user_id=current_user.id,
            username=current_user.username,
            status=presence_data.status,
            custom_message=presence_data.custom_message,
            last_seen=datetime.now(timezone.utc),
            activity=presence_data.activity,
            is_mobile=False  # Could be detected from user agent
        )

        presence_store[current_user.id] = presence

        # Broadcast presence update to connected clients
        await broadcast_presence_update(presence)

        logger.info(f"User {current_user.username} updated presence to {presence_data.status}")

        return {
            "success": True,
            "message": "Presence updated successfully",
            "presence": presence.dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Presence update error: {e}")
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update presence"
        )


@router.get()
    "/status",
    response_model=List[UserPresence],
    summary="Get user presence",
    description="Get presence information for users"
)
async def get_presence()
    user_ids: Optional[str] = None,
    current_user=Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
):
    """Get presence information for specified users or all users."""
    try:
        if user_ids:
            # Parse comma-separated user IDs
            requested_ids = [int(uid.strip()) for uid in user_ids.split(",")]
            presences = [
                presence for user_id, presence in presence_store.items()
                if user_id in requested_ids
            ]
        else:
            # Return all presences (limit to prevent abuse)
            presences = list(presence_store.values())[:100]

        return presences

    except Exception as e:
        logger.error(f"Get presence error: {e}")
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get presence information"
        )


@router.post()
    "/typing",
    summary="Update typing indicator",
    description="Update typing indicator for a channel or conversation"
)
async def update_typing_indicator()
    typing_data: TypingIndicator,
    current_user=Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
):
    """Update typing indicator."""
    try:
        # Rate limiting for typing indicators
        if not await rate_limiter.check_rate_limit()
            f"typing:{current_user.id}",
            max_requests=60,
            window_seconds=60
        ):
            raise HTTPException()
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many typing updates"
            )

        # Determine the context (channel or conversation)
        context = typing_data.channel_id or typing_data.conversation_id or "global"

        if typing_data.is_typing:
            # Add typing indicator
            if context not in typing_indicators:
                typing_indicators[context] = {}
            typing_indicators[context][current_user.id] = datetime.now(timezone.utc)
        else:
            # Remove typing indicator
            if context in typing_indicators:
                typing_indicators[context].pop(current_user.id, None)
                if not typing_indicators[context]:
                    del typing_indicators[context]

        # Broadcast typing indicator update
        await broadcast_typing_update(context, current_user.id, typing_data.is_typing)

        return {
            "success": True,
            "message": "Typing indicator updated"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Typing indicator error: {e}")
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update typing indicator"
        )


@router.get()
    "/typing/{context}",
    summary="Get typing indicators",
    description="Get current typing indicators for a context"
)
async def get_typing_indicators()
    context: str,
    current_user=Depends(from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user)
):
    """Get typing indicators for a specific context."""
    try:
        # Clean up old typing indicators (older than 10 seconds)
        cutoff_time = datetime.now(timezone.utc).timestamp() - 10

        if context in typing_indicators:
            active_typers = {
                user_id: timestamp for user_id, timestamp in typing_indicators[context].items()
                if timestamp.timestamp() > cutoff_time
            }
            typing_indicators[context] = active_typers

            if not active_typers:
                del typing_indicators[context]

        # Get current typing users
        typing_users = list(typing_indicators.get(context, {}).keys())

        return {
            "context": context,
            "typing_users": typing_users,
            "count": len(typing_users)
        }

    except Exception as e:
        logger.error(f"Get typing indicators error: {e}")
        raise HTTPException()
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get typing indicators"
        )


@router.websocket("/ws")
async def presence_websocket(websocket: WebSocket, token: str):
    """WebSocket endpoint for real-time presence updates."""
    try:
        await websocket.accept()

        # Authenticate user (simplified)
        # In production, verify the JWT token
        user_id = 1  # Placeholder

        # Add to connections
        if user_id not in websocket_connections:
            websocket_connections[user_id] = []
        websocket_connections[user_id].append(websocket)

        logger.info(f"User {user_id} connected to presence WebSocket")

        try:
            while True:
                # Keep connection alive and handle incoming messages
                data = await websocket.receive_text()
                message = json.loads(data)

                # Handle different message types
                if message.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
                elif message.get("type") == "presence_update":
                    # Handle presence updates via WebSocket
                    pass

        except WebSocketDisconnect:
            logger.info(f"User {user_id} disconnected from presence WebSocket")

        finally:
            # Clean up connection
            if user_id in websocket_connections:
                websocket_connections[user_id].remove(websocket)
                if not websocket_connections[user_id]:
                    del websocket_connections[user_id]

    except Exception as e:
        logger.error(f"Presence WebSocket error: {e}")


async def broadcast_presence_update(presence: UserPresence):
    """Broadcast presence update to all connected clients."""
    message = {
        "type": "presence_update",
        "data": presence.dict()
    }

    # Send to all connected WebSocket clients
    for user_id, connections in websocket_connections.items():
        for websocket in connections[:]:  # Copy list to avoid modification during iteration
            try:
                await websocket.send_text(json.dumps(message))
            except Exception:
                # Remove dead connections
                connections.remove(websocket)


async def broadcast_typing_update(context: str, user_id: int, is_typing: bool):
    """Broadcast typing indicator update to relevant clients."""
    message = {
        "type": "typing_update",
        "data": {
            "context": context,
            "user_id": user_id,
            "is_typing": is_typing,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    }

    # Send to all connected WebSocket clients
    for uid, connections in websocket_connections.items():
        for websocket in connections[:]:
            try:
                await websocket.send_text(json.dumps(message))
            except Exception:
                connections.remove(websocket)
