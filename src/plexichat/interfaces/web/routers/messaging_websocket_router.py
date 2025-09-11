# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

from datetime import datetime
import json

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import JSONResponse

from plexichat.core.auth.fastapi_adapter import get_auth_adapter
from plexichat.features.users.user import User
from plexichat.websockets.messaging_websocket import messaging_websocket_manager

"""
Messaging WebSocket Router
FastAPI router for real-time messaging WebSocket endpoints.
"""

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


# Create router
router = APIRouter(prefix="/ws", tags=["WebSocket Messaging"])


async def get_websocket_user(websocket: WebSocket, token: str | None = None) -> User | None:
    """Get user from WebSocket connection token."""
    try:
        if not token:
            # Try to get token from query parameters
            token = websocket.query_params.get('token')

        if not token:
            await websocket.close(code=4001, reason="Authentication token required")
            return None

        # Validate token using unified auth adapter -> UnifiedAuthManager
        adapter = get_auth_adapter()
        # Use the underlying auth manager validate_token method which returns (valid, payload)
        try:
            valid, payload = await adapter.auth_manager.validate_token(token)
        except Exception as e:
            logger.error(f"Error during token validation: {e}")
            await websocket.close(code=4001, reason="Invalid authentication token")
            return None

        if not valid or not payload:
            await websocket.close(code=4001, reason="Invalid authentication token")
            return None

        # Build a lightweight user-like object from payload
        user_id = payload.get("user_id") or payload.get("sub") or payload.get("id")
        username = payload.get("username") or payload.get("name") or str(user_id)
        permissions = set(payload.get("permissions", [])) if payload.get("permissions") is not None else set()

        # Create a simple user-like object with required attributes.
        # We avoid depending on constructor signature of User and instead return a
        # duck-typed object that has the attributes used in this module.
        class _WSUser:
            def __init__(self, user_id, username, permissions):
                self.id = user_id
                self.user_id = user_id
                self.username = username
                self.permissions = permissions
                self.is_admin = "admin" in permissions

        ws_user = _WSUser(user_id, username, permissions)

        return ws_user

    except Exception as e:
        logger.error(f"WebSocket authentication error: {e}")
        try:
            await websocket.close(code=4000, reason="Authentication error")
        except Exception:
            # ignore close errors
            pass
        return None


@router.websocket("/messaging")
async def messaging_websocket(websocket: WebSocket):
    """
    Real-time messaging WebSocket endpoint.

    Authentication: Pass token as query parameter: /ws/messaging?token=your_jwt_token

    Message Types:
    - send_message: Send a new message
    - send_reply: Send a reply to a message
    - add_reaction: Add reaction to a message
    - remove_reaction: Remove reaction from a message
    - typing_start: Start typing indicator
    - typing_stop: Stop typing indicator
    - subscribe_channel: Subscribe to channel updates
    - subscribe_guild: Subscribe to guild updates
    - ping: Ping server for connection check

    Example message format:
    {
        "type": "send_message",
        "data": {
            "content": "Hello world! :smile:",
            "channel_id": 123,
            "guild_id": 456
        }
    }
    """
    user = await get_websocket_user(websocket)
    if not user:
        return

    try:
        # Connect user
        await messaging_websocket_manager.connect(websocket, user)

        # Handle messages
        while True:
            try:
                message = await websocket.receive_text()
                await messaging_websocket_manager.handle_message(websocket, message)

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error handling WebSocket message for user {getattr(user, 'id', 'unknown')}: {e}")
                # Send error to client but continue connection
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break  # Connection is broken

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error for user {getattr(user, 'id', 'unknown')}: {e}")
    finally:
        # Disconnect user
        try:
            await messaging_websocket_manager.disconnect(websocket)
        except Exception:
            # ignore disconnect errors
            pass


@router.websocket("/messaging/{channel_id}")
async def channel_messaging_websocket(websocket: WebSocket, channel_id: int):
    """
    Channel-specific messaging WebSocket endpoint.
    Automatically subscribes to the specified channel.

    Authentication: Pass token as query parameter: /ws/messaging/123?token=your_jwt_token
    """
    user = await get_websocket_user(websocket)
    if not user:
        return

    try:
        # Connect user
        await messaging_websocket_manager.connect(websocket, user)

        # Auto-subscribe to channel
        await messaging_websocket_manager.subscribe_to_channel(websocket, channel_id)

        # Handle messages
        while True:
            try:
                message = await websocket.receive_text()
                await messaging_websocket_manager.handle_message(websocket, message)

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error handling channel WebSocket message for user {getattr(user, 'id', 'unknown')}: {e}")
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Channel WebSocket connection error for user {getattr(user, 'id', 'unknown')}: {e}")
    finally:
        try:
            await messaging_websocket_manager.disconnect(websocket)
        except Exception:
            pass


@router.websocket("/messaging/guild/{guild_id}")
async def guild_messaging_websocket(websocket: WebSocket, guild_id: int):
    """
    Guild-specific messaging WebSocket endpoint.
    Automatically subscribes to the specified guild.

    Authentication: Pass token as query parameter: /ws/messaging/guild/123?token=your_jwt_token
    """
    user = await get_websocket_user(websocket)
    if not user:
        return

    try:
        # Connect user
        await messaging_websocket_manager.connect(websocket, user)

        # Auto-subscribe to guild
        await messaging_websocket_manager.subscribe_to_guild(websocket, guild_id)

        # Handle messages
        while True:
            try:
                message = await websocket.receive_text()
                await messaging_websocket_manager.handle_message(websocket, message)

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error handling guild WebSocket message for user {getattr(user, 'id', 'unknown')}: {e}")
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Guild WebSocket connection error for user {getattr(user, 'id', 'unknown')}: {e}")
    finally:
        try:
            await messaging_websocket_manager.disconnect(websocket)
        except Exception:
            pass


@router.get("/messaging/stats")
async def get_messaging_stats(current_user: User = Depends(get_auth_adapter().get_current_user)):
    """
    Get real-time messaging statistics.
    Requires admin access.
    """
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    try:
        stats = await messaging_websocket_manager.get_connection_stats()
        return JSONResponse(content={
            "success": True,
            "data": stats
        })

    except Exception as e:
        logger.error(f"Error getting messaging stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get messaging statistics"
        )


@router.post("/messaging/broadcast")
async def broadcast_admin_message(
    message: str,
    channel_id: int | None = None,
    guild_id: int | None = None,
    current_user: User = Depends(get_auth_adapter().get_current_user)
):
    """
    Broadcast an admin message to all connected users or specific channel/guild.
    Requires admin access.
    """
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    try:
        # Create admin message
        admin_message = {
            'type': 'admin_broadcast',
            'data': {
                'message': message,
                'sender': getattr(current_user, "username", str(getattr(current_user, "user_id", ""))),
                'timestamp': datetime.now().isoformat(),
                'channel_id': channel_id,
                'guild_id': guild_id
            }
        }

        # Determine target websockets
        target_websockets = set()

        if channel_id and channel_id in getattr(messaging_websocket_manager, "channel_subscriptions", {}):
            target_websockets.update(messaging_websocket_manager.channel_subscriptions[channel_id])
        elif guild_id and guild_id in getattr(messaging_websocket_manager, "guild_subscriptions", {}):
            target_websockets.update(messaging_websocket_manager.guild_subscriptions[guild_id])
        else:
            # Broadcast to all connected users
            for websockets in getattr(messaging_websocket_manager, "active_connections", {}).values():
                target_websockets.update(websockets)

        # Send to all target websockets
        sent_count = 0
        for websocket in target_websockets:
            try:
                await websocket.send_text(json.dumps(admin_message))
                sent_count += 1
            except Exception:
                # Skip failed connections
                continue

        return JSONResponse(content={
            "success": True,
            "message": f"Broadcast sent to {sent_count} connections",
            "data": {
                "sent_count": sent_count,
                "total_targets": len(target_websockets)
            }
        })

    except Exception as e:
        logger.error(f"Error broadcasting admin message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to broadcast message"
        )


# Health check endpoint for WebSocket service
@router.get("/messaging/health")
async def websocket_health_check():
    """Health check for WebSocket messaging service."""
    try:
        stats = await messaging_websocket_manager.get_connection_stats()

        return JSONResponse(content={
            "status": "healthy",
            "service": "WebSocket Messaging",
            "connections": stats.get('total_connections', 0),
            "active_users": stats.get('active_users', 0),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"WebSocket health check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "unhealthy",
                "service": "WebSocket Messaging",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )
