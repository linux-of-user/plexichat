# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse

from plexichat.features.users.user import User
import socket
import time

try:
    from plexichat.infrastructure.utils.auth import get_current_user_from_token
except ImportError:
    def get_current_user_from_token(token: str):
        return {}}"id": 1, "username": f"user_{token[:8]}"} if token else None

try:
    from plexichat.websockets.messaging_websocket import messaging_websocket_manager
except ImportError:
    class MockWebSocketManager:
        def get_stats(self):
            return {}}"active_connections": 0, "total_messages": 0}

        async def broadcast_admin_message(self, message: str, channel_id=None, guild_id=None):
            print(f"Mock broadcast: {message} to channel {channel_id} in guild {guild_id}")

    messaging_websocket_manager = MockWebSocketManager()

"""
Messaging WebSocket Router
FastAPI router for real-time messaging WebSocket endpoints.
"""

logger = logging.getLogger(__name__)


# Create router
router = APIRouter(prefix="/ws", tags=["WebSocket Messaging"])


async def get_websocket_user(websocket: WebSocket, token: Optional[str] = None) -> Optional[User]:
    """Get user from WebSocket connection token."""
    try:
        if not token:
            # Try to get token from query parameters
            token = websocket.query_params.get('token')

        if not token:
            await websocket.close(code=4001, reason="Authentication token required")
            return None

        # Validate token and get user
        user = get_current_user_from_token(token)
        if not user:
            await websocket.close(code=4001, reason="Invalid authentication token")
            return None

        return user

    except Exception as e:
        logger.error(f"WebSocket authentication error: {e}")
        await websocket.close(code=4000, reason="Authentication error")
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
                logger.error(f"Error handling WebSocket message for user {user.id}: {e}")
                # Send error to client but continue connection
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break  # Connection is broken

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket connection error for user {user.id}: {e}")
    finally:
        # Disconnect user
        await messaging_websocket_manager.disconnect(websocket)


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
                logger.error(f"Error handling channel WebSocket message for user {user.id}: {e}")
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Channel WebSocket connection error for user {user.id}: {e}")
    finally:
        await messaging_websocket_manager.disconnect(websocket)


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
                logger.error(f"Error handling guild WebSocket message for user {user.id}: {e}")
                try:
                    await websocket.send_text('{"type": "error", "data": {"message": "Message processing error"}}')
                except Exception:
                    break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Guild WebSocket connection error for user {user.id}: {e}")
    finally:
        await messaging_websocket_manager.disconnect(websocket)


@router.get("/messaging/stats")
async def get_messaging_stats(current_user: User = Depends(get_current_user_from_token)):
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
    channel_id: Optional[int] = None,
    guild_id: Optional[int] = None,
    current_user: User = Depends(get_current_user_from_token)
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
                'sender': current_user.username,
                'timestamp': datetime.now().isoformat(),
                'channel_id': channel_id,
                'guild_id': guild_id
            }
        }

        # Determine target websockets
        target_websockets = set()

        if channel_id and channel_id in messaging_websocket_manager.channel_subscriptions:
            target_websockets.update(messaging_websocket_manager.channel_subscriptions[channel_id])
        elif guild_id and guild_id in messaging_websocket_manager.guild_subscriptions:
            target_websockets.update(messaging_websocket_manager.guild_subscriptions[guild_id])
        else:
            # Broadcast to all connected users
            for websockets in messaging_websocket_manager.active_connections.values():
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
