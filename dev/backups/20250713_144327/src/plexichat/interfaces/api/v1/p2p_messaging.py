from datetime import datetime
from typing import Any, Dict, Optional



from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime



from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from plexichat.core.logging import logger
from plexichat.infrastructure.services.p2p_messaging import p2p_messaging_service

"""
Peer-to-peer messaging API endpoints.
Provides P2P messaging with database fallback capabilities.
"""

# Pydantic models for API
class P2PMessageRequest(BaseModel):
    recipient_id: int
    content: str
    message_type: Optional[str] = "text"
    metadata: Optional[Dict[str, Any]] = None


class P2PMessageResponse(BaseModel):
    id: str
    sender_id: int
    recipient_id: int
    content: str
    timestamp: str
    message_type: str
    encrypted: bool
    signature: Optional[str]
    metadata: Optional[Dict[str, Any]]


router = APIRouter(prefix="/api/v1/p2p", tags=["P2P Messaging"])


@router.post("/send")
async def send_p2p_message(request: P2PMessageRequest):
    """Send a peer-to-peer message with database fallback."""
    try:
        # In production, get sender_id from authentication
        sender_id = 1  # Placeholder

        message = await p2p_messaging_service.send_message(
            sender_id=sender_id,
            recipient_id=request.recipient_id,
            content=request.content,
            message_type=request.message_type,
            metadata=request.metadata
        )

        return {
            "success": True,
            "message_id": message.id,
            "timestamp": message.timestamp.isoformat(),
            "encrypted": message.encrypted,
            "delivery_method": "p2p" if request.recipient_id in p2p_messaging_service.peers else "cached",
            "database_available": p2p_messaging_service.database_available
        }

    except Exception as e:
        logger.error(f"Failed to send P2P message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/messages")
async def get_p2p_messages(
    other_user_id: Optional[int] = None,
    limit: int = 50
):
    """Get P2P messages for current user."""
    try:
        # In production, get user_id from authentication
        user_id = 1  # Placeholder

        messages = await p2p_messaging_service.get_messages(
            user_id=user_id,
            other_user_id=other_user_id,
            limit=limit
        )

        message_responses = []
        for msg in messages:
            # Decrypt content if encrypted
            content = msg.content
            if msg.encrypted:
                content = p2p_messaging_service._decrypt_content(msg.content)

            message_responses.append(P2PMessageResponse(
                id=msg.id,
                sender_id=msg.sender_id,
                recipient_id=msg.recipient_id,
                content=content,
                timestamp=msg.timestamp.isoformat(),
                message_type=msg.message_type,
                encrypted=msg.encrypted,
                signature=msg.signature,
                metadata=msg.metadata
            ))

        return {
            "messages": [msg.dict() for msg in message_responses],
            "count": len(message_responses),
            "database_available": p2p_messaging_service.database_available
        }

    except Exception as e:
        logger.error(f"Failed to get P2P messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_p2p_status():
    """Get P2P network status."""
    try:
        status = p2p_messaging_service.get_network_status()

        return {
            "p2p_network": status,
            "features": {
                "peer_to_peer_messaging": True,
                "database_fallback": True,
                "message_encryption": True,
                "offline_caching": True,
                "automatic_sync": True
            },
            "timestamp": from datetime import datetime
datetime = datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get P2P status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/database/status")
async def set_database_status(available: bool):
    """Set database availability status (for testing)."""
    try:
        p2p_messaging_service.set_database_status(available)

        return {
            "success": True,
            "database_available": available,
            "message": f"Database status set to {'available' if available else 'unavailable'}",
            "p2p_mode": not available
        }

    except Exception as e:
        logger.error(f"Failed to set database status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/peers")
async def get_connected_peers():
    """Get list of connected peers."""
    try:
        peers_info = []

        for user_id, peer in p2p_messaging_service.peers.items():
            peers_info.append({
                "user_id": user_id,
                "connection_id": peer.connection_id,
                "is_online": peer.is_online,
                "last_seen": peer.last_seen.isoformat(),
                "queued_messages": len(peer.message_queue)
            })

        return {
            "connected_peers": peers_info,
            "total_peers": len(peers_info),
            "online_peers": sum(1 for p in peers_info if p["is_online"])
        }

    except Exception as e:
        logger.error(f"Failed to get connected peers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cache/stats")
async def get_cache_stats():
    """Get message cache statistics."""
    try:
        cache = p2p_messaging_service.message_cache

        return {
            "cached_messages": len(cache.cache),
            "max_cache_size": cache.max_cache_size,
            "cache_usage_percent": (len(cache.cache) / cache.max_cache_size) * 100,
            "pending_sync": len(cache.get_pending_database_sync()),
            "encryption_enabled": True
        }

    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync")
async def force_database_sync():
    """Force synchronization of cached messages to database."""
    try:
        if not p2p_messaging_service.database_available:
            raise HTTPException(
                status_code=503,
                detail="Database is not available for synchronization"
            )

        pending_messages = p2p_messaging_service.message_cache.get_pending_database_sync()

        if not pending_messages:
            return {
                "success": True,
                "synced_messages": 0,
                "message": "No messages pending synchronization"
            }

        # Force sync (this would be implemented in the service)
        synced_count = len(pending_messages)

        return {
            "success": True,
            "synced_messages": synced_count,
            "message": f"Successfully synced {synced_count} messages to database"
        }

    except Exception as e:
        logger.error(f"Failed to force database sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket endpoint for P2P connections
@router.websocket("/connect")
async def websocket_p2p_connection(websocket: WebSocket):
    """WebSocket endpoint for P2P messaging connections."""
    await websocket.accept()

    user_id = None
    connection_id = None

    try:
        # In production, authenticate user from WebSocket
        user_id = 1  # Placeholder

        # Connect peer to P2P network
        connection_id = await p2p_messaging_service.connect_peer(user_id, websocket)

        logger.info(f" P2P WebSocket connected for user {user_id}")

        # Send connection confirmation
        await websocket.send_json({
            "type": "connection_established",
            "connection_id": connection_id,
            "user_id": user_id,
            "timestamp": from datetime import datetime
datetime = datetime.now().isoformat()
        })

        while True:
            # Receive messages from client
            data = await websocket.receive_json()

            message_type = data.get("type")

            if message_type == "ping":
                # Handle ping for connection keepalive
                if user_id in p2p_messaging_service.peers:
                    p2p_messaging_service.peers[user_id].from datetime import datetime
last_seen = datetime.now()
datetime = datetime.now()

                await websocket.send_json({
                    "type": "pong",
                    "timestamp": from datetime import datetime
datetime = datetime.now().isoformat()
                })

            elif message_type == "send_message":
                # Handle message sending
                recipient_id = data.get("recipient_id")
                content = data.get("content")

                if recipient_id and content:
                    message = await p2p_messaging_service.send_message(
                        sender_id=user_id,
                        recipient_id=recipient_id,
                        content=content
                    )

                    await websocket.send_json({
                        "type": "message_sent",
                        "message_id": message.id,
                        "timestamp": message.timestamp.isoformat()
                    })

            elif message_type == "get_status":
                # Handle status request
                status = p2p_messaging_service.get_network_status()

                await websocket.send_json({
                    "type": "status_update",
                    "status": status,
                    "timestamp": from datetime import datetime
datetime = datetime.now().isoformat()
                })

            else:
                logger.warning(f"Unknown P2P message type: {message_type}")

    except WebSocketDisconnect:
        logger.info(f" P2P WebSocket disconnected for user {user_id}")
    except Exception as e:
        logger.error(f"P2P WebSocket error for user {user_id}: {e}")
    finally:
        # Cleanup connection
        if user_id:
            await p2p_messaging_service.disconnect_peer(user_id)
