"""
Real-time messaging and collaboration endpoints for PlexiChat v1 API.
Provides WebSocket support, live updates, and real-time features.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Set
from uuid import uuid4
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from pydantic import BaseModel

from .auth import get_current_user

# Router setup
router = APIRouter(prefix="/realtime", tags=["Real-time"])

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, Set[str]] = {}  # user_id -> set of connection_ids
        self.room_connections: Dict[str, Set[str]] = {}  # room_id -> set of connection_ids
        
    async def connect(self, websocket: WebSocket, connection_id: str, user_id: str):
        await websocket.accept()
        self.active_connections[connection_id] = websocket
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(connection_id)
        
    def disconnect(self, connection_id: str, user_id: str):
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(connection_id)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
    
    async def send_personal_message(self, message: str, connection_id: str):
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            await websocket.send_text(message)
    
    async def send_to_user(self, message: str, user_id: str):
        if user_id in self.user_connections:
            for connection_id in self.user_connections[user_id]:
                await self.send_personal_message(message, connection_id)
    
    async def broadcast_to_room(self, message: str, room_id: str):
        if room_id in self.room_connections:
            for connection_id in self.room_connections[room_id]:
                await self.send_personal_message(message, connection_id)
    
    def join_room(self, connection_id: str, room_id: str):
        if room_id not in self.room_connections:
            self.room_connections[room_id] = set()
        self.room_connections[room_id].add(connection_id)
    
    def leave_room(self, connection_id: str, room_id: str):
        if room_id in self.room_connections:
            self.room_connections[room_id].discard(connection_id)
            if not self.room_connections[room_id]:
                del self.room_connections[room_id]

manager = ConnectionManager()

# Models
class MessageEvent(BaseModel):
    type: str
    data: Dict
    timestamp: float = None
    user_id: str = None
    room_id: str = None

class TypingEvent(BaseModel):
    user_id: str
    room_id: str
    is_typing: bool

class PresenceEvent(BaseModel):
    user_id: str
    status: str  # online, away, busy, offline
    last_seen: float = None

# WebSocket endpoint
@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    connection_id = str(uuid4())
    await manager.connect(websocket, connection_id, user_id)
    
    # Send welcome message
    welcome_msg = MessageEvent(
        type="welcome",
        data={"connection_id": connection_id, "user_id": user_id},
        timestamp=time.time()
    )
    await websocket.send_text(welcome_msg.json())
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                await handle_websocket_message(message, connection_id, user_id)
            except json.JSONDecodeError:
                error_msg = MessageEvent(
                    type="error",
                    data={"message": "Invalid JSON format"},
                    timestamp=time.time()
                )
                await websocket.send_text(error_msg.json())
    except WebSocketDisconnect:
        manager.disconnect(connection_id, user_id)
        # Notify others that user went offline
        offline_msg = PresenceEvent(
            user_id=user_id,
            status="offline",
            last_seen=time.time()
        )
        await broadcast_presence_update(offline_msg)

async def handle_websocket_message(message: Dict, connection_id: str, user_id: str):
    """Handle incoming WebSocket messages."""
    msg_type = message.get("type")
    
    if msg_type == "join_room":
        room_id = message.get("room_id")
        if room_id:
            manager.join_room(connection_id, room_id)
            response = MessageEvent(
                type="room_joined",
                data={"room_id": room_id},
                timestamp=time.time(),
                user_id=user_id
            )
            await manager.send_personal_message(response.json(), connection_id)
    
    elif msg_type == "leave_room":
        room_id = message.get("room_id")
        if room_id:
            manager.leave_room(connection_id, room_id)
            response = MessageEvent(
                type="room_left",
                data={"room_id": room_id},
                timestamp=time.time(),
                user_id=user_id
            )
            await manager.send_personal_message(response.json(), connection_id)
    
    elif msg_type == "typing":
        room_id = message.get("room_id")
        is_typing = message.get("is_typing", False)
        if room_id:
            typing_event = TypingEvent(
                user_id=user_id,
                room_id=room_id,
                is_typing=is_typing
            )
            # Broadcast to room (except sender)
            await broadcast_to_room_except_sender(typing_event.json(), room_id, connection_id)
    
    elif msg_type == "presence":
        status = message.get("status", "online")
        presence_event = PresenceEvent(
            user_id=user_id,
            status=status,
            last_seen=time.time()
        )
        await broadcast_presence_update(presence_event)

async def broadcast_to_room_except_sender(message: str, room_id: str, sender_connection_id: str):
    """Broadcast message to all room members except the sender."""
    if room_id in manager.room_connections:
        for connection_id in manager.room_connections[room_id]:
            if connection_id != sender_connection_id:
                await manager.send_personal_message(message, connection_id)

async def broadcast_presence_update(presence_event: PresenceEvent):
    """Broadcast presence update to all connected users."""
    message = MessageEvent(
        type="presence_update",
        data=presence_event.dict(),
        timestamp=time.time()
    )
    for connection_id in manager.active_connections:
        await manager.send_personal_message(message.json(), connection_id)

# REST endpoints for real-time features
@router.get("/connections")
async def get_active_connections(current_user: dict = Depends(get_current_user)):
    """Get information about active connections."""
    return {
        "total_connections": len(manager.active_connections),
        "active_users": len(manager.user_connections),
        "active_rooms": len(manager.room_connections),
        "user_connections": {
            user_id: len(connections) 
            for user_id, connections in manager.user_connections.items()
        }
    }

@router.post("/broadcast")
async def broadcast_message(
    message: MessageEvent,
    current_user: dict = Depends(get_current_user)
):
    """Broadcast a message to all connected clients."""
    message.user_id = current_user["user_id"]
    message.timestamp = time.time()
    
    for connection_id in manager.active_connections:
        await manager.send_personal_message(message.json(), connection_id)
    
    return {"status": "Message broadcasted", "connections": len(manager.active_connections)}

@router.post("/send/{user_id}")
async def send_direct_message(
    user_id: str,
    message: MessageEvent,
    current_user: dict = Depends(get_current_user)
):
    """Send a direct message to a specific user."""
    message.user_id = current_user["user_id"]
    message.timestamp = time.time()
    
    await manager.send_to_user(message.json(), user_id)
    
    return {"status": f"Message sent to user {user_id}"}

@router.get("/status")
async def realtime_status():
    """Get real-time system status."""
    return {}
        "status": "operational",
        "active_connections": len(manager.active_connections),
        "active_users": len(manager.user_connections),
        "active_rooms": len(manager.room_connections),
        "uptime": time.time(),
        "features": [
            "websocket_messaging",
            "real_time_updates",
            "typing_indicators",
            "presence_tracking",
            "room_management"
        ]
    }
