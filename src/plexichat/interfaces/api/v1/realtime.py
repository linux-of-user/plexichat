import time
from typing import Dict, Set
from uuid import uuid4
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

router = APIRouter(prefix="/realtime", tags=["Real-time"])

class ConnectionManager:
    """Manages WebSocket connections."""
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, Set[str]] = {}
        self.room_connections: Dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket, user_id: str) -> str:
        """Accepts a new connection."""
        await websocket.accept()
        connection_id = str(uuid4())
        self.active_connections[connection_id] = websocket
        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(connection_id)
        return connection_id

    def disconnect(self, connection_id: str, user_id: str):
        """Disconnects a client."""
        self.active_connections.pop(connection_id, None)
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(connection_id)

    async def send_to_user(self, message: str, user_id: str):
        """Sends a message to a specific user."""
        if user_id in self.user_connections:
            for conn_id in self.user_connections[user_id]:
                if conn_id in self.active_connections:
                    await self.active_connections[conn_id].send_text(message)

    async def broadcast(self, message: str):
        """Broadcasts a message to all clients."""
        for connection in self.active_connections.values():
            await connection.send_text(message)

manager = ConnectionManager()

class MessageEvent(BaseModel):
    """Model for a message event."""
    type: str
    data: dict
    timestamp: float = time.time()

@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    """Main WebSocket endpoint for real-time communication."""
    connection_id = await manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = MessageEvent(type="echo", data={"original_message": data})
            await manager.send_to_user(message.json(), user_id)
    except WebSocketDisconnect:
        manager.disconnect(connection_id, user_id)

@router.get("/status")
async def realtime_status():
    """Get real-time system status."""
    return {
        "status": "operational",
        "active_connections": len(manager.active_connections),
        "active_users": len(manager.user_connections),
    }
