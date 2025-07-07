"""
NetLink Collaboration API Endpoints

Real-time collaboration endpoints providing WebSocket and REST API
for document collaboration, live code editing, whiteboards, and screen sharing.

Features:
- WebSocket endpoints for real-time collaboration
- REST API for session management
- Document collaboration with operational transforms
- Live code editing with conflict resolution
- Whiteboard collaboration
- Screen sharing coordination
- Presence awareness and user cursors
- Session management and permissions
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from ...core.auth.dependencies import require_auth, require_admin_auth
from ...core.logging import get_logger
from ...services.collaboration_service import (
    get_collaboration_service, CollaborationType, OperationType, UserRole,
    Operation, CollaborationUser, CollaborationSession
)

# Initialize router and logger
router = APIRouter(prefix="/collaboration", tags=["Real-time Collaboration"])
logger = get_logger(__name__)

# Pydantic models for API
class CreateSessionRequest(BaseModel):
    title: str
    collaboration_type: CollaborationType
    initial_content: str = ""
    max_users: int = 50

class JoinSessionRequest(BaseModel):
    role: UserRole = UserRole.EDITOR

class OperationRequest(BaseModel):
    operation_type: OperationType
    position: int
    content: str = ""
    length: int = 0
    attributes: Dict[str, Any] = {}

class UpdateCursorRequest(BaseModel):
    position: int
    selection_start: Optional[int] = None
    selection_end: Optional[int] = None

class SessionResponse(BaseModel):
    session_id: str
    title: str
    collaboration_type: CollaborationType
    owner_id: str
    created_at: datetime
    last_modified: datetime
    content: str
    version: int
    users: List[Dict[str, Any]]
    is_active: bool
    max_users: int

# WebSocket connection manager for collaboration
class CollaborationConnectionManager:
    """Manages WebSocket connections for collaboration sessions."""
    
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}  # session_id -> websockets
        self.user_connections: Dict[str, Set[WebSocket]] = {}  # user_id -> websockets
        self.websocket_info: Dict[WebSocket, Dict[str, Any]] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str, user_id: str):
        """Connect a WebSocket to a collaboration session."""
        await websocket.accept()
        
        # Store connection info
        self.websocket_info[websocket] = {
            "session_id": session_id,
            "user_id": user_id,
            "connected_at": datetime.now(timezone.utc)
        }
        
        # Add to connection sets
        if session_id not in self.connections:
            self.connections[session_id] = set()
        self.connections[session_id].add(websocket)
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(websocket)
        
        # Store user_id on websocket for easy access
        websocket.user_id = user_id
        
        logger.info(f"WebSocket connected: user {user_id} to session {session_id}")
    
    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket."""
        if websocket not in self.websocket_info:
            return
        
        info = self.websocket_info[websocket]
        session_id = info["session_id"]
        user_id = info["user_id"]
        
        # Remove from connection sets
        if session_id in self.connections:
            self.connections[session_id].discard(websocket)
            if not self.connections[session_id]:
                del self.connections[session_id]
        
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        
        # Remove connection info
        del self.websocket_info[websocket]
        
        logger.info(f"WebSocket disconnected: user {user_id} from session {session_id}")
    
    async def broadcast_to_session(self, session_id: str, message: Dict[str, Any], 
                                 exclude_user: Optional[str] = None):
        """Broadcast message to all users in a session."""
        if session_id not in self.connections:
            return
        
        connections = self.connections[session_id].copy()
        disconnected = []
        
        for websocket in connections:
            try:
                # Check if we should exclude this user
                if exclude_user and hasattr(websocket, 'user_id') and websocket.user_id == exclude_user:
                    continue
                
                await websocket.send_text(json.dumps(message, default=str))
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected WebSockets
        for websocket in disconnected:
            await self.disconnect(websocket)
    
    async def send_to_user(self, user_id: str, message: Dict[str, Any]):
        """Send message to all connections of a specific user."""
        if user_id not in self.user_connections:
            return
        
        connections = self.user_connections[user_id].copy()
        disconnected = []
        
        for websocket in connections:
            try:
                await websocket.send_text(json.dumps(message, default=str))
            except Exception as e:
                logger.error(f"Error sending to user WebSocket: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected WebSockets
        for websocket in disconnected:
            await self.disconnect(websocket)

# Global connection manager
connection_manager = CollaborationConnectionManager()

# REST API Endpoints

@router.post("/sessions", response_model=SessionResponse)
async def create_collaboration_session(
    request: CreateSessionRequest,
    current_user: dict = Depends(require_auth)
):
    """Create a new collaboration session."""
    try:
        collaboration_service = await get_collaboration_service()
        
        session_id = await collaboration_service.create_session(
            title=request.title,
            collaboration_type=request.collaboration_type,
            owner_id=current_user["user_id"],
            initial_content=request.initial_content
        )
        
        session = collaboration_service.get_session(session_id)
        if not session:
            raise HTTPException(status_code=500, detail="Failed to create session")
        
        return SessionResponse(
            session_id=session.session_id,
            title=session.title,
            collaboration_type=session.collaboration_type,
            owner_id=session.owner_id,
            created_at=session.created_at,
            last_modified=session.last_modified,
            content=session.content,
            version=session.version,
            users=[{
                "user_id": user.user_id,
                "username": user.username,
                "role": user.role.value,
                "color": user.color,
                "is_active": user.is_active
            } for user in session.users.values()],
            is_active=session.is_active,
            max_users=session.max_users
        )
        
    except Exception as e:
        logger.error(f"Error creating collaboration session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/sessions", response_model=List[SessionResponse])
async def list_user_sessions(
    current_user: dict = Depends(require_auth)
):
    """List all collaboration sessions for the current user."""
    try:
        collaboration_service = await get_collaboration_service()
        sessions = collaboration_service.get_user_sessions(current_user["user_id"])
        
        return [
            SessionResponse(
                session_id=session.session_id,
                title=session.title,
                collaboration_type=session.collaboration_type,
                owner_id=session.owner_id,
                created_at=session.created_at,
                last_modified=session.last_modified,
                content=session.content,
                version=session.version,
                users=[{
                    "user_id": user.user_id,
                    "username": user.username,
                    "role": user.role.value,
                    "color": user.color,
                    "is_active": user.is_active
                } for user in session.users.values()],
                is_active=session.is_active,
                max_users=session.max_users
            )
            for session in sessions
        ]
        
    except Exception as e:
        logger.error(f"Error listing user sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/sessions/{session_id}", response_model=SessionResponse)
async def get_collaboration_session(
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get a specific collaboration session."""
    try:
        collaboration_service = await get_collaboration_service()
        session = collaboration_service.get_session(session_id)
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Check if user has access to this session
        if current_user["user_id"] not in session.users:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return SessionResponse(
            session_id=session.session_id,
            title=session.title,
            collaboration_type=session.collaboration_type,
            owner_id=session.owner_id,
            created_at=session.created_at,
            last_modified=session.last_modified,
            content=session.content,
            version=session.version,
            users=[{
                "user_id": user.user_id,
                "username": user.username,
                "role": user.role.value,
                "color": user.color,
                "is_active": user.is_active
            } for user in session.users.values()],
            is_active=session.is_active,
            max_users=session.max_users
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting collaboration session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sessions/{session_id}/join")
async def join_collaboration_session(
    session_id: str,
    request: JoinSessionRequest,
    current_user: dict = Depends(require_auth)
):
    """Join a collaboration session."""
    try:
        collaboration_service = await get_collaboration_service()
        
        success = await collaboration_service.join_session(
            session_id=session_id,
            user_id=current_user["user_id"],
            role=request.role
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to join session")
        
        return {"message": "Successfully joined session", "session_id": session_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error joining collaboration session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sessions/{session_id}/leave")
async def leave_collaboration_session(
    session_id: str,
    current_user: dict = Depends(require_auth)
):
    """Leave a collaboration session."""
    try:
        collaboration_service = await get_collaboration_service()
        
        success = await collaboration_service.leave_session(
            session_id=session_id,
            user_id=current_user["user_id"]
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Failed to leave session")
        
        return {"message": "Successfully left session", "session_id": session_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error leaving collaboration session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_collaboration_stats(
    current_user: dict = Depends(require_admin_auth)
):
    """Get collaboration statistics (admin only)."""
    try:
        collaboration_service = await get_collaboration_service()
        stats = collaboration_service.get_session_stats()
        
        return {
            "collaboration_stats": stats,
            "connection_stats": {
                "total_websocket_connections": sum(len(conns) for conns in connection_manager.connections.values()),
                "sessions_with_connections": len(connection_manager.connections),
                "users_with_connections": len(connection_manager.user_connections)
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting collaboration stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket Endpoint

@router.websocket("/ws/{session_id}")
async def collaboration_websocket(
    websocket: WebSocket,
    session_id: str,
    token: str = Query(..., description="Authentication token")
):
    """
    Real-time collaboration WebSocket endpoint.
    
    Message Types:
    - operation: Apply collaborative operation
    - cursor_update: Update user cursor position
    - selection_update: Update user selection
    - ping: Ping server for connection check
    
    Example operation message:
    {
        "type": "operation",
        "data": {
            "operation_type": "insert",
            "position": 10,
            "content": "Hello world!",
            "attributes": {}
        }
    }
    """
    try:
        # Authenticate user (simplified - would use proper JWT validation)
        user_id = f"user_{token}"  # This would be extracted from JWT token
        
        # Get collaboration service
        collaboration_service = await get_collaboration_service()
        
        # Check if session exists
        session = collaboration_service.get_session(session_id)
        if not session:
            await websocket.close(code=4004, reason="Session not found")
            return
        
        # Check if user is in session
        if user_id not in session.users:
            await websocket.close(code=4003, reason="Access denied")
            return
        
        # Connect WebSocket
        await connection_manager.connect(websocket, session_id, user_id)
        
        # Send initial session state
        await websocket.send_text(json.dumps({
            "type": "session_state",
            "data": {
                "session_id": session_id,
                "content": session.content,
                "version": session.version,
                "users": [{
                    "user_id": user.user_id,
                    "username": user.username,
                    "role": user.role.value,
                    "color": user.color,
                    "cursor_position": user.cursor_position,
                    "selection_start": user.selection_start,
                    "selection_end": user.selection_end,
                    "is_active": user.is_active
                } for user in session.users.values()]
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, default=str))
        
        # Handle WebSocket messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                
                await handle_collaboration_message(
                    websocket, session_id, user_id, message, collaboration_service
                )
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Invalid JSON format"
                }))
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": str(e)
                }))
    
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
    finally:
        await connection_manager.disconnect(websocket)

async def handle_collaboration_message(
    websocket: WebSocket, session_id: str, user_id: str, 
    message: Dict[str, Any], collaboration_service
):
    """Handle incoming collaboration WebSocket messages."""
    message_type = message.get("type")
    data = message.get("data", {})
    
    if message_type == "operation":
        # Handle collaborative operation
        operation = Operation(
            op_id=str(uuid.uuid4()),
            user_id=user_id,
            operation_type=OperationType(data["operation_type"]),
            position=data["position"],
            content=data.get("content", ""),
            length=data.get("length", 0),
            attributes=data.get("attributes", {}),
            parent_version=data.get("parent_version", 0)
        )
        
        success = await collaboration_service.apply_operation(session_id, operation)
        if not success:
            await websocket.send_text(json.dumps({
                "type": "operation_failed",
                "message": "Failed to apply operation"
            }))
    
    elif message_type == "cursor_update":
        # Handle cursor position update
        session = collaboration_service.get_session(session_id)
        if session and user_id in session.users:
            user = session.users[user_id]
            user.cursor_position = data.get("position")
            user.selection_start = data.get("selection_start")
            user.selection_end = data.get("selection_end")
            user.last_seen = datetime.now(timezone.utc)
            
            # Broadcast cursor update to other users
            await connection_manager.broadcast_to_session(session_id, {
                "type": "cursor_update",
                "data": {
                    "user_id": user_id,
                    "position": user.cursor_position,
                    "selection_start": user.selection_start,
                    "selection_end": user.selection_end,
                    "color": user.color
                }
            }, exclude_user=user_id)
    
    elif message_type == "ping":
        # Handle ping
        await websocket.send_text(json.dumps({
            "type": "pong",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))
    
    else:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": f"Unknown message type: {message_type}"
        }))

# Export router
__all__ = ["router"]
