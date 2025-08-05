# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import json
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.config import get_config
from .base_service import BaseService


"""
import socket
import string
import time
PlexiChat Real-time Collaboration Service

Comprehensive real-time collaboration system providing document collaboration,
screen sharing, whiteboards, live code editing with conflict resolution,
and real-time synchronization across multiple users and devices.

Features:
- Document collaboration with operational transforms
- Live code editing with conflict resolution
- Real-time whiteboard collaboration
- Screen sharing coordination
- Presence awareness and cursors
- Version control and history
- Collaborative annotations
- Multi-user synchronization
- Conflict resolution algorithms
- Real-time communication
"""

class CollaborationType(Enum):
    """Types of collaboration sessions."""
    DOCUMENT = "document"
    CODE = "code"
    WHITEBOARD = "whiteboard"
    SCREEN_SHARE = "screen_share"
    PRESENTATION = "presentation"

class OperationType(Enum):
    """Types of collaborative operations."""
    INSERT = "insert"
    DELETE = "delete"
    RETAIN = "retain"
    FORMAT = "format"
    CURSOR = "cursor"
    SELECTION = "selection"

class UserRole(Enum):
    """User roles in collaboration sessions."""
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"
    COMMENTER = "commenter"

@dataclass
class CollaborationUser:
    """User participating in collaboration."""
    user_id: str
    username: str
    role: UserRole
    cursor_position: Optional[int] = None
    selection_start: Optional[int] = None
    selection_end: Optional[int] = None
    color: str = "#007bff"
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

@dataclass
class Operation:
    """Collaborative operation for operational transform."""
    op_id: str
    user_id: str
    operation_type: OperationType
    position: int
    content: str = ""
    length: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    parent_version: int = 0

@dataclass
class CollaborationSession:
    """Collaboration session data."""
    session_id: str
    title: str
    collaboration_type: CollaborationType
    owner_id: str
    created_at: datetime
    last_modified: datetime
    content: str = ""
    version: int = 0
    users: Dict[str, CollaborationUser] = field(default_factory=dict)
    operations: List[Operation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    max_users: int = 50

class OperationalTransform:
    """Operational Transform algorithm for conflict resolution."""

    @staticmethod
    def transform_operation(op1: Operation, op2: Operation) -> Tuple[Operation, Operation]:
        """Transform two concurrent operations."""
        if op1.operation_type == OperationType.INSERT and op2.operation_type == OperationType.INSERT:
            return OperationalTransform._transform_insert_insert(op1, op2)
        elif op1.operation_type == OperationType.INSERT and op2.operation_type == OperationType.DELETE:
            return OperationalTransform._transform_insert_delete(op1, op2)
        elif op1.operation_type == OperationType.DELETE and op2.operation_type == OperationType.INSERT:
            op2_prime, op1_prime = OperationalTransform._transform_insert_delete(op2, op1)
            return op1_prime, op2_prime
        elif op1.operation_type == OperationType.DELETE and op2.operation_type == OperationType.DELETE:
            return OperationalTransform._transform_delete_delete(op1, op2)
        else:
            # For other operations, return as-is for now
            return op1, op2

    @staticmethod
    def _transform_insert_insert(op1: Operation, op2: Operation) -> Tuple[Operation, Operation]:
        """Transform two concurrent insert operations."""
        if op1.position <= op2.position:
            # op1 comes before op2, adjust op2's position
            op2_prime = Operation()
                op_id=op2.op_id,
                user_id=op2.user_id,
                operation_type=op2.operation_type,
                position=op2.position + len(op1.content),
                content=op2.content,
                attributes=op2.attributes,
                timestamp=op2.timestamp,
                parent_version=op2.parent_version
            )
            return op1, op2_prime
        else:
            # op2 comes before op1, adjust op1's position
            op1_prime = Operation()
                op_id=op1.op_id,
                user_id=op1.user_id,
                operation_type=op1.operation_type,
                position=op1.position + len(op2.content),
                content=op1.content,
                attributes=op1.attributes,
                timestamp=op1.timestamp,
                parent_version=op1.parent_version
            )
            return op1_prime, op2

    @staticmethod
    def _transform_insert_delete(insert_op: Operation, delete_op: Operation) -> Tuple[Operation, Operation]:
        """Transform insert and delete operations."""
        if insert_op.position <= delete_op.position:
            # Insert comes before delete, adjust delete position
            delete_prime = Operation()
                op_id=delete_op.op_id,
                user_id=delete_op.user_id,
                operation_type=delete_op.operation_type,
                position=delete_op.position + len(insert_op.content),
                length=delete_op.length,
                attributes=delete_op.attributes,
                timestamp=delete_op.timestamp,
                parent_version=delete_op.parent_version
            )
            return insert_op, delete_prime
        elif insert_op.position >= delete_op.position + delete_op.length:
            # Insert comes after delete, adjust insert position
            insert_prime = Operation()
                op_id=insert_op.op_id,
                user_id=insert_op.user_id,
                operation_type=insert_op.operation_type,
                position=insert_op.position - delete_op.length,
                content=insert_op.content,
                attributes=insert_op.attributes,
                timestamp=insert_op.timestamp,
                parent_version=insert_op.parent_version
            )
            return insert_prime, delete_op
        else:
            # Insert is within delete range, adjust both
            insert_prime = Operation()
                op_id=insert_op.op_id,
                user_id=insert_op.user_id,
                operation_type=insert_op.operation_type,
                position=delete_op.position,
                content=insert_op.content,
                attributes=insert_op.attributes,
                timestamp=insert_op.timestamp,
                parent_version=insert_op.parent_version
            )
            return insert_prime, delete_op

    @staticmethod
    def _transform_delete_delete(op1: Operation, op2: Operation) -> Tuple[Operation, Operation]:
        """Transform two concurrent delete operations."""
        # Handle overlapping deletes
        if op1.position + op1.length <= op2.position:
            # op1 comes completely before op2
            op2_prime = Operation()
                op_id=op2.op_id,
                user_id=op2.user_id,
                operation_type=op2.operation_type,
                position=op2.position - op1.length,
                length=op2.length,
                attributes=op2.attributes,
                timestamp=op2.timestamp,
                parent_version=op2.parent_version
            )
            return op1, op2_prime
        elif op2.position + op2.length <= op1.position:
            # op2 comes completely before op1
            op1_prime = Operation()
                op_id=op1.op_id,
                user_id=op1.user_id,
                operation_type=op1.operation_type,
                position=op1.position - op2.length,
                length=op1.length,
                attributes=op1.attributes,
                timestamp=op1.timestamp,
                parent_version=op1.parent_version
            )
            return op1_prime, op2
        else:
            # Overlapping deletes - complex case
            # For simplicity, keep the earlier operation
            if op1.timestamp <= op2.timestamp:
                # Adjust op2 to account for op1
                new_position = max(op1.position, op2.position - op1.length)
                new_length = max(0, op2.length - max(0, op1.position + op1.length - op2.position))
                op2_prime = Operation()
                    op_id=op2.op_id,
                    user_id=op2.user_id,
                    operation_type=op2.operation_type,
                    position=new_position,
                    length=new_length,
                    attributes=op2.attributes,
                    timestamp=op2.timestamp,
                    parent_version=op2.parent_version
                )
                return op1, op2_prime
            else:
                # Adjust op1 to account for op2
                new_position = max(op2.position, op1.position - op2.length)
                new_length = max(0, op1.length - max(0, op2.position + op2.length - op1.position))
                op1_prime = Operation()
                    op_id=op1.op_id,
                    user_id=op1.user_id,
                    operation_type=op1.operation_type,
                    position=new_position,
                    length=new_length,
                    attributes=op1.attributes,
                    timestamp=op1.timestamp,
                    parent_version=op1.parent_version
                )
                return op1_prime, op2

class CollaborationService(BaseService):
    """Real-time collaboration service."""

    def __init__(self):
        super().__init__("collaboration")
        self.config = get_config()

        # Session management
        self.sessions: Dict[str, CollaborationSession] = {}
        self.user_sessions: Dict[str, Set[str]] = defaultdict(set)  # user_id -> session_ids

        # WebSocket connections
        self.session_connections: Dict[str, Set[Any]] = defaultdict(set)  # session_id -> websockets
        self.user_connections: Dict[str, Set[Any]] = defaultdict(set)  # user_id -> websockets

        # Operation queues for processing
        self.operation_queues: Dict[str, deque] = defaultdict(deque)  # session_id -> operations

        # Operational transform engine
        self.ot_engine = OperationalTransform()

        # Configuration
        self.max_sessions_per_user = self.config.get("collaboration.max_sessions_per_user", 10)
        self.session_timeout_hours = self.config.get("collaboration.session_timeout_hours", 24)
        self.operation_history_limit = self.config.get("collaboration.operation_history_limit", 1000)

        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.sync_task: Optional[asyncio.Task] = None

    async def _initialize(self):
        """Initialize the collaboration service."""
        self.logger.info("Initializing collaboration service")

        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.sync_task = asyncio.create_task(self._sync_loop())

        self.logger.info("Collaboration service initialized")

    async def _cleanup(self):
        """Cleanup the collaboration service."""
        self.logger.info("Cleaning up collaboration service")

        # Cancel background tasks
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.sync_task:
            self.sync_task.cancel()

        # Close all WebSocket connections
        for connections in self.session_connections.values():
            for websocket in connections:
                try:
                    await websocket.close()


        self.logger.info("Collaboration service cleaned up")

    async def _perform_health_check(self) -> Dict[str, Any]:
        """Perform collaboration service health check."""
        try:
            checks = {
                "sessions": len(self.sessions),
                "active_sessions": len([s for s in self.sessions.values() if s.is_active]),
                "total_connections": sum(len(conns) for conns in self.session_connections.values()),
                "operation_queues": len(self.operation_queues)
            }

            # Determine health status
            if checks["total_connections"] > 1000:
                status = ServiceHealth.DEGRADED
            elif any(len(queue) > 100 for queue in self.operation_queues.values()):
                status = ServiceHealth.DEGRADED
            else:
                status = ServiceHealth.HEALTHY

            return {}
                "status": status,
                "checks": checks
            }

        except Exception as e:
            return {}
                "status": ServiceHealth.UNHEALTHY,
                "error": str(e)
            }

    async def create_session(self, title: str, collaboration_type: CollaborationType,)
                           owner_id: str, initial_content: str = "") -> str:
        """Create a new collaboration session."""
        session_id = str(uuid.uuid4())

        # Check user session limit
        if len(self.user_sessions[owner_id]) >= self.max_sessions_per_user:
            raise ValueError(f"User has reached maximum session limit ({self.max_sessions_per_user})")

        # Create session
        session = CollaborationSession()
            session_id=session_id,
            title=title,
            collaboration_type=collaboration_type,
            owner_id=owner_id,
            created_at=datetime.now(timezone.utc),
            last_modified=datetime.now(timezone.utc),
            content=initial_content
        )

        # Add owner as user
        owner_user = CollaborationUser()
            user_id=owner_id,
            username=CacheKeyBuilder.user_key(owner_id),  # Would be fetched from user service
            role=UserRole.OWNER,
            color=self._generate_user_color(owner_id)
        )
        session.users[owner_id] = owner_user

        # Store session
        self.sessions[session_id] = session
        self.user_sessions[owner_id].add(session_id)

        self.logger.info(f"Created collaboration session {session_id} ({collaboration_type.value}) for user {owner_id}")
        return session_id

    async def join_session(self, session_id: str, user_id: str, role: UserRole = UserRole.EDITOR) -> bool:
        """Join a collaboration session."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        # Check if session is active
        if not session.is_active:
            return False

        # Check user limit
        if len(session.users) >= session.max_users:
            return False

        # Add user to session
        user = CollaborationUser()
            user_id=user_id,
            username=CacheKeyBuilder.user_key(user_id),  # Would be fetched from user service
            role=role,
            color=self._generate_user_color(user_id)
        )
        session.users[user_id] = user
        self.user_sessions[user_id].add(session_id)

        # Notify other users
        await self._broadcast_user_joined(session_id, user)

        self.logger.info(f"User {user_id} joined collaboration session {session_id}")
        return True

    async def leave_session(self, session_id: str, user_id: str) -> bool:
        """Leave a collaboration session."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        if user_id not in session.users:
            return False

        # Remove user from session
        user = session.users.pop(user_id)
        self.user_sessions[user_id].discard(session_id)

        # Close user's WebSocket connections for this session
        user_connections = self.user_connections.get(user_id, set())
        for websocket in user_connections:
            if websocket in self.session_connections[session_id]:
                self.session_connections[session_id].discard(websocket)
                try:
                    await websocket.close()


        # Notify other users
        await self._broadcast_user_left(session_id, user)

        # If owner left and there are other users, transfer ownership
        if user.role == UserRole.OWNER and session.users:
            new_owner_id = next(iter(session.users.keys()))
            session.users[new_owner_id].role = UserRole.OWNER
            session.owner_id = new_owner_id
            await self._broadcast_ownership_transferred(session_id, new_owner_id)

        # If no users left, mark session as inactive
        if not session.users:
            session.is_active = False

        self.logger.info(f"User {user_id} left collaboration session {session_id}")
        return True

    async def apply_operation(self, session_id: str, operation: Operation) -> bool:
        """Apply an operation to a collaboration session."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        # Check if user is in session
        if operation.user_id not in session.users:
            return False

        # Check permissions
        user = session.users[operation.user_id]
        if user.role == UserRole.VIEWER and operation.operation_type in [OperationType.INSERT, OperationType.DELETE]:
            return False

        # Add to operation queue for processing
        self.operation_queues[session_id].append(operation)

        # Process operations
        await self._process_operations(session_id)

        return True

    async def _process_operations(self, session_id: str):
        """Process queued operations for a session."""
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]
        queue = self.operation_queues[session_id]

        while queue:
            operation = queue.popleft()

            # Transform operation against concurrent operations
            transformed_op = await self._transform_operation(session, operation)

            # Apply operation to content
            session.content = self._apply_operation_to_content(session.content, transformed_op)
            session.version += 1
            session.last_modified = datetime.now(timezone.utc)

            # Add to operation history
            session.operations.append(transformed_op)

            # Limit operation history
            if len(session.operations) > self.operation_history_limit:
                session.operations = session.operations[-self.operation_history_limit:]

            # Broadcast operation to other users
            await self._broadcast_operation(session_id, transformed_op)

    async def _transform_operation(self, session: CollaborationSession, operation: Operation) -> Operation:
        """Transform operation against concurrent operations."""
        # For now, return operation as-is
        # In a full implementation, this would transform against all concurrent operations
        return operation

    def _apply_operation_to_content(self, content: str, operation: Operation) -> str:
        """Apply an operation to content string."""
        if operation.operation_type == OperationType.INSERT:
            return content[:operation.position] + operation.content + content[operation.position:]
        elif operation.operation_type == OperationType.DELETE:
            return content[:operation.position] + content[operation.position + operation.length:]
        else:
            return content

    def _generate_user_color(self, user_id: str) -> str:
        """Generate a consistent color for a user."""
        colors = [
            "#007bff", "#28a745", "#dc3545", "#ffc107", "#17a2b8",
            "#6f42c1", "#e83e8c", "#fd7e14", "#20c997", "#6c757d"
        ]
        hash_value = int(hashlib.md5(user_id.encode()).hexdigest(), 16)
        return colors[hash_value % len(colors)]

    async def _broadcast_user_joined(self, session_id: str, user: CollaborationUser):
        """Broadcast user joined event."""
        message = {
            "type": "user_joined",
            "session_id": session_id,
            "user": asdict(user),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self._broadcast_to_session(session_id, message)

    async def _broadcast_user_left(self, session_id: str, user: CollaborationUser):
        """Broadcast user left event."""
        message = {
            "type": "user_left",
            "session_id": session_id,
            "user": asdict(user),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self._broadcast_to_session(session_id, message)

    async def _broadcast_ownership_transferred(self, session_id: str, new_owner_id: str):
        """Broadcast ownership transfer event."""
        message = {
            "type": "ownership_transferred",
            "session_id": session_id,
            "new_owner_id": new_owner_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self._broadcast_to_session(session_id, message)

    async def _broadcast_operation(self, session_id: str, operation: Operation):
        """Broadcast operation to session users."""
        message = {
            "type": "operation",
            "session_id": session_id,
            "operation": asdict(operation),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        await self._broadcast_to_session(session_id, message, exclude_user=operation.user_id)

    async def _broadcast_to_session(self, session_id: str, message: Dict[str, Any], exclude_user: Optional[str] = None):
        """Broadcast message to all users in a session."""
        if session_id not in self.session_connections:
            return

        connections = self.session_connections[session_id].copy()
        disconnected = []

        for websocket in connections:
            try:
                # Check if we should exclude this user
                if exclude_user and hasattr(websocket, 'user_id') and websocket.user_id == exclude_user:
                    continue

                await websocket.send_text(json.dumps(message))
            except Exception as e:
                self.logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(websocket)

        # Clean up disconnected WebSockets
        for websocket in disconnected:
            self.session_connections[session_id].discard(websocket)

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while True:
            try:
                await self._cleanup_inactive_sessions()
                await asyncio.sleep(3600)  # Run every hour
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(3600)

    async def _sync_loop(self):
        """Background synchronization loop."""
        while True:
            try:
                await self._sync_sessions()
                await asyncio.sleep(60)  # Run every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in sync loop: {e}")
                await asyncio.sleep(60)

    async def _cleanup_inactive_sessions(self):
        """Clean up inactive sessions."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=self.session_timeout_hours)

        inactive_sessions = []
        for session_id, session in self.sessions.items():
            if session.last_modified < cutoff_time and not session.users:
                inactive_sessions.append(session_id)

        for session_id in inactive_sessions:
            del self.sessions[session_id]
            if session_id in self.operation_queues:
                del self.operation_queues[session_id]
            if session_id in self.session_connections:
                del self.session_connections[session_id]

        if inactive_sessions:
            self.logger.info(f"Cleaned up {len(inactive_sessions)} inactive sessions")

    async def _sync_sessions(self):
        """Synchronize sessions (placeholder for database sync)."""
        # This would sync sessions to database in a full implementation

    # Public API methods
    def get_session(self, session_id: str) -> Optional[CollaborationSession]:
        """Get a collaboration session."""
        return self.sessions.get(session_id)

    def get_user_sessions(self, user_id: str) -> List[CollaborationSession]:
        """Get all sessions for a user."""
        session_ids = self.user_sessions.get(user_id, set())
        return [self.sessions[sid] for sid in session_ids if sid in self.sessions]

    def get_session_stats(self) -> Dict[str, Any]:
        """Get collaboration statistics."""
        return {}
            "total_sessions": len(self.sessions),
            "active_sessions": len([s for s in self.sessions.values() if s.is_active]),
            "total_users": len(self.user_sessions),
            "total_connections": sum(len(conns) for conns in self.session_connections.values()),
            "sessions_by_type": {
                ctype.value: len([s for s in self.sessions.values() if s.collaboration_type == ctype])
                for ctype in CollaborationType
            }
        }

# Global collaboration service instance
_collaboration_service = None

async def get_collaboration_service() -> CollaborationService:
    """Get the global collaboration service instance."""
    global _collaboration_service
    if _collaboration_service is None:
        _collaboration_service = CollaborationService()
        await if _collaboration_service and hasattr(_collaboration_service, "start"): _collaboration_service.start()
    return _collaboration_service

# Export main components
__all__ = [
    "CollaborationService", "CollaborationType", "OperationType", "UserRole",
    "CollaborationUser", "Operation", "CollaborationSession", "OperationalTransform",
    "get_collaboration_service"
]
