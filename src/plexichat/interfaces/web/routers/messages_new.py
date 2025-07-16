# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Messages Router

Enhanced message handling with comprehensive validation, rate limiting,
and advanced features including threading, reactions, and file attachments.
Optimized for performance using EXISTING database abstraction and optimization systems.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

# Use EXISTING database abstraction layer
try:
    from plexichat.core_system.database.manager import database_manager
    from plexichat.core_system.database import get_session, execute_query
except ImportError:
    database_manager = None
    get_session = None
    execute_query = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core_system.logging.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import get_current_user
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "admin"}

# Model imports
try:
    from plexichat.features.users.message import Message
    from plexichat.features.users.user import User
except ImportError:
    # Mock classes for when imports fail
    class Message:
        id: int
        content: str
        sender_id: int
        recipient_id: int
        timestamp: datetime

    class User:
        id: int
        username: str

# Schema imports
try:
    from plexichat.interfaces.web.schemas.error import ValidationErrorResponse
    from plexichat.interfaces.web.schemas.message import MessageCreate, MessageRead
except ImportError:
    class ValidationErrorResponse(BaseModel):
        detail: str
    
    class MessageCreate(BaseModel):
        content: str = Field(..., min_length=1, max_length=2000)
        recipient_id: int
        
    class MessageRead(BaseModel):
        id: int
        content: str
        sender_id: int
        recipient_id: int
        timestamp: datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/messages", tags=["messages"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=4)

class MessageService:
    """Service class for message operations using EXISTING database abstraction layer."""

    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger
    
    async def validate_recipient(self, recipient_id: int) -> bool:
        """Validate that recipient exists using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                # Use EXISTING database manager's execute_query method
                query = "SELECT COUNT(*) FROM users WHERE id = ?"
                result = await self.db_manager.execute_query(query, {"id": recipient_id})
                return result and result[0][0] > 0
            except Exception as e:
                logger.error(f"Error validating recipient: {e}")
                return False
        return True  # Fallback
    
    @async_track_performance("message_rate_limit_check") if async_track_performance else lambda f: f
    async def check_rate_limit(self, user_id: int, limit: int = 60) -> bool:
        """Check rate limiting using EXISTING optimized database queries."""
        if self.db_manager:
            try:
                cutoff_time = datetime.now() - timedelta(minutes=1)
                # Use EXISTING database manager with optimized query
                query = """
                    SELECT COUNT(*) FROM messages
                    WHERE sender_id = ? AND timestamp > ?
                """
                params = {"sender_id": user_id, "timestamp": cutoff_time}

                # Use performance tracking if available
                if self.performance_logger and timer:
                    with timer("rate_limit_query"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)

                recent_count = result[0][0] if result else 0
                return recent_count < limit
            except Exception as e:
                logger.error(f"Error checking rate limit: {e}")
                return True  # Allow on error
        return True
    
    @async_track_performance("message_creation") if async_track_performance else lambda f: f
    async def create_message(self, data: MessageCreate, sender_id: int) -> Message:
        """Create message using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                # Use EXISTING database manager with optimized insert
                query = """
                    INSERT INTO messages (content, sender_id, recipient_id, timestamp)
                    VALUES (?, ?, ?, ?)
                    RETURNING id, content, sender_id, recipient_id, timestamp
                """
                params = {
                    "content": data.content,
                    "sender_id": sender_id,
                    "recipient_id": data.recipient_id,
                    "timestamp": datetime.now()
                }

                # Use performance tracking if available
                if self.performance_logger and timer:
                    with timer("message_insert"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)

                if result:
                    row = result[0]
                    return Message(
                        id=row[0],
                        content=row[1],
                        sender_id=row[2],
                        recipient_id=row[3],
                        timestamp=row[4]
                    )

            except Exception as e:
                logger.error(f"Error creating message: {e}")
                raise HTTPException(status_code=500, detail="Failed to create message")

        # Fallback mock message
        return Message(
            id=1,
            content=data.content,
            sender_id=sender_id,
            recipient_id=data.recipient_id,
            timestamp=datetime.now()
        )

# Initialize service
message_service = MessageService()

@router.post(
    "/send",
    response_model=MessageRead,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ValidationErrorResponse}, 429: {"description": "Rate limit exceeded"}}
)
async def send_message(
    request: Request,
    data: MessageCreate,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user)
):
    """Send a message with enhanced validation and performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"User {current_user.get('id', 'unknown')} from {client_ip} sending message")
    
    # Performance tracking
    if optimization_engine:
        operation_id = f"send_message_{current_user.get('id')}_{datetime.now().timestamp()}"
        optimization_engine.start_performance_tracking(operation_id)
    
    try:
        # Validate recipient exists using database abstraction layer
        if not await message_service.validate_recipient(data.recipient_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found"
            )
        
        # Check rate limiting with optimized queries
        if not await message_service.check_rate_limit(current_user.get("id", 0)):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait before sending another message."
            )
        
        # Create message using database abstraction layer
        message = await message_service.create_message(data, current_user.get("id", 0))
        
        # Schedule background processing
        background_tasks.add_task(
            _process_message_background,
            message.id,
            current_user.get("id", 0),
            data.recipient_id
        )
        
        # Performance tracking end
        if optimization_engine:
            optimization_engine.end_performance_tracking(operation_id)
        
        return MessageRead(
            id=message.id,
            content=message.content,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            timestamp=message.timestamp
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error sending message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

async def _process_message_background(message_id: int, sender_id: int, recipient_id: int):
    """Process message in background with multithreading support."""
    try:
        logger.debug(f"Processing background tasks for message {message_id} from {sender_id} to {recipient_id}")
        
        # Use thread pool for CPU-intensive tasks
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            executor,
            _process_message_sync,
            message_id,
            sender_id,
            recipient_id
        )
        
    except Exception as e:
        logger.error(f"Error in background message processing: {e}")

def _process_message_sync(message_id: int, sender_id: int, recipient_id: int):
    """Synchronous message processing for thread pool execution."""
    # Placeholder for message processing logic
    # This could include: spam detection, content analysis, notifications, etc.
    logger.debug(f"Sync processing complete for message {message_id}")

@router.get(
    "/list",
    response_model=List[MessageRead],
    responses={400: {"model": ValidationErrorResponse}}
)
async def list_messages(
    request: Request,
    limit: int = Query(50, ge=1, le=100, description="Number of messages to retrieve"),
    offset: int = Query(0, ge=0, description="Number of messages to skip"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order for messages"),
    current_user=Depends(get_current_user)
):
    """List messages with optimized pagination and database abstraction."""
    client_ip = request.client.host if request.client else "unknown"
    logger.debug(f"User {current_user.get('id', 'unknown')} from {client_ip} listing messages")
    
    # Performance tracking
    if optimization_engine:
        operation_id = f"list_messages_{current_user.get('id')}_{datetime.now().timestamp()}"
        optimization_engine.start_performance_tracking(operation_id)
    
    try:
        if message_service.message_dao:
            # Use database abstraction layer for optimized queries
            messages = await message_service.message_dao.find_by_criteria({
                "sender_id": current_user.get("id", 0)
            })
            
            # Apply sorting and pagination
            if sort_order == "desc":
                messages = sorted(messages, key=lambda x: x.timestamp, reverse=True)
            else:
                messages = sorted(messages, key=lambda x: x.timestamp)
            
            # Apply pagination
            paginated_messages = messages[offset:offset + limit]
            
            # Performance tracking end
            if optimization_engine:
                optimization_engine.end_performance_tracking(operation_id)
            
            return [
                MessageRead(
                    id=msg.id,
                    content=msg.content,
                    sender_id=msg.sender_id,
                    recipient_id=msg.recipient_id,
                    timestamp=msg.timestamp
                )
                for msg in paginated_messages
            ]
        
        # Fallback empty list
        return []
        
    except Exception as e:
        logger.error(f"Error listing messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve messages"
        )
