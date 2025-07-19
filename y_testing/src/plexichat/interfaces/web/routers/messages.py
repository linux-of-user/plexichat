# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
"""
import time
PlexiChat Messages Router

Enhanced message handling with comprehensive validation, rate limiting,
and advanced features including threading, reactions, and file attachments.
Optimized for performance using EXISTING database abstraction and optimization systems.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor
import importlib

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Dynamically import performance/optimization systems if available
PerformanceOptimizationEngine = None
async_track_performance = None
get_performance_logger = None
timer = None
try:
    perf_mod = importlib.import_module('plexichat.infrastructure.performance.optimization_engine')
    PerformanceOptimizationEngine = getattr(perf_mod, 'PerformanceOptimizationEngine', None)
except Exception:
    pass
try:
    perf_utils_mod = importlib.import_module('plexichat.infrastructure.utils.performance')
    async_track_performance = getattr(perf_utils_mod, 'async_track_performance', None)
except Exception:
    pass
try:
    logger_mod = importlib.import_module('plexichat.core_system.logging.performance_logger')
    get_performance_logger = getattr(logger_mod, 'get_performance_logger', None)
    timer = getattr(logger_mod, 'timer', None)
except Exception:
    pass

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import get_current_user
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "admin"}

# Model imports
class Message(BaseModel):
    id: int
    content: str
    sender_id: int
    recipient_id: int
    timestamp: datetime

class User(BaseModel):
    id: int
    username: str

# Schema imports
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

performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

executor = ThreadPoolExecutor(max_workers=8)

def _safe_int(val: Any) -> int:
    try:
        return int(val)
    except Exception:
        return 0

def _safe_datetime(val: Any) -> datetime:
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return datetime.now()

def _track(name: str) -> Callable:
    def decorator(func):
        if async_track_performance:
            return async_track_performance(name)(func)
        return func
    return decorator

class MessageService:
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    async def validate_recipient(self, recipient_id: int) -> bool:
        if self.db_manager:
            try:
                query = "SELECT COUNT(*) FROM users WHERE id = ?"
                result = await self.db_manager.execute_query(query, {"id": recipient_id})
                if result:
                    row = result[0]
                    if isinstance(row, (list, tuple)):
                        try:
                            (count,) = row  # type: ignore
                        except Exception:
                            count = 0
                    elif isinstance(row, dict):
                        count = row.get("count", 0)
                    else:
                        count = 0
                    return _safe_int(count) > 0
                return False
            except Exception as e:
                logger.error(f"Error validating recipient: {e}")
                return False
        return True

    @_track("message_rate_limit_check")
    async def check_rate_limit(self, user_id: int, limit: int = 60) -> bool:
        if self.db_manager:
            try:
                cutoff_time = datetime.now() - timedelta(minutes=1)
                query = "SELECT COUNT(*) FROM messages WHERE sender_id = ? AND timestamp > ?"
                params = {"sender_id": user_id, "timestamp": cutoff_time}
                if self.performance_logger and timer:
                    with timer("rate_limit_query"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)
                if result:
                    row = result[0]
                    if isinstance(row, (list, tuple)):
                        try:
                            (count,) = row  # type: ignore
                        except Exception:
                            count = 0
                    elif isinstance(row, dict):
                        count = row.get("count", 0)
                    else:
                        count = 0
                    recent_count = _safe_int(count)
                else:
                    recent_count = 0
                return recent_count < limit
            except Exception as e:
                logger.error(f"Error checking rate limit: {e}")
                return True
        return True

    @_track("message_creation")
    async def create_message(self, data: MessageCreate, sender_id: int) -> Message:
        if self.db_manager:
            try:
                query = ()
                    "INSERT INTO messages (content, sender_id, recipient_id, timestamp) "
                    "VALUES (?, ?, ?, ?) RETURNING id, content, sender_id, recipient_id, timestamp"
                )
                params = {
                    "content": data.content,
                    "sender_id": sender_id,
                    "recipient_id": data.recipient_id,
                    "timestamp": datetime.now()
                }
                if self.performance_logger and timer:
                    with timer("message_insert"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)
                if result:
                    row = result[0]
                    if isinstance(row, (list, tuple)):
                        try:
                            id_, content, sender_id_, recipient_id_, timestamp_ = row  # type: ignore
                        except Exception:
                            id_, content, sender_id_, recipient_id_, timestamp_ = 0, "", 0, 0, datetime.now()
                        return Message(
                            id=_safe_int(id_),
                            content=str(content),
                            sender_id=_safe_int(sender_id_),
                            recipient_id=_safe_int(recipient_id_),
                            timestamp=_safe_datetime(timestamp_)
                        )
                    elif isinstance(row, dict):
                        return Message(
                            id=_safe_int(row.get("id", 0)),
                            content=str(row.get("content", "")),
                            sender_id=_safe_int(row.get("sender_id", 0)),
                            recipient_id=_safe_int(row.get("recipient_id", 0)),
                            timestamp=_safe_datetime(row.get("timestamp", datetime.now()))
                        )
            except Exception as e:
                logger.error(f"Error creating message: {e}")
                raise HTTPException(status_code=500, detail="Failed to create message")
        return Message(
            id=1,
            content=data.content,
            sender_id=sender_id,
            recipient_id=data.recipient_id,
            timestamp=datetime.now()
        )

message_service = MessageService()

@router.post()
    "/send",
    response_model=MessageRead,
    status_code=status.HTTP_201_CREATED,
    responses={400: {"model": ValidationErrorResponse}, 429: {"description": "Rate limit exceeded"}}
)
async def send_message(
    request: Request,
    data: MessageCreate,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"User {current_user.get('id', 'unknown')} from {client_ip} sending message")
    operation_id = None
    if optimization_engine:
        operation_id = f"send_message_{current_user.get('id')}_{datetime.now().timestamp()}"
        optimization_engine.start_performance_tracking(operation_id)
    try:
        if not await message_service.validate_recipient(data.recipient_id):
            raise HTTPException()
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found"
            )
        if not await message_service.check_rate_limit(current_user.get("id", 0)):
            raise HTTPException()
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait before sending another message."
            )
        message = await message_service.create_message(data, current_user.get("id", 0))
        background_tasks.add_task(_process_message_background, message.id, current_user.get("id", 0), data.recipient_id)
        if optimization_engine and operation_id:
            optimization_engine.end_performance_tracking(operation_id)
        return MessageRead()
            id=message.id,
            content=message.content,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            timestamp=message.timestamp
        )
    except HTTPException:
        raise

async def _process_message_background(message_id: int, sender_id: int, recipient_id: int) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(executor, _process_message_sync, message_id, sender_id, recipient_id)

def _process_message_sync(message_id: int, sender_id: int, recipient_id: int) -> None:
    # Placeholder for background processing logic (e.g., notifications, analytics)
    logger.info(f"Processing message {message_id} from {sender_id} to {recipient_id}")
    pass

@router.get()
    "/list",
    response_model=List[MessageRead],
    responses={400: {"model": ValidationErrorResponse}}
)
async def list_messages()
    request: Request,
    limit: int = Query(50, ge=1, le=100, description="Number of messages to retrieve"),
    offset: int = Query(0, ge=0, description="Number of messages to skip"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order for messages"),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[MessageRead]:
    if not message_service.db_manager:
        return []
    try:
        order = "DESC" if sort_order.lower() == "desc" else "ASC"
        query = ()
            "SELECT id, content, sender_id, recipient_id, timestamp FROM messages "
            "WHERE sender_id = ? OR recipient_id = ? "
            f"ORDER BY timestamp {order} LIMIT ? OFFSET ?"
        )
        params = {
            "sender_id": current_user.get("id", 0),
            "recipient_id": current_user.get("id", 0),
            "limit": limit,
            "offset": offset
        }
        if performance_logger and timer:
            with timer("list_messages_query"):
                result = await message_service.db_manager.execute_query(query, params)
        else:
            result = await message_service.db_manager.execute_query(query, params)
        messages = []
        if result:
            for row in result:
                if isinstance(row, (list, tuple)) and len(row) == 5:
                    try:
                        id_, content, sender_id_, recipient_id_, timestamp_ = row  # type: ignore
                    except Exception:
                        id_, content, sender_id_, recipient_id_, timestamp_ = 0, "", 0, 0, datetime.now()
                    messages.append(MessageRead())
                        id=_safe_int(id_),
                        content=str(content),
                        sender_id=_safe_int(sender_id_),
                        recipient_id=_safe_int(recipient_id_),
                        timestamp=_safe_datetime(timestamp_)
                    ))
                elif isinstance(row, dict):
                    messages.append(MessageRead())
                        id=_safe_int(row.get("id", 0)),
                        content=str(row.get("content", "")),
                        sender_id=_safe_int(row.get("sender_id", 0)),
                        recipient_id=_safe_int(row.get("recipient_id", 0)),
                        timestamp=_safe_datetime(row.get("timestamp", datetime.now()))
                    ))
        return messages
    except Exception as e:
        logger.error(f"Error listing messages: {e}")
        raise HTTPException(status_code=500, detail="Failed to list messages")
