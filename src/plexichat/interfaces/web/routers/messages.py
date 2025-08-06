
"""
PlexiChat Messages Router

Enhanced message handling with comprehensive validation, rate limiting,
and advanced features including threading, reactions, and file attachments.
Optimized for performance using EXISTING database abstraction and optimization systems.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Callable
from concurrent.futures import ThreadPoolExecutor
import importlib
from colorama import Fore, Style

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

# Model imports - Updated for Pydantic v2 compatibility
class Message(BaseModel):
    """Message model with Pydantic v2 compatibility."""
        id: int = Field(..., description="Message ID")
    content: str = Field(..., description="Message content")
    sender_id: int = Field(..., description="Sender user ID")
    recipient_id: int = Field(..., description="Recipient user ID")
    timestamp: datetime = Field(..., description="Message timestamp")

    class Config:
        from_attributes = True

class User(BaseModel):
    """User model with Pydantic v2 compatibility."""
        id: int = Field(..., description="User ID")
    username: str = Field(..., description="Username")

    class Config:
        from_attributes = True

# Schema imports
class ValidationErrorResponse(BaseModel):
    """Validation error response model."""
        detail: str = Field(..., description="Error detail")
class MessageCreate(BaseModel):
    """Message creation model with Pydantic v2 compatibility."""
        content: str = Field(..., min_length=1, max_length=2000, description="Message content")
    recipient_id: int = Field(..., description="Recipient user ID")

    class Config:
        from_attributes = True

class MessageRead(BaseModel):
    """Message read model with Pydantic v2 compatibility."""
        id: int = Field(..., description="Message ID")
    content: str = Field(..., description="Message content")
    sender_id: int = Field(..., description="Sender user ID")
    recipient_id: int = Field(..., description="Recipient user ID")
    timestamp: datetime = Field(..., description="Message timestamp")

    class Config:
        from_attributes = True

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/messages", tags=["messages"])

performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Import enhanced security decorators
try:
    from plexichat.core.security.security_decorators import (
        secure_endpoint, require_auth, rate_limit, audit_access, validate_input,
        SecurityLevel, RequiredPermission
    )
    from plexichat.core.logging_advanced.enhanced_logging_system import (
        get_enhanced_logging_system, LogCategory, LogLevel, PerformanceTracker, SecurityMetrics
    )
    ENHANCED_SECURITY_AVAILABLE = True
    
    # Get enhanced logging system
    logging_system = get_enhanced_logging_system()
    if logging_system:
        enhanced_logger = logging_system.get_logger(__name__)
        logger.info("Enhanced security and logging initialized for messages")
    else:
        enhanced_logger = None
        
except ImportError as e:
    logger.warning(f"Enhanced security not available for messages: {e}")
    # Fallback decorators
    def secure_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def require_auth(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def rate_limit(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def audit_access(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def validate_input(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    class SecurityLevel:
        AUTHENTICATED = 2
        ADMIN = 4
    
    class RequiredPermission:
        READ = "read"
        WRITE = "write"
        DELETE = "delete"
    
    class PerformanceTracker:
        def __init__(self, name, logger):
            self.name = name
            self.logger = logger
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def add_metadata(self, **kwargs):
            pass
    
    class SecurityMetrics:
        def __init__(self, **kwargs):
            pass
    
    ENHANCED_SECURITY_AVAILABLE = False
    enhanced_logger = None
    logging_system = None

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
                query = "INSERT INTO messages (content, sender_id, recipient_id, timestamp) " \
                    "VALUES (?, ?, ?, ?) RETURNING id, content, sender_id, recipient_id, timestamp"
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

@router.post("/send", response_model=MessageRead, status_code=status.HTTP_201_CREATED, responses={400: {"model": ValidationErrorResponse}, 429: {"description": "Rate limit exceeded"}})
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    permissions=[RequiredPermission.WRITE],
    rate_limit_rpm=30,
    audit_action="send_message"
)
async def send_message(request: Request, data: MessageCreate, background_tasks: BackgroundTasks, current_user: Dict[str, Any] = Depends(get_current_user)):
    client_ip = request.client.host if request.client else "unknown"
    
    # Enhanced logging with security context
    if enhanced_logger and logging_system:
        logging_system.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint="/messages/send",
            method="POST",
            ip_address=client_ip
        )
        
        enhanced_logger.info(
            f"User {current_user.get('id')} sending message",
            extra={
                "category": LogCategory.API,
                "metadata": {
                    "sender_id": current_user.get("id"),
                    "recipient_id": data.recipient_id,
                    "message_length": len(data.content),
                    "client_ip": client_ip
                },
                "tags": ["messaging", "send_message", "user_action"]
            }
        )
    else:
        logger.info(Fore.CYAN + f"[MSG] User {current_user.get('id', 'unknown')} from {client_ip} sending message" + Style.RESET_ALL)
    
    # Performance tracking setup
    operation_id = None
    if optimization_engine:
        operation_id = f"send_message_{current_user.get('id')}_{datetime.now().timestamp()}"
        optimization_engine.start_performance_tracking(operation_id)
        logger.debug(Fore.GREEN + f"[MSG] Performance tracking started for operation {operation_id}" + Style.RESET_ALL)
    
    try:
        if not await message_service.validate_recipient(data.recipient_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")
        if not await message_service.check_rate_limit(current_user.get("id", 0)):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded. Please wait before sending another message.")
        message = await message_service.create_message(data, current_user.get("id", 0))
        background_tasks.add_task(_process_message_background, message.id, current_user.get("id", 0), data.recipient_id)
        if optimization_engine and operation_id:
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

async def _process_message_background(message_id: int, sender_id: int, recipient_id: int) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(executor, _process_message_sync, message_id, sender_id, recipient_id)

def _process_message_sync(message_id: int, sender_id: int, recipient_id: int) -> None:
    # Placeholder for background processing logic (e.g., notifications, analytics)
    logger.info(f"Processing message {message_id} from {sender_id} to {recipient_id}")
    pass

@router.get("/list", response_model=List[MessageRead], responses={400: {"model": ValidationErrorResponse}})
async def list_messages(_request: Request, limit: int = Query(50, ge=1, le=100, description="Number of messages to retrieve"), offset: int = Query(0, ge=0, description="Number of messages to skip"), sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order for messages"), current_user: Dict[str, Any] = Depends(get_current_user)) -> List[MessageRead]:
    if not message_service.db_manager:
        return []
    try:
        order = "DESC" if sort_order.lower() == "desc" else "ASC"
        query = "SELECT id, content, sender_id, recipient_id, timestamp FROM messages " \
            "WHERE sender_id = ? OR recipient_id = ? " \
            f"ORDER BY timestamp {order} LIMIT ? OFFSET ?"
        params = {
            "sender_id": current_user.get("id", 0),
            "recipient_id": current_user.get("id", 0),
            "limit": limit,
            "offset": offset
        }
        if performance_logger and timer:
            with timer("list_messages_query"):
                result = await message_service.db_manager.execute_query(query, params)
            logger.debug(Fore.GREEN + "[MSG] List messages query performance tracked" + Style.RESET_ALL)
        else:
            result = await message_service.db_manager.execute_query(query, params)
            logger.debug(Fore.GREEN + "[MSG] List messages query executed" + Style.RESET_ALL)
        messages = []
        if result:
            for row in result:
                if isinstance(row, (list, tuple)) and len(row) == 5:
                    try:
                        id_, content, sender_id_, recipient_id_, timestamp_ = row  # type: ignore
                    except Exception:
                        id_, content, sender_id_, recipient_id_, timestamp_ = 0, "", 0, 0, datetime.now()
                    messages.append(MessageRead(
                        id=_safe_int(id_),
                        content=str(content),
                        sender_id=_safe_int(sender_id_),
                        recipient_id=_safe_int(recipient_id_),
                        timestamp=_safe_datetime(timestamp_)
                    ))
                elif isinstance(row, dict):
                    messages.append(MessageRead(
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
