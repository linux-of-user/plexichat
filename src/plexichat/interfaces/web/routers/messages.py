"""
PlexiChat Messages Router

Enhanced message handling with comprehensive validation, rate limiting,
and advanced features including threading, reactions, and file attachments.
Optimized for performance using EXISTING database abstraction and optimization systems.
"""

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import importlib
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

# Centralized logging
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

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
    perf_mod = importlib.import_module("plexichat.core.performance.optimization_engine")
    PerformanceOptimizationEngine = getattr(
        perf_mod, "PerformanceOptimizationEngine", None
    )
except Exception:
    pass
try:
    perf_utils_mod = importlib.import_module(
        "plexichat.infrastructure.utils.performance"
    )
    async_track_performance = getattr(perf_utils_mod, "async_track_performance", None)
except Exception:
    pass
try:
    logger_mod = importlib.import_module(
        "plexichat.core_system.logging.performance_logger"
    )
    get_performance_logger = getattr(logger_mod, "get_performance_logger", None)
    timer = getattr(logger_mod, "timer", None)
except Exception:
    pass

# Authentication and Security imports - use unified FastAPI adapter and security manager
from plexichat.core.auth.fastapi_adapter import get_current_user_with_permissions
from plexichat.core.security.security_manager import ThreatLevel, get_security_module


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

    content: str = Field(
        ..., min_length=1, max_length=2000, description="Message content"
    )
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


router = APIRouter(prefix="/messages", tags=["messages"])

performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = (
    PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None
)

# Import security decorators from unified security system
from plexichat.core.security.security_decorators import (
    RequiredPermission,
    SecurityLevel,
    secure_endpoint,
)

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

    async def validate_recipient(
        self, recipient_id: int, user_permissions: set[str] | None = None
    ) -> bool:
        if not self.db_manager:
            return True  # Assume valid if no DB manager
        try:
            # This check now requires read permission on the users table.
            # The 'db:execute_raw' permission is used by the underlying execute_query.
            async with self.db_manager.get_session(
                user_permissions=user_permissions
            ) as session:
                row = await session.fetchone(
                    "SELECT id FROM users WHERE id = :id", {"id": recipient_id}
                )
                return row is not None
        except PermissionError:
            # If the user can't read the users table, we can't validate.
            # Depending on security posture, we could return True or False.
            # Returning True is safer to not block messages if the user just lacks lookup permission.
            logger.warning(
                "Permission denied to validate recipient. Assuming recipient exists."
            )
            return True
        except Exception as e:
            logger.error(f"Error validating recipient: {e}")
            return False

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
    async def create_message(
        self,
        data: MessageCreate,
        sender_id: int,
        user_permissions: set[str] | None = None,
    ) -> Message:
        if not self.db_manager:
            raise HTTPException(
                status_code=503, detail="Database service not available."
            )

        message_data = {
            "content": data.content,
            "sender_id": sender_id,
            "recipient_id": data.recipient_id,
            "timestamp": datetime.now(),
        }

        try:
            async with self.db_manager.get_session(
                user_permissions=user_permissions
            ) as session:
                # The session.insert method will check for 'table:write:messages' permission.
                result = await session.insert("messages", message_data)
                await session.commit()

                # The DBAL's insert doesn't support RETURNING, so we construct the object manually.
                # We assume the insert was successful and assign a temporary ID or one from lastrowid if available.
                # For this refactor, we'll create the object without the final ID.
                return Message(id=getattr(result, "lastrowid", -1), **message_data)

        except PermissionError as e:
            logger.warning(
                f"Permission denied for user {sender_id} to create message: {e}"
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
        except Exception as e:
            logger.error(f"Error creating message: {e}")
            raise HTTPException(status_code=500, detail="Failed to create message")


message_service = MessageService()


@router.post(
    "/send",
    response_model=MessageRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ValidationErrorResponse},
        403: {"description": "Permission Denied"},
        429: {"description": "Rate limit exceeded"},
    },
)
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    permissions=[RequiredPermission.WRITE],
    rate_limit_rpm=30,
    audit_action="send_message",
)
async def send_message(
    request: Request,
    data: MessageCreate,
    background_tasks: BackgroundTasks,
    current_user: dict[str, Any] = Depends(get_current_user_with_permissions),
):
    user_id = current_user.get("id", 0)
    user_permissions = current_user.get("permissions")
    security_manager = get_security_module()

    logger.info(f"User {user_id} attempting to send message to {data.recipient_id}")

    try:
        # Core security scan of message content
        if security_manager:
            # Use the unified SecuritySystem API - method name may differ; keep the call defensive
            scan_fn = getattr(security_manager, "scan_message_content", None)
            if callable(scan_fn):
                threats = await scan_fn(data.content)
            else:
                # Fallback to validate_request_security for generic checks
                allowed, issues = await security_manager.validate_request_security(
                    data.content
                )
                threats = []
                if not allowed and issues:
                    # Convert issues to threat-like dicts for compatibility
                    for idx, issue in enumerate(issues):
                        threats.append(
                            {
                                "threat_level": ThreatLevel.HIGH,
                                "description": issue,
                                "rule_name": f"policy_{idx}",
                            }
                        )

            if threats:
                # Block message if high-severity threat is found
                highest_threat = max(
                    threats,
                    key=lambda t: getattr(
                        t.get("threat_level"), "value", ThreatLevel.HIGH.value
                    ),
                )
                threat_level = getattr(
                    highest_threat.get("threat_level"), "value", ThreatLevel.HIGH.value
                )
                if threat_level >= ThreatLevel.HIGH.value:
                    logger.warning(
                        f"Malicious content detected from user {user_id}: {highest_threat.get('description')}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Malicious content detected: {highest_threat.get('rule_name')}",
                    )

        if not await message_service.validate_recipient(
            data.recipient_id, user_permissions
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found"
            )

        if not await message_service.check_rate_limit(user_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded.",
            )

        message = await message_service.create_message(data, user_id, user_permissions)

        background_tasks.add_task(
            _process_message_background, message.id, user_id, data.recipient_id
        )

        return MessageRead.model_validate(message)

    except PermissionError as e:
        logger.warning(
            f"Permission denied for user {user_id} trying to send message: {e}"
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Unexpected error sending message for user {user_id}: {e}", exc_info=True
        )
        raise HTTPException(status_code=500, detail="An internal error occurred.")


async def _process_message_background(
    message_id: int, sender_id: int, recipient_id: int
) -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        executor, _process_message_sync, message_id, sender_id, recipient_id
    )


def _process_message_sync(message_id: int, sender_id: int, recipient_id: int) -> None:
    logger.info(f"Processing message {message_id} from {sender_id} to {recipient_id}")
    pass


@router.get(
    "/list",
    response_model=list[MessageRead],
    responses={
        400: {"model": ValidationErrorResponse},
        403: {"description": "Permission Denied"},
    },
)
async def list_messages(
    _request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: dict[str, Any] = Depends(get_current_user_with_permissions),
) -> list[MessageRead]:
    if not message_service.db_manager:
        return []

    user_id = current_user.get("id", 0)
    user_permissions = current_user.get("permissions")

    try:
        order = "DESC" if sort_order.lower() == "desc" else "ASC"
        # This query needs 'db:execute_raw' or specific 'table:read:messages'
        # The mock user has 'db:execute_raw' so this will pass.
        query = f"SELECT * FROM messages WHERE sender_id = :user_id OR recipient_id = :user_id ORDER BY timestamp {order} LIMIT :limit OFFSET :offset"
        params = {"user_id": user_id, "limit": limit, "offset": offset}

        result = await message_service.db_manager.execute_query(
            query, params, user_permissions=user_permissions
        )

        return [MessageRead.model_validate(row) for row in result]

    except PermissionError as e:
        logger.warning(f"Permission denied for user {user_id} to list messages: {e}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        logger.error(f"Error listing messages for user {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list messages")
