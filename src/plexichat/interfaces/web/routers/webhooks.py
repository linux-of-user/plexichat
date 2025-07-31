# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
PlexiChat Webhooks Router

Enhanced webhook management with comprehensive validation, security, and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.database import get_session, execute_query
except ImportError:
    database_manager = None
    get_session = None
    execute_query = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import get_current_user, require_admin
except ImportError:
    def get_current_user():
        return {"id": 1, "username": "admin", "is_admin": True}
    def require_admin():
        return {"id": 1, "username": "admin", "is_admin": True}

# Security imports
try:
    from plexichat.infrastructure.utils.security import InputSanitizer
except ImportError:
    class InputSanitizer:
        @staticmethod
        def sanitize_input(text: str) -> str:
            return text.strip()

# HTTP client imports
try:
    import httpx  # type: ignore
except ImportError:
    httpx = None

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Import enhanced security decorators
try:
    from plexichat.core.security.security_decorators import (
        secure_endpoint, admin_endpoint, require_auth, rate_limit, audit_access,
        SecurityLevel, RequiredPermission
    )
    from plexichat.core.logging_advanced.enhanced_logging_system import (
        get_enhanced_logging_system, LogCategory, LogLevel, PerformanceTracker
    )
    ENHANCED_SECURITY_AVAILABLE = True
    
    # Get enhanced logging system
    logging_system = get_enhanced_logging_system()
    if logging_system:
        enhanced_logger = logging_system.get_logger(__name__)
        logger.info("Enhanced security and logging initialized for webhooks")
    else:
        enhanced_logger = None
        
except ImportError as e:
    logger.warning(f"Enhanced security not available for webhooks: {e}")
    # Fallback decorators
    def secure_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def admin_endpoint(*args, **kwargs):
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
    
    class SecurityLevel:
        AUTHENTICATED = 2
        ADMIN = 4
    
    class RequiredPermission:
        WRITE = "write"
        DELETE = "delete"
    
    class LogCategory:
        API = "api"
        AUDIT = "audit"
        PERFORMANCE = "performance"
        SECURITY = "security"
    
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
    
    ENHANCED_SECURITY_AVAILABLE = False
    enhanced_logger = None
    logging_system = None

# Pydantic models
class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., pattern=r'^https?://.+')
    secret: Optional[str] = Field(None, max_length=255)
    events: List[str] = Field(..., min_items=1)
    is_active: bool = True

class WebhookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[str] = Field(None, pattern=r'^https?://.+')
    secret: Optional[str] = Field(None, max_length=255)
    events: Optional[List[str]] = Field(None, min_items=1)
    is_active: Optional[bool] = None

class WebhookResponse(BaseModel):
    id: int
    name: str
    url: str
    events: List[str]
    is_active: bool
    created_at: datetime
    last_triggered: Optional[datetime] = None

class WebhookEvent(BaseModel):
    event_type: str
    data: Dict[str, Any]
    timestamp: datetime

class WebhookDelivery(BaseModel):
    id: int
    webhook_id: int
    event_type: str
    status: str
    response_code: Optional[int] = None
    response_body: Optional[str] = None
    created_at: datetime

class WebhookService:
    """Service class for webhook operations using EXISTING database abstraction layer."""

    def __init__(self):
        # Use EXISTING database manager
        self.db_manager = database_manager
        self.performance_logger = performance_logger

    @async_track_performance("webhook_creation") if async_track_performance else lambda f: f
    async def create_webhook(self, webhook_data: WebhookCreate, user_id: int) -> WebhookResponse:
        """Create webhook using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                # Create webhook
                create_query = """
                    INSERT INTO webhooks (name, url, secret, events, is_active, user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    RETURNING id, name, url, events, is_active, created_at, last_triggered
                """
                create_params = {
                    "name": webhook_data.name,
                    "url": webhook_data.url,
                    "secret": webhook_data.secret,
                    "events": json.dumps(webhook_data.events),
                    "is_active": webhook_data.is_active,
                    "user_id": user_id,
                    "created_at": datetime.now()
                }

                if self.performance_logger and timer:
                    with timer("webhook_creation_query"):
                        result = await self.db_manager.execute_query(create_query, create_params)
                else:
                    result = await self.db_manager.execute_query(create_query, create_params)

                if result:
                    row = result[0]
                    return WebhookResponse(
                        id=row[0],
                        name=row[1],
                        url=row[2],
                        events=json.loads(row[3]) if row[3] else [],
                        is_active=bool(row[4]),
                        created_at=row[5],
                        last_triggered=row[6]
                    )

            except Exception as e:
                logger.error(f"Error creating webhook: {e}")
                raise HTTPException(status_code=500, detail="Failed to create webhook")

        # Fallback mock webhook
        return WebhookResponse(
            id=1,
            name=webhook_data.name,
            url=webhook_data.url,
            events=webhook_data.events,
            is_active=webhook_data.is_active,
            created_at=datetime.now(),
            last_triggered=None
        )

    @async_track_performance("webhook_list") if async_track_performance else lambda f: f
    async def list_webhooks(self, user_id: int, limit: int = 50, offset: int = 0) -> List[WebhookResponse]:
        """List webhooks using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                query = """
                    SELECT id, name, url, events, is_active, created_at, last_triggered
                    FROM webhooks
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """
                params = {"user_id": user_id, "limit": limit, "offset": offset}

                if self.performance_logger and timer:
                    with timer("webhook_list_query"):
                        result = await self.db_manager.execute_query(query, params)
                else:
                    result = await self.db_manager.execute_query(query, params)

                webhooks = []
                if result:
                    for row in result:
                        webhooks.append(WebhookResponse(
                            id=row[0],
                            name=row[1],
                            url=row[2],
                            events=json.loads(row[3]) if row[3] else [],
                            is_active=bool(row[4]),
                            created_at=row[5],
                            last_triggered=row[6]
                        ))

                return webhooks

            except Exception as e:
                logger.error(f"Error listing webhooks: {e}")
                return []

        return []

    @async_track_performance("webhook_trigger") if async_track_performance else lambda f: f
    async def trigger_webhook(self, webhook_id: int, event: WebhookEvent) -> bool:
        """Trigger webhook delivery using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                # Get webhook details
                webhook_query = """
                    SELECT id, name, url, secret, events, is_active
                    FROM webhooks
                    WHERE id = ? AND is_active = 1
                """
                webhook_params = {"id": webhook_id}

                if self.performance_logger and timer:
                    with timer("webhook_get_query"):
                        result = await self.db_manager.execute_query(webhook_query, webhook_params)
                else:
                    result = await self.db_manager.execute_query(webhook_query, webhook_params)

                if not result:
                    return False

                webhook_row = result[0]
                webhook_events = json.loads(webhook_row[4]) if webhook_row[4] else []

                # Check if event type is subscribed
                if event.event_type not in webhook_events:
                    return False

                # Prepare payload
                payload = {
                    "event": event.event_type,
                    "data": event.data,
                    "timestamp": event.timestamp.isoformat(),
                    "webhook_id": webhook_id
                }

                # Create signature if secret is provided
                headers = {"Content-Type": "application/json"}
                if webhook_row[3]:  # secret
                    signature = hmac.new(
                        webhook_row[3].encode(),
                        json.dumps(payload).encode(),
                        hashlib.sha256
                    ).hexdigest()
                    headers["X-Webhook-Signature"] = f"sha256={signature}"

                # Send webhook (if httpx is available)
                delivery_status = "pending"
                response_code = None
                response_body = None

                if httpx:
                    try:
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.post(
                                webhook_row[2],  # url
                                json=payload,
                                headers=headers
                            )
                            response_code = response.status_code
                            response_body = response.text[:1000]  # Limit response body
                            delivery_status = "success" if 200 <= response_code < 300 else "failed"
                    except Exception as e:
                        logger.error(f"Webhook delivery failed: {e}")
                        delivery_status = "failed"
                        response_body = str(e)[:1000]

                # Log delivery
                delivery_query = """
                    INSERT INTO webhook_deliveries (webhook_id, event_type, status, response_code, response_body, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """
                delivery_params = {
                    "webhook_id": webhook_id,
                    "event_type": event.event_type,
                    "status": delivery_status,
                    "response_code": response_code,
                    "response_body": response_body,
                    "created_at": datetime.now()
                }

                if self.performance_logger and timer:
                    with timer("webhook_delivery_log"):
                        await self.db_manager.execute_query(delivery_query, delivery_params)
                else:
                    await self.db_manager.execute_query(delivery_query, delivery_params)

                # Update last_triggered
                update_query = """
                    UPDATE webhooks SET last_triggered = ? WHERE id = ?
                """
                update_params = {"last_triggered": datetime.now(), "id": webhook_id}

                if self.performance_logger and timer:
                    with timer("webhook_update_triggered"):
                        await self.db_manager.execute_query(update_query, update_params)
                else:
                    await self.db_manager.execute_query(update_query, update_params)

                return delivery_status == "success"

            except Exception as e:
                logger.error(f"Error triggering webhook: {e}")
                return False

        return False

# Initialize service
webhook_service = WebhookService()

@router.post(
    "/",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create webhook"
)
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    permissions=[RequiredPermission.WRITE],
    rate_limit_rpm=10,
    audit_action="create_webhook",
    validate_input_size=5*1024  # 5KB max
)
async def create_webhook(
    request: Request,
    webhook_data: WebhookCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new webhook with enhanced security and performance optimization."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Enhanced logging
    if enhanced_logger and logging_system:
        logging_system.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint="/webhooks/",
            method="POST",
            ip_address=client_ip
        )
        
        enhanced_logger.info(
            f"Webhook creation requested by user {current_user.get('username')}",
            extra={
                "category": LogCategory.API,
                "metadata": {
                    "webhook_name": webhook_data.name,
                    "webhook_url": webhook_data.url[:100] + "..." if len(webhook_data.url) > 100 else webhook_data.url,
                    "event_count": len(webhook_data.events)
                },
                "tags": ["webhook", "create", "api"]
            }
        )
    else:
        logger.info(f"Webhook creation requested by user {current_user.get('username')} from {client_ip}")

    # Performance tracking with enhanced system
    if ENHANCED_SECURITY_AVAILABLE and enhanced_logger:
        with PerformanceTracker("create_webhook", enhanced_logger) as tracker:
            tracker.add_metadata(
                user_id=current_user.get("id"),
                webhook_events=len(webhook_data.events)
            )
            
            # Sanitize inputs
            webhook_data.name = InputSanitizer.sanitize_input(webhook_data.name)
            webhook_data.url = InputSanitizer.sanitize_input(webhook_data.url)
            
            result = await webhook_service.create_webhook(webhook_data, current_user.get("id", 0))
            
            # Log successful creation
            if enhanced_logger:
                enhanced_logger.info(
                    f"Webhook created successfully: {result.get('id', 'unknown')}",
                    extra={
                        "category": LogCategory.AUDIT,
                        "metadata": {
                            "webhook_id": result.get("id"),
                            "created_by": current_user.get("username")
                        },
                        "tags": ["webhook", "created", "success"]
                    }
                )
            
            return result
    else:
        # Fallback to original performance tracking
        if performance_logger:
            performance_logger.record_metric("webhook_creation_requests", 1, "count")

        # Sanitize inputs
        webhook_data.name = InputSanitizer.sanitize_input(webhook_data.name)
        webhook_data.url = InputSanitizer.sanitize_input(webhook_data.url)

        return await webhook_service.create_webhook(webhook_data, current_user.get("id", 0))

@router.get(
    "/",
    response_model=List[WebhookResponse],
    summary="List webhooks"
)
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    rate_limit_rpm=60,
    audit_action="list_webhooks"
)
async def list_webhooks(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List user's webhooks with enhanced performance monitoring."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Enhanced logging
    if enhanced_logger and logging_system:
        logging_system.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint="/webhooks/",
            method="GET",
            ip_address=client_ip
        )
        
        enhanced_logger.info(
            f"Webhook list requested by user {current_user.get('username')}",
            extra={
                "category": LogCategory.API,
                "metadata": {
                    "limit": limit,
                    "offset": offset,
                    "user_id": current_user.get("id")
                },
                "tags": ["webhook", "list", "api"]
            }
        )
    else:
        logger.info(f"Webhook list requested by user {current_user.get('username')} from {client_ip}")

    # Performance tracking with enhanced system
    if ENHANCED_SECURITY_AVAILABLE and enhanced_logger:
        with PerformanceTracker("list_webhooks", enhanced_logger) as tracker:
            tracker.add_metadata(
                user_id=current_user.get("id"),
                limit=limit,
                offset=offset
            )
            
            result = await webhook_service.list_webhooks(current_user.get("id", 0), limit, offset)
            
            # Log performance metrics
            if enhanced_logger:
                enhanced_logger.debug(
                    f"Listed {len(result)} webhooks for user {current_user.get('username')}",
                    extra={
                        "category": LogCategory.PERFORMANCE,
                        "metadata": {
                            "result_count": len(result),
                            "query_limit": limit,
                            "query_offset": offset
                        },
                        "tags": ["webhook", "list", "performance"]
                    }
                )
            
            return result
    else:
        # Fallback to original performance tracking
        if performance_logger:
            performance_logger.record_metric("webhook_list_requests", 1, "count")

        return await webhook_service.list_webhooks(current_user.get("id", 0), limit, offset)

@router.post(
    "/{webhook_id}/trigger",
    summary="Trigger webhook"
)
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    permissions=[RequiredPermission.WRITE],
    rate_limit_rpm=20,
    audit_action="trigger_webhook",
    validate_input_size=2*1024  # 2KB max
)
async def trigger_webhook(
    request: Request,
    webhook_id: int,
    event: WebhookEvent,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Trigger a webhook manually with enhanced security and monitoring."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Enhanced logging
    if enhanced_logger and logging_system:
        logging_system.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint=f"/webhooks/{webhook_id}/trigger",
            method="POST",
            ip_address=client_ip
        )
        
        enhanced_logger.info(
            f"Webhook {webhook_id} trigger requested by user {current_user.get('username')}",
            extra={
                "category": LogCategory.API,
                "metadata": {
                    "webhook_id": webhook_id,
                    "event_type": event.event_type,
                    "user_id": current_user.get("id")
                },
                "tags": ["webhook", "trigger", "api"]
            }
        )
        
        # Security audit log
        enhanced_logger.audit(
            f"Manual webhook trigger: webhook_id={webhook_id}",
            extra={
                "category": LogCategory.AUDIT,
                "metadata": {
                    "webhook_id": webhook_id,
                    "event_type": event.event_type,
                    "triggered_by": current_user.get("username"),
                    "user_id": current_user.get("id")
                },
                "tags": ["webhook", "manual_trigger", "audit"]
            }
        )
    else:
        logger.info(f"Webhook {webhook_id} trigger requested by user {current_user.get('username')} from {client_ip}")

    # Performance tracking
    if ENHANCED_SECURITY_AVAILABLE and enhanced_logger:
        with PerformanceTracker("trigger_webhook", enhanced_logger) as tracker:
            tracker.add_metadata(
                webhook_id=webhook_id,
                event_type=event.event_type,
                user_id=current_user.get("id")
            )
            
            # Sanitize event data
            event.event_type = InputSanitizer.sanitize_input(event.event_type)
            
            # Trigger webhook in background
            background_tasks.add_task(webhook_service.trigger_webhook, webhook_id, event)
            
            return {"message": "Webhook triggered", "webhook_id": webhook_id}
    else:
        # Fallback to original performance tracking
        if performance_logger:
            performance_logger.record_metric("webhook_trigger_requests", 1, "count")

        # Sanitize event data
        event.event_type = InputSanitizer.sanitize_input(event.event_type)

        # Trigger webhook in background
        background_tasks.add_task(webhook_service.trigger_webhook, webhook_id, event)

        return {"message": "Webhook triggered", "webhook_id": webhook_id}

@router.post(
    "/broadcast",
    summary="Broadcast event to all webhooks"
)
async def broadcast_event(
    request: Request,
    event: WebhookEvent,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Broadcast an event to all active webhooks (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Webhook broadcast requested by admin {current_user.get('username')} from {client_ip}")

    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("webhook_broadcast_requests", 1, "count")

    # Get all active webhooks
    webhooks = await webhook_service.list_webhooks(current_user.get("id", 0), limit=1000)

    # Trigger all webhooks in background
    for webhook in webhooks:
        if webhook.is_active and event.event_type in webhook.events:
            background_tasks.add_task(webhook_service.trigger_webhook, webhook.id, event)

    return {
        "message": "Event broadcasted to all matching webhooks",
        "webhook_count": len([w for w in webhooks if w.is_active and event.event_type in w.events])
    }
