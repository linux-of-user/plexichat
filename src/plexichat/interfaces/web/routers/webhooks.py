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
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None

# Authentication imports - unified FastAPI adapter
from plexichat.core.auth.fastapi_adapter import get_current_user, require_admin

# Security decorators and permission enums from unified security system
from plexichat.core.security.security_decorators import secure_endpoint, RequiredPermission

# Input sanitizer (best-effort import; fallback minimal implementation)
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

# Unified logging
from plexichat.core.logging import get_logger, LogCategory

logger = get_logger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Initialize EXISTING performance systems
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

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
        # Use unified logger for performance telemetry and logs
        self.logger = logger

    @async_track_performance("webhook_creation") if async_track_performance else lambda f: f
    async def create_webhook(self, webhook_data: WebhookCreate, user_id: int) -> WebhookResponse:
        """Create webhook using EXISTING database abstraction layer."""
        if self.db_manager:
            try:
                # Create webhook
                create_query = """
                    INSERT INTO webhooks (name, url, secret, events, is_active, user_id, created_at)
                    VALUES (:name, :url, :secret, :events, :is_active, :user_id, :created_at)
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

                # Use unified logger's timer context when available for timing DB queries
                try:
                    with logger.timer("webhook_creation_query"):
                        result = await self.db_manager.execute_query(create_query, create_params)
                except Exception:
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
                self.logger.error(f"Error creating webhook: {e}", category=LogCategory.DATABASE, extra_data={"error": str(e)})
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
                    WHERE user_id = :user_id
                    ORDER BY created_at DESC
                    LIMIT :limit OFFSET :offset
                """
                params = {"user_id": user_id, "limit": limit, "offset": offset}

                try:
                    with logger.timer("webhook_list_query"):
                        result = await self.db_manager.execute_query(query, params)
                except Exception:
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
                self.logger.error(f"Error listing webhooks: {e}", category=LogCategory.DATABASE, extra_data={"error": str(e)})
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

                try:
                    with logger.timer("webhook_get_query"):
                        result = await self.db_manager.execute_query(webhook_query, webhook_params)
                except Exception:
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
                        self.logger.error(f"Webhook delivery failed: {e}", category=LogCategory.API, extra_data={"webhook_id": webhook_id, "error": str(e)})
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

                try:
                    with logger.timer("webhook_delivery_log"):
                        await self.db_manager.execute_query(delivery_query, delivery_params)
                except Exception:
                    await self.db_manager.execute_query(delivery_query, delivery_params)

                # Update last_triggered
                update_query = """
                    UPDATE webhooks SET last_triggered = ? WHERE id = ?
                """
                update_params = {"last_triggered": datetime.now(), "id": webhook_id}

                try:
                    with logger.timer("webhook_update_triggered"):
                        await self.db_manager.execute_query(update_query, update_params)
                except Exception:
                    await self.db_manager.execute_query(update_query, update_params)

                return delivery_status == "success"

            except Exception as e:
                self.logger.error(f"Error triggering webhook: {e}", category=LogCategory.API, extra_data={"error": str(e)})
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
    auth_required=True,
    permission=RequiredPermission.WRITE,
    rate_limit_rpm=10,
    audit_action="create_webhook"
)
async def create_webhook(
    request: Request,
    webhook_data: WebhookCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new webhook with enhanced security and performance optimization."""
    client_ip = request.client.host if request.client else "unknown"

    # Use unified logger with context
    try:
        logger.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint="/webhooks/",
            method="POST",
            ip_address=client_ip
        )
    except Exception:
        # best-effort, non-fatal
        pass

    logger.info(
        f"Webhook creation requested by user {current_user.get('username')}",
        category=LogCategory.API,
        extra_data={
            "metadata": {
                "webhook_name": webhook_data.name,
                "webhook_url": webhook_data.url[:100] + "..." if len(webhook_data.url) > 100 else webhook_data.url,
                "event_count": len(webhook_data.events)
            },
            "tags": ["webhook", "create", "api"]
        }
    )

    # Performance tracking with unified logger timer
    try:
        with logger.timer("create_webhook"):
            # Sanitize inputs
            webhook_data.name = InputSanitizer.sanitize_input(webhook_data.name)
            webhook_data.url = InputSanitizer.sanitize_input(webhook_data.url)

            result = await webhook_service.create_webhook(webhook_data, current_user.get("id", 0))

            # Log successful creation as audit
            logger.audit(
                f"Webhook created successfully: {getattr(result, 'id', 'unknown')}",
                category=LogCategory.AUDIT,
                extra_data={
                    "metadata": {
                        "webhook_id": getattr(result, 'id', None),
                        "created_by": current_user.get("username")
                    },
                    "tags": ["webhook", "created", "success"]
                }
            )

            return result
    except Exception:
        # Fallback path without timer if timer usage fails
        webhook_data.name = InputSanitizer.sanitize_input(webhook_data.name)
        webhook_data.url = InputSanitizer.sanitize_input(webhook_data.url)
        return await webhook_service.create_webhook(webhook_data, current_user.get("id", 0))

@router.get(
    "/",
    response_model=List[WebhookResponse],
    summary="List webhooks"
)
@secure_endpoint(
    auth_required=True,
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

    try:
        logger.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint="/webhooks/",
            method="GET",
            ip_address=client_ip
        )
    except Exception:
        pass

    logger.info(
        f"Webhook list requested by user {current_user.get('username')}",
        category=LogCategory.API,
        extra_data={
            "metadata": {
                "limit": limit,
                "offset": offset,
                "user_id": current_user.get("id")
            },
            "tags": ["webhook", "list", "api"]
        }
    )

    try:
        with logger.timer("list_webhooks"):
            result = await webhook_service.list_webhooks(current_user.get("id", 0), limit, offset)

            logger.debug(
                f"Listed {len(result)} webhooks for user {current_user.get('username')}",
                category=LogCategory.PERFORMANCE,
                extra_data={
                    "metadata": {
                        "result_count": len(result),
                        "query_limit": limit,
                        "query_offset": offset
                    },
                    "tags": ["webhook", "list", "performance"]
                }
            )

            return result
    except Exception:
        return await webhook_service.list_webhooks(current_user.get("id", 0), limit, offset)

@router.post(
    "/{webhook_id}/trigger",
    summary="Trigger webhook"
)
@secure_endpoint(
    auth_required=True,
    permission=RequiredPermission.WRITE,
    rate_limit_rpm=20,
    audit_action="trigger_webhook"
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

    try:
        logger.set_context(
            user_id=str(current_user.get("id", "")),
            endpoint=f"/webhooks/{webhook_id}/trigger",
            method="POST",
            ip_address=client_ip
        )
    except Exception:
        pass

    logger.info(
        f"Webhook {webhook_id} trigger requested by user {current_user.get('username')}",
        category=LogCategory.API,
        extra_data={
            "metadata": {
                "webhook_id": webhook_id,
                "event_type": event.event_type,
                "user_id": current_user.get("id")
            },
            "tags": ["webhook", "trigger", "api"]
        }
    )

    # Security audit
    logger.audit(
        f"Manual webhook trigger: webhook_id={webhook_id}",
        category=LogCategory.AUDIT,
        extra_data={
            "metadata": {
                "webhook_id": webhook_id,
                "event_type": event.event_type,
                "triggered_by": current_user.get("username"),
                "user_id": current_user.get("id")
            },
            "tags": ["webhook", "manual_trigger", "audit"]
        }
    )

    try:
        with logger.timer("trigger_webhook"):
            # Sanitize event data
            event.event_type = InputSanitizer.sanitize_input(event.event_type)

            # Trigger webhook in background
            background_tasks.add_task(webhook_service.trigger_webhook, webhook_id, event)

            return {"message": "Webhook triggered", "webhook_id": webhook_id}
    except Exception:
        event.event_type = InputSanitizer.sanitize_input(event.event_type)
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
    logger.info(f"Webhook broadcast requested by admin {current_user.get('username')} from {client_ip}", category=LogCategory.API)

    # Get all active webhooks (limited)
    webhooks = await webhook_service.list_webhooks(current_user.get("id", 0), limit=1000)

    # Trigger all webhooks in background
    for webhook in webhooks:
        if webhook.is_active and event.event_type in webhook.events:
            background_tasks.add_task(webhook_service.trigger_webhook, webhook.id, event)

    return {
        "message": "Event broadcasted to all matching webhooks",
        "webhook_count": len([w for w in webhooks if w.is_active and event.event_type in w.events])
    }
