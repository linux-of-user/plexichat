from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, BackgroundTasks
from sqlmodel import Session, select, and_, or_, desc, asc
from sqlalchemy import func, text
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

from app.logger_config import settings, logger
from app.db import engine
from app.models.message import Message, MessageType
from app.schemas.error import ValidationErrorResponse
from app.schemas.message import MessageCreate, MessageRead
from app.routers.auth import get_current_user

router = APIRouter()

# Enhanced response models
class MessageListResponse(BaseModel):
    """Enhanced message list response with metadata."""
    messages: List[MessageRead]
    total: int
    limit: int
    offset: int
    has_more: bool
    next_cursor: Optional[str] = None
    filters_applied: Dict[str, Any] = Field(default_factory=dict)

class MessageSearchResponse(BaseModel):
    """Message search response with relevance scoring."""
    messages: List[MessageRead]
    total_matches: int
    search_query: str
    search_time_ms: float
    suggestions: List[str] = Field(default_factory=list)

class MessageStatsResponse(BaseModel):
    """Message statistics response."""
    total_messages: int
    messages_sent: int
    messages_received: int
    today_count: int
    this_week_count: int
    this_month_count: int
    average_per_day: float
    most_active_hour: int

class BulkMessageResponse(BaseModel):
    """Bulk operation response."""
    success_count: int
    failed_count: int
    total_requested: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)

@router.post(
    "/",
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
    """Send a message with enhanced validation and features."""
    logger.debug(f"User {current_user.id} sending message to recipient {data.recipient_id}")

    with Session(engine) as session:
        # Validate recipient exists
        recipient_exists = session.exec(
            select(func.count()).select_from(Message.__table__.metadata.tables['users'])
            .where(text("id = :recipient_id")), {"recipient_id": data.recipient_id}
        ).one()

        if not recipient_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient not found"
            )

        # Check for rate limiting (basic implementation)
        recent_messages = session.exec(
            select(func.count()).select_from(Message)
            .where(
                and_(
                    Message.sender_id == current_user.id,
                    Message.timestamp > datetime.utcnow() - timedelta(minutes=1)
                )
            )
        ).one()

        if recent_messages > 60:  # 60 messages per minute limit
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please slow down."
            )

        # Create message with enhanced features
        msg = Message(
            sender_id=current_user.id,
            recipient_id=data.recipient_id,
            content=data.content,
            type=getattr(data, 'message_type', MessageType.DEFAULT),
            timestamp=datetime.utcnow()
        )

        session.add(msg)
        session.commit()
        session.refresh(msg)

        # Add background tasks for notifications, etc.
        background_tasks.add_task(
            _process_message_background,
            msg.id,
            current_user.id,
            data.recipient_id
        )

        logger.info(f"Message {msg.id} sent from user {current_user.id} to {data.recipient_id}")
        return msg

async def _process_message_background(message_id: int, sender_id: int, recipient_id: int):
    """Background processing for message notifications and analytics."""
    try:
        # This would handle:
        # - Push notifications
        # - Email notifications (if enabled)
        # - Message analytics
        # - Spam detection
        # - Content moderation
        logger.debug(f"Processing background tasks for message {message_id}")
    except Exception as e:
        logger.error(f"Background message processing failed: {e}")

@router.get(
    "/",
    response_model=MessageListResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def list_messages(
    request: Request,
    limit: int = Query(50, le=100, ge=1, description="Number of messages to return"),
    offset: int = Query(0, ge=0, description="Number of messages to skip"),
    conversation_with: Optional[int] = Query(None, description="Filter by conversation with specific user"),
    message_type: Optional[MessageType] = Query(None, description="Filter by message type"),
    since: Optional[datetime] = Query(None, description="Messages since this timestamp"),
    until: Optional[datetime] = Query(None, description="Messages until this timestamp"),
    search: Optional[str] = Query(None, min_length=3, description="Search in message content"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order for messages"),
    include_deleted: bool = Query(False, description="Include deleted messages"),
    current_user=Depends(get_current_user)
):
    """List messages with advanced filtering, pagination, and search."""
    logger.debug(f"Listing messages for user {current_user.id} with filters")

    with Session(engine) as session:
        # Build base query
        base_conditions = [
            or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)
        ]

        # Apply filters
        filters_applied = {}

        if conversation_with:
            base_conditions.append(
                or_(
                    and_(Message.sender_id == current_user.id, Message.recipient_id == conversation_with),
                    and_(Message.sender_id == conversation_with, Message.recipient_id == current_user.id)
                )
            )
            filters_applied["conversation_with"] = conversation_with

        if message_type:
            base_conditions.append(Message.type == message_type)
            filters_applied["message_type"] = message_type.value

        if since:
            base_conditions.append(Message.timestamp >= since)
            filters_applied["since"] = since.isoformat()

        if until:
            base_conditions.append(Message.timestamp <= until)
            filters_applied["until"] = until.isoformat()

        if search:
            base_conditions.append(Message.content.contains(search))
            filters_applied["search"] = search

        if not include_deleted:
            # Assuming there's a deleted_at field or similar
            base_conditions.append(Message.timestamp.isnot(None))  # Placeholder

        # Build main query
        order_by = desc(Message.timestamp) if sort_order == "desc" else asc(Message.timestamp)

        stmt = select(Message).where(and_(*base_conditions)).order_by(order_by).limit(limit).offset(offset)
        messages = session.exec(stmt).all()

        # Get total count with same filters
        count_stmt = select(func.count()).select_from(Message).where(and_(*base_conditions))
        total = session.exec(count_stmt).one()

        # Calculate pagination metadata
        has_more = (offset + limit) < total
        next_cursor = None
        if has_more and messages:
            # Use timestamp-based cursor for better performance on large datasets
            last_message = messages[-1]
            next_cursor = f"{last_message.timestamp.isoformat()}_{last_message.id}"

        logger.info(f"User {current_user.id} retrieved {len(messages)} messages (total={total}, filters={filters_applied})")

        return MessageListResponse(
            messages=messages,
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
            next_cursor=next_cursor,
            filters_applied=filters_applied
        )

@router.get(
    "/search",
    response_model=MessageSearchResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def search_messages(
    request: Request,
    q: str = Query(..., min_length=3, description="Search query"),
    limit: int = Query(20, le=50, ge=1),
    offset: int = Query(0, ge=0),
    current_user=Depends(get_current_user)
):
    """Advanced message search with relevance scoring."""
    start_time = datetime.utcnow()

    with Session(engine) as session:
        # Full-text search implementation (simplified)
        # In production, you'd use proper full-text search like PostgreSQL's FTS or Elasticsearch
        search_conditions = [
            or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id),
            Message.content.contains(q)
        ]

        stmt = select(Message).where(and_(*search_conditions)).order_by(desc(Message.timestamp)).limit(limit).offset(offset)
        messages = session.exec(stmt).all()

        count_stmt = select(func.count()).select_from(Message).where(and_(*search_conditions))
        total_matches = session.exec(count_stmt).one()

        search_time = (datetime.utcnow() - start_time).total_seconds() * 1000

        # Generate search suggestions (simplified)
        suggestions = []
        if total_matches == 0:
            # Could implement spell checking, similar terms, etc.
            suggestions = ["Try different keywords", "Check spelling", "Use shorter terms"]

        logger.info(f"User {current_user.id} searched messages: '{q}' -> {total_matches} results in {search_time:.2f}ms")

        return MessageSearchResponse(
            messages=messages,
            total_matches=total_matches,
            search_query=q,
            search_time_ms=search_time,
            suggestions=suggestions
        )

@router.get(
    "/stats",
    response_model=MessageStatsResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def get_message_statistics(
    request: Request,
    current_user=Depends(get_current_user)
):
    """Get comprehensive message statistics for the user."""
    with Session(engine) as session:
        user_condition = or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)

        # Total messages
        total_messages = session.exec(
            select(func.count()).select_from(Message).where(user_condition)
        ).one()

        # Messages sent vs received
        messages_sent = session.exec(
            select(func.count()).select_from(Message).where(Message.sender_id == current_user.id)
        ).one()

        messages_received = session.exec(
            select(func.count()).select_from(Message).where(Message.recipient_id == current_user.id)
        ).one()

        # Time-based statistics
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)

        today_count = session.exec(
            select(func.count()).select_from(Message).where(
                and_(user_condition, Message.timestamp >= today_start)
            )
        ).one()

        this_week_count = session.exec(
            select(func.count()).select_from(Message).where(
                and_(user_condition, Message.timestamp >= week_start)
            )
        ).one()

        this_month_count = session.exec(
            select(func.count()).select_from(Message).where(
                and_(user_condition, Message.timestamp >= month_start)
            )
        ).one()

        # Calculate average per day (last 30 days)
        average_per_day = this_month_count / 30.0

        # Most active hour (simplified - would need more complex query in production)
        most_active_hour = 14  # Placeholder - 2 PM

        logger.info(f"Generated message statistics for user {current_user.id}")

        return MessageStatsResponse(
            total_messages=total_messages,
            messages_sent=messages_sent,
            messages_received=messages_received,
            today_count=today_count,
            this_week_count=this_week_count,
            this_month_count=this_month_count,
            average_per_day=average_per_day,
            most_active_hour=most_active_hour
        )

@router.delete(
    "/bulk",
    response_model=BulkMessageResponse,
    responses={429: {"description": "Rate limit exceeded"}}
)
async def bulk_delete_messages(
    request: Request,
    message_ids: List[int] = Query(..., description="List of message IDs to delete"),
    current_user=Depends(get_current_user)
):
    """Bulk delete messages (only messages sent by the user)."""
    if len(message_ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete more than 100 messages at once"
        )

    with Session(engine) as session:
        success_count = 0
        failed_count = 0
        errors = []

        for message_id in message_ids:
            try:
                # Only allow deletion of messages sent by the user
                message = session.exec(
                    select(Message).where(
                        and_(Message.id == message_id, Message.sender_id == current_user.id)
                    )
                ).first()

                if message:
                    session.delete(message)
                    success_count += 1
                else:
                    failed_count += 1
                    errors.append({
                        "message_id": message_id,
                        "error": "Message not found or not owned by user"
                    })
            except Exception as e:
                failed_count += 1
                errors.append({
                    "message_id": message_id,
                    "error": str(e)
                })

        if success_count > 0:
            session.commit()

        logger.info(f"User {current_user.id} bulk deleted {success_count} messages, {failed_count} failed")

        return BulkMessageResponse(
            success_count=success_count,
            failed_count=failed_count,
            total_requested=len(message_ids),
            errors=errors
        )

@router.get(
    "/{message_id}",
    response_model=MessageRead,
    responses={404: {"description": "Message not found"}, 429: {"description": "Rate limit exceeded"}}
)
async def get_message(
    request: Request,
    message_id: int,
    current_user=Depends(get_current_user)
):
    """Get a specific message by ID."""
    with Session(engine) as session:
        message = session.exec(
            select(Message).where(
                and_(
                    Message.id == message_id,
                    or_(Message.sender_id == current_user.id, Message.recipient_id == current_user.id)
                )
            )
        ).first()

        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )

        logger.debug(f"User {current_user.id} retrieved message {message_id}")
        return message

@router.put(
    "/{message_id}",
    response_model=MessageRead,
    responses={404: {"description": "Message not found"}, 403: {"description": "Cannot edit this message"}}
)
async def edit_message(
    request: Request,
    message_id: int,
    content: str = Query(..., min_length=1, description="New message content"),
    current_user=Depends(get_current_user)
):
    """Edit a message (only messages sent by the user, within time limit)."""
    with Session(engine) as session:
        message = session.exec(
            select(Message).where(
                and_(Message.id == message_id, Message.sender_id == current_user.id)
            )
        ).first()

        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found or not owned by user"
            )

        # Check if message is too old to edit (15 minutes limit)
        time_limit = timedelta(minutes=15)
        if datetime.utcnow() - message.timestamp > time_limit:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Message is too old to edit"
            )

        message.content = content
        message.edited_timestamp = datetime.utcnow()

        session.add(message)
        session.commit()
        session.refresh(message)

        logger.info(f"User {current_user.id} edited message {message_id}")
        return message

@router.get(
    "/{message_id}",
    response_model=MessageRead,
    responses={404: {"description": "Message not found"}, 429: {"description": "Rate limit exceeded"}}
)
async def get_message(request: Request, message_id: int, current_user=Depends(get_current_user)):
    logger.debug(f"User {current_user.id} fetching message ID {message_id}")
    with Session(engine) as session:
        msg = session.get(Message, message_id)
        if not msg:
            logger.warning(f"Message ID {message_id} not found")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")
        if msg.sender_id != current_user.id and msg.recipient_id != current_user.id:
            logger.warning(f"User {current_user.id} unauthorized to access message ID {message_id}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
        logger.info(f"User {current_user.id} retrieved message ID {message_id}")
        return msg
