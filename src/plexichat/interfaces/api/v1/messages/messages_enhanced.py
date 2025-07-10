"""
Enhanced message API with file attachment support and comprehensive permissions.
Handles message creation, editing, deletion with proper file access validation.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from sqlmodel import Session, select
from pydantic import BaseModel

from plexichat.app.db import get_session
from plexichat.app.models.message import Message, MessageType
from plexichat.app.models.user import User
from plexichat.app.services.message_service import MessageService
from plexichat.app.utils.auth import get_current_user
from plexichat.app.logger_config import logger


# Pydantic models for API
class MessageCreateRequest(BaseModel):
    recipient_id: Optional[int] = None
    channel_id: Optional[int] = None
    guild_id: Optional[int] = None
    content: Optional[str] = None
    file_ids: Optional[List[int]] = None
    message_type: MessageType = MessageType.DEFAULT
    reply_to_id: Optional[int] = None
    expires_after_seconds: Optional[int] = None


class MessageUpdateRequest(BaseModel):
    content: Optional[str] = None
    add_file_ids: Optional[List[int]] = None
    remove_file_ids: Optional[List[int]] = None


class MessageResponse(BaseModel):
    id: int
    sender_id: Optional[int]
    recipient_id: Optional[int]
    channel_id: Optional[int]
    guild_id: Optional[int]
    content: Optional[str]
    message_type: str
    timestamp: datetime
    edited_timestamp: Optional[datetime]
    is_edited: bool
    is_deleted: bool
    attached_files: List[int]
    embedded_files: List[Dict[str, Any]]
    expires_at: Optional[datetime]
    accessible_files: Optional[List[Dict[str, Any]]] = None
    inaccessible_files: Optional[List[Dict[str, Any]]] = None


router = APIRouter(prefix="/api/v1/messages", tags=["Enhanced Messages"])


@router.post("/create", response_model=MessageResponse)
async def create_message(
    request: MessageCreateRequest,
    http_request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> MessageResponse:
    """Create a new message with optional file attachments."""
    message_service = MessageService(session)
    
    ip_address = http_request.client.host
    user_agent = http_request.headers.get("user-agent")
    
    message = await message_service.create_message_with_files(
        sender_id=current_user.id,
        recipient_id=request.recipient_id,
        channel_id=request.channel_id,
        guild_id=request.guild_id,
        content=request.content,
        file_ids=request.file_ids,
        message_type=request.message_type,
        reply_to_id=request.reply_to_id,
        expires_after_seconds=request.expires_after_seconds,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return MessageResponse(
        id=message.id,
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        channel_id=message.channel_id,
        guild_id=message.guild_id,
        content=message.content,
        message_type=message.type.value,
        timestamp=message.timestamp,
        edited_timestamp=message.edited_timestamp,
        is_edited=message.is_edited,
        is_deleted=message.is_deleted,
        attached_files=message.attached_files or [],
        embedded_files=message.embedded_files or [],
        expires_at=message.expires_at
    )


@router.get("/{message_id}", response_model=MessageResponse)
async def get_message(
    message_id: int,
    http_request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> MessageResponse:
    """Get a message with file access validation."""
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    
    # Check if user can access this message
    # For now, allow access if user is sender, recipient, or in the same channel/guild
    can_access = (
        message.sender_id == current_user.id or
        message.recipient_id == current_user.id or
        message.author_id == current_user.id
        # TODO: Add channel/guild membership checks
    )
    
    if not can_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot access this message"
        )
    
    # Validate file access
    message_service = MessageService(session)
    ip_address = http_request.client.host
    user_agent = http_request.headers.get("user-agent")
    
    file_access = await message_service.validate_message_file_access(
        message_id, current_user.id, ip_address, user_agent
    )
    
    return MessageResponse(
        id=message.id,
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        channel_id=message.channel_id,
        guild_id=message.guild_id,
        content=message.content,
        message_type=message.type.value,
        timestamp=message.timestamp,
        edited_timestamp=message.edited_timestamp,
        is_edited=message.is_edited,
        is_deleted=message.is_deleted,
        attached_files=message.attached_files or [],
        embedded_files=message.embedded_files or [],
        expires_at=message.expires_at,
        accessible_files=file_access["accessible_files"],
        inaccessible_files=file_access["inaccessible_files"]
    )


@router.put("/{message_id}", response_model=MessageResponse)
async def update_message(
    message_id: int,
    request: MessageUpdateRequest,
    http_request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> MessageResponse:
    """Update a message, including file attachments."""
    message_service = MessageService(session)
    
    ip_address = http_request.client.host
    user_agent = http_request.headers.get("user-agent")
    
    message = await message_service.update_message(
        message_id=message_id,
        user_id=current_user.id,
        content=request.content,
        add_file_ids=request.add_file_ids,
        remove_file_ids=request.remove_file_ids,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return MessageResponse(
        id=message.id,
        sender_id=message.sender_id,
        recipient_id=message.recipient_id,
        channel_id=message.channel_id,
        guild_id=message.guild_id,
        content=message.content,
        message_type=message.type.value,
        timestamp=message.timestamp,
        edited_timestamp=message.edited_timestamp,
        is_edited=message.is_edited,
        is_deleted=message.is_deleted,
        attached_files=message.attached_files or [],
        embedded_files=message.embedded_files or [],
        expires_at=message.expires_at
    )


@router.delete("/{message_id}")
async def delete_message(
    message_id: int,
    hard_delete: bool = Query(False),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> JSONResponse:
    """Delete a message (soft delete by default)."""
    message_service = MessageService(session)
    
    success = await message_service.delete_message(
        message_id=message_id,
        user_id=current_user.id,
        hard_delete=hard_delete
    )
    
    if success:
        return JSONResponse({
            "success": True,
            "message": "Message deleted successfully"
        })
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete message"
        )


@router.get("/{message_id}/file-access")
async def validate_message_file_access(
    message_id: int,
    http_request: Request,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Validate user's access to all files in a message."""
    message_service = MessageService(session)
    
    ip_address = http_request.client.host
    user_agent = http_request.headers.get("user-agent")
    
    return await message_service.validate_message_file_access(
        message_id, current_user.id, ip_address, user_agent
    )


@router.get("/")
async def list_messages(
    recipient_id: Optional[int] = Query(None),
    channel_id: Optional[int] = Query(None),
    guild_id: Optional[int] = Query(None),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    include_deleted: bool = Query(False),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user)
) -> List[MessageResponse]:
    """List messages with optional filtering."""
    # Build query
    statement = select(Message)
    
    # Apply filters
    if recipient_id:
        statement = statement.where(
            (Message.sender_id == current_user.id) & (Message.recipient_id == recipient_id) |
            (Message.sender_id == recipient_id) & (Message.recipient_id == current_user.id)
        )
    elif channel_id:
        statement = statement.where(Message.channel_id == channel_id)
    elif guild_id:
        statement = statement.where(Message.guild_id == guild_id)
    else:
        # Default to messages involving current user
        statement = statement.where(
            (Message.sender_id == current_user.id) | 
            (Message.recipient_id == current_user.id) |
            (Message.author_id == current_user.id)
        )
    
    if not include_deleted:
        statement = statement.where(Message.is_deleted == False)
    
    statement = statement.order_by(Message.timestamp.desc()).offset(offset).limit(limit)
    
    messages = session.exec(statement).all()
    
    result = []
    for message in messages:
        result.append(MessageResponse(
            id=message.id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            channel_id=message.channel_id,
            guild_id=message.guild_id,
            content=message.content,
            message_type=message.type.value,
            timestamp=message.timestamp,
            edited_timestamp=message.edited_timestamp,
            is_edited=message.is_edited,
            is_deleted=message.is_deleted,
            attached_files=message.attached_files or [],
            embedded_files=message.embedded_files or [],
            expires_at=message.expires_at
        ))
    
    return result
