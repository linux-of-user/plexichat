# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime
from typing import Any, Dict, List, Optional


from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from plexichat.app.logger_config import logger
from plexichat.app.models.message import MessageType
from plexichat.app.models.user import User
from plexichat.app.services.enhanced_messaging_service import EnhancedMessagingService
from plexichat.features.users.models import User
from plexichat.infrastructure.utils.auth import get_current_user


# Pydantic models for API requests/responses
class MessageCreateRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000, description="Message content")
    recipient_id: Optional[int] = Field(None, description="Direct message recipient")
    channel_id: Optional[int] = Field(None, description="Channel ID for channel messages")
    guild_id: Optional[int] = Field(None, description="Guild ID")
    message_type: Optional[str] = Field("default", description="Message type")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    is_system: Optional[bool] = Field(False, description="System message flag")


class ReplyCreateRequest(BaseModel):
    original_message_id: int = Field(..., description="ID of message being replied to")
    content: str = Field(..., min_length=1, max_length=4000, description="Reply content")
    recipient_id: Optional[int] = Field(None, description="Override recipient")
    channel_id: Optional[int] = Field(None, description="Override channel")
    guild_id: Optional[int] = Field(None, description="Override guild")


class ReactionRequest(BaseModel):
    emoji: str = Field(..., description="Emoji to react with")
    emoji_id: Optional[int] = Field(None, description="Custom emoji ID")


class MessageEditRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=4000, description="New message content")


class MessageSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Search query")
    channel_id: Optional[int] = Field(None, description="Limit to channel")
    guild_id: Optional[int] = Field(None, description="Limit to guild")
    sender_id: Optional[int] = Field(None, description="Limit to sender")
    has_emoji: Optional[bool] = Field(None, description="Filter by emoji presence")
    limit: Optional[int] = Field(50, ge=1, le=100, description="Result limit")


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
    is_system: bool
    referenced_message_id: Optional[int]
    reactions: Optional[List[Dict[str, Any]]] = None
    replies_count: Optional[int] = None
    emoji_count: Optional[int] = None
    has_emoji: Optional[bool] = None


class MessageContextResponse(BaseModel):
    message: MessageResponse
    reactions: List[Dict[str, Any]]
    replies: List[MessageResponse]
    referenced_message: Optional[MessageResponse]
    emoji_count: int
    has_emoji: bool


class EmojiStatsResponse(BaseModel):
    total_messages: int
    messages_with_emoji: int
    emoji_usage_rate: float
    unique_emojis: int
    total_emoji_uses: int
    top_emojis: List[Dict[str, Any]]


# Create router
router = APIRouter(prefix="/api/v1/messaging", tags=["Enhanced Messaging"])


@router.post("/send", response_model=MessageResponse)
async def send_message(
    request: MessageCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """Send a message with emoji support and processing."""
    try:
        message = await EnhancedMessagingService.send_message(
            sender_id=current_user.id,
            content=request.content,
            recipient_id=request.recipient_id,
            channel_id=request.channel_id,
            guild_id=request.guild_id,
            message_type=getattr(MessageType, request.message_type.upper(), MessageType.DEFAULT),
            metadata=request.metadata or {},
            is_system=request.is_system
        )

        if not message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to send message"
            )

        # Get emoji info
        emoji_count = len(EmojiService.extract_emojis(message.content or ""))
        has_emoji = EmojiService.has_emoji(message.content or "")

        return MessageResponse(
            id=message.id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            channel_id=message.channel_id,
            guild_id=message.guild_id,
            content=message.content,
            message_type=message.type.value if hasattr(message.type, 'value') else str(message.type),
            timestamp=message.timestamp,
            edited_timestamp=message.edited_timestamp,
            is_edited=message.is_edited,
            is_deleted=message.is_deleted,
            is_system=message.is_system,
            referenced_message_id=message.referenced_message_id,
            emoji_count=emoji_count,
            has_emoji=has_emoji
        )

    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/reply", response_model=MessageResponse)
async def send_reply(
    request: ReplyCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """Send a reply to a message."""
    try:
        reply = await EnhancedMessagingService.send_reply(
            sender_id=current_user.id,
            original_message_id=request.original_message_id,
            content=request.content,
            recipient_id=request.recipient_id,
            channel_id=request.channel_id,
            guild_id=request.guild_id
        )

        if not reply:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to send reply"
            )

        # Get emoji info
        emoji_count = len(EmojiService.extract_emojis(reply.content or ""))
        has_emoji = EmojiService.has_emoji(reply.content or "")

        return MessageResponse(
            id=reply.id,
            sender_id=reply.sender_id,
            recipient_id=reply.recipient_id,
            channel_id=reply.channel_id,
            guild_id=reply.guild_id,
            content=reply.content,
            message_type=reply.type.value if hasattr(reply.type, 'value') else str(reply.type),
            timestamp=reply.timestamp,
            edited_timestamp=reply.edited_timestamp,
            is_edited=reply.is_edited,
            is_deleted=reply.is_deleted,
            is_system=reply.is_system,
            referenced_message_id=reply.referenced_message_id,
            emoji_count=emoji_count,
            has_emoji=has_emoji
        )

    except Exception as e:
        logger.error(f"Failed to send reply: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/messages/{message_id}/reactions")
async def add_reaction(
    message_id: int,
    request: ReactionRequest,
    current_user: User = Depends(get_current_user)
):
    """Add a reaction to a message."""
    try:
        success = await EnhancedMessagingService.add_reaction(
            message_id=message_id,
            user_id=current_user.id,
            emoji=request.emoji
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to add reaction (already exists or rate limited)"
            )

        return {"success": True, "message": "Reaction added successfully"}

    except Exception as e:
        logger.error(f"Failed to add reaction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.delete("/messages/{message_id}/reactions")
async def remove_reaction(
    message_id: int,
    emoji: str = Query(..., description="Emoji to remove"),
    current_user: User = Depends(get_current_user)
):
    """Remove a reaction from a message."""
    try:
        success = await EnhancedMessagingService.remove_reaction(
            message_id=message_id,
            user_id=current_user.id,
            emoji=emoji
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reaction not found"
            )

        return {"success": True, "message": "Reaction removed successfully"}

    except Exception as e:
        logger.error(f"Failed to remove reaction: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/messages", response_model=List[MessageResponse])
async def get_messages(
    channel_id: Optional[int] = Query(None, description="Filter by channel"),
    guild_id: Optional[int] = Query(None, description="Filter by guild"),
    sender_id: Optional[int] = Query(None, description="Filter by sender"),
    recipient_id: Optional[int] = Query(None, description="Filter by recipient"),
    limit: int = Query(50, ge=1, le=100, description="Number of messages to return"),
    current_user: User = Depends(get_current_user)
):
    """Get messages with filters."""
    try:
        messages = await EnhancedMessagingService.get_messages(
            channel_id=channel_id,
            guild_id=guild_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            limit=limit,
            user_id=current_user.id
        )

        response_messages = []
        for message in messages:
            emoji_count = EmojiService.count_emojis(message.content or "")
            has_emoji = EmojiService.has_emoji(message.content or "")

            response_messages.append(MessageResponse(
                id=message.id,
                sender_id=message.sender_id,
                recipient_id=message.recipient_id,
                channel_id=message.channel_id,
                guild_id=message.guild_id,
                content=message.content,
                message_type=message.type.value if hasattr(message.type, 'value') else str(message.type),
                timestamp=message.timestamp,
                edited_timestamp=message.edited_timestamp,
                is_edited=message.is_edited,
                is_deleted=message.is_deleted,
                is_system=message.is_system,
                referenced_message_id=message.referenced_message_id,
                emoji_count=emoji_count,
                has_emoji=has_emoji
            ))

        return response_messages

    except Exception as e:
        logger.error(f"Failed to get messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/messages/{message_id}", response_model=MessageContextResponse)
async def get_message_context(
    message_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get a message with its full context (reactions, replies, referenced message)."""
    try:
        context = await EnhancedMessagingService.get_message_with_context(message_id)

        if not context or not context.get('message'):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )

        message = context['message']

        # Convert message to response format
        message_response = MessageResponse(
            id=message.id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            channel_id=message.channel_id,
            guild_id=message.guild_id,
            content=message.content,
            message_type=message.type.value if hasattr(message.type, 'value') else str(message.type),
            timestamp=message.timestamp,
            edited_timestamp=message.edited_timestamp,
            is_edited=message.is_edited,
            is_deleted=message.is_deleted,
            is_system=message.is_system,
            referenced_message_id=message.referenced_message_id
        )

        # Convert replies to response format
        reply_responses = []
        for reply in context.get('replies', []):
            reply_responses.append(MessageResponse(
                id=reply.id,
                sender_id=reply.sender_id,
                recipient_id=reply.recipient_id,
                channel_id=reply.channel_id,
                guild_id=reply.guild_id,
                content=reply.content,
                message_type=reply.type.value if hasattr(reply.type, 'value') else str(reply.type),
                timestamp=reply.timestamp,
                edited_timestamp=reply.edited_timestamp,
                is_edited=reply.is_edited,
                is_deleted=reply.is_deleted,
                is_system=reply.is_system,
                referenced_message_id=reply.referenced_message_id
            ))

        # Convert referenced message if exists
        referenced_response = None
        if context.get('referenced_message'):
            ref_msg = context['referenced_message']
            referenced_response = MessageResponse(
                id=ref_msg.id,
                sender_id=ref_msg.sender_id,
                recipient_id=ref_msg.recipient_id,
                channel_id=ref_msg.channel_id,
                guild_id=ref_msg.guild_id,
                content=ref_msg.content,
                message_type=ref_msg.type.value if hasattr(ref_msg.type, 'value') else str(ref_msg.type),
                timestamp=ref_msg.timestamp,
                edited_timestamp=ref_msg.edited_timestamp,
                is_edited=ref_msg.is_edited,
                is_deleted=ref_msg.is_deleted,
                is_system=ref_msg.is_system,
                referenced_message_id=ref_msg.referenced_message_id
            )

        return MessageContextResponse(
            message=message_response,
            reactions=context.get('reactions', []),
            replies=reply_responses,
            referenced_message=referenced_response,
            emoji_count=context.get('emoji_count', 0),
            has_emoji=context.get('has_emoji', False)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get message context: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.put("/messages/{message_id}", response_model=MessageResponse)
async def edit_message(
    message_id: int,
    request: MessageEditRequest,
    current_user: User = Depends(get_current_user)
):
    """Edit a message."""
    try:
        message = await EnhancedMessagingService.edit_message(
            message_id=message_id,
            user_id=current_user.id,
            new_content=request.content
        )

        if not message:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found or permission denied"
            )

        # Get emoji info
        emoji_count = len(EmojiService.extract_emojis(message.content or ""))
        has_emoji = EmojiService.has_emoji(message.content or "")

        return MessageResponse(
            id=message.id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            channel_id=message.channel_id,
            guild_id=message.guild_id,
            content=message.content,
            message_type=message.type.value if hasattr(message.type, 'value') else str(message.type),
            timestamp=message.timestamp,
            edited_timestamp=message.edited_timestamp,
            is_edited=message.is_edited,
            is_deleted=message.is_deleted,
            is_system=message.is_system,
            referenced_message_id=message.referenced_message_id,
            emoji_count=emoji_count,
            has_emoji=has_emoji
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to edit message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.delete("/messages/{message_id}")
async def delete_message(
    message_id: int,
    force: bool = Query(False, description="Force hard delete (admin only)"),
    current_user: User = Depends(get_current_user)
):
    """Delete a message."""
    try:
        # Check admin permission for force delete
        if force and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin permission required for force delete"
            )

        success = await EnhancedMessagingService.delete_message(
            message_id=message_id,
            user_id=current_user.id,
            force=force
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found or permission denied"
            )

        return {"success": True, "message": "Message deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/search", response_model=List[MessageResponse])
async def search_messages(
    request: MessageSearchRequest,
    current_user: User = Depends(get_current_user)
):
    """Search messages with text and emoji filtering."""
    try:
        messages = await EnhancedMessagingService.search_messages(
            query=request.query,
            channel_id=request.channel_id,
            guild_id=request.guild_id,
            sender_id=request.sender_id,
            has_emoji=request.has_emoji,
            limit=request.limit
        )

        response_messages = []
        for message in messages:
            emoji_count = len(EmojiService.extract_emojis(message.content or ""))
            has_emoji = EmojiService.has_emoji(message.content or "")

            response_messages.append(MessageResponse(
                id=message.id,
                sender_id=message.sender_id,
                recipient_id=message.recipient_id,
                channel_id=message.channel_id,
                guild_id=message.guild_id,
                content=message.content,
                message_type=message.type.value if hasattr(message.type, 'value') else str(message.type),
                timestamp=message.timestamp,
                edited_timestamp=message.edited_timestamp,
                is_edited=message.is_edited,
                is_deleted=message.is_deleted,
                is_system=message.is_system,
                referenced_message_id=message.referenced_message_id,
                emoji_count=emoji_count,
                has_emoji=has_emoji
            ))

        return response_messages

    except Exception as e:
        logger.error(f"Failed to search messages: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/emojis/custom")
async def get_custom_emojis(
    guild_id: Optional[int] = Query(None, description="Filter by guild"),
    current_user: User = Depends(get_current_user)
):
    """Get custom emojis."""
    try:
        emojis = await EmojiService.get_custom_emojis(guild_id=guild_id)
        return {"emojis": emojis}

    except Exception as e:
        logger.error(f"Failed to get custom emojis: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/emojis/shortcodes")
async def get_emoji_shortcodes():
    """Get available emoji shortcodes."""
    try:
        return {
            "shortcodes": EmojiService.EMOJI_SHORTCODES,
            "count": len(EmojiService.EMOJI_SHORTCODES)
        }

    except Exception as e:
        logger.error(f"Failed to get emoji shortcodes: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.get("/statistics/emojis", response_model=EmojiStatsResponse)
async def get_emoji_statistics(
    channel_id: Optional[int] = Query(None, description="Filter by channel"),
    guild_id: Optional[int] = Query(None, description="Filter by guild"),
    days: Optional[int] = Query(30, ge=1, le=365, description="Days to analyze"),
    current_user: User = Depends(get_current_user)
):
    """Get emoji usage statistics."""
    try:
        stats = await EnhancedMessagingService.get_emoji_statistics(
            channel_id=channel_id,
            guild_id=guild_id,
            days=days
        )

        if not stats:
            return EmojiStatsResponse(
                total_messages=0,
                messages_with_emoji=0,
                emoji_usage_rate=0.0,
                unique_emojis=0,
                total_emoji_uses=0,
                top_emojis=[]
            )

        return EmojiStatsResponse(**stats)

    except Exception as e:
        logger.error(f"Failed to get emoji statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
