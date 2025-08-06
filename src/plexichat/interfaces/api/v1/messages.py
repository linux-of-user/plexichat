"""
PlexiChat API v1 - Messaging Endpoints

Simple messaging system with:
- Send messages
- Receive messages
- Message history
- Message deletion
- Basic encryption
"""

import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
import logging

from .auth import get_current_user

# Import database service layer
try:
    from plexichat.core.services.database_service import get_database_service
    DATABASE_SERVICE_AVAILABLE = True
except ImportError:
    DATABASE_SERVICE_AVAILABLE = False
    async def get_database_service(): return None

# Import caching system
try:
    from plexichat.core.caching.unified_cache_integration import (
        cache_get, cache_set, cache_delete, CacheKeyBuilder
    )
    CACHE_AVAILABLE = True
except ImportError:
    # Fallback if cache not available
    async def cache_get(key: str, default=None): return default
    async def cache_set(key: str, value, ttl=None): return True
    async def cache_delete(key: str): return True
    class CacheKeyBuilder:
        @staticmethod
        def message_key(msg_id: str, suffix: str = ""): return f"msg:{msg_id}:{suffix}"
        @staticmethod
        def conversation_key(user1: str, user2: str): return f"conv:{min(user1, user2)}:{max(user1, user2)}"
        @staticmethod
        def user_conversations_key(user_id: str): return f"user_conv:{user_id}"
        @staticmethod
        def message_stats_key(user_id: str): return f"msg_stats:{user_id}"
    CACHE_AVAILABLE = False

# Fallback in-memory storage (for backward compatibility)
messages_db = {}
users_db = {}

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/messages", tags=["Messages"])

# In-memory message storage
messages_db = {}

# Models
class MessageCreate(BaseModel):
    recipient_id: str
    content: str = Field(..., max_length=10000)
    message_type: str = "text"
    encrypted: bool = True

class MessageResponse(BaseModel):
    id: str
    sender_id: str
    recipient_id: str
    content: str
    message_type: str
    encrypted: bool
    timestamp: datetime
    read: bool = False

class ConversationSummary(BaseModel):
    user_id: str
    username: str
    display_name: str
    last_message: Optional[str]
    last_message_time: Optional[datetime]
    unread_count: int

# Utility functions
def encrypt_message(content: str) -> str:
    """Simple encryption for demo (use proper encryption in production)."""
    # Simple hash-based encryption for demo
    return hashlib.sha256(content.encode()).hexdigest()

def decrypt_message(encrypted_content: str, original_content: str) -> str:
    """Simple decryption for demo."""
    # In real app, would properly decrypt
    return original_content

async def check_message_permission(sender_id: str, recipient_id: str) -> dict:
    """Check if sender can send message to recipient based on privacy settings."""
    try:
        # Get recipient's settings (fallback implementation)
        recipient_settings = await get_user_settings_by_id(recipient_id)
        if not recipient_settings:
            # If no settings found, allow by default
            return {"allowed": True, "permission_level": "default"}

        message_permission = recipient_settings.get("message_permissions", "friends_only")

        # Check permission based on setting
        if message_permission == "everyone":
            return {"allowed": True, "permission_level": "everyone"}

        elif message_permission == "friends_only":
            # Check if they are friends (simplified check for demo)
            is_friend = await check_friendship(sender_id, recipient_id)
            return {
                "allowed": is_friend,
                "reason": "Only friends can send messages to this user" if not is_friend else None,
                "permission_level": "friends_only"
            }

        elif message_permission == "verified_only":
            # Check if sender is verified
            is_verified = await check_user_verified(sender_id)
            return {
                "allowed": is_verified,
                "reason": "Only verified users can send messages to this user" if not is_verified else None,
                "permission_level": "verified_only"
            }

        elif message_permission == "contacts_only":
            # Check if they are in contacts
            is_contact = await check_contact(sender_id, recipient_id)
            return {
                "allowed": is_contact,
                "reason": "Only contacts can send messages to this user" if not is_contact else None,
                "permission_level": "contacts_only"
            }

        elif message_permission == "nobody":
            return {
                "allowed": False,
                "reason": "This user has disabled incoming messages",
                "permission_level": "nobody"
            }

        else:
            return {"allowed": True, "permission_level": "default"}  # Default allow

    except Exception as e:
        logger.error(f"Error checking message permission: {e}")
        # On error, allow by default to avoid breaking functionality
        return {"allowed": True, "permission_level": "error_fallback"}

async def get_user_settings_by_id(user_id: str) -> dict:
    """Get user settings by user ID."""
    # Simplified implementation - in real app would query database
    # For demo, return default settings that allow friends only
    return {
        "message_permissions": "friends_only",
        "blocked_users": []
    }

async def check_friendship(user1_id: str, user2_id: str) -> bool:
    """Check if two users are friends."""
    # Simplified implementation for demo
    # In real app, would check friends/contacts table
    return True  # For testing, assume everyone is friends

async def check_user_verified(user_id: str) -> bool:
    """Check if a user is verified."""
    # Simplified implementation for demo
    return True  # For testing, assume all users are verified

async def check_contact(user1_id: str, user2_id: str) -> bool:
    """Check if two users are contacts."""
    # Simplified implementation for demo
    return True  # For testing, assume everyone is a contact

# Endpoints
@router.post("/send", response_model=MessageResponse)
async def send_message(
    message_data: MessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a message to another user using database service."""
    try:
        db_service = await get_database_service()

        # Validate recipient exists
        recipient = await db_service.get_user(message_data.recipient_id)
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not found")

        # Can't send message to yourself
        if message_data.recipient_id == current_user['id']:
            raise HTTPException(status_code=400, detail="Cannot send message to yourself")

        # Check privacy settings - can sender send message to recipient?
        sender_id = current_user['id']
        privacy_check = await check_message_permission(sender_id, message_data.recipient_id)

        if not privacy_check["allowed"]:
            reason = privacy_check.get("reason", "Message not allowed by recipient's privacy settings")
            raise HTTPException(status_code=403, detail=reason)

        # Create message
        message_id = str(uuid4())
        content = message_data.content
        encrypted_content = encrypt_message(content) if message_data.encrypted else content

        message_data_dict = {
            'id': message_id,
            'sender_id': current_user['id'],
            'recipient_id': message_data.recipient_id,
            'content': encrypted_content,
            'original_content': content,  # Keep for search/display
            'message_type': message_data.message_type,
            'encrypted': message_data.encrypted,
            'created_at': datetime.now(),
            'read': False,
            'deleted': False
        }

        # Save to database
        created_id = await db_service.create_message(message_data_dict)
        if not created_id:
            raise HTTPException(status_code=500, detail="Failed to save message")

        # Fallback: also save to in-memory for backward compatibility
        messages_db[message_id] = message_data_dict

        # Invalidate relevant caches
        sender_id = current_user['id']
        recipient_id = message_data.recipient_id

        # Invalidate conversation caches for both users
        await cache_delete(CacheKeyBuilder.user_conversations_key(sender_id))
        await cache_delete(CacheKeyBuilder.user_conversations_key(recipient_id))

        # Invalidate message stats for both users
        await cache_delete(CacheKeyBuilder.message_stats_key(sender_id))
        await cache_delete(CacheKeyBuilder.message_stats_key(recipient_id))

        # Invalidate conversation pages cache
        conv_key_prefix = CacheKeyBuilder.conversation_key(sender_id, recipient_id)
        # Note: In a real implementation, you'd want to invalidate all pages
        # For now, we'll invalidate the first page which is most commonly accessed
        await cache_delete(f"{conv_key_prefix}:page:0:50")

        logger.info(f"Message sent: {message_id} from {current_user['username']} to {message_data.recipient_id}")
        logger.debug(f"Invalidated caches for message send: {sender_id} -> {recipient_id}")

        return MessageResponse(
            id=message_id,
            sender_id=current_user['id'],
            recipient_id=message_data.recipient_id,
            content=content,  # Return decrypted content to sender
            message_type=message_data.message_type,
            encrypted=message_data.encrypted,
            timestamp=message_data_dict['created_at'],
            read=False
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@router.get("/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    """Get list of conversations for current user with caching and database service."""
    try:
        user_id = current_user['id']

        # Try to get from cache first
        cache_key = CacheKeyBuilder.user_conversations_key(user_id)
        cached_conversations = await cache_get(cache_key)
        if cached_conversations is not None:
            logger.debug(f"Cache hit for conversations: {user_id}")
            return cached_conversations

        db_service = await get_database_service()

        # Get conversations from database service
        conversations = await db_service.get_user_conversations(user_id)

        # Add unread count and last message for each conversation
        for conv in conversations:
            other_user_id = conv['user_id']

            # Get recent messages to calculate unread count and last message
            recent_messages = await db_service.get_messages_for_conversation(
                user_id, other_user_id, limit=50, offset=0
            )

            unread_count = 0
            last_message = None

            for msg in reversed(recent_messages):  # Most recent first
                if not last_message:
                    last_message = msg.get('original_content', '')[:100]

                if msg.get('recipient_id') == user_id and not msg.get('read'):
                    unread_count += 1

            conv['last_message'] = last_message
            conv['unread_count'] = unread_count

        # Sort by last message time (most recent first)
        conversations.sort(
            key=lambda x: x.get('last_message_time') or datetime.min,
            reverse=True
        )

        result = {
            "conversations": conversations,
            "count": len(conversations)
        }

        # Cache the result for 5 minutes (conversations change frequently)
        await cache_set(cache_key, result, ttl=300)
        logger.debug(f"Cached conversations for user: {user_id}")

        return result

    except Exception as e:
        logger.error(f"Get conversations error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get conversations")

@router.get("/conversation/{other_user_id}")
async def get_conversation(
    other_user_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get messages in a conversation with another user using database service and caching."""
    try:
        db_service = await get_database_service()

        # Validate other user exists
        other_user = await db_service.get_user(other_user_id)
        if not other_user:
            raise HTTPException(status_code=404, detail="User not found")

        user_id = current_user['id']

        # Generate cache key for this specific conversation page
        cache_key = f"{CacheKeyBuilder.conversation_key(user_id, other_user_id)}:page:{offset}:{limit}"

        # Get messages from database service
        conversation_messages = await db_service.get_messages_for_conversation(
            user_id, other_user_id, limit, offset
        )

        # Check if there are unread messages that need to be marked as read
        has_unread = any(
            msg.get('recipient_id') == user_id and not msg.get('read')
            for msg in conversation_messages
        )

        # Try cache only if no unread messages
        if not has_unread:
            cached_result = await cache_get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for conversation: {user_id} <-> {other_user_id}")
                return cached_result

        # Mark messages as read if current user is recipient
        messages_marked_read = False
        for message in conversation_messages:
            if message.get('recipient_id') == user_id and not message.get('read'):
                # Update in database (simplified - in production you'd batch this)
                # For now, just mark in memory
                message['read'] = True
                messages_marked_read = True

        # Format response
        response_messages = []
        for message in conversation_messages:
            content = message.get('original_content', '')
            if message.get('encrypted'):
                content = decrypt_message(message.get('content', ''), message.get('original_content', ''))

            # Handle timestamp field (could be 'timestamp' or 'created_at')
            timestamp = message.get('timestamp') or message.get('created_at')

            response_messages.append(MessageResponse(
                id=message['id'],
                sender_id=message['sender_id'],
                recipient_id=message['recipient_id'],
                content=content,
                message_type=message.get('message_type', 'text'),
                encrypted=message.get('encrypted', False),
                timestamp=timestamp,
                read=message.get('read', False)
            ))

        # Get total count (for pagination)
        # In a real implementation, you'd get this from a separate count query
        total = len(conversation_messages) + offset  # Approximation

        result = {
            "messages": response_messages,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": len(conversation_messages) == limit,  # Has more if we got a full page
            "other_user": {
                "id": other_user_id,
                "username": other_user.get('username'),
                "display_name": other_user.get('display_name')
            }
        }

        # Cache the result if no messages were marked as read (10 minutes TTL)
        if not messages_marked_read:
            await cache_set(cache_key, result, ttl=600)
            logger.debug(f"Cached conversation page for: {user_id} <-> {other_user_id}")

        # If messages were marked as read, invalidate related caches
        if messages_marked_read:
            await cache_delete(CacheKeyBuilder.user_conversations_key(user_id))
            await cache_delete(CacheKeyBuilder.message_stats_key(user_id))
            logger.debug(f"Invalidated caches due to read status update: {user_id}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get conversation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get conversation")

@router.delete("/{message_id}")
async def delete_message(
    message_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a message."""
    try:
        if message_id not in messages_db:
            raise HTTPException(status_code=404, detail="Message not found")
        
        message = messages_db[message_id]
        
        # Only sender can delete message
        if message['sender_id'] != current_user['id']:
            raise HTTPException(status_code=403, detail="Not authorized to delete this message")
        
        # Mark as deleted instead of actually deleting
        message['deleted'] = True
        message['deleted_at'] = datetime.now()

        # Invalidate relevant caches
        sender_id = message['sender_id']
        recipient_id = message['recipient_id']

        # Invalidate conversation caches for both users
        await cache_delete(CacheKeyBuilder.user_conversations_key(sender_id))
        await cache_delete(CacheKeyBuilder.user_conversations_key(recipient_id))

        # Invalidate message stats for both users
        await cache_delete(CacheKeyBuilder.message_stats_key(sender_id))
        await cache_delete(CacheKeyBuilder.message_stats_key(recipient_id))

        # Invalidate conversation pages cache
        conv_key_prefix = CacheKeyBuilder.conversation_key(sender_id, recipient_id)
        await cache_delete(f"{conv_key_prefix}:page:0:50")

        logger.info(f"Message deleted: {message_id} by {current_user['username']}")
        logger.debug(f"Invalidated caches for message deletion: {sender_id} <-> {recipient_id}")

        return {
            "success": True,
            "message": "Message deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete message")

@router.get("/stats")
async def get_message_stats(current_user: dict = Depends(get_current_user)):
    """Get messaging statistics with caching."""
    try:
        user_id = current_user['id']

        # Try to get from cache first
        cache_key = CacheKeyBuilder.message_stats_key(user_id)
        cached_stats = await cache_get(cache_key)
        if cached_stats is not None:
            logger.debug(f"Cache hit for message stats: {user_id}")
            return cached_stats

        sent_count = sum(1 for m in messages_db.values()
                        if m['sender_id'] == user_id and not m.get('deleted'))
        received_count = sum(1 for m in messages_db.values()
                           if m['recipient_id'] == user_id and not m.get('deleted'))
        unread_count = sum(1 for m in messages_db.values()
                          if m['recipient_id'] == user_id and not m['read'] and not m.get('deleted'))

        stats = {
            "sent_messages": sent_count,
            "received_messages": received_count,
            "unread_messages": unread_count,
            "total_messages": len([m for m in messages_db.values() if not m.get('deleted')])
        }

        # Cache for 2 minutes (stats change frequently)
        await cache_set(cache_key, stats, ttl=120)
        logger.debug(f"Cached message stats for user: {user_id}")

        return stats

    except Exception as e:
        logger.error(f"Get message stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get message stats")
