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

from .auth import get_current_user, users_db

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

# Endpoints
@router.post("/send", response_model=MessageResponse)
async def send_message(
    message_data: MessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a message to another user."""
    try:
        # Validate recipient exists
        if message_data.recipient_id not in users_db:
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Can't send message to yourself
        if message_data.recipient_id == current_user['id']:
            raise HTTPException(status_code=400, detail="Cannot send message to yourself")
        
        # Create message
        message_id = str(uuid4())
        content = message_data.content
        encrypted_content = encrypt_message(content) if message_data.encrypted else content
        
        message = {
            'id': message_id,
            'sender_id': current_user['id'],
            'recipient_id': message_data.recipient_id,
            'content': encrypted_content,
            'original_content': content,  # Keep for search/display
            'message_type': message_data.message_type,
            'encrypted': message_data.encrypted,
            'timestamp': datetime.now(),
            'read': False,
            'deleted': False
        }
        
        messages_db[message_id] = message
        
        logger.info(f"Message sent: {message_id} from {current_user['username']} to {message_data.recipient_id}")
        
        return MessageResponse(
            id=message_id,
            sender_id=current_user['id'],
            recipient_id=message_data.recipient_id,
            content=content,  # Return decrypted content to sender
            message_type=message_data.message_type,
            encrypted=message_data.encrypted,
            timestamp=message['timestamp'],
            read=False
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Send message error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@router.get("/conversations")
async def get_conversations(current_user: dict = Depends(get_current_user)):
    """Get list of conversations for current user."""
    try:
        user_id = current_user['id']
        conversations = {}
        
        # Find all users we've had conversations with
        for message in messages_db.values():
            if message.get('deleted'):
                continue
                
            other_user_id = None
            if message['sender_id'] == user_id:
                other_user_id = message['recipient_id']
            elif message['recipient_id'] == user_id:
                other_user_id = message['sender_id']
            
            if other_user_id and other_user_id in users_db:
                if other_user_id not in conversations:
                    conversations[other_user_id] = {
                        'user_id': other_user_id,
                        'username': users_db[other_user_id]['username'],
                        'display_name': users_db[other_user_id]['display_name'],
                        'last_message': None,
                        'last_message_time': None,
                        'unread_count': 0
                    }
                
                # Update with latest message info
                if (conversations[other_user_id]['last_message_time'] is None or 
                    message['timestamp'] > conversations[other_user_id]['last_message_time']):
                    conversations[other_user_id]['last_message'] = message['original_content'][:100]
                    conversations[other_user_id]['last_message_time'] = message['timestamp']
                
                # Count unread messages
                if message['recipient_id'] == user_id and not message['read']:
                    conversations[other_user_id]['unread_count'] += 1
        
        # Convert to list and sort by last message time
        conversation_list = list(conversations.values())
        conversation_list.sort(
            key=lambda x: x['last_message_time'] or datetime.min,
            reverse=True
        )
        
        return {
            "conversations": conversation_list,
            "count": len(conversation_list)
        }
        
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
    """Get messages in a conversation with another user."""
    try:
        if other_user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        user_id = current_user['id']
        conversation_messages = []
        
        # Find messages between these two users
        for message in messages_db.values():
            if message.get('deleted'):
                continue
                
            if ((message['sender_id'] == user_id and message['recipient_id'] == other_user_id) or
                (message['sender_id'] == other_user_id and message['recipient_id'] == user_id)):
                conversation_messages.append(message)
        
        # Sort by timestamp (oldest first)
        conversation_messages.sort(key=lambda x: x['timestamp'])
        
        # Apply pagination
        total = len(conversation_messages)
        paginated_messages = conversation_messages[offset:offset + limit]
        
        # Mark messages as read if current user is recipient
        for message in paginated_messages:
            if message['recipient_id'] == user_id and not message['read']:
                message['read'] = True
        
        # Format response
        response_messages = []
        for message in paginated_messages:
            content = message['original_content']
            if message['encrypted']:
                content = decrypt_message(message['content'], message['original_content'])
            
            response_messages.append(MessageResponse(
                id=message['id'],
                sender_id=message['sender_id'],
                recipient_id=message['recipient_id'],
                content=content,
                message_type=message['message_type'],
                encrypted=message['encrypted'],
                timestamp=message['timestamp'],
                read=message['read']
            ))
        
        return {
            "messages": response_messages,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total,
            "other_user": {
                "id": other_user_id,
                "username": users_db[other_user_id]['username'],
                "display_name": users_db[other_user_id]['display_name']
            }
        }
        
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
        
        logger.info(f"Message deleted: {message_id} by {current_user['username']}")
        
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
    """Get messaging statistics."""
    try:
        user_id = current_user['id']
        
        sent_count = sum(1 for m in messages_db.values() 
                        if m['sender_id'] == user_id and not m.get('deleted'))
        received_count = sum(1 for m in messages_db.values() 
                           if m['recipient_id'] == user_id and not m.get('deleted'))
        unread_count = sum(1 for m in messages_db.values() 
                          if m['recipient_id'] == user_id and not m['read'] and not m.get('deleted'))
        
        return {
            "sent_messages": sent_count,
            "received_messages": received_count,
            "unread_messages": unread_count,
            "total_messages": len([m for m in messages_db.values() if not m.get('deleted')])
        }
        
    except Exception as e:
        logger.error(f"Get message stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get message stats")
