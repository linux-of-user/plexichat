# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from typing import Optional
import logging

from plexichat.core.messaging.unified_messaging_system import get_messaging_system

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["Collaboration Chat"])

class TypingRequest(BaseModel):
    user_id: str
    channel_id: str

class MessageRequest(BaseModel):
    user_id: str
    channel_id: str
    content: str
    message_type: Optional[str] = "text"

@router.get("/messages")
def get_messages(channel_id: str = None):
    """Get chat messages for a channel."""
    try:
        messaging_system = get_messaging_system()
        if channel_id:
            # Get messages for specific channel
            messages = messaging_system.get_channel_messages(channel_id)
            return {"messages": messages, "channel_id": channel_id}
        else:
            # Return empty for now - could implement global messages later
            return {"messages": []}
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        raise HTTPException(status_code=500, detail="Failed to get messages")

@router.post("/typing/start")
async def start_typing(request: TypingRequest):
    """Start typing indicator for user in channel."""
    try:
        messaging_system = get_messaging_system()
        success = await messaging_system.handle_typing_start(request.user_id, request.channel_id)
        if success:
            return {"status": "success", "action": "typing_started", "user_id": request.user_id, "channel_id": request.channel_id}
        else:
            raise HTTPException(status_code=400, detail="Failed to start typing")
    except Exception as e:
        logger.error(f"Error starting typing: {e}")
        raise HTTPException(status_code=500, detail="Failed to start typing")

@router.post("/typing/stop")
async def stop_typing(request: TypingRequest):
    """Stop typing indicator for user in channel."""
    try:
        messaging_system = get_messaging_system()
        success = await messaging_system.handle_typing_stop(request.user_id, request.channel_id)
        if success:
            return {"status": "success", "action": "typing_stopped", "user_id": request.user_id, "channel_id": request.channel_id}
        else:
            raise HTTPException(status_code=400, detail="Failed to stop typing")
    except Exception as e:
        logger.error(f"Error stopping typing: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop typing")

@router.get("/typing/{channel_id}")
def get_typing_users(channel_id: str):
    """Get users currently typing in channel."""
    try:
        messaging_system = get_messaging_system()
        typing_users = messaging_system.get_typing_users(channel_id)
        return {"channel_id": channel_id, "typing_users": typing_users}
    except Exception as e:
        logger.error(f"Error getting typing users: {e}")
        raise HTTPException(status_code=500, detail="Failed to get typing users")

@router.post("/messages/send")
async def send_message(request: MessageRequest):
    """Send a message to a channel."""
    try:
        messaging_system = get_messaging_system()
        success, message_id, message = await messaging_system.send_message(
            sender_id=request.user_id,
            channel_id=request.channel_id,
            content=request.content,
            message_type=request.message_type or "text"
        )
        if success:
            return {"status": "success", "message_id": message_id, "message": message}
        else:
            raise HTTPException(status_code=400, detail=message_id)
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")