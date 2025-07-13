from datetime import datetime
from typing import List, Optional


from ...core.logging import get_logger
from ...services.communication_service import (

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ...core.auth.dependencies import from plexichat.infrastructure.utils.auth import require_admin_auth, require_auth

"""
PlexiChat Advanced Communication API Endpoints

REST API endpoints for advanced communication features including
voice messages, reactions, threads, translations, and smart notifications.
"""

    NotificationPriority,
    ReactionType,
    ThreadStatus,
    get_communication_service,
)

# Initialize router and logger
router = APIRouter(prefix="/communication", tags=["Advanced Communication"])
logger = get_logger(__name__)

# Pydantic Models

class VoiceMessageResponse(BaseModel):
    """Voice message response model."""
    message_id: str
    user_id: str
    chat_id: str
    duration: float
    transcript: Optional[str] = None
    is_transcribed: bool = False
    created_at: datetime
    
    class Config:
        from_attributes = True

class CreateReactionRequest(BaseModel):
    """Create reaction request model."""
    message_id: str = Field(..., description="ID of the message to react to")
    reaction_type: ReactionType = Field(..., description="Type of reaction")

class ReactionResponse(BaseModel):
    """Reaction response model."""
    reaction_id: str
    message_id: str
    user_id: str
    reaction_type: ReactionType
    created_at: datetime
    
    class Config:
        from_attributes = True

class CreateThreadRequest(BaseModel):
    """Create thread request model."""
    parent_message_id: str = Field(..., description="ID of the parent message")
    chat_id: str = Field(..., description="ID of the chat")
    title: Optional[str] = Field(None, description="Optional thread title")

class ThreadResponse(BaseModel):
    """Thread response model."""
    thread_id: str
    parent_message_id: str
    chat_id: str
    title: Optional[str]
    status: ThreadStatus
    participants: List[str]
    message_count: int
    last_activity: datetime
    created_at: datetime
    created_by: Optional[str]
    
    class Config:
        from_attributes = True

class TranslateMessageRequest(BaseModel):
    """Translate message request model."""
    message_id: str = Field(..., description="ID of the message to translate")
    original_text: str = Field(..., description="Original text to translate")
    target_language: str = Field(..., description="Target language code")
    source_language: str = Field("auto", description="Source language code")

class TranslationResponse(BaseModel):
    """Translation response model."""
    request_id: str
    message_id: str
    user_id: str
    source_language: str
    target_language: str
    original_text: str
    translated_text: Optional[str]
    confidence_score: Optional[float]
    created_at: datetime
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class CreateNotificationRequest(BaseModel):
    """Create notification request model."""
    message_id: str = Field(..., description="ID of the related message")
    chat_id: str = Field(..., description="ID of the chat")
    title: str = Field(..., description="Notification title")
    content: str = Field(..., description="Notification content")
    priority: NotificationPriority = Field(NotificationPriority.NORMAL, description="Notification priority")

class NotificationResponse(BaseModel):
    """Notification response model."""
    notification_id: str
    user_id: str
    message_id: str
    chat_id: str
    priority: NotificationPriority
    title: str
    content: str
    ai_summary: Optional[str]
    action_required: bool
    read: bool
    delivered: bool
    created_at: datetime
    scheduled_for: Optional[datetime]
    expires_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# Voice Message Endpoints

@router.post("/voice-messages", response_model=VoiceMessageResponse)
async def create_voice_message(
    chat_id: str = Form(...),
    audio_file: UploadFile = File(...),
    current_user: dict = Depends(require_auth)
):
    """Create a new voice message."""
    try:
        communication_service = await get_communication_service()
        
        # Validate audio file
        if not audio_file.content_type.startswith('audio/'):
            raise HTTPException(status_code=400, detail="File must be an audio file")
        
        # Read audio data
        audio_data = await audio_file.read()
        
        # Estimate duration (simplified - in real implementation, use audio library)
        duration = len(audio_data) / 16000  # Rough estimate
        
        # Create voice message
        voice_message = await communication_service.create_voice_message(
            user_id=current_user["user_id"],
            chat_id=chat_id,
            audio_data=audio_data,
            duration=duration
        )
        
        return VoiceMessageResponse.from_orm(voice_message)
        
    except Exception as e:
        logger.error(f"Failed to create voice message: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create voice message: {str(e)}")

@router.get("/voice-messages/{message_id}", response_model=VoiceMessageResponse)
async def get_voice_message(
    message_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get voice message by ID."""
    try:
        communication_service = await get_communication_service()
        
        voice_message = await communication_service.get_voice_message(message_id)
        if not voice_message:
            raise HTTPException(status_code=404, detail="Voice message not found")
        
        return VoiceMessageResponse.from_orm(voice_message)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get voice message: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get voice message: {str(e)}")

@router.get("/voice-messages/{message_id}/audio")
async def get_voice_message_audio(
    message_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get voice message audio file."""
    try:
        communication_service = await get_communication_service()
        
        voice_message = await communication_service.get_voice_message(message_id)
        if not voice_message:
            raise HTTPException(status_code=404, detail="Voice message not found")
        
        return FileResponse(
            voice_message.file_path,
            media_type="audio/wav",
            filename=f"voice_message_{message_id}.wav"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get voice message audio: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get voice message audio: {str(e)}")

# Reaction Endpoints

@router.post("/reactions", response_model=ReactionResponse)
async def add_reaction(
    request: CreateReactionRequest,
    current_user: dict = Depends(require_auth)
):
    """Add reaction to a message."""
    try:
        communication_service = await get_communication_service()
        
        reaction = await communication_service.add_reaction(
            message_id=request.message_id,
            user_id=current_user["user_id"],
            reaction_type=request.reaction_type
        )
        
        return ReactionResponse.from_orm(reaction)
        
    except Exception as e:
        logger.error(f"Failed to add reaction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add reaction: {str(e)}")

@router.delete("/reactions/{message_id}/{reaction_type}")
async def remove_reaction(
    message_id: str,
    reaction_type: ReactionType,
    current_user: dict = Depends(require_auth)
):
    """Remove reaction from a message."""
    try:
        communication_service = await get_communication_service()
        
        success = await communication_service.remove_reaction(
            message_id=message_id,
            user_id=current_user["user_id"],
            reaction_type=reaction_type
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Reaction not found")
        
        return {"message": "Reaction removed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove reaction: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove reaction: {str(e)}")

@router.get("/reactions/{message_id}", response_model=List[ReactionResponse])
async def get_message_reactions(
    message_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get all reactions for a message."""
    try:
        communication_service = await get_communication_service()
        
        reactions = await communication_service.get_message_reactions(message_id)
        
        return [ReactionResponse.from_orm(reaction) for reaction in reactions]
        
    except Exception as e:
        logger.error(f"Failed to get message reactions: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get message reactions: {str(e)}")

# Thread Endpoints

@router.post("/threads", response_model=ThreadResponse)
async def create_thread(
    request: CreateThreadRequest,
    current_user: dict = Depends(require_auth)
):
    """Create a new message thread."""
    try:
        communication_service = await get_communication_service()
        
        thread = await communication_service.create_thread(
            parent_message_id=request.parent_message_id,
            chat_id=request.chat_id,
            user_id=current_user["user_id"],
            title=request.title
        )
        
        return ThreadResponse.from_orm(thread)
        
    except Exception as e:
        logger.error(f"Failed to create thread: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create thread: {str(e)}")

@router.get("/threads/{thread_id}", response_model=ThreadResponse)
async def get_thread(
    thread_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get thread by ID."""
    try:
        communication_service = await get_communication_service()
        
        thread = await communication_service.get_thread(thread_id)
        if not thread:
            raise HTTPException(status_code=404, detail="Thread not found")
        
        return ThreadResponse.from_orm(thread)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get thread: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get thread: {str(e)}")

@router.post("/threads/{thread_id}/participants/{user_id}")
async def add_thread_participant(
    thread_id: str,
    user_id: str,
    current_user: dict = Depends(require_auth)
):
    """Add participant to thread."""
    try:
        communication_service = await get_communication_service()
        
        success = await communication_service.add_thread_participant(thread_id, user_id)
        if not success:
            raise HTTPException(status_code=404, detail="Thread not found")
        
        return {"message": "Participant added successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add thread participant: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add thread participant: {str(e)}")

@router.put("/threads/{thread_id}/status")
async def update_thread_status(
    thread_id: str,
    status: ThreadStatus,
    current_user: dict = Depends(require_auth)
):
    """Update thread status."""
    try:
        communication_service = await get_communication_service()
        
        success = await communication_service.update_thread_status(thread_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Thread not found")
        
        return {"message": "Thread status updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update thread status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update thread status: {str(e)}")

@router.get("/chats/{chat_id}/threads", response_model=List[ThreadResponse])
async def get_chat_threads(
    chat_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get all threads for a chat."""
    try:
        communication_service = await get_communication_service()
        
        threads = await communication_service.get_chat_threads(chat_id)
        
        return [ThreadResponse.from_orm(thread) for thread in threads]
        
    except Exception as e:
        logger.error(f"Failed to get chat threads: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get chat threads: {str(e)}")

# Translation Endpoints

@router.post("/translations", response_model=TranslationResponse)
async def translate_message(
    request: TranslateMessageRequest,
    current_user: dict = Depends(require_auth)
):
    """Translate a message."""
    try:
        communication_service = await get_communication_service()
        
        translation = await communication_service.translate_message(
            message_id=request.message_id,
            user_id=current_user["user_id"],
            original_text=request.original_text,
            target_language=request.target_language,
            source_language=request.source_language
        )
        
        return TranslationResponse.from_orm(translation)
        
    except Exception as e:
        logger.error(f"Failed to translate message: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to translate message: {str(e)}")

@router.get("/translations/{request_id}", response_model=TranslationResponse)
async def get_translation(
    request_id: str,
    current_user: dict = Depends(require_auth)
):
    """Get translation by request ID."""
    try:
        communication_service = await get_communication_service()
        
        translation = await communication_service.get_translation(request_id)
        if not translation:
            raise HTTPException(status_code=404, detail="Translation not found")
        
        return TranslationResponse.from_orm(translation)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get translation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get translation: {str(e)}")

# Notification Endpoints

@router.post("/notifications", response_model=NotificationResponse)
async def create_notification(
    request: CreateNotificationRequest,
    target_user_id: str = Query(..., description="Target user ID for the notification"),
    current_user: dict = Depends(require_auth)
):
    """Create a smart notification."""
    try:
        communication_service = await get_communication_service()
        
        notification = await communication_service.create_smart_notification(
            user_id=target_user_id,
            message_id=request.message_id,
            chat_id=request.chat_id,
            title=request.title,
            content=request.content,
            priority=request.priority
        )
        
        return NotificationResponse.from_orm(notification)
        
    except Exception as e:
        logger.error(f"Failed to create notification: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create notification: {str(e)}")

@router.get("/notifications", response_model=List[NotificationResponse])
async def get_user_notifications(
    unread_only: bool = Query(False, description="Return only unread notifications"),
    current_user: dict = Depends(require_auth)
):
    """Get notifications for the current user."""
    try:
        communication_service = await get_communication_service()
        
        notifications = await communication_service.get_user_notifications(
            user_id=current_user["user_id"],
            unread_only=unread_only
        )
        
        return [NotificationResponse.from_orm(notification) for notification in notifications]
        
    except Exception as e:
        logger.error(f"Failed to get user notifications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user notifications: {str(e)}")

@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(require_auth)
):
    """Mark notification as read."""
    try:
        communication_service = await get_communication_service()
        
        success = await communication_service.mark_notification_read(
            notification_id=notification_id,
            user_id=current_user["user_id"]
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        return {"message": "Notification marked as read"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark notification as read: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to mark notification as read: {str(e)}")

# Admin Endpoints

@router.get("/admin/stats", dependencies=[Depends(from plexichat.infrastructure.utils.auth import require_admin_auth)])
async def get_communication_stats():
    """Get communication service statistics (admin only)."""
    try:
        communication_service = await get_communication_service()
        
        health_status = await communication_service.get_health_status()
        
        return {
            "service_status": health_status,
            "supported_languages": communication_service.supported_languages,
            "max_voice_duration": communication_service.max_voice_duration,
            "voice_storage_path": str(communication_service.voice_storage_path)
        }
        
    except Exception as e:
        logger.error(f"Failed to get communication stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get communication stats: {str(e)}")

# Export router
__all__ = ["router"]
