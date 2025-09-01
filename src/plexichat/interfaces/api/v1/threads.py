import json
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from plexichat.core.messaging.unified_messaging_system import get_messaging_system, MessageType

# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}

router = APIRouter(prefix="/threads", tags=["Threads"])

class ThreadCreate(BaseModel):
    title: str = Field(..., max_length=200, description="Thread title")
    channel_id: str = Field(..., description="Channel ID where thread belongs")
    parent_message_id: Optional[str] = Field(None, description="Parent message ID if replying to a message")

class ThreadResponse(BaseModel):
    thread_id: str
    title: str
    channel_id: str
    creator_id: str
    parent_message_id: Optional[str]
    is_resolved: bool
    participant_count: int
    message_count: int
    last_message_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    participants: List[str]

class ThreadMessageCreate(BaseModel):
    content: str = Field(..., max_length=10000, description="Message content")
    message_type: str = Field("text", description="Message type")
    reply_to: Optional[str] = Field(None, description="Reply to message ID")

@router.post("/", response_model=ThreadResponse)
async def create_thread(thread_data: ThreadCreate, current_user: dict = Depends(get_current_user)):
    """Create a new thread."""
    messaging_system = get_messaging_system()

    success, thread_id_or_error, thread = await messaging_system.create_thread(
        title=thread_data.title,
        channel_id=thread_data.channel_id,
        creator_id=current_user["id"],
        parent_message_id=thread_data.parent_message_id
    )

    if not success:
        raise HTTPException(status_code=400, detail=thread_id_or_error)

    return ThreadResponse(
        thread_id=thread.thread_id,
        title=thread.title,
        channel_id=thread.channel_id,
        creator_id=thread.creator_id,
        parent_message_id=thread.parent_message_id,
        is_resolved=thread.is_resolved,
        participant_count=thread.participant_count,
        message_count=thread.message_count,
        last_message_at=thread.last_message_at,
        created_at=thread.created_at,
        updated_at=thread.updated_at,
        participants=list(thread.participants)
    )

@router.get("/{thread_id}", response_model=ThreadResponse)
async def get_thread(thread_id: str, current_user: dict = Depends(get_current_user)):
    """Get a thread by ID."""
    messaging_system = get_messaging_system()
    thread = messaging_system.get_thread(thread_id)

    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    return ThreadResponse(
        thread_id=thread.thread_id,
        title=thread.title,
        channel_id=thread.channel_id,
        creator_id=thread.creator_id,
        parent_message_id=thread.parent_message_id,
        is_resolved=thread.is_resolved,
        participant_count=thread.participant_count,
        message_count=thread.message_count,
        last_message_at=thread.last_message_at,
        created_at=thread.created_at,
        updated_at=thread.updated_at,
        participants=list(thread.participants)
    )

@router.get("/channel/{channel_id}", response_model=List[ThreadResponse])
async def get_channel_threads(
    channel_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get all threads in a channel."""
    messaging_system = get_messaging_system()
    threads = messaging_system.get_channel_threads(channel_id)

    # Apply pagination
    paginated_threads = threads[offset:offset + limit]

    return [
        ThreadResponse(
            thread_id=thread.thread_id,
            title=thread.title,
            channel_id=thread.channel_id,
            creator_id=thread.creator_id,
            parent_message_id=thread.parent_message_id,
            is_resolved=thread.is_resolved,
            participant_count=thread.participant_count,
            message_count=thread.message_count,
            last_message_at=thread.last_message_at,
            created_at=thread.created_at,
            updated_at=thread.updated_at,
            participants=list(thread.participants)
        )
        for thread in paginated_threads
    ]

@router.post("/{thread_id}/messages")
async def send_thread_message(
    thread_id: str,
    message_data: ThreadMessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Send a message in a thread."""
    messaging_system = get_messaging_system()

    success, message_id_or_error, message = await messaging_system.send_thread_message(
        sender_id=current_user["id"],
        thread_id=thread_id,
        content=message_data.content,
        message_type=MessageType(message_data.message_type),
        reply_to=message_data.reply_to
    )

    if not success:
        raise HTTPException(status_code=400, detail=message_id_or_error)

    return {
        "message_id": message_id_or_error,
        "thread_id": thread_id,
        "sender_id": current_user["id"],
        "content": message_data.content,
        "timestamp": message.metadata.timestamp.isoformat() if message else datetime.now().isoformat()
    }

@router.get("/{thread_id}/messages")
async def get_thread_messages(
    thread_id: str,
    limit: int = Query(50, ge=1, le=100),
    before_message_id: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """Get messages in a thread."""
    messaging_system = get_messaging_system()
    messages = await messaging_system.get_thread_messages(
        thread_id=thread_id,
        limit=limit,
        before_message_id=before_message_id
    )

    return [
        {
            "message_id": msg.metadata.message_id,
            "sender_id": msg.metadata.sender_id,
            "content": msg.content,
            "timestamp": msg.metadata.timestamp.isoformat(),
            "message_type": msg.metadata.message_type.value,
            "thread_id": msg.metadata.thread_id,
            "reply_to": msg.metadata.reply_to,
            "reactions": msg.reactions,
            "attachments": msg.attachments
        }
        for msg in messages
    ]

@router.post("/{thread_id}/resolve")
async def resolve_thread(thread_id: str, current_user: dict = Depends(get_current_user)):
    """Mark a thread as resolved."""
    messaging_system = get_messaging_system()
    success = await messaging_system.resolve_thread(thread_id, current_user["id"])

    if not success:
        raise HTTPException(status_code=404, detail="Thread not found")

    return {"message": "Thread resolved successfully"}

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)