from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from plexichat.core.authentication import get_auth_manager
from plexichat.core.messaging.unified_messaging_system import get_messaging_system
from plexichat.core.services.message_threads_service import get_message_threads_service

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user from token."""
    token = credentials.credentials

    auth_manager = get_auth_manager()
    valid, payload = await auth_manager.validate_token(token)

    if not valid or not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "id": payload.get("user_id"),
        "username": payload.get("username", ""),
        "permissions": payload.get("permissions", []),
        "roles": payload.get("roles", [])
    }

router = APIRouter(prefix="/threads", tags=["Threads"])

class ThreadCreate(BaseModel):
    title: str = Field(..., max_length=200, description="Thread title")
    parent_message_id: str | None = Field(None, description="Parent message ID if replying to a message")

class ThreadResponse(BaseModel):
    thread_id: str
    title: str
    channel_id: str | None
    creator_id: str
    parent_message_id: str | None
    is_resolved: bool
    participant_count: int
    message_count: int
    last_message_at: datetime | None
    created_at: datetime
    updated_at: datetime
    participants: list[str]

class ThreadMessageCreate(BaseModel):
    content: str = Field(..., max_length=10000, description="Message content")
    message_type: str = Field("text", description="Message type")
    reply_to: str | None = Field(None, description="Reply to message ID")

class ThreadUpdate(BaseModel):
    title: str = Field(..., max_length=200, description="New thread title")

@router.post("/", response_model=ThreadResponse)
async def create_thread(thread_data: ThreadCreate, current_user: dict = Depends(get_current_user)):
    """Create a new thread."""
    threads_service = get_message_threads_service()

    success, thread_id_or_error, thread = await threads_service.create_thread(
        parent_message_id=thread_data.parent_message_id,
        title=thread_data.title,
        creator_id=current_user["id"]
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

@router.get("/{thread_id}")
async def get_thread(thread_id: str, current_user: dict = Depends(get_current_user)):
    """Get a thread by ID with replies."""
    threads_service = get_message_threads_service()
    thread = await threads_service.get_thread(thread_id)

    if not thread:
        raise HTTPException(status_code=404, detail="Thread not found")

    # Get replies
    replies = await threads_service.get_thread_replies(thread_id, limit=50, offset=0)

    return {
        "thread": ThreadResponse(
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
        ),
        "replies": replies
    }

@router.get("/", response_model=list[ThreadResponse])
async def get_threads(
    channel_id: str = Query(..., description="Channel ID to filter threads"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get all threads in a channel."""
    threads_service = get_message_threads_service()
    threads = await threads_service.get_channel_threads(channel_id)

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

@router.post("/{thread_id}/replies")
async def add_reply(
    thread_id: str,
    message_data: ThreadMessageCreate,
    current_user: dict = Depends(get_current_user)
):
    """Add a reply to a thread."""
    threads_service = get_message_threads_service()

    success, reply_id_or_error = await threads_service.add_reply(
        thread_id=thread_id,
        message_content=message_data.content,
        user_id=current_user["id"]
    )

    if not success:
        raise HTTPException(status_code=400, detail=reply_id_or_error)

    return {
        "reply_id": reply_id_or_error,
        "thread_id": thread_id,
        "user_id": current_user["id"],
        "content": message_data.content,
        "timestamp": datetime.now().isoformat()
    }

@router.put("/{thread_id}")
async def update_thread_title(
    thread_id: str,
    thread_data: ThreadUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update thread title."""
    threads_service = get_message_threads_service()

    success = await threads_service.update_thread_title(
        thread_id=thread_id,
        new_title=thread_data.title,
        user_id=current_user["id"]
    )

    if not success:
        raise HTTPException(status_code=403, detail="Permission denied or thread not found")

    return {"message": "Thread title updated successfully"}

@router.delete("/{thread_id}")
async def delete_thread(thread_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a thread."""
    threads_service = get_message_threads_service()

    success = await threads_service.delete_thread(
        thread_id=thread_id,
        user_id=current_user["id"]
    )

    if not success:
        raise HTTPException(status_code=403, detail="Permission denied or thread not found")

    return {"message": "Thread deleted successfully"}


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
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
