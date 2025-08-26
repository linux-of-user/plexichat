import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}

router = APIRouter(prefix="/messages", tags=["Messages"])

# In-memory storage for demonstration
messages_db: Dict[str, Dict] = {}

class MessageCreate(BaseModel):
    recipient_id: str
    content: str = Field(..., max_length=10000)

class MessageResponse(BaseModel):
    id: str
    sender_id: str
    recipient_id: str
    content: str
    timestamp: datetime

def encrypt_message(content: str) -> str:
    """Simulates message encryption."""
    return hashlib.sha256(content.encode()).hexdigest()

@router.post("/send", response_model=MessageResponse)
async def send_message(message_data: MessageCreate, current_user: dict = Depends(get_current_user)):
    """Send a message to another user."""
    sender_id = current_user["id"]
    if message_data.recipient_id == sender_id:
        raise HTTPException(status_code=400, detail="Cannot send a message to yourself.")

    message_id = str(uuid4())
    timestamp = datetime.now()

    # In a real app, content would be properly encrypted and stored.
    message_record = {
        "id": message_id,
        "sender_id": sender_id,
        "recipient_id": message_data.recipient_id,
        "content": message_data.content,  # Storing raw content for simplicity
        "timestamp": timestamp,
    }
    messages_db[message_id] = message_record

    return MessageResponse(**message_record)

@router.get("/conversation/{other_user_id}", response_model=List[MessageResponse])
async def get_conversation(
    other_user_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """Get messages in a conversation with another user."""
    user_id = current_user["id"]

    conversation = [
        MessageResponse(**msg) for msg in messages_db.values()
        if (msg["sender_id"] == user_id and msg["recipient_id"] == other_user_id) or \
           (msg["sender_id"] == other_user_id and msg["recipient_id"] == user_id)
    ]

    conversation.sort(key=lambda m: m.timestamp)

    return conversation[offset : offset + limit]

@router.delete("/{message_id}")
async def delete_message(message_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a message."""
    message = messages_db.get(message_id)
    if not message or message["sender_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Message not found or not owned by user.")
        
    del messages_db[message_id]
    return {"message": "Message deleted"}

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
