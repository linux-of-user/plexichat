from datetime import datetime
import hashlib
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from plexichat.core.messaging.system import get_messaging_system


# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}


router = APIRouter(prefix="/messages", tags=["Messages"])

# In-memory storage for demonstration
messages_db: dict[str, dict] = {}


class MessageCreate(BaseModel):
    recipient_id: str
    content: str = Field(..., max_length=10000)
    thread_id: str | None = None
    reply_to: str | None = None


class MessageCreate(BaseModel):
    recipient_id: str
    content: str = Field(..., max_length=10000)


class MessageResponse(BaseModel):
    id: str
    sender_id: str
    recipient_id: str
    content: str
    timestamp: datetime
    reactions: dict[str, list[str]] | None = None


class ReactionCreate(BaseModel):
    emoji: str = Field(..., max_length=10, description="Emoji to react with")


class ReactionResponse(BaseModel):
    emoji: str
    users: list[str]
    count: int


@router.post("/send", response_model=MessageResponse)
async def send_message(
    message_data: MessageCreate, current_user: dict = Depends(get_current_user)
):
    """Send a message to another user or in a thread."""
    messaging_system = get_messaging_system()

    # Determine if this is a direct message or thread message
    if message_data.thread_id:
        # Send message in thread
        success, message_id_or_error, message = (
            await messaging_system.send_thread_message(
                sender_id=current_user["id"],
                thread_id=message_data.thread_id,
                content=message_data.content,
                reply_to=message_data.reply_to,
            )
        )
    else:
        # Send direct message
        success, message_id_or_error, message = await messaging_system.send_message(
            sender_id=current_user["id"],
            channel_id=message_data.recipient_id,  # Using recipient_id as channel_id for now
            content=message_data.content,
            reply_to=message_data.reply_to,
            thread_id=message_data.thread_id,
        )

    if not success:
        raise HTTPException(status_code=400, detail=message_id_or_error)

    return MessageResponse(
        id=message_id_or_error,
        sender_id=current_user["id"],
        recipient_id=message_data.recipient_id,
        content=message_data.content,
        timestamp=datetime.now(),
        reactions=None,
    )


def encrypt_message(content: str) -> str:
    """Simulates message encryption."""
    return hashlib.sha256(content.encode()).hexdigest()


@router.post("/send", response_model=MessageResponse)
async def send_message(
    message_data: MessageCreate, current_user: dict = Depends(get_current_user)
):
    """Send a message to another user."""
    sender_id = current_user["id"]
    if message_data.recipient_id == sender_id:
        raise HTTPException(
            status_code=400, detail="Cannot send a message to yourself."
        )

    message_id = str(uuid4())
    timestamp = datetime.now()

    # In a real app, content would be properly encrypted and stored.
    message_record = {
        "id": message_id,
        "sender_id": sender_id,
        "recipient_id": message_data.recipient_id,
        "content": message_data.content,  # Storing raw content for simplicity
        "timestamp": timestamp,
        "reactions": {},
    }
    messages_db[message_id] = message_record

    return MessageResponse(**message_record)


@router.get("/conversation/{other_user_id}", response_model=list[MessageResponse])
async def get_conversation(
    other_user_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    """Get messages in a conversation with another user."""
    user_id = current_user["id"]

    conversation = []
    for msg in messages_db.values():
        if (msg["sender_id"] == user_id and msg["recipient_id"] == other_user_id) or (
            msg["sender_id"] == other_user_id and msg["recipient_id"] == user_id
        ):
            # Ensure reactions field exists
            if "reactions" not in msg:
                msg["reactions"] = {}
            conversation.append(MessageResponse(**msg))

    conversation.sort(key=lambda m: m.timestamp)

    return conversation[offset : offset + limit]


@router.delete("/{message_id}")
async def delete_message(
    message_id: str, current_user: dict = Depends(get_current_user)
):
    """Delete a message."""
    message = messages_db.get(message_id)
    if not message or message["sender_id"] != current_user["id"]:
        raise HTTPException(
            status_code=404, detail="Message not found or not owned by user."
        )

    del messages_db[message_id]
    return {"message": "Message deleted"}


@router.post("/{message_id}/reactions", response_model=ReactionResponse)
async def add_reaction(
    message_id: str,
    reaction: ReactionCreate,
    current_user: dict = Depends(get_current_user),
):
    """Add a reaction to a message."""
    messaging_system = get_messaging_system()

    # Check if message exists
    if message_id not in messaging_system.messages:
        raise HTTPException(status_code=404, detail="Message not found")

    message = messaging_system.messages[message_id]
    user_id = current_user["id"]

    # Check if user can react (basic permission - user is in the channel or is sender/recipient)
    # For now, allow if user is not the sender (to prevent self-reactions)
    if message.metadata.sender_id == user_id:
        raise HTTPException(status_code=403, detail="Cannot react to your own message")

    # Add reaction
    emoji = reaction.emoji
    if emoji not in message.reactions:
        message.reactions[emoji] = []

    if user_id not in message.reactions[emoji]:
        message.reactions[emoji].append(user_id)

    # Update message in storage
    message.metadata.update_timestamp()

    # Broadcast reaction update via WebSocket
    from plexichat.core.websocket.websocket_manager import send_to_channel

    reaction_update = {
        "type": "reaction_added",
        "message_id": message_id,
        "emoji": emoji,
        "user_id": user_id,
        "timestamp": datetime.now().isoformat(),
    }
    await send_to_channel(message.metadata.channel_id, reaction_update)

    return ReactionResponse(
        emoji=emoji, users=message.reactions[emoji], count=len(message.reactions[emoji])
    )


@router.delete("/{message_id}/reactions/{emoji}")
async def remove_reaction(
    message_id: str, emoji: str, current_user: dict = Depends(get_current_user)
):
    """Remove a reaction from a message."""
    messaging_system = get_messaging_system()

    # Check if message exists
    if message_id not in messaging_system.messages:
        raise HTTPException(status_code=404, detail="Message not found")

    message = messaging_system.messages[message_id]
    user_id = current_user["id"]

    # Check if reaction exists
    if emoji not in message.reactions or user_id not in message.reactions[emoji]:
        raise HTTPException(status_code=404, detail="Reaction not found")

    # Remove reaction
    message.reactions[emoji].remove(user_id)
    if not message.reactions[emoji]:
        del message.reactions[emoji]

    # Update message timestamp
    message.metadata.update_timestamp()

    # Broadcast reaction update via WebSocket
    from plexichat.core.websocket.websocket_manager import send_to_channel

    reaction_update = {
        "type": "reaction_removed",
        "message_id": message_id,
        "emoji": emoji,
        "user_id": user_id,
        "timestamp": datetime.now().isoformat(),
    }
    await send_to_channel(message.metadata.channel_id, reaction_update)

    return {"message": "Reaction removed"}


@router.get("/{message_id}/reactions", response_model=list[ReactionResponse])
async def get_reactions(
    message_id: str, current_user: dict = Depends(get_current_user)
):
    """Get all reactions for a message."""
    messaging_system = get_messaging_system()

    # Check if message exists
    if message_id not in messaging_system.messages:
        raise HTTPException(status_code=404, detail="Message not found")

    message = messaging_system.messages[message_id]

    reactions = []
    for emoji, users in message.reactions.items():
        reactions.append(ReactionResponse(emoji=emoji, users=users, count=len(users)))

    return reactions


if __name__ == "__main__":
    # Example of how to run this API with uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
