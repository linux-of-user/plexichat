from typing import Any
import json
from datetime import datetime, timezone

from plexichat.core.messaging.system import Message, MessageMetadata, MessageType
from plexichat.core.logging import get_logger

logger = get_logger(__name__)

# Mock optimizer for now if not available
class Optimizer:
    def register_function(self, *args, **kwargs):
        pass

optimizer = Optimizer()

class MessageService:
    """Central service that implements the shared message logic.

    This is intentionally generic so both API and Web routers can delegate
    without losing any behavior. Extend with hooks for persistence, moderation,
    encryption, etc., preserving existing features.
    """

    def __init__(self) -> None:
        self._history_enabled = True

    def format_message(self, data: dict[str, Any]) -> dict[str, Any]:
        content = str(data.get("content", ""))
        sender = data.get("sender")
        channel = data.get("channel")
        msg_type_str = data.get("type", "text")
        
        # Map string type to enum
        try:
            message_type = MessageType(msg_type_str)
        except ValueError:
            message_type = MessageType.TEXT

        # Create metadata
        metadata = MessageMetadata(
            message_id="", # Generated later or passed in
            sender_id=sender,
            channel_id=channel,
            message_type=message_type,
            timestamp=datetime.now(timezone.utc)
        )

        msg = Message(
            metadata=metadata,
            content=content,
            attachments=data.get("attachments", []),
            reactions=data.get("reactions", {}),
            mentions=data.get("mentions", [])
        )
        
        # Calculate checksum (mock or real)
        checksum = self._calculate_checksum(msg)

        result = {
            "content": msg.content,
            "sender": msg.metadata.sender_id,
            "channel": msg.metadata.channel_id,
            "type": msg.metadata.message_type.value,
            "timestamp": msg.metadata.timestamp.isoformat(),
            "checksum": checksum,
        }
        logger.debug("Formatted message: %s", result)
        return result

    def _calculate_checksum(self, msg: Message) -> str:
        """Calculate message checksum."""
        # TODO: Implement actual checksum logic
        return "checksum_placeholder"

    async def save_if_enabled(self, formatted: dict[str, Any]) -> None:
        if not self._history_enabled:
            return
        # Hook for persistence; safe no-op default to avoid feature loss
        try:
            # e.g., await message_repository.save(formatted)
            logger.debug(
                "Persisting message (noop hook): %s", formatted.get("checksum")
            )
        except Exception as e:
            logger.warning("Message persistence hook failed: %s", e)

    def enable_history(self, enabled: bool) -> None:
        self._history_enabled = enabled


    async def get_message_by_id(self, message_id: int) -> Message | None:
        """Get message by ID."""
        from plexichat.core.database.manager import database_manager
        
        try:
            query = "SELECT * FROM messages WHERE id = :id"
            result = await database_manager.fetch_one(query, {"id": message_id})
            if result:
                # Map DB result to Message object
                # Note: This assumes Message dataclass structure matches DB columns roughly
                # or we map manually.
                # For now, we'll return a Message object with metadata populated
                try:
                    msg_type = MessageType(result.get("message_type", "text"))
                except ValueError:
                    msg_type = MessageType.TEXT
                    
                metadata = MessageMetadata(
                    message_id=str(result["id"]),
                    sender_id=str(result["user_id"]),
                    channel_id=str(result["channel_id"]),
                    message_type=msg_type,
                    timestamp=result["created_at"] if isinstance(result["created_at"], datetime) else datetime.fromisoformat(str(result["created_at"]))
                )
                
                msg = Message(
                    metadata=metadata,
                    content=result["content"],
                    attachments=json.loads(result.get("attachments") or "[]") if isinstance(result.get("attachments"), str) else (result.get("attachments") or []),
                    reactions={}, # TODO: Load reactions
                    mentions=[] # TODO: Load mentions
                )
                # Attach custom fields if they exist in DB (not in standard schema yet)
                if "custom_fields" in result:
                     msg.custom_fields = json.loads(result["custom_fields"]) if isinstance(result["custom_fields"], str) else result["custom_fields"]
                else:
                     msg.custom_fields = {}
                     
                return msg
            return None
        except Exception as e:
            logger.error(f"Error getting message {message_id}: {e}")
            return None

    async def update_message(self, message_id: int, sender_id: int, update_data: Any) -> bool:
        """Update a message."""
        from plexichat.core.database.manager import database_manager
        
        try:
            # Construct update query
            # This is a basic implementation
            query = "UPDATE messages SET content = :content, edited_at = :edited_at WHERE id = :id AND user_id = :user_id"
            params = {
                "content": update_data.content if hasattr(update_data, "content") else str(update_data),
                "edited_at": datetime.now(timezone.utc),
                "id": message_id,
                "user_id": sender_id
            }
            
            await database_manager.execute_query(query, params)
            return True
        except Exception as e:
            logger.error(f"Error updating message {message_id}: {e}")
            return False

# Singleton-like shared instance
message_service = MessageService()
