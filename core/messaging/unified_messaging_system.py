from .base import MessageBaseProcessor
import asyncio
import logging
from typing import Callable, Any, dict
from ..errors.base import PlexiError
from ..security.encryption import decrypt_message  # For unified-specific decryption
from ..database.storage import update_message_storage  # Assuming unified storage pattern

logger = logging.getLogger(__name__)

class UnifiedMessagingProcessor(MessageBaseProcessor):
    def __init__(self):
        super().__init__()
        self.name = "UnifiedMessagingProcessor"

    def _get_processor(self, msg_type: str) -> Callable[[dict], Any]:
        # Unified routing for various message types, e.g., integrate with storage
        if msg_type in ['unified_text', 'encrypted', 'multimedia']:
            return self._process_unified_message
        else:
            raise PlexiError(f"Unsupported unified message type: {msg_type}")

    async def _process_unified_message(self, message: dict) -> dict:
        """Type-specific processing for unified messages with storage integration."""
        content = message.get('content', '')
        if not content:
            raise PlexiError("Unified content required")
        
        processed = {
            'type': message['type'],
            'content': content,
            'timestamp': asyncio.get_event_loop().time(),
            'sender': message.get('sender', 'unknown'),
            'unified_id': message.get('unified_id', 'default')
        }
        
        logger.debug(f"Processed unified message of type {message['type']}")
        return processed

    async def _process_message(self, message: dict) -> Any:
        """Override base for additional unified-specific decryption."""
        # Call base processing first
        processed = await super()._process_message(message)
        
        # Additional decryption for unified messages if encrypted
        if 'encrypted' in message.get('flags', []):
            if 'content' in processed:
                processed['content'] = decrypt_message(processed['content'])
        
        # Unified storage pattern
        await update_message_storage(processed)
        
        logger.info(f"Unified processing complete for message {processed.get('unified_id', 'unknown')}")
        return processed

    async def start(self) -> None:
        """Start the unified processing loop."""
        logger.info(f"Starting {self.name}")
        await self._processing_loop()