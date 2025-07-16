"""
PlexiChat Message Processor

Message processing with threading and performance optimization.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

try:
    from plexichat.core_system.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class MessageData:
    """Message data structure."""
    message_id: str
    sender_id: int
    recipient_id: Optional[int]
    channel_id: Optional[int]
    content: str
    message_type: str
    timestamp: datetime
    metadata: Dict[str, Any]

class MessageProcessor:
    """Message processor with threading support."""
    
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        self.message_queue = asyncio.Queue()
        self.processing = False
        self.processors = {
            "text": self._process_text_message,
            "image": self._process_image_message,
            "file": self._process_file_message,
            "system": self._process_system_message,
        }
    
    async def start_processing(self):
        """Start message processing loop."""
        if self.processing:
            return
        
        self.processing = True
        asyncio.create_task(self._processing_loop())
        logger.info("Message processor started")
    
    async def stop_processing(self):
        """Stop message processing."""
        self.processing = False
        logger.info("Message processor stopped")
    
    async def _processing_loop(self):
        """Main message processing loop."""
        while self.processing:
            try:
                # Get message from queue with timeout
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)
                
                # Process message in thread
                if self.async_thread_manager:
                    await self.async_thread_manager.run_in_thread(
                        self._process_message_sync, message
                    )
                else:
                    await self._process_message(message)
                
                self.message_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Message processing error: {e}")
    
    def _process_message_sync(self, message: MessageData):
        """Synchronous message processing for threading."""
        try:
            processor = self.processors.get(message.message_type, self._process_default_message)
            result = processor(message)
            
            if self.performance_logger:
                self.performance_logger.record_metric("messages_processed", 1, "count")
            
            return result
        except Exception as e:
            logger.error(f"Error processing message {message.message_id}: {e}")
            if self.performance_logger:
                self.performance_logger.record_metric("message_processing_errors", 1, "count")
            raise
    
    async def _process_message(self, message: MessageData):
        """Async message processing."""
        try:
            start_time = time.time()
            
            # Process based on message type
            processor = self.processors.get(message.message_type, self._process_default_message)
            
            if asyncio.iscoroutinefunction(processor):
                result = await processor(message)
            else:
                result = processor(message)
            
            # Store processed message
            await self._store_processed_message(message, result)
            
            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("message_processing_duration", duration, "seconds")
                self.performance_logger.record_metric("messages_processed", 1, "count")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing message {message.message_id}: {e}")
            if self.performance_logger:
                self.performance_logger.record_metric("message_processing_errors", 1, "count")
            raise
    
    def _process_text_message(self, message: MessageData) -> Dict[str, Any]:
        """Process text message."""
        try:
            # Extract mentions
            mentions = self._extract_mentions(message.content)
            
            # Extract hashtags
            hashtags = self._extract_hashtags(message.content)
            
            # Extract URLs
            urls = self._extract_urls(message.content)
            
            # Content analysis
            word_count = len(message.content.split())
            char_count = len(message.content)
            
            return {
                "processed_content": message.content,
                "mentions": mentions,
                "hashtags": hashtags,
                "urls": urls,
                "word_count": word_count,
                "char_count": char_count,
                "sentiment": self._analyze_sentiment(message.content)
            }
        except Exception as e:
            logger.error(f"Error processing text message: {e}")
            return {"error": str(e)}
    
    def _process_image_message(self, message: MessageData) -> Dict[str, Any]:
        """Process image message."""
        try:
            # Extract image metadata from message
            image_data = message.metadata.get("image", {})
            
            return {
                "image_url": image_data.get("url"),
                "image_size": image_data.get("size"),
                "image_type": image_data.get("type"),
                "alt_text": image_data.get("alt_text", ""),
                "processed": True
            }
        except Exception as e:
            logger.error(f"Error processing image message: {e}")
            return {"error": str(e)}
    
    def _process_file_message(self, message: MessageData) -> Dict[str, Any]:
        """Process file message."""
        try:
            # Extract file metadata
            file_data = message.metadata.get("file", {})
            
            return {
                "file_name": file_data.get("name"),
                "file_size": file_data.get("size"),
                "file_type": file_data.get("type"),
                "file_url": file_data.get("url"),
                "virus_scan_status": "pending",
                "processed": True
            }
        except Exception as e:
            logger.error(f"Error processing file message: {e}")
            return {"error": str(e)}
    
    def _process_system_message(self, message: MessageData) -> Dict[str, Any]:
        """Process system message."""
        try:
            return {
                "system_type": message.metadata.get("system_type", "unknown"),
                "processed": True,
                "timestamp": message.timestamp.isoformat()
            }
        except Exception as e:
            logger.error(f"Error processing system message: {e}")
            return {"error": str(e)}
    
    def _process_default_message(self, message: MessageData) -> Dict[str, Any]:
        """Default message processing."""
        return {
            "message_type": message.message_type,
            "processed": True,
            "content_length": len(message.content)
        }
    
    def _extract_mentions(self, content: str) -> List[str]:
        """Extract @mentions from content."""
        import re
        mentions = re.findall(r'@(\w+)', content)
        return list(set(mentions))
    
    def _extract_hashtags(self, content: str) -> List[str]:
        """Extract #hashtags from content."""
        import re
        hashtags = re.findall(r'#(\w+)', content)
        return list(set(hashtags))
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content."""
        import re
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        return list(set(urls))
    
    def _analyze_sentiment(self, content: str) -> str:
        """Basic sentiment analysis."""
        positive_words = ["good", "great", "awesome", "excellent", "love", "like", "happy"]
        negative_words = ["bad", "terrible", "awful", "hate", "dislike", "sad", "angry"]
        
        content_lower = content.lower()
        positive_count = sum(1 for word in positive_words if word in content_lower)
        negative_count = sum(1 for word in negative_words if word in content_lower)
        
        if positive_count > negative_count:
            return "positive"
        elif negative_count > positive_count:
            return "negative"
        else:
            return "neutral"
    
    async def _store_processed_message(self, message: MessageData, result: Dict[str, Any]):
        """Store processed message to database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO processed_messages (
                        message_id, sender_id, recipient_id, channel_id,
                        content, message_type, processed_data, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "message_id": message.message_id,
                    "sender_id": message.sender_id,
                    "recipient_id": message.recipient_id,
                    "channel_id": message.channel_id,
                    "content": message.content,
                    "message_type": message.message_type,
                    "processed_data": json.dumps(result),
                    "timestamp": message.timestamp
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing processed message: {e}")
    
    async def queue_message(self, message: MessageData):
        """Queue message for processing."""
        await self.message_queue.put(message)
        
        if self.performance_logger:
            self.performance_logger.record_metric("messages_queued", 1, "count")
    
    async def process_message_immediate(self, message: MessageData) -> Dict[str, Any]:
        """Process message immediately without queuing."""
        return await self._process_message(message)
    
    def get_queue_size(self) -> int:
        """Get current queue size."""
        return self.message_queue.qsize()
    
    def get_status(self) -> Dict[str, Any]:
        """Get processor status."""
        return {
            "processing": self.processing,
            "queue_size": self.get_queue_size(),
            "supported_types": list(self.processors.keys())
        }

# Global message processor
message_processor = MessageProcessor()

# Convenience functions
async def queue_message(message_id: str, sender_id: int, content: str, message_type: str = "text", **kwargs):
    """Queue message for processing."""
    message = MessageData(
        message_id=message_id,
        sender_id=sender_id,
        recipient_id=kwargs.get("recipient_id"),
        channel_id=kwargs.get("channel_id"),
        content=content,
        message_type=message_type,
        timestamp=datetime.now(),
        metadata=kwargs.get("metadata", {})
    )
    await message_processor.queue_message(message)

async def process_message_now(message_id: str, sender_id: int, content: str, message_type: str = "text", **kwargs):
    """Process message immediately."""
    message = MessageData(
        message_id=message_id,
        sender_id=sender_id,
        recipient_id=kwargs.get("recipient_id"),
        channel_id=kwargs.get("channel_id"),
        content=content,
        message_type=message_type,
        timestamp=datetime.now(),
        metadata=kwargs.get("metadata", {})
    )
    return await message_processor.process_message_immediate(message)
