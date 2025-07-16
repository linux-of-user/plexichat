"""
PlexiChat Event Manager

Event management with threading and performance optimization.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass
from uuid import uuid4

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
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

class EventPriority(Enum):
    """Event priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Event:
    """Event data structure."""
    event_id: str
    event_type: str
    source: str
    timestamp: datetime
    priority: EventPriority
    data: Dict[str, Any]
    metadata: Dict[str, Any]
    processed: bool = False

@dataclass
class EventHandler:
    """Event handler registration."""
    handler_id: str
    event_type: str
    handler_func: Callable
    priority: int
    async_handler: bool
    filter_func: Optional[Callable] = None

class EventManager:
    """Event manager with threading support."""
    
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Event storage
        self.event_queue = asyncio.PriorityQueue()
        self.handlers: Dict[str, List[EventHandler]] = {}
        self.global_handlers: List[EventHandler] = []
        
        # Processing state
        self.processing = False
        self.processor_tasks: List[asyncio.Task] = []
        self.max_processors = 5
        
        # Statistics
        self.events_processed = 0
        self.events_failed = 0
        self.handlers_registered = 0
        self.total_processing_time = 0.0
    
    async def start_processing(self):
        """Start event processing."""
        if self.processing:
            return
        
        self.processing = True
        
        # Start processor tasks
        for i in range(self.max_processors):
            task = asyncio.create_task(self._processor_loop(f"processor_{i}"))
            self.processor_tasks.append(task)
        
        logger.info(f"Event processing started with {self.max_processors} processors")
    
    async def stop_processing(self):
        """Stop event processing."""
        if not self.processing:
            return
        
        self.processing = False
        
        # Cancel processor tasks
        for task in self.processor_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.processor_tasks:
            await asyncio.gather(*self.processor_tasks, return_exceptions=True)
        
        self.processor_tasks.clear()
        logger.info("Event processing stopped")
    
    async def _processor_loop(self, processor_name: str):
        """Event processor loop."""
        while self.processing:
            try:
                # Get event from queue with timeout
                try:
                    priority, event = await asyncio.wait_for(
                        self.event_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process event
                await self._process_event(event, processor_name)
                
                # Mark task done
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Processor {processor_name} error: {e}")
                await asyncio.sleep(1)
    
    async def _process_event(self, event: Event, processor_name: str):
        """Process a single event."""
        try:
            start_time = time.time()
            
            # Get handlers for event type
            event_handlers = self.handlers.get(event.event_type, [])
            all_handlers = event_handlers + self.global_handlers
            
            # Sort handlers by priority
            all_handlers.sort(key=lambda h: h.priority, reverse=True)
            
            # Process handlers
            results = []
            for handler in all_handlers:
                try:
                    # Apply filter if present
                    if handler.filter_func and not handler.filter_func(event):
                        continue
                    
                    # Execute handler
                    if handler.async_handler:
                        if self.async_thread_manager:
                            result = await self.async_thread_manager.run_in_thread(
                                self._execute_handler_sync, handler, event
                            )
                        else:
                            result = await self._execute_handler_async(handler, event)
                    else:
                        result = await self._execute_handler_async(handler, event)
                    
                    if result is not None:
                        results.append(result)
                        
                except Exception as e:
                    logger.error(f"Handler {handler.handler_id} error: {e}")
                    self.events_failed += 1
            
            # Mark event as processed
            event.processed = True
            
            # Store event in database
            await self._store_event(event, results)
            
            # Performance tracking
            processing_time = time.time() - start_time
            self.total_processing_time += processing_time
            self.events_processed += 1
            
            if self.performance_logger:
                self.performance_logger.record_metric("event_processing_duration", processing_time, "seconds")
                self.performance_logger.record_metric("events_processed", 1, "count")
                self.performance_logger.record_metric("event_handlers_executed", len(all_handlers), "count")
            
            # Track analytics
            if track_event:
                await track_event(
                    "event_processed",
                    properties={
                        "event_type": event.event_type,
                        "event_source": event.source,
                        "event_priority": event.priority.value,
                        "handlers_count": len(all_handlers),
                        "processing_time": processing_time,
                        "processor": processor_name
                    }
                )
            
            logger.debug(f"Event processed: {event.event_id} by {processor_name} in {processing_time:.3f}s")
            
        except Exception as e:
            logger.error(f"Error processing event {event.event_id}: {e}")
            self.events_failed += 1
    
    def _execute_handler_sync(self, handler: EventHandler, event: Event) -> Any:
        """Execute handler synchronously for threading."""
        try:
            return handler.handler_func(event)
        except Exception as e:
            logger.error(f"Sync handler execution error: {e}")
            raise
    
    async def _execute_handler_async(self, handler: EventHandler, event: Event) -> Any:
        """Execute handler asynchronously."""
        try:
            if asyncio.iscoroutinefunction(handler.handler_func):
                return await handler.handler_func(event)
            else:
                return handler.handler_func(event)
        except Exception as e:
            logger.error(f"Async handler execution error: {e}")
            raise
    
    async def emit_event(self, event_type: str, source: str, data: Dict[str, Any],
                        priority: EventPriority = EventPriority.NORMAL,
                        metadata: Dict[str, Any] = None) -> str:
        """Emit an event."""
        try:
            event_id = str(uuid4())
            
            event = Event(
                event_id=event_id,
                event_type=event_type,
                source=source,
                timestamp=datetime.now(),
                priority=priority,
                data=data,
                metadata=metadata or {}
            )
            
            # Add to queue with priority
            priority_value = self._get_priority_value(priority)
            await self.event_queue.put((priority_value, event))
            
            logger.debug(f"Event emitted: {event_type} from {source} (ID: {event_id})")
            return event_id
            
        except Exception as e:
            logger.error(f"Error emitting event: {e}")
            raise
    
    def _get_priority_value(self, priority: EventPriority) -> int:
        """Get numeric priority value (lower = higher priority)."""
        priority_map = {
            EventPriority.CRITICAL: 0,
            EventPriority.HIGH: 1,
            EventPriority.NORMAL: 2,
            EventPriority.LOW: 3
        }
        return priority_map.get(priority, 2)
    
    def register_handler(self, event_type: str, handler_func: Callable,
                        priority: int = 100, handler_id: Optional[str] = None,
                        filter_func: Optional[Callable] = None) -> str:
        """Register event handler."""
        try:
            handler_id = handler_id or str(uuid4())
            
            handler = EventHandler(
                handler_id=handler_id,
                event_type=event_type,
                handler_func=handler_func,
                priority=priority,
                async_handler=asyncio.iscoroutinefunction(handler_func),
                filter_func=filter_func
            )
            
            if event_type == "*":
                # Global handler
                self.global_handlers.append(handler)
            else:
                # Specific event type handler
                if event_type not in self.handlers:
                    self.handlers[event_type] = []
                self.handlers[event_type].append(handler)
            
            self.handlers_registered += 1
            
            logger.debug(f"Handler registered: {handler_id} for {event_type}")
            return handler_id
            
        except Exception as e:
            logger.error(f"Error registering handler: {e}")
            raise
    
    def unregister_handler(self, handler_id: str) -> bool:
        """Unregister event handler."""
        try:
            # Remove from global handlers
            for i, handler in enumerate(self.global_handlers):
                if handler.handler_id == handler_id:
                    del self.global_handlers[i]
                    logger.debug(f"Global handler unregistered: {handler_id}")
                    return True
            
            # Remove from specific event handlers
            for event_type, handlers in self.handlers.items():
                for i, handler in enumerate(handlers):
                    if handler.handler_id == handler_id:
                        del handlers[i]
                        logger.debug(f"Handler unregistered: {handler_id} for {event_type}")
                        return True
            
            logger.warning(f"Handler not found for unregistration: {handler_id}")
            return False
            
        except Exception as e:
            logger.error(f"Error unregistering handler: {e}")
            return False
    
    async def _store_event(self, event: Event, results: List[Any]):
        """Store event in database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO events (
                        event_id, event_type, source, timestamp, priority,
                        data, metadata, processed, results
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "source": event.source,
                    "timestamp": event.timestamp,
                    "priority": event.priority.value,
                    "data": json.dumps(event.data),
                    "metadata": json.dumps(event.metadata),
                    "processed": event.processed,
                    "results": json.dumps(results, default=str)
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing event: {e}")
    
    async def get_events(self, event_type: Optional[str] = None, 
                        source: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get events from database."""
        try:
            if not self.db_manager:
                return []
            
            query = "SELECT * FROM events WHERE 1=1"
            params = {}
            
            if event_type:
                query += " AND event_type = ?"
                params["event_type"] = event_type
            
            if source:
                query += " AND source = ?"
                params["source"] = source
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params["limit"] = limit
            
            result = await self.db_manager.execute_query(query, params)
            
            events = []
            for row in result:
                events.append({
                    "event_id": row[0],
                    "event_type": row[1],
                    "source": row[2],
                    "timestamp": row[3].isoformat() if row[3] else None,
                    "priority": row[4],
                    "data": json.loads(row[5]) if row[5] else {},
                    "metadata": json.loads(row[6]) if row[6] else {},
                    "processed": row[7],
                    "results": json.loads(row[8]) if row[8] else []
                })
            
            return events
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    def get_handlers(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all registered handlers."""
        try:
            result = {}
            
            # Add specific event handlers
            for event_type, handlers in self.handlers.items():
                result[event_type] = [
                    {
                        "handler_id": h.handler_id,
                        "priority": h.priority,
                        "async_handler": h.async_handler,
                        "has_filter": h.filter_func is not None
                    }
                    for h in handlers
                ]
            
            # Add global handlers
            if self.global_handlers:
                result["*"] = [
                    {
                        "handler_id": h.handler_id,
                        "priority": h.priority,
                        "async_handler": h.async_handler,
                        "has_filter": h.filter_func is not None
                    }
                    for h in self.global_handlers
                ]
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting handlers: {e}")
            return {}
    
    def get_queue_size(self) -> int:
        """Get current queue size."""
        return self.event_queue.qsize()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event manager statistics."""
        avg_processing_time = (
            self.total_processing_time / self.events_processed 
            if self.events_processed > 0 else 0
        )
        
        return {
            "processing": self.processing,
            "max_processors": self.max_processors,
            "active_processors": len(self.processor_tasks),
            "queue_size": self.get_queue_size(),
            "events_processed": self.events_processed,
            "events_failed": self.events_failed,
            "handlers_registered": self.handlers_registered,
            "total_processing_time": self.total_processing_time,
            "average_processing_time": avg_processing_time,
            "event_types": list(self.handlers.keys()),
            "global_handlers": len(self.global_handlers)
        }

# Global event manager
event_manager = EventManager()

# Convenience functions
async def emit_event(event_type: str, source: str, data: Dict[str, Any], **kwargs) -> str:
    """Emit event using global event manager."""
    return await event_manager.emit_event(event_type, source, data, **kwargs)

def register_event_handler(event_type: str, handler_func: Callable, **kwargs) -> str:
    """Register event handler using global event manager."""
    return event_manager.register_handler(event_type, handler_func, **kwargs)

def unregister_event_handler(handler_id: str) -> bool:
    """Unregister event handler using global event manager."""
    return event_manager.unregister_handler(handler_id)

async def get_events(event_type: Optional[str] = None, source: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Get events using global event manager."""
    return await event_manager.get_events(event_type, source, limit)

# Decorators
def event_handler(event_type: str, priority: int = 100, filter_func: Optional[Callable] = None):
    """Decorator to register event handler."""
    def decorator(func):
        handler_id = register_event_handler(event_type, func, priority=priority, filter_func=filter_func)
        func._event_handler_id = handler_id
        return func
    return decorator

def global_event_handler(priority: int = 100, filter_func: Optional[Callable] = None):
    """Decorator to register global event handler."""
    def decorator(func):
        handler_id = register_event_handler("*", func, priority=priority, filter_func=filter_func)
        func._event_handler_id = handler_id
        return func
    return decorator
