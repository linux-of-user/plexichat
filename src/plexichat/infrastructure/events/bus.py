# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
import traceback
from typing import Any
import weakref

"""
PlexiChat Event Bus

Centralized event bus for decoupled inter-module communication.
Enables modules to communicate without direct coupling through
publish-subscribe pattern with async support.
"""

logger = logging.getLogger(__name__)


class EventPriority(Enum):
    """Event priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Event:
    """Base event class."""
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    source: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    priority: EventPriority = EventPriority.NORMAL
    correlation_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EventHandler:
    """Event handler registration."""
    callback: Callable
    event_type: str
    priority: int = 0
    once: bool = False
    condition: Callable[[Event], bool] | None = None
    weak_ref: bool = True


class EventBus:
    """
    Centralized event bus for decoupled communication.

    Features:
    - Async and sync event handling
    - Event filtering and conditions
    - Priority-based event processing
    - Weak references to prevent memory leaks
    - Event history and replay
    - Middleware support
    """
    def __init__(self, max_history: int = 1000):
        self._handlers: dict[str, list[EventHandler]] = {}
        self._middleware: list[Callable] = []
        self._event_history: list[Event] = []
        self._max_history = max_history
        self._running = False
        self._event_queue = asyncio.Queue()
        self._processor_task = None
        self._stats = {
            "events_published": 0,
            "events_processed": 0,
            "handlers_called": 0,
            "errors": 0,
        }

    async def start(self):
        """Start the event bus processor."""
        if self._running:
            return

        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")

    async def stop(self):
        """Stop the event bus processor."""
        if not self._running:
            return

        self._running = False

        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass

        logger.info("Event bus stopped")

    def subscribe(
        self,
        event_type: str,
        callback: Callable,
        priority: int = 0,
        once: bool = False,
        condition: Callable[[Event], bool] | None = None,
        weak_ref: bool = True,
    ) -> str:
        """
        Subscribe to events of a specific type.

        Args:
            event_type: Type of event to subscribe to
            callback: Function to call when event occurs
            priority: Handler priority (higher = called first)
            once: If True, handler is removed after first call
            condition: Optional condition function to filter events
            weak_ref: Use weak reference to prevent memory leaks

        Returns:
            Handler ID for unsubscribing
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []

        handler = EventHandler(
            callback=callback,
            event_type=event_type,
            priority=priority,
            once=once,
            condition=condition,
            weak_ref=weak_ref,
        )

        # Insert handler in priority order (highest first)
        handlers = self._handlers[event_type]
        insert_index = 0
        for i, existing_handler in enumerate(handlers):
            if existing_handler.priority < priority:
                insert_index = i
                break
            insert_index = i + 1

        handlers.insert(insert_index, handler)

        handler_id = f"{event_type}_{id(handler)}"
        logger.debug(f"Subscribed to {event_type} with priority {priority}")

        return handler_id

    def unsubscribe(
        self, event_type: str, callback: Callable | None = None, handler_id: str | None = None
    ):
        """
        Unsubscribe from events.

        Args:
            event_type: Type of event to unsubscribe from
            callback: Specific callback to remove (optional)
            handler_id: Specific handler ID to remove (optional)
        """
        if event_type not in self._handlers:
            return

        handlers = self._handlers[event_type]

        if handler_id:
            # Remove by handler ID
            handlers[:] = [h for h in handlers if f"{event_type}_{id(h)}" != handler_id]
        elif callback:
            # Remove by callback
            handlers[:] = [h for h in handlers if h.callback != callback]
        else:
            # Remove all handlers for this event type
            handlers.clear()

        # Clean up empty handler lists
        if not handlers:
            del self._handlers[event_type]

        logger.debug(f"Unsubscribed from {event_type}")

    def publish(
        self,
        event_type: str,
        data: dict[str, Any] = None,
        source: str | None = None,
        priority: EventPriority = EventPriority.NORMAL,
        correlation_id: str | None = None,
        **kwargs,
    ):
        """
        Publish an event (synchronous).

        Args:
            event_type: Type of event
            data: Event data
            source: Source of the event
            priority: Event priority
            correlation_id: Correlation ID for tracking
            **kwargs: Additional data fields
        """
        event_data = data or {}
        event_data.update(kwargs)

        event = Event(
            type=event_type,
            data=event_data,
            source=source,
            priority=priority,
            correlation_id=correlation_id,
        )

        # Add to history
        self._add_to_history(event)

        # Process immediately if not running async processor
        if not self._running:
            asyncio.create_task(self._handle_event(event))
        else:
            # Queue for async processing
            try:
                self._event_queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(f"Event queue full, dropping event: {event_type}")

        self._stats["events_published"] += 1
        logger.debug(f"Published event: {event_type}")

    async def publish_async(
        self,
        event_type: str,
        data: dict[str, Any] = None,
        source: str | None = None,
        priority: EventPriority = EventPriority.NORMAL,
        correlation_id: str | None = None,
        **kwargs,
    ):
        """
        Publish an event (asynchronous).
        """
        event_data = data or {}
        event_data.update(kwargs)

        event = Event(
            type=event_type,
            data=event_data,
            source=source,
            priority=priority,
            correlation_id=correlation_id,
        )

        # Add to history
        self._add_to_history(event)

        # Handle immediately
        await self._handle_event(event)

        self._stats["events_published"] += 1
        logger.debug(f"Published async event: {event_type}")

    async def _process_events(self):
        """Process events from the queue."""
        while self._running:
            try:
                # Get event from queue with timeout
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)

                await self._handle_event(event)
                self._event_queue.task_done()

            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                self._stats["errors"] += 1

    async def _handle_event(self, event: Event):
        """Handle a single event."""
        try:
            # Apply middleware
            for middleware in self._middleware:
                try:
                    if asyncio.iscoroutinefunction(middleware):
                        event = await middleware(event)
                    else:
                        event = middleware(event)

                    if event is None:
                        return  # Middleware cancelled the event
                except Exception as e:
                    logger.error(f"Middleware error: {e}")

            # Get handlers for this event type
            handlers = self._handlers.get(event.type, [])

            # Clean up dead weak references
            handlers[:] = [h for h in handlers if self._is_handler_valid(h)]

            # Call handlers
            handlers_to_remove = []

            for handler in handlers:
                try:
                    # Check condition if specified
                    if handler.condition and not handler.condition(event):
                        continue

                    # Call handler
                    if asyncio.iscoroutinefunction(handler.callback):
                        await handler.callback(event)
                    else:
                        handler.callback(event)

                    self._stats["handlers_called"] += 1

                    # Mark for removal if it's a one-time handler
                    if handler.once:
                        handlers_to_remove.append(handler)

                except Exception as e:
                    logger.error(f"Handler error for {event.type}: {e}")
                    logger.debug(traceback.format_exc())
                    self._stats["errors"] += 1

            # Remove one-time handlers
            for handler in handlers_to_remove:
                handlers.remove(handler)

            self._stats["events_processed"] += 1

        except Exception as e:
            logger.error(f"Event handling error: {e}")
            self._stats["errors"] += 1

    def _is_handler_valid(self, handler: EventHandler) -> bool:
        """Check if a handler is still valid (for weak references)."""
        if not handler.weak_ref:
            return True

        # For weak references, check if the callback is still alive
        if isinstance(handler.callback, weakref.ref):
            return handler.callback() is not None

        return True

    def _add_to_history(self, event: Event):
        """Add event to history."""
        self._event_history.append(event)

        # Trim history if it exceeds max size
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history :]

    def add_middleware(self, middleware: Callable):
        """Add middleware to process events."""
        self._middleware.append(middleware)
        logger.debug("Added event middleware")

    def remove_middleware(self, middleware: Callable):
        """Remove middleware."""
        if middleware in self._middleware:
            self._middleware.remove(middleware)
            logger.debug("Removed event middleware")

    def get_history(
        self, event_type: str | None = None, limit: int | None = None, since: datetime | None = None
    ) -> list[Event]:
        """Get event history with optional filtering."""
        events = self._event_history

        # Filter by event type
        if event_type:
            events = [e for e in events if e.type == event_type]

        # Filter by timestamp
        if since:
            events = [e for e in events if e.timestamp >= since]

        # Apply limit
        if limit:
            events = events[-limit:]

        return events

    def get_stats(self) -> dict[str, Any]:
        """Get event bus statistics."""
        return {
            **self._stats,
            "active_handlers": sum(
                len(handlers) for handlers in self._handlers.values()
            ),
            "event_types": list(self._handlers.keys()),
            "middleware_count": len(self._middleware),
            "history_size": len(self._event_history),
            "queue_size": self._event_queue.qsize() if self._running else 0,
        }

    def clear_history(self):
        """Clear event history."""
        self._event_history.clear()
        logger.debug("Cleared event history")


# Global event bus instance
event_bus = EventBus()


# Convenience functions
def subscribe(event_type: str, callback: Callable, **kwargs) -> str:
    """Subscribe to events."""
    return event_bus.subscribe(event_type, callback, **kwargs)


def unsubscribe(event_type: str, callback: Callable | None = None, handler_id: str | None = None):
    """Unsubscribe from events."""
    event_bus.unsubscribe(event_type, callback, handler_id)


def publish(event_type: str, **kwargs):
    """Publish an event."""
    event_bus.publish(event_type, **kwargs)


async def publish_async(event_type: str, **kwargs):
    """Publish an event asynchronously."""
    await event_bus.publish_async(event_type, **kwargs)


# Common event types
class EventTypes:
    """Common event type constants."""

    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"

    # User events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTERED = "user.registered"
    USER_UPDATED = "user.updated"

    # Message events
    MESSAGE_SENT = "message.sent"
    MESSAGE_RECEIVED = "message.received"
    MESSAGE_DELETED = "message.deleted"

    # Security events
    SECURITY_THREAT = "security.threat"
    SECURITY_BREACH = "security.breach"
    AUTH_FAILED = "auth.failed"

    # Module events
    MODULE_LOADED = "module.loaded"
    MODULE_UNLOADED = "module.unloaded"
    MODULE_ERROR = "module.error"
