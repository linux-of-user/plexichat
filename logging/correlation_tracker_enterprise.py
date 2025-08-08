import asyncio
import logging
import threading
import time
import uuid
from collections import defaultdict, deque
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set
from weakref import WeakValueDictionary

logger = logging.getLogger(__name__)


@dataclass
class CorrelationContext:
    """Correlation context for tracking related operations."""
    correlation_id: str
    parent_id: Optional[str] = None
    root_id: Optional[str] = None
    operation_name: str = ""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    trace_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.root_id:
            self.root_id = self.correlation_id


@dataclass
class CorrelationChain:
    """Represents a chain of correlated operations."""
    root_id: str
    contexts: Dict[str, CorrelationContext] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_context(self, context: CorrelationContext):
        """Add a correlation context to the chain."""
        self.contexts[context.correlation_id] = context
        self.last_updated = datetime.now(timezone.utc)
        
        # Update root_id if not set
        if not context.root_id:
            context.root_id = self.root_id


class EnterpriseCorrelationTracker:
    """Enterprise-grade correlation tracking system.
    
    Features:
    - Thread-safe correlation tracking
    - Hierarchical correlation chains
    - Performance metrics collection
    - Automatic cleanup of expired correlations
    - Context variable integration
    - Distributed tracing support
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.active_correlations: Dict[str, CorrelationContext] = {}
        self.correlation_chains: Dict[str, CorrelationChain] = {}
        self.performance_metrics: Dict[str, List[float]] = defaultdict(list)
        self.correlation_callbacks: List[Callable[[CorrelationContext], None]] = []
        self._lock = threading.RLock()
        self._cleanup_interval = self.config.get("cleanup_interval_seconds", 300)  # 5 minutes
        self._max_correlation_age = self.config.get("max_correlation_age_hours", 24)
        self._running = False
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Weak references for automatic cleanup
        self._weak_contexts: WeakValueDictionary = WeakValueDictionary()
        
    async def initialize(self):
        """Initialize the correlation tracker."""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Enterprise Correlation Tracker initialized")
    
    async def shutdown(self):
        """Shutdown the correlation tracker."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Enterprise Correlation Tracker shutdown complete")
    
    def create_correlation(self, operation_name: str = "", 
                         parent_id: Optional[str] = None,
                         metadata: Optional[Dict[str, Any]] = None,
                         tags: Optional[Set[str]] = None) -> CorrelationContext:
        """Create a new correlation context."""
        correlation_id = str(uuid.uuid4())
        
        # Determine root_id
        root_id = correlation_id
        if parent_id:
            with self._lock:
                parent_context = self.active_correlations.get(parent_id)
                if parent_context:
                    root_id = parent_context.root_id
        
        context = CorrelationContext(
            correlation_id=correlation_id,
            parent_id=parent_id,
            root_id=root_id,
            operation_name=operation_name,
            metadata=metadata or {},
            tags=tags or set()
        )
        
        with self._lock:
            self.active_correlations[correlation_id] = context
            self._weak_contexts[correlation_id] = context
            
            # Add to correlation chain
            if root_id not in self.correlation_chains:
                self.correlation_chains[root_id] = CorrelationChain(root_id=root_id)
            
            self.correlation_chains[root_id].add_context(context)
        
        # Notify callbacks
        for callback in self.correlation_callbacks:
            try:
                callback(context)
            except Exception as e:
                logger.error(f"Error in correlation callback: {e}")
        
        logger.debug(f"Created correlation {correlation_id} for operation '{operation_name}'")
        return context
    
    def get_correlation(self, correlation_id: str) -> Optional[CorrelationContext]:
        """Get a correlation context by ID."""
        with self._lock:
            return self.active_correlations.get(correlation_id)
    
    def get_current_correlation(self) -> Optional[CorrelationContext]:
        """Get the current correlation context from context variables."""
        correlation_id = _current_correlation_id.get(None)
        if correlation_id:
            return self.get_correlation(correlation_id)
        return None
    
    def update_correlation(self, correlation_id: str, **updates):
        """Update correlation context metadata."""
        with self._lock:
            context = self.active_correlations.get(correlation_id)
            if context:
                for key, value in updates.items():
                    if hasattr(context, key):
                        setattr(context, key, value)
                    else:
                        context.metadata[key] = value
                
                # Update chain
                if context.root_id in self.correlation_chains:
                    self.correlation_chains[context.root_id].last_updated = datetime.now(timezone.utc)
    
    def end_correlation(self, correlation_id: str, 
                       metadata: Optional[Dict[str, Any]] = None):
        """End a correlation and record performance metrics."""
        with self._lock:
            context = self.active_correlations.get(correlation_id)
            if context:
                context.end_time = datetime.now(timezone.utc)
                
                if metadata:
                    context.metadata.update(metadata)
                
                # Record performance metrics
                if context.operation_name:
                    duration = (context.end_time - context.start_time).total_seconds()
                    self.performance_metrics[context.operation_name].append(duration)
                    
                    # Keep only recent metrics
                    max_metrics = self.config.get("max_metrics_per_operation", 1000)
                    if len(self.performance_metrics[context.operation_name]) > max_metrics:
                        self.performance_metrics[context.operation_name] = \
                            self.performance_metrics[context.operation_name][-max_metrics:]
                
                logger.debug(f"Ended correlation {correlation_id}")
    
    def get_correlation_chain(self, root_id: str) -> Optional[CorrelationChain]:
        """Get a complete correlation chain by root ID."""
        with self._lock:
            return self.correlation_chains.get(root_id)
    
    def get_child_correlations(self, parent_id: str) -> List[CorrelationContext]:
        """Get all child correlations for a parent."""
        children = []
        with self._lock:
            for context in self.active_correlations.values():
                if context.parent_id == parent_id:
                    children.append(context)
        return children
    
    def get_performance_metrics(self, operation_name: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics for operations."""
        with self._lock:
            if operation_name:
                metrics = self.performance_metrics.get(operation_name, [])
                if metrics:
                    return {
                        "operation": operation_name,
                        "count": len(metrics),
                        "avg_duration": sum(metrics) / len(metrics),
                        "min_duration": min(metrics),
                        "max_duration": max(metrics),
                        "total_duration": sum(metrics)
                    }
                return {"operation": operation_name, "count": 0}
            else:
                # Return summary for all operations
                summary = {}
                for op_name, metrics in self.performance_metrics.items():
                    if metrics:
                        summary[op_name] = {
                            "count": len(metrics),
                            "avg_duration": sum(metrics) / len(metrics),
                            "min_duration": min(metrics),
                            "max_duration": max(metrics),
                            "total_duration": sum(metrics)
                        }
                return summary
    
    def add_correlation_callback(self, callback: Callable[[CorrelationContext], None]):
        """Add a callback for correlation events."""
        self.correlation_callbacks.append(callback)
    
    def remove_correlation_callback(self, callback: Callable[[CorrelationContext], None]):
        """Remove a correlation callback."""
        if callback in self.correlation_callbacks:
            self.correlation_callbacks.remove(callback)
    
    def get_active_correlations_count(self) -> int:
        """Get the number of active correlations."""
        with self._lock:
            return len(self.active_correlations)
    
    def get_correlation_chains_count(self) -> int:
        """Get the number of correlation chains."""
        with self._lock:
            return len(self.correlation_chains)
    
    async def _cleanup_loop(self):
        """Background cleanup of expired correlations."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired_correlations()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in correlation cleanup: {e}")
    
    async def _cleanup_expired_correlations(self):
        """Clean up expired correlations and chains."""
        current_time = datetime.now(timezone.utc)
        max_age = timedelta(hours=self._max_correlation_age)
        
        expired_correlations = []
        expired_chains = []
        
        with self._lock:
            # Find expired correlations
            for correlation_id, context in list(self.active_correlations.items()):
                if current_time - context.start_time > max_age:
                    expired_correlations.append(correlation_id)
            
            # Remove expired correlations
            for correlation_id in expired_correlations:
                del self.active_correlations[correlation_id]
            
            # Find expired chains
            for root_id, chain in list(self.correlation_chains.items()):
                if current_time - chain.last_updated > max_age:
                    expired_chains.append(root_id)
            
            # Remove expired chains
            for root_id in expired_chains:
                del self.correlation_chains[root_id]
        
        if expired_correlations or expired_chains:
            logger.info(f"Cleaned up {len(expired_correlations)} correlations and {len(expired_chains)} chains")


# Context variables for thread-local correlation tracking
_current_correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


def get_current_correlation_id() -> Optional[str]:
    """Get the current correlation ID from context."""
    return _current_correlation_id.get(None)


def set_current_correlation_id(correlation_id: Optional[str]):
    """Set the current correlation ID in context."""
    _current_correlation_id.set(correlation_id)


class CorrelationContextManager:
    """Context manager for correlation tracking."""
    
    def __init__(self, tracker: EnterpriseCorrelationTracker, 
                 operation_name: str = "",
                 parent_id: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None,
                 tags: Optional[Set[str]] = None):
        self.tracker = tracker
        self.operation_name = operation_name
        self.parent_id = parent_id
        self.metadata = metadata
        self.tags = tags
        self.context: Optional[CorrelationContext] = None
        self.previous_correlation_id: Optional[str] = None
    
    def __enter__(self) -> CorrelationContext:
        # Save previous correlation ID
        self.previous_correlation_id = get_current_correlation_id()
        
        # Create new correlation
        self.context = self.tracker.create_correlation(
            operation_name=self.operation_name,
            parent_id=self.parent_id or self.previous_correlation_id,
            metadata=self.metadata,
            tags=self.tags
        )
        
        # Set as current correlation
        set_current_correlation_id(self.context.correlation_id)
        
        return self.context
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.context:
            # Add exception info if there was an error
            if exc_type:
                self.context.metadata['exception'] = {
                    'type': exc_type.__name__,
                    'message': str(exc_val),
                    'traceback': str(exc_tb) if exc_tb else None
                }
            
            # End correlation
            self.tracker.end_correlation(self.context.correlation_id)
        
        # Restore previous correlation ID
        set_current_correlation_id(self.previous_correlation_id)


# Global tracker instance
_correlation_tracker: Optional[EnterpriseCorrelationTracker] = None


def get_correlation_tracker() -> EnterpriseCorrelationTracker:
    """Get the global correlation tracker instance."""
    global _correlation_tracker
    if _correlation_tracker is None:
        _correlation_tracker = EnterpriseCorrelationTracker()
    return _correlation_tracker


async def initialize_correlation_tracker(config: Optional[Dict[str, Any]] = None) -> EnterpriseCorrelationTracker:
    """Initialize and return the correlation tracker."""
    tracker = get_correlation_tracker()
    if config:
        tracker.config.update(config)
    await tracker.initialize()
    return tracker


def correlate(operation_name: str = "", 
             parent_id: Optional[str] = None,
             metadata: Optional[Dict[str, Any]] = None,
             tags: Optional[Set[str]] = None) -> CorrelationContextManager:
    """Create a correlation context manager."""
    return CorrelationContextManager(
        get_correlation_tracker(),
        operation_name,
        parent_id,
        metadata,
        tags
    )
