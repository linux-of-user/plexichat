"""
Advanced Correlation Tracking System

Provides comprehensive request correlation tracking across the entire system:
- Request correlation IDs
- Cross-service tracing
- Performance correlation
- Error correlation
- User session correlation
- Database operation correlation
"""

import asyncio
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from contextvars import ContextVar
from enum import Enum
import threading
import json

from ..logging.unified_logging import get_logger

logger = get_logger(__name__)


class CorrelationType(Enum):
    """Types of correlation tracking."""
    REQUEST = "request"
    USER_SESSION = "user_session"
    DATABASE_OPERATION = "database_operation"
    EXTERNAL_API = "external_api"
    BACKGROUND_TASK = "background_task"
    ERROR_CHAIN = "error_chain"
    PERFORMANCE_TRACE = "performance_trace"


@dataclass
class CorrelationContext:
    """Correlation context information."""
    correlation_id: str
    correlation_type: CorrelationType
    parent_id: Optional[str] = None
    root_id: Optional[str] = None
    
    # Timing information
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    # Context metadata
    component: str = ""
    operation: str = ""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Request context
    request_method: str = ""
    request_path: str = ""
    request_params: Dict[str, Any] = field(default_factory=dict)
    response_status: Optional[int] = None
    
    # Performance metrics
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    db_queries: int = 0
    external_calls: int = 0
    
    # Error information
    error_count: int = 0
    error_types: List[str] = field(default_factory=list)
    
    # Custom attributes
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def finish(self):
        """Mark correlation as finished and calculate duration."""
        self.end_time = datetime.now()
        if self.start_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000


@dataclass
class CorrelationChain:
    """Represents a chain of correlated operations."""
    root_id: str
    correlations: Dict[str, CorrelationContext] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    
    def add_correlation(self, context: CorrelationContext):
        """Add a correlation to the chain."""
        self.correlations[context.correlation_id] = context
        self.last_activity = datetime.now()
    
    def get_total_duration(self) -> Optional[float]:
        """Get total duration of the correlation chain."""
        if not self.correlations:
            return None
        
        start_times = [c.start_time for c in self.correlations.values() if c.start_time]
        end_times = [c.end_time for c in self.correlations.values() if c.end_time]
        
        if not start_times or not end_times:
            return None
        
        earliest_start = min(start_times)
        latest_end = max(end_times)
        
        return (latest_end - earliest_start).total_seconds() * 1000
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary for the correlation chain."""
        total_errors = sum(c.error_count for c in self.correlations.values())
        error_types = set()
        for c in self.correlations.values():
            error_types.update(c.error_types)
        
        return {}}
            'total_errors': total_errors,
            'error_types': list(error_types),
            'has_errors': total_errors > 0
        }


class CorrelationTracker:
    """Advanced correlation tracking system."""
    
    def __init__(self, max_chains: int = 10000, cleanup_interval: int = 3600):
        self.correlation_chains: Dict[str, CorrelationChain] = {}
        self.active_correlations: Dict[str, CorrelationContext] = {}
        self.max_chains = max_chains
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        self._lock = threading.RLock()
        
        # Performance tracking
        self.performance_metrics = {
            'total_correlations': 0,
            'active_correlations': 0,
            'average_duration': 0.0,
            'error_rate': 0.0
        }
        
        # Correlation callbacks
        self.correlation_callbacks: List[Callable[[CorrelationContext], None]] = []
        
    def start_correlation(self, 
                         correlation_type: CorrelationType,
                         component: str = "",
                         operation: str = "",
                         parent_id: Optional[str] = None,
                         user_id: Optional[str] = None,
                         session_id: Optional[str] = None,
                         **attributes) -> str:
        """Start a new correlation tracking."""
        correlation_id = str(uuid.uuid4())
        
        # Determine root ID
        root_id = correlation_id
        if parent_id and parent_id in self.active_correlations:
            parent_context = self.active_correlations[parent_id]
            root_id = parent_context.root_id or parent_context.correlation_id
        
        # Create correlation context
        context = CorrelationContext(
            correlation_id=correlation_id,
            correlation_type=correlation_type,
            parent_id=parent_id,
            root_id=root_id,
            component=component,
            operation=operation,
            user_id=user_id,
            session_id=session_id,
            attributes=attributes
        )
        
        with self._lock:
            # Add to active correlations
            self.active_correlations[correlation_id] = context
            
            # Add to correlation chain
            if root_id not in self.correlation_chains:
                self.correlation_chains[root_id] = CorrelationChain(root_id=root_id)
            
            self.correlation_chains[root_id].add_correlation(context)
            
            # Update metrics
            self.performance_metrics['total_correlations'] += 1
            self.performance_metrics['active_correlations'] = len(self.active_correlations)
        
        # Log correlation start
        logger.info(f"Started correlation {correlation_id}", extra={
            'correlation_id': correlation_id,
            'correlation_type': correlation_type.value,
            'component': component,
            'operation': operation,
            'parent_id': parent_id,
            'root_id': root_id
        })
        
        # Trigger callbacks
        for callback in self.correlation_callbacks:
            try:
                callback(context)
            except Exception as e:
                logger.error(f"Error in correlation callback: {e}")
        
        return correlation_id
    
    def finish_correlation(self, 
                          correlation_id: str,
                          response_status: Optional[int] = None,
                          error_count: int = 0,
                          error_types: Optional[List[str]] = None,
                          **attributes):
        """Finish correlation tracking."""
        with self._lock:
            if correlation_id not in self.active_correlations:
                logger.warning(f"Attempted to finish unknown correlation: {correlation_id}")
                return
            
            context = self.active_correlations[correlation_id]
            
            # Update context
            context.finish()
            context.response_status = response_status
            context.error_count = error_count
            context.error_types = error_types or []
            context.attributes.update(attributes)
            
            # Add performance metrics if available
            try:
                import psutil
                context.cpu_usage = psutil.cpu_percent(interval=0.1)
                context.memory_usage = psutil.virtual_memory().percent
            except ImportError:
                pass
            
            # Remove from active correlations
            del self.active_correlations[correlation_id]
            
            # Update metrics
            self.performance_metrics['active_correlations'] = len(self.active_correlations)
            
            if context.duration_ms:
                current_avg = self.performance_metrics['average_duration']
                total_correlations = self.performance_metrics['total_correlations']
                self.performance_metrics['average_duration'] = (
                    (current_avg * (total_correlations - 1) + context.duration_ms) / total_correlations
                )
            
            # Update error rate
            if error_count > 0:
                total_correlations = self.performance_metrics['total_correlations']
                current_errors = self.performance_metrics.get('total_errors', 0) + error_count
                self.performance_metrics['total_errors'] = current_errors
                self.performance_metrics['error_rate'] = current_errors / total_correlations
        
        # Log correlation completion
        logger.info(f"Finished correlation {correlation_id}", extra={
            'correlation_id': correlation_id,
            'duration_ms': context.duration_ms,
            'response_status': response_status,
            'error_count': error_count,
            'component': context.component,
            'operation': context.operation
        })
        
        # Cleanup old chains periodically
        if time.time() - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_chains()
    
    def add_correlation_attribute(self, correlation_id: str, key: str, value: Any):
        """Add attribute to active correlation."""
        with self._lock:
            if correlation_id in self.active_correlations:
                self.active_correlations[correlation_id].attributes[key] = value
    
    def increment_db_queries(self, correlation_id: str, count: int = 1):
        """Increment database query count for correlation."""
        with self._lock:
            if correlation_id in self.active_correlations:
                self.active_correlations[correlation_id].db_queries += count
    
    def increment_external_calls(self, correlation_id: str, count: int = 1):
        """Increment external API call count for correlation."""
        with self._lock:
            if correlation_id in self.active_correlations:
                self.active_correlations[correlation_id].external_calls += count
    
    def get_correlation_context(self, correlation_id: str) -> Optional[CorrelationContext]:
        """Get correlation context by ID."""
        with self._lock:
            return self.active_correlations.get(correlation_id)
    
    def get_correlation_chain(self, root_id: str) -> Optional[CorrelationChain]:
        """Get correlation chain by root ID."""
        with self._lock:
            return self.correlation_chains.get(root_id)
    
    def get_user_correlations(self, user_id: str) -> List[CorrelationContext]:
        """Get all correlations for a specific user."""
        with self._lock:
            return [
                context for context in self.active_correlations.values()
                if context.user_id == user_id
            ]
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self._lock:
            return self.performance_metrics.copy()
    
    def add_correlation_callback(self, callback: Callable[[CorrelationContext], None]):
        """Add callback to be called when correlations are created."""
        self.correlation_callbacks.append(callback)
    
    def _cleanup_old_chains(self):
        """Clean up old correlation chains."""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        with self._lock:
            chains_to_remove = [
                root_id for root_id, chain in self.correlation_chains.items()
                if chain.last_activity < cutoff_time
            ]
            
            for root_id in chains_to_remove:
                del self.correlation_chains[root_id]
            
            # Limit total chains
            if len(self.correlation_chains) > self.max_chains:
                # Remove oldest chains
                sorted_chains = sorted(
                    self.correlation_chains.items(),
                    key=lambda x: x[1].last_activity
                )
                
                chains_to_remove = sorted_chains[:len(self.correlation_chains) - self.max_chains]
                for root_id, _ in chains_to_remove:
                    del self.correlation_chains[root_id]
        
        self.last_cleanup = time.time()
        logger.info(f"Cleaned up {len(chains_to_remove)} old correlation chains")
    
    def export_correlation_data(self, root_id: str) -> Optional[Dict[str, Any]]:
        """Export correlation chain data for analysis."""
        with self._lock:
            chain = self.correlation_chains.get(root_id)
            if not chain:
                return None
            
            return {}}
                'root_id': chain.root_id,
                'created_at': chain.created_at.isoformat(),
                'last_activity': chain.last_activity.isoformat(),
                'total_duration_ms': chain.get_total_duration(),
                'error_summary': chain.get_error_summary(),
                'correlations': [
                    {
                        'correlation_id': context.correlation_id,
                        'correlation_type': context.correlation_type.value,
                        'parent_id': context.parent_id,
                        'component': context.component,
                        'operation': context.operation,
                        'start_time': context.start_time.isoformat(),
                        'end_time': context.end_time.isoformat() if context.end_time else None,
                        'duration_ms': context.duration_ms,
                        'response_status': context.response_status,
                        'error_count': context.error_count,
                        'error_types': context.error_types,
                        'db_queries': context.db_queries,
                        'external_calls': context.external_calls,
                        'attributes': context.attributes
                    }
                    for context in chain.correlations.values()
                ]
            }


# Context variable for current correlation ID
current_correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

# Global correlation tracker instance
correlation_tracker = CorrelationTracker()


def get_current_correlation_id() -> Optional[str]:
    """Get current correlation ID from context."""
    return current_correlation_id.get()


def set_current_correlation_id(correlation_id: str):
    """Set current correlation ID in context."""
    current_correlation_id.set(correlation_id)


async def with_correlation(correlation_type: CorrelationType,
                          component: str = "",
                          operation: str = "",
                          **attributes):
    """Async context manager for correlation tracking."""
    correlation_id = correlation_tracker.start_correlation(
        correlation_type=correlation_type,
        component=component,
        operation=operation,
        parent_id=get_current_correlation_id(),
        **attributes
    )
    
    # Set as current correlation
    token = current_correlation_id.set(correlation_id)
    
    try:
        yield correlation_id
    except Exception as e:
        correlation_tracker.add_correlation_attribute(correlation_id, 'exception', str(e))
        correlation_tracker.finish_correlation(
            correlation_id,
            error_count=1,
            error_types=[type(e).__name__]
        )
        raise
    else:
        correlation_tracker.finish_correlation(correlation_id)
    finally:
        current_correlation_id.reset(token)
