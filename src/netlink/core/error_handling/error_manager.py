"""
NetLink Core Error Manager

Unified error management system that consolidates all error handling
functionality into a single, comprehensive manager.
"""

import asyncio
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable, Type
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import traceback
import uuid

from .context import ErrorContext
from .exceptions import BaseAPIException
from ..app.core.error_handling.enhanced_error_handler import EnhancedErrorHandler
from ..app.core.error_handling.circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from ..app.core.error_handling.crash_reporter import CrashReporter

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class ErrorCategory(Enum):
    """Error categories."""
    SYSTEM = "system"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    EXTERNAL_SERVICE = "external_service"
    FILE_OPERATION = "file_operation"
    RATE_LIMITING = "rate_limiting"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


@dataclass
class ErrorMetrics:
    """Error metrics and statistics."""
    total_errors: int = 0
    errors_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    errors_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_rate_per_minute: float = 0.0
    average_resolution_time: float = 0.0
    circuit_breaker_trips: int = 0
    recovery_success_rate: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ErrorPattern:
    """Detected error pattern."""
    pattern_id: str
    error_type: str
    frequency: int
    first_occurrence: datetime
    last_occurrence: datetime
    affected_components: List[str]
    severity_trend: str
    suggested_actions: List[str]


class ErrorManager:
    """
    Unified error management system.
    
    Features:
    - Comprehensive error tracking and classification
    - Advanced error recovery mechanisms
    - Circuit breaker management
    - Error pattern detection and analysis
    - Real-time monitoring and alerting
    - Integration with external error reporting services
    - Automatic error resolution suggestions
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Core components
        self.enhanced_handler = EnhancedErrorHandler()
        self.crash_reporter = CrashReporter()
        
        # Error tracking
        self.error_history: deque = deque(maxlen=self.config.get("max_history_size", 10000))
        self.error_metrics = ErrorMetrics()
        self.error_patterns: Dict[str, ErrorPattern] = {}
        
        # Circuit breakers
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.circuit_breaker_configs: Dict[str, CircuitBreakerConfig] = {}
        
        # Recovery strategies
        self.recovery_strategies: Dict[Type[Exception], Callable] = {}
        self.recovery_attempts: Dict[str, int] = defaultdict(int)
        
        # Error callbacks and handlers
        self.error_callbacks: List[Callable] = []
        self.severity_handlers: Dict[ErrorSeverity, List[Callable]] = defaultdict(list)
        
        # Monitoring and alerting
        self.alert_thresholds = self.config.get("alert_thresholds", {})
        self.monitoring_enabled = self.config.get("monitoring_enabled", True)
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.initialized = False
    
    async def initialize(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the error manager."""
        if self.initialized:
            return
        
        try:
            if config:
                self.config.update(config)
            
            # Initialize components
            await self.enhanced_handler.initialize(self.config.get("enhanced_handler", {}))
            await self.crash_reporter.initialize(self.config.get("crash_reporter", {}))
            
            # Load default circuit breaker configurations
            self._load_default_circuit_breakers()
            
            # Load default recovery strategies
            self._load_default_recovery_strategies()
            
            # Start background monitoring tasks
            if self.monitoring_enabled:
                self.background_tasks.extend([
                    asyncio.create_task(self._metrics_collection_loop()),
                    asyncio.create_task(self._pattern_detection_loop()),
                    asyncio.create_task(self._health_monitoring_loop()),
                    asyncio.create_task(self._cleanup_loop())
                ])
            
            self.initialized = True
            logger.info("✅ Error Manager initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Error Manager: {e}")
            raise
    
    def handle_error(self, exception: Exception, context: Optional[Dict[str, Any]] = None,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    component: str = None, user_id: str = None,
                    request_id: str = None, attempt_recovery: bool = True) -> ErrorContext:
        """Handle an error with comprehensive processing."""
        
        error_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        
        # Create error context
        error_context = ErrorContext(
            error_id=error_id,
            timestamp=timestamp,
            exception=exception,
            severity=severity,
            category=category,
            component=component,
            user_id=user_id,
            request_id=request_id,
            context=context or {},
            stack_trace=traceback.format_exc()
        )
        
        try:
            # Use enhanced handler for detailed processing
            enhanced_context = self.enhanced_handler.handle_error(
                exception=exception,
                severity=severity,
                category=category,
                component=component,
                user_id=user_id,
                request_id=request_id,
                additional_data=context,
                attempt_recovery=attempt_recovery
            )
            
            # Update error context with enhanced details
            error_context.recovery_attempted = enhanced_context.recovery_attempted
            error_context.recovery_successful = enhanced_context.recovery_successful
            error_context.additional_data = enhanced_context.additional_data
            
            # Update metrics
            self._update_error_metrics(error_context)
            
            # Store in history
            with self.lock:
                self.error_history.append(error_context)
            
            # Detect patterns
            self._detect_error_patterns(error_context)
            
            # Check for alerts
            self._check_alert_thresholds(error_context)
            
            # Notify callbacks
            self._notify_error_callbacks(error_context)
            
            # Handle severity-specific actions
            self._handle_severity_actions(error_context)
            
            logger.info(f"🔍 Error handled: {error_id} - {type(exception).__name__}")
            
        except Exception as handling_error:
            logger.error(f"❌ Error in error handling: {handling_error}")
            # Fallback to basic error context
            error_context.additional_data["handling_error"] = str(handling_error)
        
        return error_context
    
    def report_crash(self, exception: Exception, context: Optional[Dict[str, Any]] = None,
                    severity: ErrorSeverity = ErrorSeverity.CRITICAL) -> str:
        """Report a crash with detailed context."""
        try:
            crash_context = self.crash_reporter.report_crash(
                exception=exception,
                severity=severity,
                category=ErrorCategory.SYSTEM,
                additional_context=context
            )
            
            # Also handle as regular error for tracking
            error_context = self.handle_error(
                exception=exception,
                context=context,
                severity=severity,
                category=ErrorCategory.SYSTEM,
                attempt_recovery=False
            )
            
            logger.critical(f"💥 Crash reported: {crash_context.error_id}")
            return crash_context.error_id
            
        except Exception as e:
            logger.error(f"❌ Failed to report crash: {e}")
            return str(uuid.uuid4())
    
    def create_circuit_breaker(self, name: str, config: Optional[Dict[str, Any]] = None) -> CircuitBreaker:
        """Create or get a circuit breaker."""
        if name in self.circuit_breakers:
            return self.circuit_breakers[name]
        
        # Create configuration
        breaker_config = CircuitBreakerConfig(
            failure_threshold=config.get("failure_threshold", 5) if config else 5,
            timeout=config.get("timeout", 60) if config else 60,
            recovery_timeout=config.get("recovery_timeout", 30) if config else 30,
            expected_exception=config.get("expected_exception", Exception) if config else Exception
        )
        
        # Create circuit breaker
        circuit_breaker = CircuitBreaker(name, breaker_config)
        
        with self.lock:
            self.circuit_breakers[name] = circuit_breaker
            self.circuit_breaker_configs[name] = breaker_config
        
        logger.info(f"🔌 Circuit breaker created: {name}")
        return circuit_breaker
    
    def get_circuit_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get an existing circuit breaker."""
        return self.circuit_breakers.get(name)
    
    def register_recovery_strategy(self, exception_type: Type[Exception], strategy: Callable):
        """Register a recovery strategy for a specific exception type."""
        with self.lock:
            self.recovery_strategies[exception_type] = strategy
        
        logger.info(f"🔧 Recovery strategy registered for {exception_type.__name__}")
    
    def register_error_callback(self, callback: Callable):
        """Register a callback to be called when errors occur."""
        with self.lock:
            self.error_callbacks.append(callback)
        
        logger.info("📞 Error callback registered")
    
    def register_severity_handler(self, severity: ErrorSeverity, handler: Callable):
        """Register a handler for specific error severity."""
        with self.lock:
            self.severity_handlers[severity].append(handler)
        
        logger.info(f"⚠️ Severity handler registered for {severity.value}")
    
    def get_error_metrics(self) -> ErrorMetrics:
        """Get current error metrics."""
        with self.lock:
            return self.error_metrics
    
    def get_error_history(self, limit: int = 100) -> List[ErrorContext]:
        """Get recent error history."""
        with self.lock:
            return list(self.error_history)[-limit:]
    
    def get_error_patterns(self) -> List[ErrorPattern]:
        """Get detected error patterns."""
        with self.lock:
            return list(self.error_patterns.values())
    
    def get_circuit_breaker_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        status = {}
        
        with self.lock:
            for name, breaker in self.circuit_breakers.items():
                status[name] = {
                    "state": breaker.state.value,
                    "failure_count": breaker.failure_count,
                    "success_count": breaker.success_count,
                    "last_failure_time": breaker.last_failure_time,
                    "stats": {
                        "total_requests": breaker.stats.total_requests,
                        "successful_requests": breaker.stats.successful_requests,
                        "failed_requests": breaker.stats.failed_requests,
                        "circuit_opened_count": breaker.stats.circuit_opened_count
                    }
                }
        
        return status
    
    async def shutdown(self):
        """Gracefully shutdown the error manager."""
        try:
            # Cancel background tasks
            for task in self.background_tasks:
                task.cancel()
            
            # Wait for tasks to complete
            if self.background_tasks:
                await asyncio.gather(*self.background_tasks, return_exceptions=True)
            
            # Shutdown components
            await self.enhanced_handler.shutdown()
            await self.crash_reporter.shutdown()
            
            logger.info("✅ Error Manager shutdown complete")
            
        except Exception as e:
            logger.error(f"❌ Error during Error Manager shutdown: {e}")
    
    def _load_default_circuit_breakers(self):
        """Load default circuit breaker configurations."""
        default_configs = {
            "database": {"failure_threshold": 3, "timeout": 30, "recovery_timeout": 60},
            "external_api": {"failure_threshold": 5, "timeout": 10, "recovery_timeout": 30},
            "file_operations": {"failure_threshold": 3, "timeout": 15, "recovery_timeout": 45},
            "authentication": {"failure_threshold": 10, "timeout": 5, "recovery_timeout": 300}
        }
        
        for name, config in default_configs.items():
            self.create_circuit_breaker(name, config)
    
    def _load_default_recovery_strategies(self):
        """Load default recovery strategies."""
        # Add default recovery strategies here
        pass
    
    def _update_error_metrics(self, error_context: ErrorContext):
        """Update error metrics."""
        with self.lock:
            self.error_metrics.total_errors += 1
            self.error_metrics.errors_by_severity[error_context.severity.value] += 1
            self.error_metrics.errors_by_category[error_context.category.value] += 1
            self.error_metrics.errors_by_type[type(error_context.exception).__name__] += 1
            self.error_metrics.last_updated = datetime.now(timezone.utc)
    
    def _detect_error_patterns(self, error_context: ErrorContext):
        """Detect error patterns."""
        # Pattern detection logic here
        pass
    
    def _check_alert_thresholds(self, error_context: ErrorContext):
        """Check if error triggers any alerts."""
        # Alert threshold checking logic here
        pass
    
    def _notify_error_callbacks(self, error_context: ErrorContext):
        """Notify registered error callbacks."""
        for callback in self.error_callbacks:
            try:
                callback(error_context)
            except Exception as e:
                logger.error(f"❌ Error callback failed: {e}")
    
    def _handle_severity_actions(self, error_context: ErrorContext):
        """Handle severity-specific actions."""
        handlers = self.severity_handlers.get(error_context.severity, [])
        for handler in handlers:
            try:
                handler(error_context)
            except Exception as e:
                logger.error(f"❌ Severity handler failed: {e}")
    
    async def _metrics_collection_loop(self):
        """Collect metrics periodically."""
        while True:
            try:
                await asyncio.sleep(60)  # Collect every minute
                await self._collect_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Metrics collection error: {e}")
                await asyncio.sleep(60)
    
    async def _pattern_detection_loop(self):
        """Detect error patterns periodically."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                await self._analyze_patterns()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Pattern detection error: {e}")
                await asyncio.sleep(300)
    
    async def _health_monitoring_loop(self):
        """Monitor system health."""
        while True:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                await self._check_system_health()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Health monitoring error: {e}")
                await asyncio.sleep(30)
    
    async def _cleanup_loop(self):
        """Clean up old data periodically."""
        while True:
            try:
                await asyncio.sleep(3600)  # Clean up every hour
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Cleanup error: {e}")
                await asyncio.sleep(3600)
    
    async def _collect_metrics(self):
        """Collect current metrics."""
        # Calculate error rate
        now = datetime.now(timezone.utc)
        one_minute_ago = now - timedelta(minutes=1)
        
        recent_errors = [
            error for error in self.error_history
            if error.timestamp > one_minute_ago
        ]
        
        with self.lock:
            self.error_metrics.error_rate_per_minute = len(recent_errors)
    
    async def _analyze_patterns(self):
        """Analyze error patterns."""
        # Pattern analysis logic here
        pass
    
    async def _check_system_health(self):
        """Check overall system health."""
        # Health checking logic here
        pass
    
    async def _cleanup_old_data(self):
        """Clean up old error data."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
        
        with self.lock:
            # Clean up old patterns
            expired_patterns = [
                pattern_id for pattern_id, pattern in self.error_patterns.items()
                if pattern.last_occurrence < cutoff_time
            ]
            
            for pattern_id in expired_patterns:
                del self.error_patterns[pattern_id]


# Global instance
error_manager = ErrorManager()
