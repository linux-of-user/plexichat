"""
PlexiChat Enhanced Error Handler

Advanced error handling with intelligent recovery, pattern detection,
and comprehensive logging capabilities.
"""

import asyncio
import logging
import traceback
from typing import Optional, Dict, Any, List, Callable, Type
from datetime import datetime, timedelta
from collections import defaultdict, deque

from .exceptions import ErrorSeverity, ErrorCategory, BaseAPIException
from .crash_reporter import CrashReporter
from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig

logger = logging.getLogger(__name__)


class ErrorPattern:
    """Represents a detected error pattern."""
    
    def __init__(self, pattern_type: str, threshold: int = 5, window_minutes: int = 10):
        self.pattern_type = pattern_type
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.occurrences: deque = deque()
        self.last_alert_time: Optional[datetime] = None
        self.alert_cooldown_minutes = 30
    
    def add_occurrence(self, timestamp: datetime = None):
        """Add an occurrence of this pattern."""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.occurrences.append(timestamp)
        
        # Remove old occurrences outside the window
        cutoff_time = timestamp - timedelta(minutes=self.window_minutes)
        while self.occurrences and self.occurrences[0] < cutoff_time:
            self.occurrences.popleft()
    
    def is_pattern_detected(self) -> bool:
        """Check if pattern threshold is exceeded."""
        return len(self.occurrences) >= self.threshold
    
    def should_alert(self) -> bool:
        """Check if we should send an alert for this pattern."""
        if not self.is_pattern_detected():
            return False
        
        if self.last_alert_time is None:
            return True
        
        return datetime.now() - self.last_alert_time > timedelta(minutes=self.alert_cooldown_minutes)
    
    def mark_alerted(self):
        """Mark that an alert was sent for this pattern."""
        self.last_alert_time = datetime.now()


class EnhancedErrorHandler:
    """Enhanced error handler with advanced features."""
    
    def __init__(self):
        self.crash_reporter = CrashReporter()
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_patterns: Dict[str, ErrorPattern] = {}
        self.error_callbacks: List[Callable] = []
        self.recovery_strategies: Dict[Type[Exception], Callable] = {}
        
        # Error tracking
        self.error_history: deque = deque(maxlen=10000)
        self.error_counts = defaultdict(int)
        self.component_errors = defaultdict(int)
        
        # Configuration
        self.auto_recovery_enabled = True
        self.pattern_detection_enabled = True
        self.circuit_breaker_enabled = True
        self.initialized = False
        
        # Initialize default patterns
        self._initialize_default_patterns()
    
    async def initialize(self, config: Dict[str, Any] = None):
        """Initialize the enhanced error handler."""
        if config:
            self.auto_recovery_enabled = config.get('auto_recovery_enabled', True)
            self.pattern_detection_enabled = config.get('pattern_detection_enabled', True)
            self.circuit_breaker_enabled = config.get('circuit_breaker_enabled', True)
        
        await self.crash_reporter.initialize(config.get('crash_reporter', {}) if config else {})
        self.initialized = True
        logger.info("Enhanced Error Handler initialized")
    
    def _initialize_default_patterns(self):
        """Initialize default error patterns to detect."""
        self.error_patterns.update({
            'database_connection_failures': ErrorPattern('database_connection', threshold=3, window_minutes=5),
            'authentication_failures': ErrorPattern('authentication', threshold=10, window_minutes=15),
            'external_service_failures': ErrorPattern('external_service', threshold=5, window_minutes=10),
            'file_operation_failures': ErrorPattern('file_operation', threshold=5, window_minutes=10),
            'network_timeouts': ErrorPattern('network_timeout', threshold=3, window_minutes=5),
        })
    
    async def handle_error(self, exception: Exception, 
                          context: Dict[str, Any] = None,
                          severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                          category: ErrorCategory = ErrorCategory.UNKNOWN,
                          component: str = None,
                          attempt_recovery: bool = True) -> Dict[str, Any]:
        """Handle an error with comprehensive processing."""
        
        error_info = {
            'exception': exception,
            'exception_type': type(exception).__name__,
            'message': str(exception),
            'severity': severity,
            'category': category,
            'component': component,
            'context': context or {},
            'timestamp': datetime.now(),
            'recovered': False,
            'recovery_method': None
        }
        
        # Add to error history
        self.error_history.append(error_info)
        self.error_counts[type(exception).__name__] += 1
        if component:
            self.component_errors[component] += 1
        
        # Pattern detection
        if self.pattern_detection_enabled:
            await self._detect_patterns(error_info)
        
        # Attempt recovery
        if attempt_recovery and self.auto_recovery_enabled:
            recovery_result = await self._attempt_recovery(exception, context)
            error_info.update(recovery_result)
        
        # Circuit breaker handling
        if self.circuit_breaker_enabled and component:
            await self._handle_circuit_breaker(component, exception)
        
        # Crash reporting for critical errors
        if severity in [ErrorSeverity.CRITICAL, ErrorSeverity.EMERGENCY]:
            crash_context = self.crash_reporter.report_crash(
                exception=exception,
                severity=severity,
                category=category,
                component=component,
                additional_context=context
            )
            error_info['crash_id'] = crash_context.error_id
        
        # Notify callbacks
        await self._notify_callbacks(error_info)
        
        # Log the error
        self._log_error(error_info)
        
        return error_info
    
    async def _detect_patterns(self, error_info: Dict[str, Any]):
        """Detect error patterns and trigger alerts."""
        exception_type = error_info['exception_type']
        category = error_info['category']
        component = error_info['component']
        
        # Check for specific patterns
        pattern_checks = {
            'database_connection_failures': lambda: 'database' in exception_type.lower() or category == ErrorCategory.DATABASE,
            'authentication_failures': lambda: category == ErrorCategory.AUTHENTICATION,
            'external_service_failures': lambda: category == ErrorCategory.EXTERNAL_SERVICE,
            'file_operation_failures': lambda: category == ErrorCategory.FILE_OPERATION,
            'network_timeouts': lambda: 'timeout' in str(error_info['exception']).lower() or category == ErrorCategory.NETWORK,
        }
        
        for pattern_name, check_func in pattern_checks.items():
            if check_func():
                pattern = self.error_patterns[pattern_name]
                pattern.add_occurrence()
                
                if pattern.should_alert():
                    await self._send_pattern_alert(pattern_name, pattern)
                    pattern.mark_alerted()
    
    async def _attempt_recovery(self, exception: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Attempt to recover from the error."""
        exception_type = type(exception)
        
        # Check for registered recovery strategy
        if exception_type in self.recovery_strategies:
            try:
                recovery_func = self.recovery_strategies[exception_type]
                if asyncio.iscoroutinefunction(recovery_func):
                    await recovery_func(exception, context)
                else:
                    recovery_func(exception, context)
                
                return {'recovered': True, 'recovery_method': 'custom_strategy'}
            except Exception as recovery_error:
                logger.error(f"Recovery strategy failed: {recovery_error}")
        
        # Default recovery strategies
        if hasattr(exception, 'retry_count') and exception.retry_count < 3:
            return {'recovered': False, 'recovery_method': 'retry_suggested'}
        
        return {'recovered': False, 'recovery_method': None}
    
    async def _handle_circuit_breaker(self, component: str, exception: Exception):
        """Handle circuit breaker for component."""
        if component not in self.circuit_breakers:
            config = CircuitBreakerConfig(
                failure_threshold=5,
                timeout_seconds=60,
                expected_exceptions=[type(exception)]
            )
            self.circuit_breakers[component] = CircuitBreaker(component, config)
        
        # The circuit breaker will be used by the calling code
        # This just ensures it exists
    
    async def _send_pattern_alert(self, pattern_name: str, pattern: ErrorPattern):
        """Send alert for detected error pattern."""
        alert_message = f"Error pattern detected: {pattern_name} - {len(pattern.occurrences)} occurrences in {pattern.window_minutes} minutes"
        logger.warning(alert_message)
        
        # Here you could integrate with alerting systems like:
        # - Email notifications
        # - Slack/Discord webhooks
        # - PagerDuty
        # - Custom monitoring systems
    
    async def _notify_callbacks(self, error_info: Dict[str, Any]):
        """Notify registered error callbacks."""
        for callback in self.error_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(error_info)
                else:
                    callback(error_info)
            except Exception as e:
                logger.error(f"Error callback failed: {e}")
    
    def _log_error(self, error_info: Dict[str, Any]):
        """Log error with appropriate level."""
        severity = error_info['severity']
        message = f"[{error_info['component'] or 'UNKNOWN'}] {error_info['exception_type']}: {error_info['message']}"
        
        if severity == ErrorSeverity.LOW:
            logger.info(message)
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(message)
        elif severity == ErrorSeverity.HIGH:
            logger.error(message)
        else:  # CRITICAL or EMERGENCY
            logger.critical(message)
    
    def register_recovery_strategy(self, exception_type: Type[Exception], recovery_func: Callable):
        """Register a recovery strategy for an exception type."""
        self.recovery_strategies[exception_type] = recovery_func
    
    def register_error_callback(self, callback: Callable):
        """Register a callback to be called on errors."""
        self.error_callbacks.append(callback)
    
    def get_circuit_breaker(self, component: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker for a component."""
        return self.circuit_breakers.get(component)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics."""
        return {
            'total_errors': len(self.error_history),
            'error_counts_by_type': dict(self.error_counts),
            'error_counts_by_component': dict(self.component_errors),
            'active_patterns': {
                name: {
                    'occurrences': len(pattern.occurrences),
                    'threshold': pattern.threshold,
                    'is_detected': pattern.is_pattern_detected()
                }
                for name, pattern in self.error_patterns.items()
            },
            'circuit_breakers': {
                name: breaker.get_stats()
                for name, breaker in self.circuit_breakers.items()
            }
        }
