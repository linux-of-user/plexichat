"""
Enhanced Error Handling System for NetLink
Provides comprehensive error handling, logging, and recovery mechanisms.
"""

import sys
import traceback
import functools
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Type
from dataclasses import dataclass
from enum import Enum
import logging

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for better classification."""
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    EXTERNAL_SERVICE = "external_service"
    USER_INPUT = "user_input"
    UNKNOWN = "unknown"

@dataclass
class ErrorContext:
    """Context information for errors."""
    timestamp: datetime
    error_id: str
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    details: str
    stack_trace: str
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    component: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False
    additional_data: Optional[Dict[str, Any]] = None

class EnhancedErrorHandler:
    """Enhanced error handling system with recovery mechanisms."""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_history: List[ErrorContext] = []
        self.error_counts: Dict[str, int] = {}
        self.recovery_strategies: Dict[Type[Exception], Callable] = {}
        self.error_callbacks: List[Callable] = []
        self.max_history_size = 1000
        self.lock = threading.Lock()
        
        # Register default recovery strategies
        self._register_default_recovery_strategies()
    
    def _register_default_recovery_strategies(self):
        """Register default recovery strategies for common exceptions."""
        self.recovery_strategies.update({
            ConnectionError: self._recover_connection_error,
            TimeoutError: self._recover_timeout_error,
            FileNotFoundError: self._recover_file_not_found,
            PermissionError: self._recover_permission_error,
            ImportError: self._recover_import_error,
            ValueError: self._recover_value_error,
            KeyError: self._recover_key_error,
        })
    
    def handle_error(self, 
                    exception: Exception, 
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    component: str = None,
                    user_id: str = None,
                    request_id: str = None,
                    additional_data: Dict[str, Any] = None,
                    attempt_recovery: bool = True) -> ErrorContext:
        """Handle an error with comprehensive logging and recovery."""
        
        error_id = self._generate_error_id()
        
        # Create error context
        error_context = ErrorContext(
            timestamp=datetime.now(),
            error_id=error_id,
            severity=severity,
            category=category,
            message=str(exception),
            details=f"{type(exception).__name__}: {exception}",
            stack_trace=traceback.format_exc(),
            user_id=user_id,
            request_id=request_id,
            component=component,
            additional_data=additional_data or {}
        )
        
        # Log the error
        self._log_error(error_context)
        
        # Attempt recovery if enabled
        if attempt_recovery:
            recovery_result = self._attempt_recovery(exception, error_context)
            error_context.recovery_attempted = True
            error_context.recovery_successful = recovery_result
        
        # Store error in history
        with self.lock:
            self.error_history.append(error_context)
            if len(self.error_history) > self.max_history_size:
                self.error_history.pop(0)
            
            # Update error counts
            error_key = f"{type(exception).__name__}:{category.value}"
            self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        # Notify callbacks
        self._notify_error_callbacks(error_context)
        
        return error_context
    
    def _generate_error_id(self) -> str:
        """Generate a unique error ID."""
        import uuid
        return f"ERR-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    
    def _log_error(self, error_context: ErrorContext):
        """Log the error with appropriate level."""
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }.get(error_context.severity, logging.ERROR)
        
        log_message = (
            f"[{error_context.error_id}] {error_context.category.value.upper()} ERROR: "
            f"{error_context.message}"
        )
        
        extra_data = {
            'error_id': error_context.error_id,
            'severity': error_context.severity.value,
            'category': error_context.category.value,
            'component': error_context.component,
            'user_id': error_context.user_id,
            'request_id': error_context.request_id,
            'recovery_attempted': error_context.recovery_attempted,
            'recovery_successful': error_context.recovery_successful
        }
        
        self.logger.log(log_level, log_message, extra=extra_data)
        
        # Log stack trace for high severity errors
        if error_context.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.logger.error(f"Stack trace for {error_context.error_id}:\n{error_context.stack_trace}")
    
    def _attempt_recovery(self, exception: Exception, error_context: ErrorContext) -> bool:
        """Attempt to recover from the error."""
        exception_type = type(exception)
        
        # Try exact type match first
        if exception_type in self.recovery_strategies:
            try:
                return self.recovery_strategies[exception_type](exception, error_context)
            except Exception as recovery_error:
                self.logger.error(f"Recovery strategy failed for {exception_type.__name__}: {recovery_error}")
                return False
        
        # Try parent class matches
        for registered_type, strategy in self.recovery_strategies.items():
            if isinstance(exception, registered_type):
                try:
                    return strategy(exception, error_context)
                except Exception as recovery_error:
                    self.logger.error(f"Recovery strategy failed for {registered_type.__name__}: {recovery_error}")
                    return False
        
        return False
    
    def _notify_error_callbacks(self, error_context: ErrorContext):
        """Notify registered error callbacks."""
        for callback in self.error_callbacks:
            try:
                callback(error_context)
            except Exception as callback_error:
                self.logger.error(f"Error callback failed: {callback_error}")
    
    # Default recovery strategies
    def _recover_connection_error(self, exception: ConnectionError, context: ErrorContext) -> bool:
        """Attempt to recover from connection errors."""
        self.logger.info(f"Attempting connection recovery for {context.error_id}")
        
        # Wait and retry logic
        for attempt in range(3):
            time.sleep(2 ** attempt)  # Exponential backoff
            try:
                # This would contain actual reconnection logic
                self.logger.info(f"Connection recovery attempt {attempt + 1} for {context.error_id}")
                # Simulate recovery success/failure
                return attempt == 2  # Succeed on third attempt for demo
            except Exception as retry_error:
                self.logger.warning(f"Connection recovery attempt {attempt + 1} failed: {retry_error}")
        
        return False
    
    def _recover_timeout_error(self, exception: TimeoutError, context: ErrorContext) -> bool:
        """Attempt to recover from timeout errors."""
        self.logger.info(f"Attempting timeout recovery for {context.error_id}")
        # Implement timeout-specific recovery logic
        return False
    
    def _recover_file_not_found(self, exception: FileNotFoundError, context: ErrorContext) -> bool:
        """Attempt to recover from file not found errors."""
        self.logger.info(f"Attempting file recovery for {context.error_id}")
        
        # Try to create missing directories or use fallback files
        try:
            import os
            filename = str(exception).split("'")[1] if "'" in str(exception) else None
            if filename:
                # Create directory if it doesn't exist
                directory = os.path.dirname(filename)
                if directory and not os.path.exists(directory):
                    os.makedirs(directory, exist_ok=True)
                    self.logger.info(f"Created missing directory: {directory}")
                    return True
        except Exception as recovery_error:
            self.logger.error(f"File recovery failed: {recovery_error}")
        
        return False
    
    def _recover_permission_error(self, exception: PermissionError, context: ErrorContext) -> bool:
        """Attempt to recover from permission errors."""
        self.logger.warning(f"Permission error detected for {context.error_id}")
        # Log permission issues for manual resolution
        return False
    
    def _recover_import_error(self, exception: ImportError, context: ErrorContext) -> bool:
        """Attempt to recover from import errors."""
        self.logger.info(f"Attempting import recovery for {context.error_id}")
        
        # Try to install missing packages (in development mode only)
        module_name = str(exception).split("'")[1] if "'" in str(exception) else None
        if module_name:
            self.logger.warning(f"Missing module: {module_name}")
            # In production, this would just log the issue
            # In development, could attempt pip install
        
        return False
    
    def _recover_value_error(self, exception: ValueError, context: ErrorContext) -> bool:
        """Attempt to recover from value errors."""
        self.logger.info(f"Value error recovery for {context.error_id}")
        # Implement value-specific recovery logic
        return False
    
    def _recover_key_error(self, exception: KeyError, context: ErrorContext) -> bool:
        """Attempt to recover from key errors."""
        self.logger.info(f"Key error recovery for {context.error_id}")
        # Implement key-specific recovery logic
        return False
    
    def register_recovery_strategy(self, exception_type: Type[Exception], strategy: Callable):
        """Register a custom recovery strategy."""
        self.recovery_strategies[exception_type] = strategy
    
    def add_error_callback(self, callback: Callable):
        """Add an error callback function."""
        self.error_callbacks.append(callback)
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        with self.lock:
            total_errors = len(self.error_history)
            
            # Count by severity
            severity_counts = {}
            for severity in ErrorSeverity:
                severity_counts[severity.value] = sum(
                    1 for error in self.error_history if error.severity == severity
                )
            
            # Count by category
            category_counts = {}
            for category in ErrorCategory:
                category_counts[category.value] = sum(
                    1 for error in self.error_history if error.category == category
                )
            
            # Recovery statistics
            recovery_attempted = sum(1 for error in self.error_history if error.recovery_attempted)
            recovery_successful = sum(1 for error in self.error_history if error.recovery_successful)
            
            return {
                'total_errors': total_errors,
                'severity_breakdown': severity_counts,
                'category_breakdown': category_counts,
                'recovery_stats': {
                    'attempted': recovery_attempted,
                    'successful': recovery_successful,
                    'success_rate': (recovery_successful / max(recovery_attempted, 1)) * 100
                },
                'most_common_errors': dict(sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            }
    
    def get_recent_errors(self, count: int = 10) -> List[ErrorContext]:
        """Get recent errors."""
        with self.lock:
            return self.error_history[-count:]
    
    def clear_error_history(self):
        """Clear error history."""
        with self.lock:
            self.error_history.clear()
            self.error_counts.clear()

# Decorator for automatic error handling
def handle_errors(severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.UNKNOWN,
                 component: str = None,
                 attempt_recovery: bool = True,
                 reraise: bool = False):
    """Decorator for automatic error handling."""
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Get error handler instance (would be injected in real implementation)
                error_handler = getattr(wrapper, '_error_handler', None)
                if error_handler:
                    error_context = error_handler.handle_error(
                        e, severity, category, component or func.__name__, 
                        attempt_recovery=attempt_recovery
                    )
                    
                    if reraise:
                        raise
                    
                    return None
                else:
                    # Fallback logging
                    logging.error(f"Unhandled error in {func.__name__}: {e}")
                    if reraise:
                        raise
                    return None
        
        return wrapper
    return decorator

# Global error handler instance
global_error_handler = EnhancedErrorHandler()
