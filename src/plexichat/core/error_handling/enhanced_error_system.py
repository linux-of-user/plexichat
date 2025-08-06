"""
Enhanced Error Handling System with Descriptive Messages and Advanced Logging

Provides enterprise-grade error handling with:
- Descriptive error messages with context
- Correlation ID tracking across requests
- Advanced error categorization and severity
- User-friendly error responses
- Comprehensive error analytics
- Security-aware error handling


import asyncio
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from enum import Enum
from dataclasses import dataclass, field
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import traceback
import sys
import os

from ..logging.unified_logging import get_logger
from ..exceptions import ErrorSeverity, ErrorCategory

logger = get_logger(__name__)


class ErrorType(Enum):
    """Enhanced error type classification."""
        VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMIT = "rate_limit"
    SYSTEM = "system"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"
    BUSINESS_LOGIC = "business_logic"
    EXTERNAL_SERVICE = "external_service"


class ErrorContext(Enum):
    """Error context for better user experience."""
    USER_ACTION = "user_action"
    SYSTEM_OPERATION = "system_operation"
    API_REQUEST = "api_request"
    BACKGROUND_TASK = "background_task"
    SECURITY_CHECK = "security_check"


@dataclass
class ErrorDetails:
    """Comprehensive error details with context."""
        error_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = ""
    error_type: ErrorType = ErrorType.SYSTEM
    error_context: ErrorContext = ErrorContext.SYSTEM_OPERATION
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    category: ErrorCategory = ErrorCategory.SYSTEM
    
    # Core error information
    title: str = ""
    message: str = ""
    user_message: str = ""
    technical_details: str = ""
    
    # Context information
    component: str = ""
    operation: str = ""
    resource: str = ""
    user_id: Optional[str] = None
    
    # Request context
    request_method: str = ""
    request_path: str = ""
    request_params: Dict[str, Any] = field(default_factory=dict)
    client_ip: str = ""
    user_agent: str = ""
    
    # Error metadata
    timestamp: datetime = field(default_factory=datetime.now)
    stack_trace: str = ""
    exception_type: str = ""
    
    # Recovery information
    suggested_actions: List[str] = field(default_factory=list)
    retry_after: Optional[int] = None
    help_url: Optional[str] = None
    
    # Analytics
    frequency_count: int = 1
    first_occurrence: datetime = field(default_factory=datetime.now)
    last_occurrence: datetime = field(default_factory=datetime.now)


class EnhancedErrorHandler:
    """Enhanced error handler with descriptive messages and analytics.
        def __init__(self):
        self.error_templates = self._load_error_templates()
        self.error_analytics = {}
        self.correlation_tracker = {}
        
    def _load_error_templates(self) -> Dict[str, Dict[str, str]]:
        """Load error message templates for different error types."""
        return {
            ErrorType.VALIDATION.value: {
                "title": "Input Validation Error",
                "user_message": "The information you provided is not valid. Please check your input and try again.",
                "help_url": "/docs/validation-errors"
            },
            ErrorType.AUTHENTICATION.value: {
                "title": "Authentication Required",
                "user_message": "You need to sign in to access this resource. Please log in and try again.",
                "help_url": "/docs/authentication"
            },
            ErrorType.AUTHORIZATION.value: {
                "title": "Access Denied",
                "user_message": "You don't have permission to access this resource. Contact your administrator if you believe this is an error.",
                "help_url": "/docs/permissions"
            },
            ErrorType.NOT_FOUND.value: {
                "title": "Resource Not Found",
                "user_message": "The requested resource could not be found. It may have been moved or deleted.",
                "help_url": "/docs/resources"
            },
            ErrorType.CONFLICT.value: {
                "title": "Conflict Error",
                "user_message": "The operation conflicts with the current state. Please refresh and try again.",
                "help_url": "/docs/conflicts"
            },
            ErrorType.RATE_LIMIT.value: {
                "title": "Rate Limit Exceeded",
                "user_message": "You're making requests too quickly. Please wait a moment and try again.",
                "help_url": "/docs/rate-limits"
            },
            ErrorType.SYSTEM.value: {
                "title": "System Error",
                "user_message": "An unexpected system error occurred. Our team has been notified and is working on a fix.",
                "help_url": "/docs/system-errors"
            },
            ErrorType.DATABASE.value: {
                "title": "Database Error",
                "user_message": "There was a problem accessing the database. Please try again in a few moments.",
                "help_url": "/docs/database-errors"
            },
            ErrorType.SECURITY.value: {
                "title": "Security Error",
                "user_message": "A security issue was detected with your request. Please ensure you're using the application correctly.",
                "help_url": "/docs/security"
            }
        }
    
    async def handle_error(self, 
                        exception: Exception,
                        request: Optional[Request] = None,
                        correlation_id: Optional[str] = None,
                        context: Optional[Dict[str, Any]] = None) -> ErrorDetails:
        """Handle error with comprehensive analysis and response generation.
        
        # Generate correlation ID if not provided
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        
        # Analyze the error
        error_details = await self._analyze_error(exception, request, correlation_id, context)
        
        # Track error analytics
        await self._track_error_analytics(error_details)
        
        # Log the error with full context
        await self._log_error_with_context(error_details)
        
        # Check if this is a security-related error
        if error_details.error_type == ErrorType.SECURITY:
            await self._handle_security_error(error_details)
        
        return error_details
    
    async def _analyze_error(self, 
                        exception: Exception,
                        request: Optional[Request],
                        correlation_id: str,
                        context: Optional[Dict[str, Any]]) -> ErrorDetails:
        """Analyze error and create comprehensive error details."""
        
        error_details = ErrorDetails(correlation_id=correlation_id)
        
        # Basic exception information
        error_details.exception_type = type(exception).__name__
        error_details.technical_details = str(exception)
        error_details.stack_trace = traceback.format_exc()
        
        # Determine error type and context
        error_details.error_type = self._classify_error(exception)
        error_details.error_context = self._determine_context(request, context)
        
        # Set severity based on error type
        error_details.severity = self._determine_severity(exception, error_details.error_type)
        
        # Generate user-friendly messages
        template = self.error_templates.get(error_details.error_type.value, {})
        error_details.title = template.get("title", "An Error Occurred")
        error_details.user_message = template.get("user_message", "An unexpected error occurred. Please try again.")
        error_details.help_url = template.get("help_url")
        
        # Add request context if available
        if request:
            error_details.request_method = request.method
            error_details.request_path = str(request.url.path)
            error_details.request_params = dict(request.query_params)
            error_details.client_ip = request.client.host if request.client else "unknown"
            error_details.user_agent = request.headers.get("user-agent", "unknown")
            
            # Extract user ID if available
            if hasattr(request.state, 'user_id'):
                error_details.user_id = request.state.user_id
        
        # Add context information
        if context:
            error_details.component = context.get("component", "unknown")
            error_details.operation = context.get("operation", "unknown")
            error_details.resource = context.get("resource", "unknown")
        
        # Generate suggested actions
        error_details.suggested_actions = self._generate_suggested_actions(error_details)
        
        return error_details
    
    def _classify_error(self, exception: Exception) -> ErrorType:
        """Classify error based on exception type and content.
        exception_name = type(exception).__name__.lower()
        exception_message = str(exception).lower()
        
        # HTTP exceptions
        if isinstance(exception, HTTPException):
            status_code = getattr(exception, 'status_code', 500)
            if status_code == 400:
                return ErrorType.VALIDATION
            elif status_code == 401:
                return ErrorType.AUTHENTICATION
            elif status_code == 403:
                return ErrorType.AUTHORIZATION
            elif status_code == 404:
                return ErrorType.NOT_FOUND
            elif status_code == 409:
                return ErrorType.CONFLICT
            elif status_code == 429:
                return ErrorType.RATE_LIMIT
        
        # Database errors
        if any(db_term in exception_name for db_term in ['database', 'sql', 'connection', 'integrity']):
            return ErrorType.DATABASE
        
        # Network errors
        if any(net_term in exception_name for net_term in ['connection', 'timeout', 'network', 'socket']):
            return ErrorType.NETWORK
        
        # Security errors
        if any(sec_term in exception_message for sec_term in ['security', 'malicious', 'attack', 'injection']):
            return ErrorType.SECURITY
        
        # Validation errors
        if any(val_term in exception_name for val_term in ['validation', 'value', 'type', 'format']):
            return ErrorType.VALIDATION
        
        return ErrorType.SYSTEM
    
    def _determine_context(self, request: Optional[Request], context: Optional[Dict[str, Any]]) -> ErrorContext:
        """Determine error context based on request and additional context."""
        if context and context.get("context_type"):
            return ErrorContext(context["context_type"])
        
        if request:
            if request.url.path.startswith("/api/"):
                return ErrorContext.API_REQUEST
            else:
                return ErrorContext.USER_ACTION
        
        return ErrorContext.SYSTEM_OPERATION
    
    def _determine_severity(self, exception: Exception, error_type: ErrorType) -> ErrorSeverity:
        """Determine error severity based on exception and type.
        if error_type == ErrorType.SECURITY:
            return ErrorSeverity.HIGH
        elif error_type in [ErrorType.DATABASE, ErrorType.SYSTEM]:
            return ErrorSeverity.MEDIUM
        elif error_type in [ErrorType.VALIDATION, ErrorType.NOT_FOUND]:
            return ErrorSeverity.LOW
        else:
            return ErrorSeverity.MEDIUM
    
    def _generate_suggested_actions(self, error_details: ErrorDetails) -> List[str]:
        """Generate suggested actions based on error type."""
        actions = []
        
        if error_details.error_type == ErrorType.VALIDATION:
            actions.extend([
                "Check that all required fields are filled out",
                "Verify that data formats match the expected patterns",
                "Review the API documentation for correct parameter formats"
            ])
        elif error_details.error_type == ErrorType.AUTHENTICATION:
            actions.extend([
                "Sign in to your account",
                "Check that your session hasn't expired",
                "Verify your credentials are correct"
            ])
        elif error_details.error_type == ErrorType.AUTHORIZATION:
            actions.extend([
                "Contact your administrator for access",
                "Verify you have the necessary permissions",
                "Check if your account status is active"
            ])
        elif error_details.error_type == ErrorType.RATE_LIMIT:
            actions.extend([
                f"Wait {error_details.retry_after or 60} seconds before trying again",
                "Reduce the frequency of your requests",
                "Consider implementing request batching"
            ])
        elif error_details.error_type == ErrorType.SYSTEM:
            actions.extend([
                "Try again in a few moments",
                "Contact support if the problem persists",
                "Check the system status page for known issues"
            ])
        
        return actions
    
    async def _track_error_analytics(self, error_details: ErrorDetails):
        """Track error analytics for monitoring and improvement."""
        error_key = f"{error_details.error_type.value}:{error_details.exception_type}"
        
        if error_key in self.error_analytics:
            analytics = self.error_analytics[error_key]
            analytics['count'] += 1
            analytics['last_occurrence'] = error_details.timestamp
        else:
            self.error_analytics[error_key] = {
                'count': 1,
                'first_occurrence': error_details.timestamp,
                'last_occurrence': error_details.timestamp,
                'error_type': error_details.error_type.value,
                'severity': error_details.severity.value
            }
    
    async def _log_error_with_context(self, error_details: ErrorDetails):
        """Log error with comprehensive context information."""
        log_data = {
            'error_id': error_details.error_id,
            'correlation_id': error_details.correlation_id,
            'error_type': error_details.error_type.value,
            'severity': error_details.severity.value,
            'title': error_details.title,
            'message': error_details.technical_details,
            'component': error_details.component,
            'operation': error_details.operation,
            'user_id': error_details.user_id,
            'request_method': error_details.request_method,
            'request_path': error_details.request_path,
            'client_ip': error_details.client_ip,
            'timestamp': error_details.timestamp.isoformat()
        }
        
        if error_details.severity == ErrorSeverity.HIGH:
            logger.error(f"HIGH SEVERITY ERROR: {error_details.title}", extra=log_data)
        elif error_details.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"MEDIUM SEVERITY ERROR: {error_details.title}", extra=log_data)
        else:
            logger.info(f"LOW SEVERITY ERROR: {error_details.title}", extra=log_data)
    
    async def _handle_security_error(self, error_details: ErrorDetails):
        """Handle security-related errors with special attention."""
        security_log_data = {
            'security_event': 'error_detected',
            'error_id': error_details.error_id,
            'client_ip': error_details.client_ip,
            'user_agent': error_details.user_agent,
            'request_path': error_details.request_path,
            'technical_details': error_details.technical_details
        }
        
        logger.critical(f"SECURITY ERROR DETECTED: {error_details.title}", extra=security_log_data)
        
        # Additional security measures could be implemented here
        # such as rate limiting, IP blocking, or alerting
    
    def create_error_response(self, error_details: ErrorDetails, include_debug: bool = False) -> JSONResponse:
        """Create a comprehensive error response.
        response_data = {
            'error': {
                'id': error_details.error_id,
                'correlation_id': error_details.correlation_id,
                'type': error_details.error_type.value,
                'title': error_details.title,
                'message': error_details.user_message,
                'timestamp': error_details.timestamp.isoformat(),
                'suggested_actions': error_details.suggested_actions
            }
        }
        
        if error_details.help_url:
            response_data['error']['help_url'] = error_details.help_url
        
        if error_details.retry_after:
            response_data['error']['retry_after'] = error_details.retry_after
        
        # Include debug information in development
        if include_debug:
            response_data['debug'] = {
                'exception_type': error_details.exception_type,
                'technical_details': error_details.technical_details,
                'component': error_details.component,
                'operation': error_details.operation,
                'stack_trace': error_details.stack_trace
            }
        
        # Determine HTTP status code
        status_code = self._get_http_status_code(error_details.error_type)
        
        headers = {
            'X-Error-ID': error_details.error_id,
            'X-Correlation-ID': error_details.correlation_id
        }
        
        if error_details.retry_after:
            headers['Retry-After'] = str(error_details.retry_after)
        
        return JSONResponse(
            content=response_data,
            status_code=status_code,
            headers=headers
        )
    
    def _get_http_status_code(self, error_type: ErrorType) -> int:
        """Get appropriate HTTP status code for error type."""
        status_map = {
            ErrorType.VALIDATION: 400,
            ErrorType.AUTHENTICATION: 401,
            ErrorType.AUTHORIZATION: 403,
            ErrorType.NOT_FOUND: 404,
            ErrorType.CONFLICT: 409,
            ErrorType.RATE_LIMIT: 429,
            ErrorType.SYSTEM: 500,
            ErrorType.DATABASE: 500,
            ErrorType.NETWORK: 502,
            ErrorType.SECURITY: 400,
            ErrorType.BUSINESS_LOGIC: 422,
            ErrorType.EXTERNAL_SERVICE: 503
        }
        return status_map.get(error_type, 500)


# Global enhanced error handler instance
enhanced_error_handler = EnhancedErrorHandler()
