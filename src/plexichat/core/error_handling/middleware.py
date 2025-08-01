import asyncio
import logging
import time
import traceback
import uuid
from datetime import datetime
from typing import Any, Callable, Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .beautiful_error_handler import BeautifulErrorHandler
from .error_manager import error_manager
from .exceptions import BaseAPIException, ErrorCategory, ErrorSeverity
from .enhanced_error_system import enhanced_error_handler, ErrorType
from ..logging.correlation_tracker import correlation_tracker, CorrelationType, set_current_correlation_id
from ..logging.unified_logging import get_logger

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse

"""
PlexiChat Error Handling Middleware

FastAPI middleware for comprehensive error handling, logging,
and response formatting across the entire application.
"""

logger = get_logger(__name__)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Comprehensive error handling middleware for FastAPI."""

    def __init__(self, app: ASGIApp,
                 debug: bool = False,
                 include_request_details: bool = True,
                 log_errors: bool = True,
                 enable_beautiful_errors: bool = True):
        super().__init__(app)
        self.debug = debug
        self.include_request_details = include_request_details
        self.log_errors = log_errors
        self.enable_beautiful_errors = enable_beautiful_errors

        # Initialize beautiful error handler
        if self.enable_beautiful_errors:
            self.beautiful_handler = BeautifulErrorHandler()

        # Error statistics
        self.error_stats: Dict[str, int] = {}
        self.request_count = 0
        self.error_count = 0

        # Performance tracking
        self.response_times: list = []
        self.max_response_times = 1000  # Keep last 1000 response times

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with comprehensive error handling and correlation tracking."""
        start_time = time.time()

        # Start correlation tracking for this request
        correlation_id = correlation_tracker.start_correlation(
            correlation_type=CorrelationType.REQUEST,
            component="http_middleware",
            operation=f"{request.method} {request.url.path}",
            user_id=getattr(request.state, 'user_id', None),
            session_id=getattr(request.state, 'session_id', None),
            request_method=request.method,
            request_path=str(request.url.path),
            request_params=dict(request.query_params),
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown")
        )

        # Set correlation ID in context and request state
        set_current_correlation_id(correlation_id)
        request.state.correlation_id = correlation_id
        request.state.request_id = correlation_id[:8]  # Short ID for backwards compatibility

        self.request_count += 1

        try:
            # Process the request
            response = await call_next(request)

            # Track response time
            response_time = time.time() - start_time
            self._track_response_time(response_time)

            # Add comprehensive headers
            response.headers["X-Request-ID"] = request.state.request_id
            response.headers["X-Correlation-ID"] = correlation_id
            response.headers["X-Response-Time"] = f"{response_time:.3f}s"

            # Finish correlation tracking
            correlation_tracker.finish_correlation(
                correlation_id,
                response_status=response.status_code
            )

            return response

        except Exception as e:
            # Handle the error with enhanced system
            return await self._handle_error_enhanced(request, e, correlation_id, start_time)

    async def _handle_error_enhanced(self, request: Request, exception: Exception,
                                   correlation_id: str, start_time: float) -> Response:
        """Handle errors using the enhanced error system."""
        response_time = time.time() - start_time
        self.error_count += 1

        # Use enhanced error handler
        error_details = await enhanced_error_handler.handle_error(
            exception=exception,
            request=request,
            correlation_id=correlation_id,
            context={
                'component': 'http_middleware',
                'operation': f"{request.method} {request.url.path}",
                'response_time': response_time
            }
        )

        # Finish correlation tracking with error information
        correlation_tracker.finish_correlation(
            correlation_id,
            response_status=error_details._get_http_status_code(error_details.error_type),
            error_count=1,
            error_types=[error_details.exception_type]
        )

        # Update error statistics
        self._update_error_stats_enhanced(error_details)

        # Create appropriate response
        if self._is_api_request(request):
            return enhanced_error_handler.create_error_response(
                error_details,
                include_debug=self.debug
            )
        else:
            return await self._create_web_error_response_enhanced(error_details, request)

    async def _handle_error(self, request: Request, exception: Exception,)
                           request_id: str, start_time: float) -> Response:
        """Handle errors with comprehensive logging and response formatting."""

        response_time = time.time() - start_time
        self.error_count += 1

        # Determine error type and details
        error_info = await self._analyze_error(exception, request, request_id)

        # Log the error
        if self.log_errors:
            await self._log_error(error_info, request, response_time)

        # Update error statistics
        self._update_error_stats(error_info)

        # Record error for monitoring
        await self._record_error_for_monitoring(error_info, request)

        # Generate appropriate response
        if self._is_api_request(request):
            return await self._create_api_error_response(error_info, request_id, response_time)
        else:
            return await self._create_web_error_response(error_info, request, request_id)

    async def _analyze_error(self, exception: Exception, request: Request,)
                           request_id: str) -> Dict[str, Any]:
        """Analyze the error and extract relevant information."""

        error_info = {
            'request_id': request_id,
            'timestamp': datetime.now(),
            'exception': exception,
            'exception_type': type(exception).__name__,
            'message': str(exception),
            'stack_trace': traceback.format_exc() if self.debug else None,
        }

        # Handle different exception types
        if isinstance(exception, BaseAPIException):
            error_info.update({)
                'severity': ErrorSeverity.MEDIUM,
                'category': ErrorCategory.BUSINESS_LOGIC,
                'status_code': exception.status_code,
                'error_code': exception.error_code,
                'details': exception.details
            })
        elif isinstance(exception, HTTPException):
            error_info.update({)
                'severity': ErrorSeverity.LOW if exception.status_code < 500 else ErrorSeverity.HIGH,
                'category': ErrorCategory.VALIDATION if exception.status_code == 422 else ErrorCategory.SYSTEM,
                'status_code': exception.status_code,
                'error_code': f"HTTP_{exception.status_code}",
                'details': {'detail': exception.detail}
            })
        elif isinstance(exception, ValueError):
            error_info.update({)
                'severity': ErrorSeverity.LOW,
                'category': ErrorCategory.VALIDATION,
                'status_code': 400,
                'error_code': 'VALIDATION_ERROR',
                'details': {}
            })
        elif isinstance(exception, PermissionError):
            error_info.update({)
                'severity': ErrorSeverity.MEDIUM,
                'category': ErrorCategory.AUTHORIZATION,
                'status_code': 403,
                'error_code': 'PERMISSION_DENIED',
                'details': {}
            })
        elif isinstance(exception, FileNotFoundError):
            error_info.update({)
                'severity': ErrorSeverity.LOW,
                'category': ErrorCategory.FILE_OPERATION,
                'status_code': 404,
                'error_code': 'FILE_NOT_FOUND',
                'details': {}
            })
        elif isinstance(exception, asyncio.TimeoutError):
            error_info.update({)
                'severity': ErrorSeverity.MEDIUM,
                'category': ErrorCategory.NETWORK,
                'status_code': 504,
                'error_code': 'TIMEOUT_ERROR',
                'details': {}
            })
        else:
            # Unknown error - treat as internal server error
            error_info.update({)
                'severity': ErrorSeverity.HIGH,
                'category': ErrorCategory.SYSTEM,
                'status_code': 500,
                'error_code': 'INTERNAL_SERVER_ERROR',
                'details': {}
            })

        # Add request context if enabled
        if self.include_request_details:
            error_info['request_details'] = {
                'method': request.method,
                'url': str(request.url),
                'headers': dict(request.headers),
                'client_ip': request.client.host if request.client else None,
                'user_agent': request.headers.get('user-agent'),
            }

        return error_info

    async def _log_error(self, error_info: Dict[str, Any], request: Request,)
                        response_time: float):
        """Log error with appropriate level and context."""

        severity = error_info.get('severity', ErrorSeverity.MEDIUM)
        status_code = error_info.get('status_code', 500)

        log_message = ()
            f"[{error_info['request_id']}] {request.method} {request.url} - "
            f"{status_code} {error_info['exception_type']}: {error_info['message']} "
            f"({response_time:.3f}s)"
        )

        log_context = {
            'request_id': error_info['request_id'],
            'method': request.method,
            'url': str(request.url),
            'status_code': status_code,
            'response_time': response_time,
            'exception_type': error_info['exception_type'],
            'error_code': error_info.get('error_code'),
        }

        if severity == ErrorSeverity.LOW:
            logger.info(log_message, extra=log_context)
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message, extra=log_context)
        elif severity == ErrorSeverity.HIGH:
            logger.error(log_message, extra=log_context)
        else:  # CRITICAL or EMERGENCY
            logger.critical(log_message, extra=log_context)

            # Also log stack trace for critical errors
            if error_info.get('stack_trace'):
                logger.critical(f"Stack trace for {error_info['request_id']}:\n{error_info['stack_trace']}")

    def _update_error_stats(self, error_info: Dict[str, Any]):
        """Update error statistics."""
        exception_type = error_info['exception_type']
        status_code = error_info.get('status_code', 500)

        self.error_stats[f"exception_{exception_type}"] = self.error_stats.get(f"exception_{exception_type}", 0) + 1
        self.error_stats[f"status_{status_code}"] = self.error_stats.get(f"status_{status_code}", 0) + 1

    async def _record_error_for_monitoring(self, error_info: Dict[str, Any], request: Request):
        """Record error for monitoring systems."""
        try:
            # Import here to avoid circular imports
            context = {
                'request_id': error_info['request_id'],
                'method': request.method,
                'url': str(request.url),
                'status_code': error_info.get('status_code'),
                'user_agent': request.headers.get('user-agent'),
                'client_ip': request.client.host if request.client else None,
            }

            await error_manager.handle_error()
                exception=error_info['exception'],
                context=context,
                severity=error_info.get('severity', ErrorSeverity.MEDIUM),
                category=error_info.get('category', ErrorCategory.SYSTEM),
                component='web_middleware'
            )
        except Exception as e:
            logger.error(f"Failed to record error for monitoring: {e}")

    def _is_api_request(self, request: Request) -> bool:
        """Determine if request is an API request."""
        # Check if request is for API endpoint
        path = request.url.path
        accept_header = request.headers.get('accept', '')

        return ()
            path.startswith('/api/') or
            path.startswith('/v1/') or
            'application/json' in accept_header or
            request.headers.get('content-type', '').startswith('application/json')
        )

    async def _create_api_error_response(self, error_info: Dict[str, Any],)
                                       request_id: str, response_time: float) -> JSONResponse:
        """Create JSON error response for API requests."""

        status_code = error_info.get('status_code', 500)

        response_data = {
            'error': True,
            'request_id': request_id,
            'error_code': error_info.get('error_code', 'UNKNOWN_ERROR'),
            'message': error_info['message'],
            'status_code': status_code,
            'timestamp': error_info['timestamp'].isoformat(),
            'response_time': f"{response_time:.3f}s"
        }

        # Add details if available
        if error_info.get('details'):
            response_data['details'] = error_info['details']

        # Add stack trace in debug mode
        if self.debug and error_info.get('stack_trace'):
            response_data['stack_trace'] = error_info['stack_trace']

        # Add request details if enabled
        if self.include_request_details and error_info.get('request_details'):
            response_data['request'] = error_info['request_details']

        return JSONResponse()
            status_code=status_code,
            content=response_data,
            headers={
                'X-Request-ID': request_id,
                'X-Response-Time': f"{response_time:.3f}s"
            }
        )

    async def _create_web_error_response(self, error_info: Dict[str, Any],)
                                       request: Request, request_id: str) -> Response:
        """Create HTML error response for web requests."""

        if self.enable_beautiful_errors:
            status_code = error_info.get('status_code', 500)
            return await self.beautiful_handler.handle_error()
                request=request,
                status_code=status_code,
                exception=error_info['exception']
            )
        else:
            # Simple text response
            status_code = error_info.get('status_code', 500)
            return Response()
                content=f"Error {status_code}: {error_info['message']}",
                status_code=status_code,
                media_type="text/plain",
                headers={'X-Request-ID': request_id}
            )

    def _track_response_time(self, response_time: float):
        """Track response times for performance monitoring."""
        self.response_times.append(response_time)
        if len(self.response_times) > self.max_response_times:
            self.response_times.pop(0)

    def get_middleware_stats(self) -> Dict[str, Any]:
        """Get middleware statistics."""
        avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

        return {
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'error_rate': (self.error_count / max(self.request_count, 1)) * 100,
            'average_response_time': avg_response_time,
            'error_breakdown': self.error_stats,
            'recent_response_times': self.response_times[-10:] if self.response_times else []
        }

    def _update_error_stats_enhanced(self, error_details):
        """Update error statistics with enhanced error details."""
        error_key = f"{error_details.error_type.value}:{error_details.exception_type}"
        self.error_stats[error_key] = self.error_stats.get(error_key, 0) + 1

        # Also track by severity
        severity_key = f"severity:{error_details.severity.value}"
        self.error_stats[severity_key] = self.error_stats.get(severity_key, 0) + 1

    async def _create_web_error_response_enhanced(self, error_details, request: Request) -> Response:
        """Create enhanced web error response."""
        if self.enable_beautiful_errors:
            status_code = enhanced_error_handler._get_http_status_code(error_details.error_type)
            return await self.beautiful_handler.handle_error(
                request=request,
                status_code=status_code,
                exception=Exception(error_details.technical_details)
            )
        else:
            # Simple text response with enhanced information
            status_code = enhanced_error_handler._get_http_status_code(error_details.error_type)
            return Response(
                content=f"Error {status_code}: {error_details.user_message}",
                status_code=status_code,
                media_type="text/plain",
                headers={
                    'X-Request-ID': error_details.correlation_id[:8],
                    'X-Correlation-ID': error_details.correlation_id,
                    'X-Error-ID': error_details.error_id
                }
            )
