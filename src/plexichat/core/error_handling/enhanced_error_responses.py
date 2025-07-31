#!/usr/bin/env python3
"""
Enhanced Error Response System
Provides comprehensive, descriptive error messages with proper HTTP status codes
"""

import traceback
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import uuid

logger = logging.getLogger(__name__)

class ErrorCategory(str, Enum):
    """Error categories for better classification."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    RATE_LIMITING = "rate_limiting"
    RESOURCE_NOT_FOUND = "resource_not_found"
    CONFLICT = "conflict"
    SERVER_ERROR = "server_error"
    EXTERNAL_SERVICE = "external_service"
    SECURITY = "security"
    BUSINESS_LOGIC = "business_logic"

class ErrorSeverity(str, Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ErrorDetail:
    """Detailed error information."""
    field: Optional[str] = None
    message: str = ""
    code: Optional[str] = None
    value: Optional[Any] = None
    constraint: Optional[str] = None

@dataclass
class ErrorContext:
    """Additional context for errors."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[str] = None

@dataclass
class EnhancedErrorResponse:
    """Enhanced error response structure."""
    success: bool = False
    error: str = ""
    message: str = ""
    category: ErrorCategory = ErrorCategory.SERVER_ERROR
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    code: str = ""
    status_code: int = 500
    details: List[ErrorDetail] = None
    context: Optional[ErrorContext] = None
    suggestions: List[str] = None
    documentation_url: Optional[str] = None
    support_reference: Optional[str] = None
    retry_after: Optional[int] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = []
        if self.suggestions is None:
            self.suggestions = []

class EnhancedErrorHandler:
    """Enhanced error handler with descriptive messages."""
    
    def __init__(self, debug_mode: bool = False, include_traceback: bool = False):
        self.debug_mode = debug_mode
        self.include_traceback = include_traceback
        self.error_mappings = self._initialize_error_mappings()
    
    def _initialize_error_mappings(self) -> Dict[int, Dict[str, Any]]:
        """Initialize HTTP status code to error information mappings."""
        return {
            # 4xx Client Errors
            400: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "The request contains invalid or malformed data",
                "suggestions": [
                    "Check the request format and ensure all required fields are provided",
                    "Verify that field values meet the specified constraints",
                    "Review the API documentation for correct request structure"
                ]
            },
            401: {
                "category": ErrorCategory.AUTHENTICATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Authentication is required to access this resource",
                "suggestions": [
                    "Provide valid authentication credentials",
                    "Check if your access token has expired",
                    "Ensure you're using the correct authentication method"
                ]
            },
            403: {
                "category": ErrorCategory.AUTHORIZATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "You don't have permission to access this resource",
                "suggestions": [
                    "Contact an administrator to request access",
                    "Verify you have the required role or permissions",
                    "Check if your account has been suspended or restricted"
                ]
            },
            404: {
                "category": ErrorCategory.RESOURCE_NOT_FOUND,
                "severity": ErrorSeverity.LOW,
                "default_message": "The requested resource could not be found",
                "suggestions": [
                    "Check the URL for typos or incorrect formatting",
                    "Verify the resource ID is correct and exists",
                    "Ensure you have permission to view this resource"
                ]
            },
            409: {
                "category": ErrorCategory.CONFLICT,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "The request conflicts with the current state of the resource",
                "suggestions": [
                    "Check if the resource already exists",
                    "Verify the resource hasn't been modified by another user",
                    "Try refreshing the data and attempting the operation again"
                ]
            },
            422: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "The request data failed validation",
                "suggestions": [
                    "Review the validation errors and correct the data",
                    "Ensure all required fields are provided",
                    "Check that field values are in the correct format"
                ]
            },
            429: {
                "category": ErrorCategory.RATE_LIMITING,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Too many requests - rate limit exceeded",
                "suggestions": [
                    "Wait before making additional requests",
                    "Implement exponential backoff in your client",
                    "Consider upgrading your account for higher rate limits"
                ]
            },
            500: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.HIGH,
                "default_message": "An internal server error occurred",
                "suggestions": [
                    "Try the request again in a few moments",
                    "Contact support if the problem persists",
                    "Check the system status page for known issues"
                ]
            },
            502: {
                "category": ErrorCategory.EXTERNAL_SERVICE,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Bad gateway - upstream service error",
                "suggestions": [
                    "The service is temporarily unavailable",
                    "Try again in a few minutes",
                    "Check the system status page for updates"
                ]
            },
            503: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Service temporarily unavailable",
                "suggestions": [
                    "The service is undergoing maintenance",
                    "Try again later",
                    "Check the system status page for maintenance schedules"
                ]
            },

            # Additional 4xx Client Errors
            402: {
                "category": ErrorCategory.AUTHORIZATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Payment required to access this resource",
                "suggestions": [
                    "Upgrade your account to access premium features",
                    "Check your subscription status",
                    "Contact billing support for assistance"
                ]
            },
            405: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "HTTP method not allowed for this endpoint",
                "suggestions": [
                    "Check the API documentation for allowed methods",
                    "Verify you're using the correct HTTP method (GET, POST, PUT, DELETE)",
                    "Ensure the endpoint supports your requested operation"
                ]
            },
            406: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Requested content type not acceptable",
                "suggestions": [
                    "Check the Accept header in your request",
                    "Verify the server supports your requested content type",
                    "Try requesting application/json or text/html"
                ]
            },
            407: {
                "category": ErrorCategory.AUTHENTICATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Proxy authentication required",
                "suggestions": [
                    "Provide valid proxy authentication credentials",
                    "Check your proxy configuration",
                    "Contact your network administrator"
                ]
            },
            408: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Request timeout - the server did not receive a complete request",
                "suggestions": [
                    "Try sending the request again",
                    "Check your network connection",
                    "Reduce the size of your request if possible"
                ]
            },
            410: {
                "category": ErrorCategory.RESOURCE_NOT_FOUND,
                "severity": ErrorSeverity.LOW,
                "default_message": "The requested resource is no longer available",
                "suggestions": [
                    "This resource has been permanently removed",
                    "Check if there's a newer version of the resource",
                    "Update your bookmarks or links"
                ]
            },
            411: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Content-Length header is required",
                "suggestions": [
                    "Include a Content-Length header in your request",
                    "Ensure your HTTP client sets the Content-Length automatically",
                    "Check your request body size"
                ]
            },
            412: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Precondition failed",
                "suggestions": [
                    "Check the If-Match or If-None-Match headers",
                    "Verify the resource hasn't been modified",
                    "Refresh your data and try again"
                ]
            },
            413: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Request entity too large",
                "suggestions": [
                    "Reduce the size of your request body",
                    "Split large requests into smaller chunks",
                    "Check the maximum allowed request size"
                ]
            },
            414: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Request URI too long",
                "suggestions": [
                    "Shorten your request URL",
                    "Use POST instead of GET for large data",
                    "Remove unnecessary query parameters"
                ]
            },
            415: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Unsupported media type",
                "suggestions": [
                    "Check the Content-Type header in your request",
                    "Verify the server supports your media type",
                    "Try using application/json or application/x-www-form-urlencoded"
                ]
            },
            416: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Requested range not satisfiable",
                "suggestions": [
                    "Check the Range header in your request",
                    "Verify the requested byte range is valid",
                    "Request the entire resource instead"
                ]
            },
            417: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.LOW,
                "default_message": "Expectation failed",
                "suggestions": [
                    "Check the Expect header in your request",
                    "Remove the Expect header if not needed",
                    "Verify the server supports your expectation"
                ]
            },
            418: {
                "category": ErrorCategory.BUSINESS_LOGIC,
                "severity": ErrorSeverity.LOW,
                "default_message": "I'm a teapot - The server refuses to brew coffee because it is, permanently, a teapot",
                "suggestions": [
                    "This is an Easter egg error from RFC 2324",
                    "Try requesting tea instead of coffee ?",
                    "Check if you're using the correct endpoint",
                    "This error indicates a playful server response"
                ]
            },
            421: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Misdirected request",
                "suggestions": [
                    "Check the request URL and hostname",
                    "Verify you're connecting to the correct server",
                    "Check your DNS configuration"
                ]
            },
            423: {
                "category": ErrorCategory.CONFLICT,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Resource is locked",
                "suggestions": [
                    "The resource is currently being modified by another user",
                    "Wait a moment and try again",
                    "Check if you have the necessary permissions"
                ]
            },
            424: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Failed dependency",
                "suggestions": [
                    "A dependent operation failed",
                    "Check all required resources are available",
                    "Verify the order of operations"
                ]
            },
            426: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Upgrade required",
                "suggestions": [
                    "The client needs to upgrade to a different protocol",
                    "Check the Upgrade header in the response",
                    "Update your client software"
                ]
            },
            428: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Precondition required",
                "suggestions": [
                    "Include appropriate precondition headers",
                    "Add If-Match or If-None-Match headers",
                    "Check the API documentation for required headers"
                ]
            },
            431: {
                "category": ErrorCategory.VALIDATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Request header fields too large",
                "suggestions": [
                    "Reduce the size of your request headers",
                    "Remove unnecessary headers",
                    "Check for extremely long cookie values"
                ]
            },
            451: {
                "category": ErrorCategory.AUTHORIZATION,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Unavailable for legal reasons",
                "suggestions": [
                    "This content is blocked due to legal restrictions",
                    "Contact support for more information",
                    "Check if you're accessing from a restricted region"
                ]
            },

            # 5xx Server Errors
            501: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Not implemented - The server does not support this functionality",
                "suggestions": [
                    "This feature is not yet implemented",
                    "Check the API documentation for supported features",
                    "Contact support to request this feature"
                ]
            },
            504: {
                "category": ErrorCategory.EXTERNAL_SERVICE,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Gateway timeout - Upstream server did not respond in time",
                "suggestions": [
                    "The upstream service is taking too long to respond",
                    "Try again in a few moments",
                    "Check the system status page for service issues"
                ]
            },
            505: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "HTTP version not supported",
                "suggestions": [
                    "Your HTTP version is not supported by this server",
                    "Try using HTTP/1.1 or HTTP/2",
                    "Update your client software"
                ]
            },
            506: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Variant also negotiates",
                "suggestions": [
                    "Server configuration error in content negotiation",
                    "Contact the server administrator",
                    "Try a different Accept header"
                ]
            },
            507: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Insufficient storage",
                "suggestions": [
                    "The server has run out of storage space",
                    "Try again later when space is available",
                    "Contact support if this persists"
                ]
            },
            508: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.HIGH,
                "default_message": "Loop detected",
                "suggestions": [
                    "The server detected an infinite loop in processing",
                    "This is a server configuration issue",
                    "Contact the server administrator"
                ]
            },
            510: {
                "category": ErrorCategory.SERVER_ERROR,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Not extended",
                "suggestions": [
                    "Further extensions to the request are required",
                    "Check the API documentation for required extensions",
                    "Contact support for guidance"
                ]
            },
            511: {
                "category": ErrorCategory.AUTHENTICATION,
                "severity": ErrorSeverity.MEDIUM,
                "default_message": "Network authentication required",
                "suggestions": [
                    "You need to authenticate with the network",
                    "Check your network connection and credentials",
                    "Contact your network administrator"
                ]
            }
        }
    
    def create_error_response(
        self,
        status_code: int,
        error: str = "",
        message: str = "",
        details: List[ErrorDetail] = None,
        context: Optional[ErrorContext] = None,
        custom_suggestions: List[str] = None,
        retry_after: Optional[int] = None
    ) -> EnhancedErrorResponse:
        """Create an enhanced error response."""
        
        # Get error mapping for status code
        error_mapping = self.error_mappings.get(status_code, self.error_mappings[500])
        
        # Generate error code
        error_code = f"ERR_{status_code}_{error_mapping['category'].upper()}"
        if error:
            error_code += f"_{error.upper().replace(' ', '_')}"
        
        # Use provided message or default
        if not message:
            message = error_mapping["default_message"]
        
        # Combine suggestions
        suggestions = custom_suggestions or []
        suggestions.extend(error_mapping["suggestions"])
        
        # Generate support reference
        support_reference = f"REF_{uuid.uuid4().hex[:8].upper()}"
        
        # Create error response
        error_response = EnhancedErrorResponse(
            success=False,
            error=error or f"HTTP {status_code}",
            message=message,
            category=error_mapping["category"],
            severity=error_mapping["severity"],
            code=error_code,
            status_code=status_code,
            details=details or [],
            context=context,
            suggestions=suggestions,
            documentation_url=f"https://docs.plexichat.com/errors/{status_code}",
            support_reference=support_reference,
            retry_after=retry_after
        )
        
        return error_response
    
    def handle_validation_error(self, exc: RequestValidationError, request: Request) -> JSONResponse:
        """Handle FastAPI validation errors."""
        details = []
        
        for error in exc.errors():
            field_path = " -> ".join(str(loc) for loc in error["loc"])
            detail = ErrorDetail(
                field=field_path,
                message=error["msg"],
                code=error["type"],
                value=error.get("input"),
                constraint=error.get("ctx", {}).get("limit_value")
            )
            details.append(detail)
        
        context = self._extract_context(request)
        
        error_response = self.create_error_response(
            status_code=422,
            error="Validation Error",
            message="The request data failed validation. Please check the details and try again.",
            details=details,
            context=context,
            custom_suggestions=[
                "Review the field-specific errors below",
                "Ensure all required fields are provided with valid values",
                "Check the API documentation for field requirements"
            ]
        )
        
        return self._create_json_response(error_response)
    
    def handle_http_exception(self, exc: HTTPException, request: Request) -> JSONResponse:
        """Handle FastAPI HTTP exceptions."""
        context = self._extract_context(request)
        
        # Extract additional details from exception
        details = []
        if hasattr(exc, 'detail') and isinstance(exc.detail, dict):
            if 'details' in exc.detail:
                for detail_info in exc.detail['details']:
                    if isinstance(detail_info, dict):
                        details.append(ErrorDetail(**detail_info))
        
        error_response = self.create_error_response(
            status_code=exc.status_code,
            error=getattr(exc, 'error', ''),
            message=str(exc.detail) if exc.detail else "",
            details=details,
            context=context
        )
        
        return self._create_json_response(error_response)
    
    def handle_generic_exception(self, exc: Exception, request: Request) -> JSONResponse:
        """Handle generic exceptions."""
        context = self._extract_context(request)
        
        # Log the full exception for debugging
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        
        error_message = "An unexpected error occurred while processing your request"
        if self.debug_mode:
            error_message += f": {str(exc)}"
        
        details = []
        if self.include_traceback and self.debug_mode:
            details.append(ErrorDetail(
                field="traceback",
                message=traceback.format_exc(),
                code="TRACEBACK"
            ))
        
        error_response = self.create_error_response(
            status_code=500,
            error="Internal Server Error",
            message=error_message,
            details=details,
            context=context,
            custom_suggestions=[
                "This appears to be a server-side issue",
                "Please try again in a few moments",
                f"If the problem persists, contact support with reference: {context.request_id if context else 'N/A'}"
            ]
        )
        
        return self._create_json_response(error_response)
    
    def create_business_logic_error(
        self,
        message: str,
        error_code: str = "",
        field: str = None,
        suggestions: List[str] = None
    ) -> HTTPException:
        """Create a business logic error."""
        details = []
        if field:
            details.append(ErrorDetail(
                field=field,
                message=message,
                code=error_code
            ))
        
        error_response = self.create_error_response(
            status_code=400,
            error="Business Logic Error",
            message=message,
            details=details,
            custom_suggestions=suggestions or [
                "Review the business rules for this operation",
                "Check if all prerequisites are met",
                "Contact support if you believe this is an error"
            ]
        )
        
        raise HTTPException(
            status_code=400,
            detail=asdict(error_response)
        )
    
    def create_resource_not_found_error(
        self,
        resource_type: str,
        resource_id: str = "",
        suggestions: List[str] = None
    ) -> HTTPException:
        """Create a resource not found error."""
        message = f"{resource_type} not found"
        if resource_id:
            message += f" with ID: {resource_id}"
        
        error_response = self.create_error_response(
            status_code=404,
            error="Resource Not Found",
            message=message,
            custom_suggestions=suggestions or [
                f"Verify the {resource_type.lower()} ID is correct",
                f"Check if the {resource_type.lower()} exists and you have permission to access it",
                "The resource may have been deleted or moved"
            ]
        )
        
        raise HTTPException(
            status_code=404,
            detail=asdict(error_response)
        )
    
    def create_rate_limit_error(
        self,
        limit_type: str = "requests",
        retry_after: int = 60,
        current_usage: int = None,
        limit: int = None
    ) -> HTTPException:
        """Create a rate limit error."""
        message = f"Rate limit exceeded for {limit_type}"
        if current_usage and limit:
            message += f" ({current_usage}/{limit})"
        
        suggestions = [
            f"Wait {retry_after} seconds before making another request",
            "Implement exponential backoff in your client",
            "Consider upgrading your account for higher rate limits"
        ]
        
        if limit_type == "concurrent requests":
            suggestions.append("Reduce the number of simultaneous requests")
        
        error_response = self.create_error_response(
            status_code=429,
            error="Rate Limit Exceeded",
            message=message,
            retry_after=retry_after,
            custom_suggestions=suggestions
        )
        
        raise HTTPException(
            status_code=429,
            detail=asdict(error_response),
            headers={"Retry-After": str(retry_after)}
        )
    
    def _extract_context(self, request: Request) -> ErrorContext:
        """Extract context information from request."""
        return ErrorContext(
            request_id=getattr(request.state, 'request_id', str(uuid.uuid4())),
            endpoint=request.url.path,
            method=request.method,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
            timestamp=datetime.now().isoformat(),
            user_id=getattr(request.state, 'user_id', None),
            session_id=getattr(request.state, 'session_id', None)
        )
    
    def _create_json_response(self, error_response: EnhancedErrorResponse) -> JSONResponse:
        """Create JSON response from error response."""
        response_data = asdict(error_response)
        
        # Remove None values for cleaner response
        response_data = {k: v for k, v in response_data.items() if v is not None}
        
        headers = {}
        if error_response.retry_after:
            headers["Retry-After"] = str(error_response.retry_after)
        
        return JSONResponse(
            status_code=error_response.status_code,
            content=response_data,
            headers=headers
        )

# Global error handler instance
error_handler = EnhancedErrorHandler()

# Convenience functions
def create_validation_error(field: str, message: str, value: Any = None) -> HTTPException:
    """Create a validation error for a specific field."""
    details = [ErrorDetail(field=field, message=message, value=value)]
    error_response = error_handler.create_error_response(
        status_code=422,
        error="Validation Error",
        message=f"Validation failed for field: {field}",
        details=details
    )
    raise HTTPException(status_code=422, detail=asdict(error_response))

def create_authentication_error(message: str = "Authentication required") -> HTTPException:
    """Create an authentication error."""
    error_response = error_handler.create_error_response(
        status_code=401,
        error="Authentication Required",
        message=message
    )
    raise HTTPException(status_code=401, detail=asdict(error_response))

def create_authorization_error(message: str = "Insufficient permissions") -> HTTPException:
    """Create an authorization error."""
    error_response = error_handler.create_error_response(
        status_code=403,
        error="Authorization Failed",
        message=message
    )
    raise HTTPException(status_code=403, detail=asdict(error_response))

def create_teapot_error(request_content: str = "") -> HTTPException:
    """Create the famous 418 'I'm a teapot' error.

    This is triggered only by very specific conditions to avoid disrupting normal use:
    - Request must contain 'coffee' in the content
    - Must be a POST request to a specific endpoint
    - Must include a special header
    """
    import hashlib
    import time

    # Only trigger if very specific conditions are met
    current_hour = time.localtime().tm_hour
    content_hash = hashlib.md5(request_content.lower().encode()).hexdigest()

    # Easter egg conditions (very specific to avoid normal operation disruption)
    coffee_keywords = ['coffee', 'espresso', 'latte', 'cappuccino', 'brew']
    has_coffee_keyword = any(keyword in request_content.lower() for keyword in coffee_keywords)

    # Only trigger during specific hours and with specific content
    if has_coffee_keyword and current_hour in [10, 14, 16] and content_hash.startswith('c0ff33'):
        error_response = error_handler.create_error_response(
            status_code=418,
            error="I'm a teapot",
            message="I'm a teapot - The server refuses to brew coffee because it is, permanently, a teapot ?",
            custom_suggestions=[
                "This is an Easter egg error from RFC 2324 (April 1, 1998)",
                "Try requesting tea instead of coffee ?",
                "The server is having a bit of fun with you!",
                "This error only appears under very specific conditions",
                "Don't worry, your request wasn't actually processed incorrectly"
            ]
        )
        raise HTTPException(status_code=418, detail=asdict(error_response))

    # If conditions aren't met, return a normal validation error instead
    return create_validation_error("content", "Invalid request content", request_content)

def check_for_teapot_condition(request_content: str, endpoint: str, headers: dict) -> bool:
    """Check if the teapot error should be triggered.

    This is a very specific check to ensure the 418 error only appears
    as an Easter egg and doesn't disrupt normal operations.
    """
    # Very specific conditions that are unlikely to occur in normal use
    special_header = headers.get('X-Brew-Coffee', '').lower()
    coffee_request = 'coffee' in request_content.lower()
    teapot_endpoint = '/api/v1/brew' in endpoint
    magic_phrase = 'please brew coffee' in request_content.lower()

    # All conditions must be met for the Easter egg
    return (special_header == 'true' and
            coffee_request and
            teapot_endpoint and
            magic_phrase)

# FastAPI exception handlers
def setup_exception_handlers(app):
    """Setup exception handlers for FastAPI app."""

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return error_handler.handle_validation_error(exc, request)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return error_handler.handle_http_exception(exc, request)

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
        # Convert Starlette exception to FastAPI exception
        fastapi_exc = HTTPException(status_code=exc.status_code, detail=exc.detail)
        return error_handler.handle_http_exception(fastapi_exc, request)

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        return error_handler.handle_generic_exception(exc, request)

    logger.info("Enhanced exception handlers registered with FastAPI app")
