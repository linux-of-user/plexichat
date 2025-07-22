# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Beautiful Error Handler

Comprehensive error handling with beautiful error pages and detailed logging.
"""

import json
import logging
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import Request, HTTPException  # type: ignore
    from fastapi.responses import HTMLResponse, JSONResponse  # type: ignore
    from fastapi.templating import Jinja2Templates  # type: ignore
    FASTAPI_AVAILABLE = True
except ImportError:
    Request = None
    HTTPException = None
    HTMLResponse = None
    JSONResponse = None
    Jinja2Templates = None
    FASTAPI_AVAILABLE = False

logger = logging.getLogger(__name__)


class ErrorCode:
    """Standardized error codes with witty messages."""

    # Client Errors (4xx)
    BAD_REQUEST = ("ERR_400_BAD_VIBES", "Your request has some bad vibes. Let's fix that!")
    UNAUTHORIZED = ("ERR_401_WHO_ARE_YOU", "Who goes there? Please identify yourself!")
    FORBIDDEN = ("ERR_403_NO_ENTRY", "Access denied! This area is off-limits.")
    NOT_FOUND = ("ERR_404_LOST_IN_SPACE", "This page has gone on an adventure without us!")
    METHOD_NOT_ALLOWED = ("ERR_405_WRONG_MOVE", "That's not the right move! Try a different approach.")
    RATE_LIMITED = ("ERR_429_SLOW_DOWN", "Whoa there, speed racer! Take a breather.")

    # Server Errors (5xx)
    INTERNAL_ERROR = ("ERR_500_OOPS", "Oops! Our servers are having a moment.")
    NOT_IMPLEMENTED = ("ERR_501_COMING_SOON", "This feature is still in the oven!")
    BAD_GATEWAY = ("ERR_502_GATEWAY_BLUES", "Our gateway is feeling a bit blue today.")
    SERVICE_UNAVAILABLE = ("ERR_503_TAKING_A_NAP", "Our service is taking a quick nap.")
    GATEWAY_TIMEOUT = ("ERR_504_TIMEOUT_PARTY", "The gateway threw a timeout party!")

    # Custom Application Errors
    DATABASE_ERROR = ("ERR_DB_HICCUP", "Our database had a little hiccup!")
    VALIDATION_ERROR = ("ERR_VALIDATION_FAIL", "Something doesn't look quite right...")
    AUTHENTICATION_ERROR = ("ERR_AUTH_MYSTERY", "Authentication mystery needs solving!")
    PERMISSION_ERROR = ("ERR_PERM_DENIED", "Permission slip required for this area!")
    PLUGIN_ERROR = ("ERR_PLUGIN_TANTRUM", "A plugin is throwing a tantrum!")
    AI_ERROR = ("ERR_AI_CONFUSED", "Our AI is a bit confused right now!")


class ErrorContext:
    """Context information for errors."""
    
    def __init__(self, request: Optional[Any] = None, user_id: Optional[str] = None):
        self.request = request
        self.user_id = user_id
        self.timestamp = datetime.now()
        self.request_id = getattr(request, 'state', {}).get('request_id') if request else None


class BeautifulErrorHandler:
    """Beautiful error handler with comprehensive logging and user-friendly pages."""

    def __init__(self, templates_dir: str = "src/plexichat/app/web/templates"):
        self.templates_dir = Path(templates_dir)
        self.templates = Jinja2Templates(directory=str(self.templates_dir)) if Jinja2Templates else None
        self.error_log_file = Path("error_log.json")
        self.crash_log_file = Path("crash_log.json")

        # Error statistics
        self.error_stats: Dict[str, int] = {}
        self.recent_errors: List[Dict[str, Any]] = []

        # Load existing error logs
        self._load_error_logs()

    def _load_error_logs(self):
        """Load existing error logs."""
        try:
            if self.error_log_file.exists():
                with open(self.error_log_file, 'r') as f:
                    data = json.load(f)
                    self.error_stats = data.get('stats', {})
                    self.recent_errors = data.get('recent', [])[-100:]  # Keep last 100
        except Exception as e:
            logger.error(f"Failed to load error logs: {e}")

    def _save_error_logs(self):
        """Save error logs to file."""
        try:
            data = {
                'stats': self.error_stats,
                'recent': self.recent_errors[-100:],  # Keep last 100
                'last_updated': datetime.now().isoformat()
            }
            with open(self.error_log_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save error logs: {e}")

    def log_error(self, error: Exception, context: Optional[ErrorContext] = None):
        """Log an error with context."""
        error_type = type(error).__name__
        error_message = str(error)
        
        # Update statistics
        self.error_stats[error_type] = self.error_stats.get(error_type, 0) + 1
        
        # Create error record
        error_record = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'type': error_type,
            'message': error_message,
            'traceback': traceback.format_exc(),
            'user_id': context.user_id if context else None,
            'request_id': context.request_id if context else None,
            'request_path': getattr(context.request, 'url', {}).path if context and context.request else None,
            'request_method': getattr(context.request, 'method', None) if context and context.request else None,
            'user_agent': getattr(context.request, 'headers', {}).get('user-agent') if context and context.request else None,
            'ip_address': getattr(context.request, 'client', {}).host if context and context.request else None
        }
        
        self.recent_errors.append(error_record)
        
        # Keep only recent errors
        if len(self.recent_errors) > 100:
            self.recent_errors = self.recent_errors[-100:]
        
        # Save to file
        self._save_error_logs()
        
        # Log to standard logger
        logger.error(f"{error_type}: {error_message}", extra=error_record)

    def create_error_response(self, error: Exception, request: Optional[Any] = None) -> Any:
        """Create a beautiful error response."""
        if not self.templates or not FASTAPI_AVAILABLE:
            return {
                "error": str(error),
                "type": type(error).__name__,
                "timestamp": datetime.now().isoformat()
            }
            
        error_type = type(error).__name__
        status_code = getattr(error, 'status_code', 500)
        
        # Get error code and message
        error_code, friendly_message = self._get_error_code_and_message(error_type, status_code)
        
        # Determine error template
        template_name = "errors/500.html"
        if status_code == 404:
            template_name = "errors/404.html"
        elif status_code == 403:
            template_name = "errors/403.html"
        elif status_code == 400:
            template_name = "errors/400.html"
        
        context = {
            "request": request,
            "error_type": error_type,
            "error_message": str(error),
            "friendly_message": friendly_message,
            "error_code": error_code,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "support_email": "support@plexichat.com",
            "error_id": str(uuid.uuid4())
        }
        
        try:
            return self.templates.TemplateResponse(template_name, context)
        except Exception:
            # Fallback to JSON response
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": str(error),
                    "type": error_type,
                    "error_code": error_code,
                    "friendly_message": friendly_message,
                    "status_code": status_code,
                    "timestamp": datetime.now().isoformat()
                }
            ) if JSONResponse else context

    def _get_error_code_and_message(self, error_type: str, status_code: int) -> tuple:
        """Get error code and friendly message based on error type and status code."""
        if status_code == 400:
            return ErrorCode.BAD_REQUEST
        elif status_code == 401:
            return ErrorCode.UNAUTHORIZED
        elif status_code == 403:
            return ErrorCode.FORBIDDEN
        elif status_code == 404:
            return ErrorCode.NOT_FOUND
        elif status_code == 405:
            return ErrorCode.METHOD_NOT_ALLOWED
        elif status_code == 429:
            return ErrorCode.RATE_LIMITED
        elif status_code == 500:
            return ErrorCode.INTERNAL_ERROR
        elif status_code == 501:
            return ErrorCode.NOT_IMPLEMENTED
        elif status_code == 502:
            return ErrorCode.BAD_GATEWAY
        elif status_code == 503:
            return ErrorCode.SERVICE_UNAVAILABLE
        elif status_code == 504:
            return ErrorCode.GATEWAY_TIMEOUT
        elif "validation" in error_type.lower():
            return ErrorCode.VALIDATION_ERROR
        elif "auth" in error_type.lower():
            return ErrorCode.AUTHENTICATION_ERROR
        elif "permission" in error_type.lower():
            return ErrorCode.PERMISSION_ERROR
        elif "plugin" in error_type.lower():
            return ErrorCode.PLUGIN_ERROR
        elif "ai" in error_type.lower():
            return ErrorCode.AI_ERROR
        elif "database" in error_type.lower() or "db" in error_type.lower():
            return ErrorCode.DATABASE_ERROR
        else:
            return ErrorCode.INTERNAL_ERROR

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        total_errors = sum(self.error_stats.values())

        # Calculate error rates
        recent_24h = [
            e for e in self.recent_errors
            if datetime.fromisoformat(e['timestamp']) > datetime.now().replace(hour=0, minute=0, second=0)
        ]

        return {
            'total_errors': total_errors,
            'error_types': self.error_stats,
            'recent_24h_count': len(recent_24h),
            'most_common_error': max(self.error_stats.items(), key=lambda x: x[1]) if self.error_stats else None,
            'recent_errors': self.recent_errors[-10:],  # Last 10 errors
            'error_rate_24h': len(recent_24h) / 24 if recent_24h else 0  # Errors per hour
        }

    def clear_error_logs(self):
        """Clear all error logs."""
        self.error_stats.clear()
        self.recent_errors.clear()
        self._save_error_logs()

    def export_error_logs(self, format: str = "json") -> str:
        """Export error logs in specified format."""
        data = {
            'statistics': self.error_stats,
            'recent_errors': self.recent_errors,
            'exported_at': datetime.now().isoformat()
        }
        
        if format.lower() == "json":
            return json.dumps(data, indent=2, default=str)
        else:
            return str(data)


# Global error handler instance
_error_handler: Optional[BeautifulErrorHandler] = None


def get_error_handler() -> BeautifulErrorHandler:
    """Get the global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = BeautifulErrorHandler()
    return _error_handler


def configure_error_handler(templates_dir: str):
    """Configure the global error handler."""
    global _error_handler
    _error_handler = BeautifulErrorHandler(templates_dir)


# Convenience functions
def log_error(error: Exception, context: Optional[ErrorContext] = None):
    """Log an error using the global handler."""
    handler = get_error_handler()
    handler.log_error(error, context)


def create_error_response(error: Exception, request: Optional[Any] = None) -> Any:
    """Create an error response using the global handler."""
    handler = get_error_handler()
    return handler.create_error_response(error, request)


def get_error_statistics() -> Dict[str, Any]:
    """Get error statistics using the global handler."""
    handler = get_error_handler()
    return handler.get_error_statistics()
