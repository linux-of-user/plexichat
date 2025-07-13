import json
import logging
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

"""
Beautiful Error Handler System
Comprehensive error handling with attractive error pages and detailed logging.
"""

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

class BeautifulErrorHandler:
    """Beautiful error handler with comprehensive logging and user-friendly pages."""
    
    def __init__(self, templates_dir: str = "src/plexichat/app/web/templates"):
        self.templates_dir = from pathlib import Path
Path(templates_dir)
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        self.error_log_file = from pathlib import Path
Path("error_log.json")
        self.crash_log_file = from pathlib import Path
Path("crash_log.json")
        
        # Error statistics
        self.error_stats: Dict[str, int] = {}
        self.recent_errors: list = []
        
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
                'last_updated': from datetime import datetime
datetime.now().isoformat()
            }
            with open(self.error_log_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save error logs: {e}")
    
    def _log_error(self, error_id: str, error_code: str, error_message: str,
                   request: Optional[Request] = None, exception: Optional[Exception] = None):
        """Log error with comprehensive details."""
        error_entry = {
            'error_id': error_id,
            'error_code': error_code,
            'message': error_message,
            'timestamp': from datetime import datetime
datetime.now().isoformat(),
            'request_info': self._extract_request_info(request) if request else None,
            'exception_info': self._extract_exception_info(exception) if exception else None
        }
        
        # Add to recent errors
        self.recent_errors.append(error_entry)
        
        # Update statistics
        if error_code not in self.error_stats:
            self.error_stats[error_code] = 0
        self.error_stats[error_code] += 1
        
        # Save to file
        self._save_error_logs()
        
        # Log to standard logger
        logger.error(f"Error {error_id}: {error_code} - {error_message}")
        if exception:
            logger.error(f"Exception details: {str(exception)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _extract_request_info(self, request: Request) -> Dict[str, Any]:
        """Extract relevant information from request."""
        return {
            'method': request.method,
            'url': str(request.url),
            'path': request.url.path,
            'query_params': dict(request.query_params),
            'headers': dict(request.headers),
            'client_ip': request.client.host if request.client else None,
            'user_agent': request.headers.get('user-agent', 'Unknown')
        }
    
    def _extract_exception_info(self, exception: Exception) -> Dict[str, Any]:
        """Extract exception information."""
        return {
            'type': type(exception).__name__,
            'message': str(exception),
            'traceback': traceback.format_exc(),
            'args': exception.args if hasattr(exception, 'args') else None
        }
    
    def _get_error_context(self, error_id: str, error_code: str, error_message: str,
                          status_code: int, request: Optional[Request] = None) -> Dict[str, Any]:
        """Get context for error template."""
        return {
            'error_id': error_id,
            'error_code': error_code,
            'error_message': error_message,
            'status_code': status_code,
            'timestamp': from datetime import datetime
datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'server_id': 'PlexiChat-Server-01',  # Could be dynamic
            'request': request,
            'support_url': '/support',
            'docs_url': '/docs',
            'home_url': '/',
            'dashboard_url': '/ui'
        }
    
    async def handle_404(self, request: Request) -> HTMLResponse:
        """Handle 404 Not Found errors."""
        error_id = str(uuid.uuid4())[:8]
        error_code, error_message = ErrorCode.NOT_FOUND
        
        self._log_error(error_id, error_code, error_message, request)
        
        context = self._get_error_context(error_id, error_code, error_message, 404, request)
        
        return self.templates.TemplateResponse(
            "errors/404.html",
            {"request": request, **context}
        )
    
    async def handle_500(self, request: Request, exception: Optional[Exception] = None) -> HTMLResponse:
        """Handle 500 Internal Server Error."""
        error_id = str(uuid.uuid4())[:8]
        error_code, error_message = ErrorCode.INTERNAL_ERROR
        
        self._log_error(error_id, error_code, error_message, request, exception)
        
        context = self._get_error_context(error_id, error_code, error_message, 500, request)
        
        return self.templates.TemplateResponse(
            "errors/500.html",
            {"request": request, **context}
        )
    
    async def handle_403(self, request: Request) -> HTMLResponse:
        """Handle 403 Forbidden errors."""
        error_id = str(uuid.uuid4())[:8]
        error_code, error_message = ErrorCode.FORBIDDEN
        
        self._log_error(error_id, error_code, error_message, request)
        
        context = self._get_error_context(error_id, error_code, error_message, 403, request)
        
        return self.templates.TemplateResponse(
            "errors/403.html",
            {"request": request, **context}
        )
    
    async def handle_rate_limit(self, request: Request) -> HTMLResponse:
        """Handle 429 Rate Limit errors."""
        error_id = str(uuid.uuid4())[:8]
        error_code, error_message = ErrorCode.RATE_LIMITED
        
        self._log_error(error_id, error_code, error_message, request)
        
        context = self._get_error_context(error_id, error_code, error_message, 429, request)
        
        return self.templates.TemplateResponse(
            "errors/429.html",
            {"request": request, **context}
        )
    
    async def handle_api_error(self, request: Request, status_code: int,
                              error_code: str, error_message: str,
                              details: Optional[Dict[str, Any]] = None) -> JSONResponse:
        """Handle API errors with JSON response."""
        error_id = str(uuid.uuid4())[:8]
        
        self._log_error(error_id, error_code, error_message, request)
        
        response_data = {
            'error': True,
            'error_id': error_id,
            'error_code': error_code,
            'message': error_message,
            'status_code': status_code,
            'timestamp': from datetime import datetime
datetime.now().isoformat(),
            'details': details or {}
        }
        
        return JSONResponse(
            status_code=status_code,
            content=response_data
        )
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics."""
        total_errors = sum(self.error_stats.values())
        
        # Calculate error rates
        recent_24h = [
            e for e in self.recent_errors 
            if datetime.fromisoformat(e['timestamp']) > from datetime import datetime
datetime.now().replace(hour=0, minute=0, second=0)
        ]
        
        return {
            'total_errors': total_errors,
            'error_types': self.error_stats,
            'recent_24h_count': len(recent_24h),
            'most_common_error': max(self.error_stats.items(), key=lambda x: x[1]) if self.error_stats else None,
            'recent_errors': self.recent_errors[-10:],  # Last 10 errors
            'error_rate_24h': len(recent_24h) / 24 if recent_24h else 0  # Errors per hour
        }
    
    def create_crash_report(self, exception: Exception, context: Optional[Dict[str, Any]] = None) -> str:
        """Create detailed crash report."""
        crash_id = str(uuid.uuid4())
        
        crash_report = {
            'crash_id': crash_id,
            'timestamp': from datetime import datetime
datetime.now().isoformat(),
            'exception': self._extract_exception_info(exception),
            'context': context or {},
            'system_info': {
                'python_version': None,  # Could add sys.version
                'platform': None,        # Could add platform.platform()
                'memory_usage': None     # Could add memory info
            }
        }
        
        # Save crash report
        try:
            crash_reports = []
            if self.crash_log_file.exists():
                with open(self.crash_log_file, 'r') as f:
                    crash_reports = json.load(f)
            
            crash_reports.append(crash_report)
            
            # Keep only last 50 crash reports
            crash_reports = crash_reports[-50:]
            
            with open(self.crash_log_file, 'w') as f:
                json.dump(crash_reports, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save crash report: {e}")
        
        logger.critical(f"CRASH REPORT {crash_id}: {str(exception)}")
        return crash_id
