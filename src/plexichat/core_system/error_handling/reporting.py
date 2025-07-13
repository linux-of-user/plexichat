import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .context import ErrorContext, ErrorSeverity



"""
PlexiChat Error Reporting System

Comprehensive error reporting with multiple backends and intelligent routing.
"""

class ErrorReporter:
    """
    Centralized error reporting system with multiple backends.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the error reporter."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.backends = []
        self.enabled = True
        
        # Initialize default backends
        self._setup_backends()
    
    def _setup_backends(self):
        """Setup reporting backends based on configuration."""
        # File backend (always enabled)
        self.backends.append(FileReportingBackend(self.config.get('file', {})))
        
        # Console backend
        if self.config.get('console', {}).get('enabled', True):
            self.backends.append(ConsoleReportingBackend(self.config.get('console', {})))
        
        # Email backend (if configured)
        if self.config.get('email', {}).get('enabled', False):
            self.backends.append(EmailReportingBackend(self.config.get('email', {})))
        
        # Webhook backend (if configured)
        if self.config.get('webhook', {}).get('enabled', False):
            self.backends.append(WebhookReportingBackend(self.config.get('webhook', {})))
    
    async def report_error(self, context: ErrorContext) -> bool:
        """Report an error through all configured backends."""
        if not self.enabled:
            return False
        
        try:
            # Report to all backends
            results = []
            for backend in self.backends:
                try:
                    result = await backend.report(context)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Backend {backend.__class__.__name__} failed: {e}")
                    results.append(False)
            
            return any(results)
        
        except Exception as e:
            self.logger.error(f"Error reporting failed: {e}")
            return False
    
    def enable(self):
        """Enable error reporting."""
        self.enabled = True
    
    def disable(self):
        """Disable error reporting."""
        self.enabled = False
    
    def add_backend(self, backend):
        """Add a custom reporting backend."""
        self.backends.append(backend)
    
    def remove_backend(self, backend_class):
        """Remove a reporting backend by class."""
        self.backends = [b for b in self.backends if not isinstance(b, backend_class)]

    async def shutdown(self):
        """Shutdown the error reporter and cleanup resources."""
        try:
            # Shutdown all backends
            for backend in self.backends:
                if hasattr(backend, 'shutdown'):
                    await backend.shutdown()

            self.enabled = False
            self.logger.info("Error reporter shutdown completed")
        except Exception as e:
            self.logger.error(f"Error during error reporter shutdown: {e}")


class ReportingBackend:
    """Base class for error reporting backends."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def report(self, context: ErrorContext) -> bool:
        """Report an error. Must be implemented by subclasses."""
        raise NotImplementedError
    
    def format_error(self, context: ErrorContext) -> Dict[str, Any]:
        """Format error context for reporting."""
        return {
            'timestamp': context.timestamp.isoformat(),
            'error_id': context.error_id,
            'severity': context.severity.value if context.severity else 'unknown',
            'category': context.category.value if context.category else 'unknown',
            'message': str(context.exception) if context.exception else context.message,
            'traceback': context.traceback,
            'context_data': context.context_data or {},
            'user_id': context.user_id,
            'request_id': context.request_id,
            'component': context.component,
            'operation': context.operation
        }


class FileReportingBackend(ReportingBackend):
    """File-based error reporting backend."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.log_dir = from pathlib import Path
Path(config.get('log_dir', 'logs'))
        self.log_dir.mkdir(exist_ok=True)
        self.error_file = self.log_dir / 'errors.jsonl'
    
    async def report(self, context: ErrorContext) -> bool:
        """Write error to file."""
        try:
            error_data = self.format_error(context)
            
            with open(self.error_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(error_data) + '\n')
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to write error to file: {e}")
            return False


class ConsoleReportingBackend(ReportingBackend):
    """Console-based error reporting backend."""
    
    async def report(self, context: ErrorContext) -> bool:
        """Print error to console."""
        try:
            severity_colors = {
                ErrorSeverity.LOW: '\033[32m',      # Green
                ErrorSeverity.MEDIUM: '\033[33m',   # Yellow
                ErrorSeverity.HIGH: '\033[31m',     # Red
                ErrorSeverity.CRITICAL: '\033[35m'  # Magenta
            }
            
            reset_color = '\033[0m'
            color = severity_colors.get(context.severity, '')
            
            print(f"{color}[ERROR] {context.severity.value if context.severity else 'UNKNOWN'}{reset_color}")
            print(f"ID: {context.error_id}")
            print(f"Message: {context.exception or context.message}")
            if context.component:
                print(f"Component: {context.component}")
            if context.operation:
                print(f"Operation: {context.operation}")
            print("-" * 50)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to print error to console: {e}")
            return False


class EmailReportingBackend(ReportingBackend):
    """Email-based error reporting backend."""
    
    async def report(self, context: ErrorContext) -> bool:
        """Send error via email."""
        try:
            # This would integrate with an email service
            # For now, just log that we would send an email
            self.logger.info(f"Would send email for error {context.error_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to send error email: {e}")
            return False


class WebhookReportingBackend(ReportingBackend):
    """Webhook-based error reporting backend."""
    
    async def report(self, context: ErrorContext) -> bool:
        """Send error via webhook."""
        try:
            # This would send to a webhook endpoint
            # For now, just log that we would send a webhook
            self.logger.info(f"Would send webhook for error {context.error_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to send error webhook: {e}")
            return False


# Global error reporter instance
error_reporter = ErrorReporter()


def configure_error_reporting(config: Dict[str, Any]):
    """Configure the global error reporter."""
    global error_reporter
    error_reporter = ErrorReporter(config)


async def report_error(context: ErrorContext) -> bool:
    """Convenience function to report an error."""
    return await error_reporter.report_error(context)
