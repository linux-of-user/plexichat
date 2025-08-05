import json
import platform
import sys
import traceback
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    from .exceptions import ErrorCategory, ErrorSeverity
except ImportError:
    class ErrorCategory:
        SYSTEM = "system"
    class ErrorSeverity:
        CRITICAL = "critical"

try:
    import psutil
except ImportError:
    psutil = None

import logging

"""
PlexiChat Crash Reporter

Comprehensive crash reporting system with detailed context collection,
automatic recovery suggestions, and integration with monitoring systems.
"""

logger = logging.getLogger(__name__)

@dataclass
class CrashContext:
    """Comprehensive crash context information."""
    error_id: str
    timestamp: datetime
    exception_type: str
    exception_message: str
    stack_trace: str
    severity: ErrorSeverity
    category: ErrorCategory

    # System information
    python_version: str
    platform_info: str
    memory_usage: Dict[str, Any]
    cpu_usage: float

    # Application context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    component: Optional[str] = None

    # Additional context
    additional_context: Dict[str, Any] = None
    recovery_suggestions: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        data['category'] = self.category.value
        return data


class CrashReporter:
    """Advanced crash reporting system."""

    def __init__(self, crash_log_dir: str = "logs/crashes"):
        from pathlib import Path
self.crash_log_dir = Path(crash_log_dir)
        self.crash_log_dir.mkdir(parents=True, exist_ok=True)

        self.crash_history: List[CrashContext] = []
        self.max_history_size = 1000
        self.initialized = False

        # Recovery suggestions database
        self.recovery_suggestions = {
            'DatabaseError': [
                "Check database connection",
                "Verify database credentials",
                "Check database server status",
                "Review recent schema changes"
            ],
            'NetworkError': [
                "Check internet connection",
                "Verify firewall settings",
                "Check proxy configuration",
                "Retry with exponential backoff"
            ],
            'FileError': [
                "Check file permissions",
                "Verify file path exists",
                "Check disk space",
                "Ensure file is not locked"
            ],
            'AuthenticationError': [
                "Verify credentials",
                "Check token expiration",
                "Review authentication configuration",
                "Clear authentication cache"
            ]
        }

    async def initialize(self, config: Dict[str, Any] = None):
        """Initialize the crash reporter."""
        if config:
            from pathlib import Path
self.crash_log_dir = Path(config.get('crash_log_dir', self.crash_log_dir))
            self.max_history_size = config.get('max_history_size', self.max_history_size)

        self.crash_log_dir.mkdir(parents=True, exist_ok=True)
        self.initialized = True

    def report_crash(self, exception: Exception, ):
                    severity: ErrorSeverity = ErrorSeverity.CRITICAL,
                    category: ErrorCategory = ErrorCategory.SYSTEM,
                    user_id: Optional[str] = None, session_id: Optional[str] = None,
                    request_id: Optional[str] = None, component: Optional[str] = None,
                    additional_context: Dict[str, Any] = None) -> CrashContext:
        """Report a crash with comprehensive context."""

        # Generate unique error ID
        error_id = str(uuid.uuid4())

        # Collect system information
        system_info = self._collect_system_info()

        # Get stack trace
        stack_trace = traceback.format_exc()

        # Get recovery suggestions
        exception_type = type(exception).__name__
        suggestions = self.recovery_suggestions.get(exception_type, [
            "Check application logs for more details",
            "Restart the affected component",
            "Contact system administrator if issue persists"
        ])

        # Create crash context
        crash_context = CrashContext()
            error_id=error_id,

            timestamp = datetime().now(),
            exception_type=exception_type,
            exception_message=str(exception),
            stack_trace=stack_trace,
            severity=severity,
            category=category,
            python_version=system_info['python_version'],
            platform_info=system_info['platform_info'],
            memory_usage=system_info['memory_usage'],
            cpu_usage=system_info['cpu_usage'],
            user_id=user_id,
            session_id=session_id,
            request_id=request_id,
            component=component,
            additional_context=additional_context or {},
            recovery_suggestions=suggestions
        )

        # Store crash context
        self._store_crash_context(crash_context)

        # Add to history
        self.crash_history.append(crash_context)
        if len(self.crash_history) > self.max_history_size:
            self.crash_history.pop(0)

        return crash_context

    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect comprehensive system information."""
        try:
            memory = import psutil
psutil.virtual_memory()
            cpu_percent = import psutil
psutil.cpu_percent(interval=1)

            return {}
                'python_version': sys.version,
                'platform_info': platform.platform(),
                'memory_usage': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'cpu_usage': cpu_percent
            }
        except Exception as e:
            return {}
                'python_version': sys.version,
                'platform_info': platform.platform(),
                'memory_usage': {'error': str(e)},
                'cpu_usage': 0.0
            }

    def _store_crash_context(self, crash_context: CrashContext):
        """Store crash context to file."""
        try:
            crash_file = self.crash_log_dir / f"crash_{crash_context.error_id}.json"
            with open(crash_file, 'w') as f:
                json.dump(crash_context.to_dict(), f, indent=2, default=str)
        except Exception as e:
            logger.info(f"Failed to store crash context: {e}")

    def get_crash_history(self, limit: int = 100) -> List[CrashContext]:
        """Get recent crash history."""
        return self.crash_history[-limit:]

    def get_crash_statistics(self) -> Dict[str, Any]:
        """Get crash statistics."""
        if not self.crash_history:
            return {}'total_crashes': 0}

        # Count by exception type
        exception_counts = {}
        severity_counts = {}
        category_counts = {}

        for crash in self.crash_history:
            exception_counts[crash.exception_type] = exception_counts.get(crash.exception_type, 0) + 1
            severity_counts[crash.severity.value] = severity_counts.get(crash.severity.value, 0) + 1
            category_counts[crash.category.value] = category_counts.get(crash.category.value, 0) + 1

        return {}
            'total_crashes': len(self.crash_history),
            'exception_types': exception_counts,
            'severity_distribution': severity_counts,
            'category_distribution': category_counts,
            'most_recent': self.crash_history[-1].to_dict() if self.crash_history else None
        }

    def clear_crash_history(self):
        """Clear crash history."""
        self.crash_history.clear()

    async def shutdown(self):
        """Shutdown the crash reporter and cleanup resources."""
        try:
            # Save any pending crash data
            if self.crash_history:
                summary_file = self.crash_log_dir / "crash_summary.json"
                with open(summary_file, 'w') as f:
                    json.dump({)
                        'total_crashes': len(self.crash_history),
                        'statistics': self.get_crash_statistics(),
                        'shutdown_time': datetime.now().isoformat()
                    }, f, indent=2, default=str)

            self.initialized = False
        except Exception as e:
            logger.info(f"Error during crash reporter shutdown: {e}")


# Global crash reporter instance
crash_reporter = CrashReporter()
