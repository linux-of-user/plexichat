"""
Advanced Error Handling System
Comprehensive error handling with detailed codes, crash logging, and witty messages.
"""

import traceback
import sys
import json
import time
from typing import Any, Dict, List, Optional, Type
from datetime import datetime
from pathlib import Path
from enum import Enum
import logging

logger = logging.getLogger("netlink.errors")

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    SYSTEM = "system"
    USER_INPUT = "user_input"
    EXTERNAL_API = "external_api"

class NetLinkError(Exception):
    """Base exception class for NetLink with enhanced error handling."""
    
    def __init__(self, message: str, error_code: str = None, 
                 category: ErrorCategory = None, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 details: Dict[str, Any] = None, user_message: str = None):
        super().__init__(message)
        
        self.message = message
        self.error_code = error_code or self._generate_error_code()
        self.category = category or ErrorCategory.SYSTEM
        self.severity = severity
        self.details = details or {}
        self.user_message = user_message or self._get_user_friendly_message()
        self.timestamp = datetime.now()
        self.traceback_info = traceback.format_exc()
        
        # Log the error
        self._log_error()
    
    def _generate_error_code(self) -> str:
        """Generate unique error code."""
        timestamp = int(time.time() * 1000)
        return f"NL{timestamp % 100000:05d}"
    
    def _get_user_friendly_message(self) -> str:
        """Get user-friendly error message."""
        witty_messages = {
            ErrorCategory.AUTHENTICATION: [
                "Looks like you're not who you say you are! 🕵️",
                "Authentication failed - are you sure you're you?",
                "Access denied - this isn't the user you're looking for",
                "Login failed - did you forget your password again?"
            ],
            ErrorCategory.AUTHORIZATION: [
                "You shall not pass! (Insufficient permissions) ⚔️",
                "Access denied - you need more power!",
                "Forbidden zone - authorized personnel only",
                "Permission denied - talk to your admin"
            ],
            ErrorCategory.VALIDATION: [
                "That input doesn't look right to me 🤔",
                "Validation failed - please check your data",
                "Something's not quite right with that input",
                "Data validation error - please try again"
            ],
            ErrorCategory.DATABASE: [
                "The database is having a moment 💾",
                "Database error - our data is feeling shy",
                "Storage issue - the database needs a coffee break",
                "Data access error - please try again"
            ],
            ErrorCategory.NETWORK: [
                "Network hiccup - the internet is having a bad day 🌐",
                "Connection error - are you connected to the internet?",
                "Network timeout - the request took too long",
                "Communication error - please check your connection"
            ],
            ErrorCategory.SYSTEM: [
                "System error - something went wrong on our end 🔧",
                "Internal error - our servers are having issues",
                "System malfunction - please try again later",
                "Technical difficulties - we're working on it"
            ]
        }
        
        messages = witty_messages.get(self.category, ["An error occurred - please try again"])
        import random
        return random.choice(messages)
    
    def _log_error(self):
        """Log the error with appropriate level."""
        log_data = {
            "error_code": self.error_code,
            "message": self.message,
            "category": self.category.value,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }
        
        if self.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"CRITICAL ERROR [{self.error_code}]: {self.message}", extra=log_data)
        elif self.severity == ErrorSeverity.HIGH:
            logger.error(f"ERROR [{self.error_code}]: {self.message}", extra=log_data)
        elif self.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"WARNING [{self.error_code}]: {self.message}", extra=log_data)
        else:
            logger.info(f"INFO [{self.error_code}]: {self.message}", extra=log_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "user_message": self.user_message,
            "category": self.category.value,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

class AuthenticationError(NetLinkError):
    """Authentication related errors."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )

class AuthorizationError(NetLinkError):
    """Authorization related errors."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )

class ValidationError(NetLinkError):
    """Validation related errors."""
    
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )

class DatabaseError(NetLinkError):
    """Database related errors."""
    
    def __init__(self, message: str = "Database error", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.DATABASE,
            severity=ErrorSeverity.HIGH,
            **kwargs
        )

class NetworkError(NetLinkError):
    """Network related errors."""
    
    def __init__(self, message: str = "Network error", **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.MEDIUM,
            **kwargs
        )

class CrashReporter:
    """Advanced crash reporting system."""
    
    def __init__(self):
        self.crash_dir = Path("logs/crashes")
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        
        self.crash_stats = {
            "total_crashes": 0,
            "crashes_by_category": {},
            "crashes_by_severity": {},
            "last_crash": None
        }
        
        # Load existing stats
        self._load_crash_stats()
        
        # Set up global exception handler
        sys.excepthook = self._handle_uncaught_exception
    
    def report_crash(self, error: Exception, context: Dict[str, Any] = None):
        """Report a crash with detailed information."""
        try:
            crash_id = f"crash_{int(time.time() * 1000)}"
            
            # Gather crash information
            crash_info = {
                "crash_id": crash_id,
                "timestamp": datetime.now().isoformat(),
                "error_type": type(error).__name__,
                "error_message": str(error),
                "traceback": traceback.format_exc(),
                "context": context or {},
                "system_info": self._get_system_info(),
                "witty_message": self._get_witty_crash_message()
            }
            
            # Add NetLink error details if applicable
            if isinstance(error, NetLinkError):
                crash_info.update({
                    "error_code": error.error_code,
                    "category": error.category.value,
                    "severity": error.severity.value,
                    "details": error.details
                })
            
            # Save crash report
            crash_file = self.crash_dir / f"{crash_id}.json"
            with open(crash_file, 'w', encoding='utf-8') as f:
                json.dump(crash_info, f, indent=2, default=str)
            
            # Update statistics
            self._update_crash_stats(crash_info)
            
            # Log crash
            logger.critical(f"CRASH REPORTED [{crash_id}]: {error}", extra=crash_info)
            
            return crash_id
            
        except Exception as e:
            logger.error(f"Failed to report crash: {e}")
            return None
    
    def get_crash_report(self, crash_id: str) -> Optional[Dict[str, Any]]:
        """Get crash report by ID."""
        try:
            crash_file = self.crash_dir / f"{crash_id}.json"
            if crash_file.exists():
                with open(crash_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load crash report {crash_id}: {e}")
        
        return None
    
    def get_recent_crashes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent crash reports."""
        try:
            crash_files = sorted(
                self.crash_dir.glob("*.json"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            crashes = []
            for crash_file in crash_files[:limit]:
                try:
                    with open(crash_file, 'r', encoding='utf-8') as f:
                        crash_data = json.load(f)
                        crashes.append(crash_data)
                except Exception:
                    continue
            
            return crashes
            
        except Exception as e:
            logger.error(f"Failed to get recent crashes: {e}")
            return []
    
    def get_crash_statistics(self) -> Dict[str, Any]:
        """Get crash statistics."""
        return self.crash_stats.copy()
    
    def _handle_uncaught_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions."""
        if issubclass(exc_type, KeyboardInterrupt):
            # Don't report keyboard interrupts
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        # Report the crash
        self.report_crash(exc_value, {
            "uncaught": True,
            "exception_type": exc_type.__name__
        })
        
        # Call the default handler
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for crash reports."""
        import platform
        import psutil
        
        try:
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_usage": psutil.disk_usage('/').percent if psutil.disk_usage('/') else None
            }
        except Exception:
            return {"error": "Failed to gather system info"}
    
    def _get_witty_crash_message(self) -> str:
        """Get a witty crash message."""
        messages = [
            "Oops! Something went spectacularly wrong! 💥",
            "Well, that wasn't supposed to happen... 🤔",
            "Houston, we have a problem! 🚀",
            "The application has decided to take an unscheduled break ☕",
            "Error 404: Stability not found 🔍",
            "The code has achieved sentience and rebelled! 🤖",
            "Congratulations! You found a bug! 🐛",
            "The application has left the building 🏃‍♂️",
            "Something broke, but at least the error handling works! ✅",
            "The system has encountered a wild exception! 🎮"
        ]
        
        import random
        return random.choice(messages)
    
    def _load_crash_stats(self):
        """Load crash statistics."""
        try:
            stats_file = self.crash_dir / "crash_stats.json"
            if stats_file.exists():
                with open(stats_file, 'r', encoding='utf-8') as f:
                    self.crash_stats.update(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load crash stats: {e}")
    
    def _save_crash_stats(self):
        """Save crash statistics."""
        try:
            stats_file = self.crash_dir / "crash_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.crash_stats, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save crash stats: {e}")
    
    def _update_crash_stats(self, crash_info: Dict[str, Any]):
        """Update crash statistics."""
        self.crash_stats["total_crashes"] += 1
        self.crash_stats["last_crash"] = crash_info["timestamp"]
        
        # Update category stats
        category = crash_info.get("category", "unknown")
        if category not in self.crash_stats["crashes_by_category"]:
            self.crash_stats["crashes_by_category"][category] = 0
        self.crash_stats["crashes_by_category"][category] += 1
        
        # Update severity stats
        severity = crash_info.get("severity", "unknown")
        if severity not in self.crash_stats["crashes_by_severity"]:
            self.crash_stats["crashes_by_severity"][severity] = 0
        self.crash_stats["crashes_by_severity"][severity] += 1
        
        self._save_crash_stats()

# Global crash reporter instance
crash_reporter = CrashReporter()

# Decorator for error handling
def handle_errors(error_class: Type[NetLinkError] = NetLinkError, 
                 reraise: bool = True, report_crash: bool = True):
    """Decorator for comprehensive error handling."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if report_crash:
                    crash_reporter.report_crash(e, {
                        "function": func.__name__,
                        "args": str(args)[:200],  # Limit arg length
                        "kwargs": str(kwargs)[:200]
                    })
                
                if reraise:
                    if isinstance(e, NetLinkError):
                        raise
                    else:
                        raise error_class(f"Error in {func.__name__}: {str(e)}")
                
                return None
        
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if report_crash:
                    crash_reporter.report_crash(e, {
                        "function": func.__name__,
                        "args": str(args)[:200],
                        "kwargs": str(kwargs)[:200]
                    })
                
                if reraise:
                    if isinstance(e, NetLinkError):
                        raise
                    else:
                        raise error_class(f"Error in {func.__name__}: {str(e)}")
                
                return None
        
        import asyncio
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper
    return decorator
