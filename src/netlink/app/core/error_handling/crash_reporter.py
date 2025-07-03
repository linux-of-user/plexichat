"""
Advanced Crash Reporter for NetLink
Detailed error codes, crash logging, and witty crash report messages.
"""

import os
import sys
import traceback
import json
import time
import platform
import psutil
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import logging
import threading
import inspect

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    FATAL = "fatal"

class ErrorCategory(Enum):
    """Error categories."""
    SYSTEM = "system"
    NETWORK = "network"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"
    USER_INPUT = "user_input"
    EXTERNAL_API = "external_api"
    UNKNOWN = "unknown"

@dataclass
class CrashContext:
    """Context information for crash reports."""
    timestamp: datetime
    error_id: str
    error_code: str
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    exception_type: str
    exception_message: str
    traceback_text: str
    function_name: str
    file_name: str
    line_number: int
    system_info: Dict[str, Any]
    process_info: Dict[str, Any]
    user_context: Dict[str, Any]
    request_context: Dict[str, Any]
    recovery_suggestions: List[str]
    witty_message: str

class WittyMessageGenerator:
    """Generates witty and helpful crash messages."""
    
    WITTY_MESSAGES = [
        "🤖 Oops! I had a little digital hiccup. Don't worry, I'm tougher than I look!",
        "💥 Well, that didn't go as planned. Time to channel my inner Phoenix and rise from the ashes!",
        "🎭 Plot twist! This wasn't supposed to happen. But hey, at least we're consistent in our inconsistency!",
        "🔧 Houston, we have a problem... but also a solution! Let me gather some intel first.",
        "🎪 Ladies and gentlemen, for my next trick, I'll make this error disappear! *waves debugging wand*",
        "🚀 Minor course correction needed! Even rockets need to adjust their trajectory sometimes.",
        "🎯 Missed the target this time, but I'm already calculating the next shot!",
        "🧩 Found a piece that doesn't quite fit the puzzle. Time to reshape it!",
        "⚡ Short circuit detected! Good thing I have excellent error recovery protocols.",
        "🎨 This error is like abstract art - confusing at first, but there's meaning behind it!",
        "🔍 Elementary, my dear user! The game is afoot, and I shall solve this mystery.",
        "🎪 Step right up to see the amazing disappearing error! *debugging intensifies*",
        "🌟 Every error is just a feature waiting to be properly implemented!",
        "🎭 To err is human, to crash is divine... wait, that's not how it goes.",
        "🚨 Red alert! But don't panic - I've handled worse situations before breakfast!",
        "🎲 Rolled a critical failure, but I've got plenty of retry tokens left!",
        "🔮 The crystal ball shows... a bug! But also shows the path to fixing it.",
        "🎪 Welcome to the error circus! Today's main act: The Spectacular Recovery!",
        "🌈 Every crash has a silver lining - it's an opportunity to make things better!",
        "🎯 Bullseye! Wait, no... that was supposed to hit the success target. Recalibrating!"
    ]
    
    RECOVERY_MESSAGES = {
        ErrorCategory.NETWORK: [
            "Check your internet connection - even I need WiFi to work my magic!",
            "Network hiccup detected. Try refreshing, or blame the router like everyone else.",
            "The internet seems to be having a moment. Give it a few seconds to collect itself."
        ],
        ErrorCategory.DATABASE: [
            "Database is taking a coffee break. It'll be back shortly!",
            "Data storage is reorganizing itself. Very feng shui of it.",
            "Database connection playing hard to get. Persistence is key!"
        ],
        ErrorCategory.AUTHENTICATION: [
            "Authentication service is being extra security-conscious today.",
            "Login credentials are having an identity crisis. Try again?",
            "Security checkpoint is being thorough. Your patience is appreciated!"
        ],
        ErrorCategory.VALIDATION: [
            "Input validation is being picky about data quality. Can't blame it!",
            "Data format checker is having high standards today.",
            "Validation service is channeling its inner perfectionist."
        ],
        ErrorCategory.PERFORMANCE: [
            "System is taking a breather. Even computers need rest!",
            "Performance optimizer is working overtime to make things faster.",
            "Resource manager is juggling too many balls. Give it a moment!"
        ]
    }
    
    @classmethod
    def get_witty_message(cls, category: ErrorCategory = None) -> str:
        """Get a random witty message."""
        import random
        return random.choice(cls.WITTY_MESSAGES)
    
    @classmethod
    def get_recovery_message(cls, category: ErrorCategory) -> str:
        """Get a category-specific recovery message."""
        import random
        messages = cls.RECOVERY_MESSAGES.get(category, [
            "Something unexpected happened, but I'm on it!",
            "Technical difficulties detected. Deploying solution protocols!",
            "Error encountered, but recovery systems are already engaged!"
        ])
        return random.choice(messages)

class ErrorCodeGenerator:
    """Generates structured error codes."""
    
    # Error code format: NL-{CATEGORY}-{SEVERITY}-{SEQUENCE}
    # Example: NL-SYS-HIGH-001, NL-NET-MED-042
    
    CATEGORY_CODES = {
        ErrorCategory.SYSTEM: "SYS",
        ErrorCategory.NETWORK: "NET",
        ErrorCategory.DATABASE: "DB",
        ErrorCategory.AUTHENTICATION: "AUTH",
        ErrorCategory.AUTHORIZATION: "AUTHZ",
        ErrorCategory.VALIDATION: "VAL",
        ErrorCategory.PERFORMANCE: "PERF",
        ErrorCategory.CONFIGURATION: "CFG",
        ErrorCategory.USER_INPUT: "INPUT",
        ErrorCategory.EXTERNAL_API: "API",
        ErrorCategory.UNKNOWN: "UNK"
    }
    
    SEVERITY_CODES = {
        ErrorSeverity.LOW: "LOW",
        ErrorSeverity.MEDIUM: "MED",
        ErrorSeverity.HIGH: "HIGH",
        ErrorSeverity.CRITICAL: "CRIT",
        ErrorSeverity.FATAL: "FATAL"
    }
    
    def __init__(self):
        self.sequence_counters = {}
        self.lock = threading.Lock()
    
    def generate_code(self, category: ErrorCategory, severity: ErrorSeverity) -> str:
        """Generate a unique error code."""
        with self.lock:
            cat_code = self.CATEGORY_CODES.get(category, "UNK")
            sev_code = self.SEVERITY_CODES.get(severity, "UNK")
            
            key = f"{cat_code}-{sev_code}"
            if key not in self.sequence_counters:
                self.sequence_counters[key] = 0
            
            self.sequence_counters[key] += 1
            sequence = str(self.sequence_counters[key]).zfill(3)
            
            return f"NL-{cat_code}-{sev_code}-{sequence}"

class CrashReporter:
    """Advanced crash reporting system."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.crash_dir = Path("logs/crashes")
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        
        self.error_code_generator = ErrorCodeGenerator()
        self.witty_generator = WittyMessageGenerator()
        
        # Crash statistics
        self.crash_stats = {
            "total_crashes": 0,
            "crashes_by_category": {},
            "crashes_by_severity": {},
            "recent_crashes": []
        }
        
        # Recovery handlers
        self.recovery_handlers: Dict[str, Callable] = {}
        
        # Load existing crash stats
        self._load_crash_stats()
    
    def report_crash(self, 
                    exception: Exception,
                    severity: ErrorSeverity = ErrorSeverity.HIGH,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    user_context: Dict[str, Any] = None,
                    request_context: Dict[str, Any] = None) -> CrashContext:
        """Report a crash with full context."""
        
        # Generate unique error ID and code
        error_id = str(uuid.uuid4())
        error_code = self.error_code_generator.generate_code(category, severity)
        
        # Get exception details
        exc_type = type(exception).__name__
        exc_message = str(exception)
        tb_text = traceback.format_exc()
        
        # Get caller information
        frame = inspect.currentframe()
        try:
            # Go up the stack to find the actual caller
            caller_frame = frame.f_back.f_back if frame.f_back else frame
            function_name = caller_frame.f_code.co_name
            file_name = caller_frame.f_code.co_filename
            line_number = caller_frame.f_lineno
        except:
            function_name = "unknown"
            file_name = "unknown"
            line_number = 0
        finally:
            del frame
        
        # Collect system information
        system_info = self._collect_system_info()
        process_info = self._collect_process_info()
        
        # Generate recovery suggestions
        recovery_suggestions = self._generate_recovery_suggestions(category, exception)
        
        # Generate witty message
        witty_message = self.witty_generator.get_witty_message(category)
        
        # Create crash context
        crash_context = CrashContext(
            timestamp=datetime.now(),
            error_id=error_id,
            error_code=error_code,
            severity=severity,
            category=category,
            message=exc_message,
            exception_type=exc_type,
            exception_message=exc_message,
            traceback_text=tb_text,
            function_name=function_name,
            file_name=file_name,
            line_number=line_number,
            system_info=system_info,
            process_info=process_info,
            user_context=user_context or {},
            request_context=request_context or {},
            recovery_suggestions=recovery_suggestions,
            witty_message=witty_message
        )
        
        # Save crash report
        self._save_crash_report(crash_context)
        
        # Update statistics
        self._update_crash_stats(crash_context)
        
        # Log the crash
        self._log_crash(crash_context)
        
        # Attempt automatic recovery
        self._attempt_recovery(crash_context)
        
        return crash_context
    
    def _collect_system_info(self) -> Dict[str, Any]:
        """Collect system information."""
        try:
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "architecture": platform.architecture(),
                "processor": platform.processor(),
                "hostname": platform.node(),
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": dict(psutil.disk_usage('/')._asdict()),
                "boot_time": psutil.boot_time(),
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
        except Exception as e:
            return {"error": f"Failed to collect system info: {e}"}
    
    def _collect_process_info(self) -> Dict[str, Any]:
        """Collect current process information."""
        try:
            process = psutil.Process()
            return {
                "pid": process.pid,
                "name": process.name(),
                "status": process.status(),
                "cpu_percent": process.cpu_percent(),
                "memory_info": dict(process.memory_info()._asdict()),
                "memory_percent": process.memory_percent(),
                "num_threads": process.num_threads(),
                "create_time": process.create_time(),
                "cwd": process.cwd(),
                "cmdline": process.cmdline()
            }
        except Exception as e:
            return {"error": f"Failed to collect process info: {e}"}
    
    def _generate_recovery_suggestions(self, category: ErrorCategory, exception: Exception) -> List[str]:
        """Generate recovery suggestions based on error category and type."""
        suggestions = []
        
        # Category-specific suggestions
        if category == ErrorCategory.NETWORK:
            suggestions.extend([
                "Check internet connectivity",
                "Verify firewall settings",
                "Try again in a few moments",
                "Check if external services are available"
            ])
        elif category == ErrorCategory.DATABASE:
            suggestions.extend([
                "Check database connection settings",
                "Verify database service is running",
                "Check disk space for database files",
                "Review database logs for errors"
            ])
        elif category == ErrorCategory.AUTHENTICATION:
            suggestions.extend([
                "Verify credentials are correct",
                "Check if account is locked",
                "Clear browser cache and cookies",
                "Try logging out and back in"
            ])
        elif category == ErrorCategory.PERFORMANCE:
            suggestions.extend([
                "Check system resource usage",
                "Close unnecessary applications",
                "Clear cache if available",
                "Restart the application"
            ])
        
        # Exception-specific suggestions
        exc_type = type(exception).__name__
        if exc_type == "ConnectionError":
            suggestions.append("Check network connectivity and try again")
        elif exc_type == "TimeoutError":
            suggestions.append("Operation timed out - try again or increase timeout")
        elif exc_type == "PermissionError":
            suggestions.append("Check file/directory permissions")
        elif exc_type == "FileNotFoundError":
            suggestions.append("Verify file path exists and is accessible")
        elif exc_type == "MemoryError":
            suggestions.append("Close other applications to free memory")
        
        # Add recovery message
        recovery_msg = self.witty_generator.get_recovery_message(category)
        suggestions.append(recovery_msg)
        
        return suggestions
    
    def _save_crash_report(self, crash_context: CrashContext):
        """Save crash report to file."""
        try:
            # Create filename with timestamp and error code
            timestamp_str = crash_context.timestamp.strftime("%Y%m%d_%H%M%S")
            filename = f"crash_{timestamp_str}_{crash_context.error_code}.json"
            filepath = self.crash_dir / filename
            
            # Convert to dictionary for JSON serialization
            crash_dict = asdict(crash_context)
            crash_dict["timestamp"] = crash_context.timestamp.isoformat()
            
            # Save to file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(crash_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Crash report saved: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save crash report: {e}")
    
    def _update_crash_stats(self, crash_context: CrashContext):
        """Update crash statistics."""
        self.crash_stats["total_crashes"] += 1
        
        # Update category stats
        cat_key = crash_context.category.value
        if cat_key not in self.crash_stats["crashes_by_category"]:
            self.crash_stats["crashes_by_category"][cat_key] = 0
        self.crash_stats["crashes_by_category"][cat_key] += 1
        
        # Update severity stats
        sev_key = crash_context.severity.value
        if sev_key not in self.crash_stats["crashes_by_severity"]:
            self.crash_stats["crashes_by_severity"][sev_key] = 0
        self.crash_stats["crashes_by_severity"][sev_key] += 1
        
        # Add to recent crashes (keep last 100)
        recent_crash = {
            "timestamp": crash_context.timestamp.isoformat(),
            "error_id": crash_context.error_id,
            "error_code": crash_context.error_code,
            "category": crash_context.category.value,
            "severity": crash_context.severity.value,
            "message": crash_context.message
        }
        
        self.crash_stats["recent_crashes"].append(recent_crash)
        if len(self.crash_stats["recent_crashes"]) > 100:
            self.crash_stats["recent_crashes"] = self.crash_stats["recent_crashes"][-100:]
        
        # Save updated stats
        self._save_crash_stats()
    
    def _load_crash_stats(self):
        """Load crash statistics from file."""
        stats_file = self.crash_dir / "crash_stats.json"
        try:
            if stats_file.exists():
                with open(stats_file, 'r') as f:
                    self.crash_stats.update(json.load(f))
        except Exception as e:
            self.logger.warning(f"Failed to load crash stats: {e}")
    
    def _save_crash_stats(self):
        """Save crash statistics to file."""
        stats_file = self.crash_dir / "crash_stats.json"
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.crash_stats, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save crash stats: {e}")
    
    def _log_crash(self, crash_context: CrashContext):
        """Log crash to standard logger."""
        log_level = {
            ErrorSeverity.LOW: logging.INFO,
            ErrorSeverity.MEDIUM: logging.WARNING,
            ErrorSeverity.HIGH: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.FATAL: logging.CRITICAL
        }.get(crash_context.severity, logging.ERROR)
        
        self.logger.log(
            log_level,
            f"CRASH REPORT [{crash_context.error_code}]: {crash_context.message}",
            extra={
                "error_id": crash_context.error_id,
                "error_code": crash_context.error_code,
                "category": crash_context.category.value,
                "severity": crash_context.severity.value,
                "function": crash_context.function_name,
                "file": crash_context.file_name,
                "line": crash_context.line_number,
                "witty_message": crash_context.witty_message
            }
        )
    
    def _attempt_recovery(self, crash_context: CrashContext):
        """Attempt automatic recovery based on error type."""
        recovery_key = f"{crash_context.category.value}_{crash_context.exception_type}"
        
        if recovery_key in self.recovery_handlers:
            try:
                self.recovery_handlers[recovery_key](crash_context)
                self.logger.info(f"Recovery attempted for {crash_context.error_code}")
            except Exception as e:
                self.logger.error(f"Recovery failed for {crash_context.error_code}: {e}")
    
    def register_recovery_handler(self, category: ErrorCategory, exception_type: str, handler: Callable):
        """Register a recovery handler for specific error types."""
        key = f"{category.value}_{exception_type}"
        self.recovery_handlers[key] = handler
        self.logger.info(f"Recovery handler registered for {key}")
    
    def get_crash_stats(self) -> Dict[str, Any]:
        """Get crash statistics."""
        return self.crash_stats.copy()
    
    def get_recent_crashes(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent crash reports."""
        return self.crash_stats["recent_crashes"][-limit:]
    
    def cleanup_old_reports(self, days: int = 30):
        """Clean up old crash reports."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            for crash_file in self.crash_dir.glob("crash_*.json"):
                if crash_file.stat().st_mtime < cutoff_date.timestamp():
                    crash_file.unlink()
                    self.logger.info(f"Cleaned up old crash report: {crash_file}")
        except Exception as e:
            self.logger.error(f"Failed to cleanup old crash reports: {e}")

# Global crash reporter instance
crash_reporter = CrashReporter()

# Decorator for automatic crash reporting
def crash_handler(severity: ErrorSeverity = ErrorSeverity.HIGH, 
                 category: ErrorCategory = ErrorCategory.UNKNOWN):
    """Decorator to automatically handle crashes in functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                crash_context = crash_reporter.report_crash(
                    exception=e,
                    severity=severity,
                    category=category
                )
                # Re-raise the exception after reporting
                raise e
        return wrapper
    return decorator
