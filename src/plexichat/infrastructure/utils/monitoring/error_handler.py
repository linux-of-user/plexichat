# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
import time
import traceback
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)
monitoring_logger = logging.getLogger("plexichat.monitoring")

class ErrorSeverity:
    """Error severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SystemMonitor:
    """System monitoring and health checking."""

    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.error_counts = {}
        self.last_health_check = None
        
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics."""
        try:
            if not PSUTIL_AVAILABLE:
                return {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": "psutil not available",
                    "uptime_seconds": (datetime.now(timezone.utc) - self.start_time).total_seconds()
                }

            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Process info
            process = psutil.Process()
            process_memory = process.memory_info()
            
            # Application uptime
            uptime = datetime.now(timezone.utc) - self.start_time
            
            metrics = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "uptime_seconds": uptime.total_seconds(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count()
                },
                "memory": {
                    "total_mb": memory.total // 1024 // 1024,
                    "available_mb": memory.available // 1024 // 1024,
                    "percent_used": memory.percent,
                    "process_rss_mb": process_memory.rss // 1024 // 1024,
                    "process_vms_mb": process_memory.vms // 1024 // 1024
                },
                "disk": {
                    "total_gb": disk.total // 1024 // 1024 // 1024,
                    "free_gb": disk.free // 1024 // 1024 // 1024,
                    "percent_used": (disk.used / disk.total) * 100
                },
                "error_counts": self.error_counts.copy()
            }
            
            return metrics
            
        except Exception as e:
            logger.error("Failed to collect system metrics: %s", e)
            return {"error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}
    
    def check_system_health(self) -> Dict[str, Any]:
        """Perform comprehensive system health check."""
        health_status = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": "HEALTHY",
            "checks": {},
            "alerts": []
        }
        
        try:
            metrics = self.get_system_metrics()
            
            # Memory check
            memory_usage = metrics.get("memory", {}).get("percent_used", 0)
            if memory_usage > 90:
                health_status["checks"]["memory"] = "CRITICAL"
                health_status["alerts"].append(f"High memory usage: {memory_usage:.1f}%")
                health_status["overall_status"] = "CRITICAL"
            elif memory_usage > 80:
                health_status["checks"]["memory"] = "WARNING"
                health_status["alerts"].append(f"Elevated memory usage: {memory_usage:.1f}%")
                if health_status["overall_status"] == "HEALTHY":
                    health_status["overall_status"] = "WARNING"
            else:
                health_status["checks"]["memory"] = "OK"
            
            # CPU check
            cpu_usage = metrics.get("cpu", {}).get("percent", 0)
            if cpu_usage > 95:
                health_status["checks"]["cpu"] = "CRITICAL"
                health_status["alerts"].append(f"High CPU usage: {cpu_usage:.1f}%")
                health_status["overall_status"] = "CRITICAL"
            elif cpu_usage > 80:
                health_status["checks"]["cpu"] = "WARNING"
                health_status["alerts"].append(f"Elevated CPU usage: {cpu_usage:.1f}%")
                if health_status["overall_status"] == "HEALTHY":
                    health_status["overall_status"] = "WARNING"
            else:
                health_status["checks"]["cpu"] = "OK"
            
            # Disk check
            disk_usage = metrics.get("disk", {}).get("percent_used", 0)
            if disk_usage > 95:
                health_status["checks"]["disk"] = "CRITICAL"
                health_status["alerts"].append(f"Disk space critical: {disk_usage:.1f}%")
                health_status["overall_status"] = "CRITICAL"
            elif disk_usage > 85:
                health_status["checks"]["disk"] = "WARNING"
                health_status["alerts"].append(f"Disk space low: {disk_usage:.1f}%")
                if health_status["overall_status"] == "HEALTHY":
                    health_status["overall_status"] = "WARNING"
            else:
                health_status["checks"]["disk"] = "OK"
            
            # Error rate check
            total_errors = sum(self.error_counts.values())
            if total_errors > 100:  # More than 100 errors
                health_status["checks"]["errors"] = "CRITICAL"
                health_status["alerts"].append(f"High error count: {total_errors}")
                health_status["overall_status"] = "CRITICAL"
            elif total_errors > 50:
                health_status["checks"]["errors"] = "WARNING"
                health_status["alerts"].append(f"Elevated error count: {total_errors}")
                if health_status["overall_status"] == "HEALTHY":
                    health_status["overall_status"] = "WARNING"
            else:
                health_status["checks"]["errors"] = "OK"
            
            self.last_health_check = datetime.now(timezone.utc)
            
        except Exception as e:
            health_status["overall_status"] = "ERROR"
            health_status["error"] = str(e)
            logger.error("Health check failed: %s", e)
        
        return health_status
    
    def record_error(self, error_type: str, severity: str = ErrorSeverity.MEDIUM):
        """Record an error occurrence."""
        key = f"{error_type}_{severity}"
        self.error_counts[key] = self.error_counts.get(key, 0) + 1
        
        # Check if monitoring is enabled (simplified)
        monitoring_enabled = True  # Default to True for now
        if monitoring_enabled:
            monitoring_logger.warning("ERROR_RECORDED: type=%s severity=%s count=%d", 
                                    error_type, severity, self.error_counts[key])


class ErrorHandler:
    """Comprehensive error handling with context and recovery."""
    
    def __init__(self):
        self.monitor = SystemMonitor()
        self.error_log_file = Path("logs") / "errors.jsonl"
        self.error_log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None, 
                    severity: str = ErrorSeverity.MEDIUM, 
                    recovery_action: Optional[Callable] = None) -> Dict[str, Any]:
        """Handle an error with comprehensive logging and optional recovery."""
        
        error_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "severity": severity,
            "context": context or {},
            "traceback": traceback.format_exc(),
            "system_metrics": self.monitor.get_system_metrics()
        }
        
        # Log the error
        if severity == ErrorSeverity.CRITICAL:
            logger.critical("CRITICAL ERROR: %s - %s", error_info["error_type"], error_info["error_message"])
        elif severity == ErrorSeverity.HIGH:
            logger.error("HIGH SEVERITY ERROR: %s - %s", error_info["error_type"], error_info["error_message"])
        elif severity == ErrorSeverity.MEDIUM:
            logger.warning("ERROR: %s - %s", error_info["error_type"], error_info["error_message"])
        else:
            logger.info("LOW SEVERITY ERROR: %s - %s", error_info["error_type"], error_info["error_message"])
        
        # Record error for monitoring
        self.monitor.record_error(error_info["error_type"], severity)
        
        # Save detailed error info to file
        try:
            with open(self.error_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(error_info) + "\n")
        except Exception as e:
            logger.error("Failed to write error log: %s", e)
        
        # Attempt recovery if provided
        recovery_result = None
        if recovery_action:
            try:
                logger.info("Attempting error recovery for %s", error_info["error_type"])
                recovery_result = recovery_action()
                logger.info("Error recovery successful for %s", error_info["error_type"])
                error_info["recovery_attempted"] = True
                error_info["recovery_successful"] = True
                error_info["recovery_result"] = recovery_result
            except Exception as recovery_error:
                logger.error("Error recovery failed for %s: %s", error_info["error_type"], recovery_error)
                error_info["recovery_attempted"] = True
                error_info["recovery_successful"] = False
                error_info["recovery_error"] = str(recovery_error)
        
        return error_info

def error_handler_decorator(severity: str = ErrorSeverity.MEDIUM, 
                          recovery_action: Optional[Callable] = None):
    """Decorator for automatic error handling."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler = ErrorHandler()
                error_info = handler.handle_error(e, 
                                               context={"function": func.__name__},
                                               severity=severity,
                                               recovery_action=recovery_action)
                raise
        return wrapper
    return decorator

def monitor_performance(func):
    """Decorator to monitor function performance."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Check if monitoring is enabled (simplified)
            monitoring_enabled = True  # Default to True for now
            monitoring_log_performance = True  # Default to True for now
            
            if monitoring_enabled and monitoring_log_performance:
                monitoring_logger.info("PERFORMANCE: %s.%s duration=%.3fs status=success", 
                                     func.__module__, func.__name__, duration)
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            monitoring_logger.error("PERFORMANCE: %s.%s duration=%.3fs status=error error=%s", 
                                  func.__module__, func.__name__, duration, str(e))
            raise
    
    return wrapper

# Global instances
error_handler = ErrorHandler()
system_monitor = SystemMonitor()
