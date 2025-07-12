# app/utils/monitoring/error_handler.py
"""
Comprehensive error handling and monitoring system with alerting,
diagnostics, and recovery mechanisms.
"""

import sys
import traceback
import psutil
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Callable
from functools import wraps
from pathlib import Path
import json

import logging
from plexichat.core.config.settings import settings

logger = logging.getLogger(__name__)
monitoring_logger = logging.getLogger(f"{__name__}.monitoring")


class ErrorSeverity:
    """Error severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SystemMonitor:
    """System monitoring and diagnostics."""
    
    def __init__(self):
        self.start_time = datetime.now(timezone.utc)
        self.error_counts = {}
        self.last_health_check = None
        
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics."""
        try:
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
        
        if settings.MONITORING_ENABLED:
            monitoring_logger.warning("ERROR_RECORDED: type=%s severity=%s count=%d", 
                                    error_type, severity, self.error_counts[key])


class ErrorHandler:
    """Comprehensive error handling with context and recovery."""
    
    def __init__(self):
        self.monitor = SystemMonitor()
        self.error_log_file = Path(settings.LOG_DIR) / "errors.jsonl"
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
            "system_metrics": self.monitor.get_system_metrics() if settings.MONITORING_LOG_PERFORMANCE else None
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
    
    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the specified time period."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            recent_errors = []
            
            if self.error_log_file.exists():
                with open(self.error_log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            error_data = json.loads(line.strip())
                            error_time = datetime.fromisoformat(error_data["timestamp"].replace("Z", "+00:00"))
                            if error_time >= cutoff_time:
                                recent_errors.append(error_data)
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
            
            # Analyze errors
            error_types = {}
            severity_counts = {}
            
            for error in recent_errors:
                error_type = error.get("error_type", "Unknown")
                severity = error.get("severity", ErrorSeverity.MEDIUM)
                
                error_types[error_type] = error_types.get(error_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            return {
                "period_hours": hours,
                "total_errors": len(recent_errors),
                "error_types": error_types,
                "severity_counts": severity_counts,
                "most_common_error": max(error_types.items(), key=lambda x: x[1])[0] if error_types else None,
                "critical_errors": severity_counts.get(ErrorSeverity.CRITICAL, 0),
                "health_status": self.monitor.check_system_health()
            }
            
        except Exception as e:
            logger.error("Failed to generate error summary: %s", e)
            return {"error": str(e), "period_hours": hours}


def error_handler_decorator(severity: str = ErrorSeverity.MEDIUM, 
                          recovery_action: Optional[Callable] = None,
                          reraise: bool = True):
    """Decorator for automatic error handling."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                context = {
                    "function": func.__name__,
                    "module": func.__module__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys())
                }
                
                error_handler.handle_error(e, context, severity, recovery_action)
                
                if reraise:
                    raise
                return None
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
            
            if settings.MONITORING_ENABLED and settings.MONITORING_LOG_PERFORMANCE:
                monitoring_logger.info("PERFORMANCE: %s.%s duration=%.3fs status=success", 
                                     func.__module__, func.__name__, duration)
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            
            if settings.MONITORING_ENABLED and settings.MONITORING_LOG_PERFORMANCE:
                monitoring_logger.warning("PERFORMANCE: %s.%s duration=%.3fs status=error error=%s", 
                                        func.__module__, func.__name__, duration, str(e))
            raise
    return wrapper


# Global instances
system_monitor = SystemMonitor()
error_handler = ErrorHandler()
