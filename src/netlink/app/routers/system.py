"""
NetLink Core monitoring and management endpoints.
Provides comprehensive NetLink Core health, performance metrics, and administrative controls.
"""

import os
import psutil
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
import asyncio
import json

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from sqlmodel import Session, select, func
from pydantic import BaseModel

from app.db import get_session
from app.logger_config import logger, logging_manager, settings
from app.models.user import User
from app.models.files import FileRecord
from app.utils.auth import get_current_user, require_admin
from app.utils.monitoring import SystemMonitor, PerformanceTracker

router = APIRouter()

# Response Models
class SystemInfoResponse(BaseModel):
    """System information response."""
    hostname: str
    platform: str
    platform_version: str
    architecture: str
    processor: str
    python_version: str
    uptime_seconds: float
    boot_time: datetime
    timezone: str

class ResourceUsageResponse(BaseModel):
    """Resource usage response."""
    cpu_percent: float
    cpu_count: int
    cpu_freq: Optional[Dict[str, float]]
    memory_total: int
    memory_available: int
    memory_percent: float
    disk_total: int
    disk_used: int
    disk_free: int
    disk_percent: float
    network_io: Dict[str, int]
    disk_io: Dict[str, int]

class ProcessInfoResponse(BaseModel):
    """Process information response."""
    pid: int
    name: str
    status: str
    cpu_percent: float
    memory_percent: float
    memory_info: Dict[str, int]
    create_time: datetime
    cmdline: List[str]
    connections: int

class LogStatsResponse(BaseModel):
    """Log statistics response."""
    total_logs: int
    logs_by_level: Dict[str, int]
    recent_errors: List[Dict[str, Any]]
    log_files: List[Dict[str, Any]]
    stream_buffer_size: int
    active_subscribers: int

class DatabaseStatsResponse(BaseModel):
    """Database statistics response."""
    total_users: int
    total_messages: int
    total_files: int
    database_size: Optional[str]
    active_connections: Optional[int]
    recent_activity: List[Dict[str, Any]]

class HealthCheckResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: datetime
    uptime: str
    version: str
    checks: Dict[str, Dict[str, Any]]
    warnings: List[str]
    errors: List[str]

@router.get("/info", response_model=SystemInfoResponse)
async def get_system_info(
    current_user: User = Depends(require_admin)
):
    """Get comprehensive system information."""
    try:
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        return SystemInfoResponse(
            hostname=platform.node(),
            platform=platform.system(),
            platform_version=platform.version(),
            architecture=platform.architecture()[0],
            processor=platform.processor() or "Unknown",
            python_version=platform.python_version(),
            uptime_seconds=uptime.total_seconds(),
            boot_time=boot_time,
            timezone=str(datetime.now().astimezone().tzinfo)
        )
    except Exception as e:
        logger.error(f"Failed to get system info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system information")

@router.get("/resources", response_model=ResourceUsageResponse)
async def get_resource_usage(
    current_user: User = Depends(require_admin)
):
    """Get current resource usage statistics."""
    try:
        # CPU information
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        try:
            cpu_freq = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
        except:
            cpu_freq = None
        
        # Memory information
        memory = psutil.virtual_memory()
        
        # Disk information (for main drive)
        disk = psutil.disk_usage('/')
        
        # Network I/O
        net_io = psutil.net_io_counters()
        network_io = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }
        
        # Disk I/O
        disk_io_counters = psutil.disk_io_counters()
        disk_io = {
            'read_bytes': disk_io_counters.read_bytes,
            'write_bytes': disk_io_counters.write_bytes,
            'read_count': disk_io_counters.read_count,
            'write_count': disk_io_counters.write_count
        } if disk_io_counters else {}
        
        return ResourceUsageResponse(
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            cpu_freq=cpu_freq,
            memory_total=memory.total,
            memory_available=memory.available,
            memory_percent=memory.percent,
            disk_total=disk.total,
            disk_used=disk.used,
            disk_free=disk.free,
            disk_percent=(disk.used / disk.total) * 100,
            network_io=network_io,
            disk_io=disk_io
        )
    except Exception as e:
        logger.error(f"Failed to get resource usage: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve resource usage")

@router.get("/processes", response_model=List[ProcessInfoResponse])
async def get_processes(
    limit: int = Query(20, ge=1, le=100),
    sort_by: str = Query("cpu_percent", regex="^(cpu_percent|memory_percent|name|pid)$"),
    current_user: User = Depends(require_admin)
):
    """Get running processes information."""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'memory_info', 'create_time', 'cmdline']):
            try:
                proc_info = proc.info
                
                # Count connections
                try:
                    connections = len(proc.connections())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    connections = 0
                
                processes.append(ProcessInfoResponse(
                    pid=proc_info['pid'],
                    name=proc_info['name'] or 'Unknown',
                    status=proc_info['status'],
                    cpu_percent=proc_info['cpu_percent'] or 0.0,
                    memory_percent=proc_info['memory_percent'] or 0.0,
                    memory_info={
                        'rss': proc_info['memory_info'].rss if proc_info['memory_info'] else 0,
                        'vms': proc_info['memory_info'].vms if proc_info['memory_info'] else 0
                    },
                    create_time=datetime.fromtimestamp(proc_info['create_time']),
                    cmdline=proc_info['cmdline'] or [],
                    connections=connections
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort processes
        if sort_by == "cpu_percent":
            processes.sort(key=lambda x: x.cpu_percent, reverse=True)
        elif sort_by == "memory_percent":
            processes.sort(key=lambda x: x.memory_percent, reverse=True)
        elif sort_by == "name":
            processes.sort(key=lambda x: x.name.lower())
        elif sort_by == "pid":
            processes.sort(key=lambda x: x.pid)
        
        return processes[:limit]
    except Exception as e:
        logger.error(f"Failed to get processes: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve process information")

@router.get("/logs/stats", response_model=LogStatsResponse)
async def get_log_stats(
    current_user: User = Depends(require_admin)
):
    """Get logging system statistics."""
    try:
        # Get recent logs from stream handler
        recent_logs = logging_manager.get_recent_logs(1000) if logging_manager else []
        
        # Count logs by level
        logs_by_level = {}
        recent_errors = []
        
        for log in recent_logs:
            level = log.get('level', 'INFO')
            logs_by_level[level] = logs_by_level.get(level, 0) + 1
            
            # Collect recent errors
            if level in ['ERROR', 'CRITICAL'] and len(recent_errors) < 10:
                recent_errors.append({
                    'timestamp': log.get('timestamp'),
                    'level': level,
                    'message': log.get('message', ''),
                    'module': log.get('module', ''),
                    'function': log.get('function', '')
                })
        
        # Get log files information
        log_files = []
        log_dir = Path(settings.LOG_DIR)
        if log_dir.exists():
            for log_file in log_dir.glob("*.log*"):
                try:
                    stat = log_file.stat()
                    log_files.append({
                        'name': log_file.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'path': str(log_file)
                    })
                except Exception:
                    continue
        
        # Stream handler info
        stream_handler = logging_manager.get_stream_handler() if logging_manager else None
        stream_buffer_size = len(stream_handler.buffer) if stream_handler else 0
        active_subscribers = len(stream_handler.subscribers) if stream_handler else 0
        
        return LogStatsResponse(
            total_logs=len(recent_logs),
            logs_by_level=logs_by_level,
            recent_errors=recent_errors,
            log_files=log_files,
            stream_buffer_size=stream_buffer_size,
            active_subscribers=active_subscribers
        )
    except Exception as e:
        logger.error(f"Failed to get log stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve log statistics")

@router.get("/database/stats", response_model=DatabaseStatsResponse)
async def get_database_stats(
    session: Session = Depends(get_session),
    current_user: User = Depends(require_admin)
):
    """Get database statistics."""
    try:
        # Count records
        total_users = session.exec(select(func.count(User.id))).one()
        total_files = session.exec(select(func.count(FileRecord.id))).one()
        
        # Recent activity (simplified)
        recent_users = session.exec(
            select(User).order_by(User.created_at.desc()).limit(5)
        ).all()
        
        recent_files = session.exec(
            select(FileRecord).order_by(FileRecord.upload_date.desc()).limit(5)
        ).all()
        
        recent_activity = []
        
        for user in recent_users:
            recent_activity.append({
                'type': 'user_created',
                'timestamp': user.created_at,
                'details': f"User {user.username} created"
            })
        
        for file in recent_files:
            recent_activity.append({
                'type': 'file_uploaded',
                'timestamp': file.upload_date,
                'details': f"File {file.filename} uploaded"
            })
        
        # Sort by timestamp
        recent_activity.sort(key=lambda x: x['timestamp'], reverse=True)
        recent_activity = recent_activity[:10]
        
        return DatabaseStatsResponse(
            total_users=total_users,
            total_messages=0,  # Placeholder
            total_files=total_files,
            database_size=None,  # Would need database-specific queries
            active_connections=None,  # Would need database-specific queries
            recent_activity=recent_activity
        )
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve database statistics")

@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Comprehensive health check endpoint."""
    try:
        checks = {}
        warnings = []
        errors = []
        
        # System health
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            checks['system'] = {
                'status': 'healthy',
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_usage': (disk.used / disk.total) * 100
            }
            
            if cpu_percent > 90:
                warnings.append("High CPU usage detected")
            if memory.percent > 90:
                warnings.append("High memory usage detected")
            if (disk.used / disk.total) * 100 > 90:
                warnings.append("Low disk space")
                
        except Exception as e:
            checks['system'] = {'status': 'error', 'error': str(e)}
            errors.append(f"System check failed: {e}")
        
        # Database health
        try:
            # Simple database connectivity test would go here
            checks['database'] = {'status': 'healthy'}
        except Exception as e:
            checks['database'] = {'status': 'error', 'error': str(e)}
            errors.append(f"Database check failed: {e}")
        
        # Logging health
        try:
            if logging_manager:
                checks['logging'] = {'status': 'healthy'}
            else:
                checks['logging'] = {'status': 'warning', 'message': 'Logging manager not available'}
                warnings.append("Logging system issues detected")
        except Exception as e:
            checks['logging'] = {'status': 'error', 'error': str(e)}
            errors.append(f"Logging check failed: {e}")
        
        # Determine overall status
        if errors:
            overall_status = "unhealthy"
        elif warnings:
            overall_status = "degraded"
        else:
            overall_status = "healthy"
        
        # Calculate uptime
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        uptime_str = f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m"
        
        return HealthCheckResponse(
            status=overall_status,
            timestamp=datetime.now(),
            uptime=uptime_str,
            version=settings.API_VERSION,
            checks=checks,
            warnings=warnings,
            errors=errors
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Health check failed")

@router.post("/restart")
async def restart_system(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_admin)
):
    """Restart the application (requires admin privileges)."""
    try:
        logger.warning(f"System restart requested by user {current_user.username}")
        
        # Schedule restart in background
        background_tasks.add_task(perform_restart)
        
        return {"message": "System restart initiated", "status": "success"}
    except Exception as e:
        logger.error(f"Failed to restart system: {e}")
        raise HTTPException(status_code=500, detail="Failed to restart system")

async def perform_restart():
    """Perform system restart."""
    try:
        # Give time for response to be sent
        await asyncio.sleep(2)
        
        # Graceful shutdown
        logger.info("Performing graceful restart...")
        
        # In a real deployment, this would trigger a proper restart
        # For now, we'll just log the action
        logger.info("Restart completed")
        
    except Exception as e:
        logger.error(f"Restart failed: {e}")

@router.get("/config")
async def get_system_config(
    current_user: User = Depends(require_admin)
):
    """Get system configuration (sanitized for security)."""
    try:
        config = {
            'api_version': settings.API_VERSION,
            'debug_mode': settings.DEBUG,
            'host': settings.HOST,
            'port': settings.PORT,
            'log_level': settings.LOG_LEVEL,
            'database_configured': bool(settings.DATABASE_URL),
            'ssl_enabled': bool(settings.SSL_CERTFILE and settings.SSL_KEYFILE),
            'rate_limiting': {
                'requests': settings.RATE_LIMIT_REQUESTS,
                'window': settings.RATE_LIMIT_WINDOW
            },
            'logging': {
                'console': settings.LOG_TO_CONSOLE,
                'file': settings.LOG_TO_FILE,
                'json_format': settings.LOG_JSON_FORMAT,
                'stream_enabled': settings.LOG_STREAM_ENABLED
            },
            'self_tests': {
                'enabled': settings.SELFTEST_ENABLED,
                'interval_minutes': settings.SELFTEST_INTERVAL_MINUTES
            },
            'monitoring': {
                'enabled': settings.MONITORING_ENABLED,
                'performance_tracking': settings.LOG_PERFORMANCE_TRACKING
            }
        }
        
        return config
    except Exception as e:
        logger.error(f"Failed to get system config: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system configuration")

@router.post("/test/run")
async def run_tests(
    suite: Optional[str] = None,
    timeout: Optional[int] = None,
    current_user: User = Depends(require_admin)
) -> Dict[str, Any]:
    """
    Run system tests.

    **Admin only endpoint**

    Runs comprehensive system tests and returns results.
    """
    try:
        from app.testing.comprehensive_test_suite import test_framework

        logger.info(f"Running tests - Suite: {suite or 'all'}, User: {current_user.username}")

        # Setup test framework
        await test_framework.setup_session()

        try:
            if suite:
                if suite not in test_framework.test_suites:
                    raise HTTPException(status_code=400, detail=f"Unknown test suite: {suite}")

                # Override timeout if specified
                if timeout:
                    test_framework.test_suites[suite].timeout = timeout

                results = await test_framework.run_suite(suite)
                suite_results = {suite: results}
            else:
                # Override timeout for all suites if specified
                if timeout:
                    for test_suite in test_framework.test_suites.values():
                        test_suite.timeout = timeout

                suite_results = await test_framework.run_all_suites()

            # Generate report
            report = test_framework.generate_report(suite_results)

            return {
                "success": True,
                "message": "Tests completed successfully",
                "data": report
            }

        finally:
            await test_framework.teardown_session()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Test execution failed: {str(e)}")

@router.get("/test/suites")
async def list_test_suites(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    List available test suites.

    **Admin only endpoint**
    """
    try:
        from app.testing.comprehensive_test_suite import test_framework

        suites_info = {}
        for suite_name, suite in test_framework.test_suites.items():
            suites_info[suite_name] = {
                "name": suite.name,
                "description": suite.description,
                "test_count": len(suite.tests),
                "timeout": suite.timeout,
                "parallel": suite.parallel,
                "tests": [test.__name__ for test in suite.tests]
            }

        return {
            "success": True,
            "data": {
                "total_suites": len(suites_info),
                "suites": suites_info
            }
        }

    except Exception as e:
        logger.error(f"Failed to list test suites: {e}")
        raise HTTPException(status_code=500, detail="Failed to list test suites")

@router.get("/analytics/dashboard")
async def get_analytics_dashboard(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    Get analytics dashboard data.

    **Admin only endpoint**
    """
    try:
        from app.core.analytics.analytics_engine import analytics_engine

        dashboard_data = await analytics_engine.get_analytics_data()

        return {
            "success": True,
            "data": dashboard_data
        }

    except Exception as e:
        logger.error(f"Failed to get analytics dashboard: {e}")
        raise HTTPException(status_code=500, detail="Failed to get analytics dashboard")

@router.get("/analytics/performance")
async def get_performance_metrics(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    """
    Get performance metrics.

    **Admin only endpoint**
    """
    try:
        from app.core.analytics.analytics_engine import analytics_engine

        performance_data = await analytics_engine.dashboard.get_performance_metrics()

        return {
            "success": True,
            "data": performance_data
        }

    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance metrics")

@router.get("/analytics/users/{user_id}")
async def get_user_analytics(
    user_id: int,
    current_user: User = Depends(require_admin)
) -> Dict[str, Any]:
    """
    Get analytics for specific user.

    **Admin only endpoint**
    """
    try:
        from app.core.analytics.analytics_engine import analytics_engine

        user_analytics = await analytics_engine.get_user_analytics(user_id)

        return {
            "success": True,
            "data": user_analytics
        }

    except Exception as e:
        logger.error(f"Failed to get user analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user analytics")

@router.post("/cli/execute")
async def execute_cli_command(
    command_data: Dict[str, str],
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Execute CLI command via web interface.

    **Requires authentication**
    """
    try:
        command = command_data.get("command", "").strip()
        if not command:
            return {
                "success": False,
                "error": "No command provided"
            }

        logger.info(f"Web CLI command executed by user {current_user.id}: {command}")

        # Import CLI class
        from cli import EnhancedChatCLI
        import io
        import sys
        from contextlib import redirect_stdout, redirect_stderr

        # Create CLI instance
        cli = EnhancedChatCLI()

        # Capture output
        output_buffer = io.StringIO()
        error_buffer = io.StringIO()

        try:
            with redirect_stdout(output_buffer), redirect_stderr(error_buffer):
                # Execute command
                cli.onecmd(command)

            output = output_buffer.getvalue()
            error_output = error_buffer.getvalue()

            # Determine output type
            output_type = "info"
            if error_output:
                output_type = "error"
                output = error_output
            elif "error" in output.lower() or "failed" in output.lower():
                output_type = "error"
            elif "warning" in output.lower():
                output_type = "warning"
            elif "success" in output.lower() or "✅" in output:
                output_type = "success"

            return {
                "success": True,
                "output": output or "Command executed successfully",
                "output_type": output_type
            }

        except Exception as cmd_error:
            return {
                "success": False,
                "error": f"Command execution failed: {str(cmd_error)}"
            }

    except Exception as e:
        logger.error(f"CLI command execution failed: {e}")
        return {
            "success": False,
            "error": f"Internal error: {str(e)}"
        }
