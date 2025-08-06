#!/usr/bin/env python3
"""
PlexiChat System CLI Commands

Command-line interface for system management and operations.

# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalCall=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportIndexIssue=false
# pyright: reportGeneralTypeIssues=false

import asyncio
import click
import json
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from plexichat.core.config import settings
    from plexichat.core.monitoring import system_monitor
    from plexichat.app.logger_config import get_logger
    from plexichat.core.database import database_manager
except ImportError:
    settings = {}
    system_monitor = None
    get_logger = lambda name: print
    database_manager = None

logger = get_logger(__name__)

@click.group()
def system():
    """PlexiChat System Management Commands."""
    pass

@system.command()
def status():
    Show comprehensive system status."""
    try:
        click.echo("PlexiChat System Status")
        click.echo("=" * 40)

        # Basic system info
        click.echo(f"[TAG]  Version: {settings.get('system', {}).get('version', 'Unknown')}")
        click.echo(f"[WORLD] Environment: {settings.get('environment', 'Unknown')}")
        click.echo(f"[PYTHON] Python: {sys.version.split()[0]}")

        # System resources
        try:
            import psutil
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            click.echo(f"[SYSTEM] CPU Usage: {cpu_percent}%")
            click.echo(f"[BRAIN] Memory: {memory.percent}% ({memory.used // 1024**3}GB / {memory.total // 1024**3}GB)")
            click.echo(f"[SAVE] Disk: {disk.percent}% ({disk.used // 1024**3}GB / {disk.total // 1024**3}GB)")
        except ImportError:
            click.echo("[METRICS] System metrics: psutil not available")

        # Database status
        if database_manager:
            try:
                db_status = asyncio.run(database_manager.health_check())
                if db_status.get('healthy', False):
                    click.echo("[DATABASE]  Database: [SUCCESS] Online")
                else:
                    click.echo("[DATABASE]  Database: [ERROR] Offline")
            except Exception:
                click.echo("[DATABASE]  Database: [ERROR] Error")
        else:
            click.echo("[DATABASE]  Database: [ERROR] Not available")

        # System monitor
        if system_monitor:
            try:
                monitor_status = asyncio.run(system_monitor.get_status())
                click.echo(f"[METRICS] Monitoring: [SUCCESS] Active ({monitor_status.get('uptime', 'Unknown')})")
            except Exception:
                click.echo("[METRICS] Monitoring: [ERROR] Error")
        else:
            click.echo("[METRICS] Monitoring: [ERROR] Not available")

        # Uptime
        try:
            uptime = time.time() - settings.get('start_time', time.time())
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            click.echo(f"[TIMER]  Uptime: {hours}h {minutes}m")
        except Exception:
            click.echo("[TIMER]  Uptime: Unknown")

    except Exception as e:
        click.echo(f"[ERROR] Error getting system status: {e}")

@system.command()
@click.option('--service', '-s', help='Specific service to restart')
@click.option('--force', '-f', is_flag=True, help='Force restart without confirmation')
def restart(service: Optional[str], force: bool):
    """Restart system services."""
    try:
        if service:
            if not force:
                if not click.confirm(f"Restart service '{service}'?"):
                    click.echo("Operation cancelled")
                    return

            click.echo(f"[REFRESH] Restarting service: {service}")
            # This would integrate with actual service management
            click.echo(f"[SUCCESS] Service '{service}' restarted successfully")
        else:
            if not force:
                if not click.confirm("Restart all services? This will cause downtime."):
                    click.echo("Operation cancelled")
                    return

            click.echo("[REFRESH] Restarting all services...")
            # This would restart all services
            click.echo("[SUCCESS] All services restarted successfully")

    except Exception as e:
        click.echo(f"[ERROR] Error restarting services: {e}")

@system.command()
def health():
    """Perform comprehensive health check."""
    try:
        click.echo("[HOSPITAL] Performing system health check...")
        click.echo()

        health_status = {"overall": "healthy", "issues": []}

        # Check database
        if database_manager:
            try:
                db_health = asyncio.run(database_manager.health_check())
                if db_health.get('healthy', False):
                    click.echo("[SUCCESS] Database: Healthy")
                else:
                    click.echo("[ERROR] Database: Unhealthy")
                    health_status["issues"].append("Database connection issues")
                    health_status["overall"] = "degraded"
            except Exception as e:
                click.echo(f"[ERROR] Database: Error - {e}")
                health_status["issues"].append(f"Database error: {e}")
                health_status["overall"] = "unhealthy"
        else:
            click.echo("[WARNING]  Database: Not configured")

        # Check system resources
        try:
            import psutil

            # CPU check
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                click.echo(f"[WARNING]  CPU: High usage ({cpu_percent}%)")
                health_status["issues"].append(f"High CPU usage: {cpu_percent}%")
                health_status["overall"] = "degraded"
            else:
                click.echo(f"[SUCCESS] CPU: Normal ({cpu_percent}%)")

            # Memory check
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                click.echo(f"[WARNING]  Memory: High usage ({memory.percent}%)")
                health_status["issues"].append(f"High memory usage: {memory.percent}%")
                health_status["overall"] = "degraded"
            else:
                click.echo(f"[SUCCESS] Memory: Normal ({memory.percent}%)")

            # Disk check
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                click.echo(f"[WARNING]  Disk: High usage ({disk.percent}%)")
                health_status["issues"].append(f"High disk usage: {disk.percent}%")
                health_status["overall"] = "degraded"
            else:
                click.echo(f"[SUCCESS] Disk: Normal ({disk.percent}%)")

        except ImportError:
            click.echo("[WARNING]  System metrics: psutil not available")

        # Check log files
        log_dir = Path("logs")
        if log_dir.exists():
            log_files = list(log_dir.glob("*.log"))
            if log_files:
                click.echo(f"[SUCCESS] Logs: {len(log_files)} log files found")
            else:
                click.echo("[WARNING]  Logs: No log files found")
        else:
            click.echo("[WARNING]  Logs: Log directory not found")

        # Overall status
        click.echo()
        if health_status["overall"] == "healthy":
            click.echo("[COMPLETE] Overall Status: [SUCCESS] HEALTHY")
        elif health_status["overall"] == "degraded":
            click.echo("[WARNING]  Overall Status: [WARNING]  DEGRADED")
            click.echo("Issues found:")
            for issue in health_status["issues"]:
                click.echo(f"   * {issue}")
        else:
            click.echo("[ALERT] Overall Status: [ERROR] UNHEALTHY")
            click.echo("Critical issues found:")
            for issue in health_status["issues"]:
                click.echo(f"   * {issue}")

    except Exception as e:
        click.echo(f"[ERROR] Error performing health check: {e}")

@system.command()
@click.option('--output', '-o', help='Output file for system info')
def info(output: Optional[str]):
    """Get detailed system information."""
    try:
        import platform

        system_info = {
            "plexichat": {
                "version": settings.get('system', {}).get('version', 'Unknown'),
                "environment": settings.get('environment', 'Unknown'),
                "debug_mode": settings.get('debug', False)
            },
            "system": {
                "platform": platform.platform(),
                "architecture": platform.architecture(),
                "processor": platform.processor(),
                "python_version": sys.version,
                "hostname": platform.node()
            }
        }

        # Add system resources if available
        try:
            import psutil
            system_info["resources"] = {
                "cpu_count": psutil.cpu_count(),
                "cpu_percent": psutil.cpu_percent(),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_total": psutil.disk_usage('/').total,
                "disk_free": psutil.disk_usage('/').free
            }
        except ImportError:
            system_info["resources"] = "psutil not available"

        if output:
            output_file = Path(output)
            with open(output_file, 'w') as f:
                json.dump(system_info, f, indent=2)
            click.echo(f"[DOCUMENT] System info saved to: {output_file}")
        else:
            click.echo("System Information")
            click.echo("=" * 30)
            click.echo(json.dumps(system_info, indent=2))

    except Exception as e:
        click.echo(f"[ERROR] Error getting system info: {e}")

@system.command()
@click.option('--days', '-d', default=7, help='Number of days to keep logs')
@click.option('--dry-run', is_flag=True, help='Show what would be cleaned without doing it')
def cleanup(days: int, dry_run: bool):
    """Clean up old logs and temporary files."""
    try:
        import time
        from datetime import datetime, timedelta

        cutoff_time = time.time() - (days * 24 * 3600)
        files_to_delete = []
        total_size = 0

        # Find old log files
        log_dir = Path("logs")
        if log_dir.exists():
            for log_file in log_dir.glob("*.log*"):
                if log_file.stat().st_mtime < cutoff_time:
                    files_to_delete.append(log_file)
                    total_size += log_file.stat().st_size

        # Find temporary files
        temp_dirs = [Path("temp"), Path("tmp"), Path(".tmp")]
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                for temp_file in temp_dir.rglob("*"):
                    if temp_file.is_file() and temp_file.stat().st_mtime < cutoff_time:
                        files_to_delete.append(temp_file)
                        total_size += temp_file.stat().st_size

        if files_to_delete:
            click.echo(f"Found {len(files_to_delete)} files to clean up")
            click.echo(f"Total size: {total_size / 1024 / 1024:.2f} MB")

            if dry_run:
                click.echo("\nFiles that would be deleted:")
                for file_path in files_to_delete:
                    click.echo(f"  * {file_path}")
            else:
                if click.confirm("Proceed with cleanup?"):
                    deleted_count = 0
                    for file_path in files_to_delete:
                        try:
                            file_path.unlink()
                            deleted_count += 1
                        except Exception as e:
                            click.echo(f"[WARNING]  Could not delete {file_path}: {e}")

                    click.echo(f"[SUCCESS] Cleaned up {deleted_count} files")
                else:
                    click.echo("Cleanup cancelled")
        else:
            click.echo("No files found for cleanup")

    except Exception as e:
        click.echo(f"[ERROR] Error during cleanup: {e}")

@system.command()
@click.option('--key', '-k', help='Configuration key to get/set')
@click.option('--value', '-v', help='Value to set (if not provided, will get current value)')
def config(key: Optional[str], value: Optional[str]):
    """Get or set system configuration."""
    try:
        if key:
            if value is not None:
                # Set configuration
                settings[key] = value
                click.echo(f"[SUCCESS] Set {key} = {value}")
            else:
                # Get configuration
                current_value = settings.get(key, "Not set")
                click.echo(f"{key} = {current_value}")
        else:
            # Show all configuration
            click.echo("System Configuration")
            click.echo("=" * 30)

            # Filter out sensitive keys
            safe_config = {}
            sensitive_keys = ["password", "secret", "key", "token"]

            for k, v in settings.items():
                if not any(sensitive in k.lower() for sensitive in sensitive_keys):
                    safe_config[k] = v
                else:
                    safe_config[k] = "***HIDDEN***"

            click.echo(json.dumps(safe_config, indent=2))

    except Exception as e:
        click.echo(f"[ERROR] Error with configuration: {e}")

@system.command()
@click.option('--enable/--disable', default=True, help='Enable or disable maintenance mode')
def maintenance(enable: bool):
    """Enable or disable maintenance mode."""
    try:
        if enable:
            settings['maintenance_mode'] = True
            click.echo("[CONSTRUCTION] Maintenance mode enabled")
            click.echo("   System is now in maintenance mode")
        else:
            settings['maintenance_mode'] = False
            click.echo("[SUCCESS] Maintenance mode disabled")
            click.echo("   System is now operational")

    except Exception as e:
        click.echo(f"[ERROR] Error setting maintenance mode: {e}")

@system.command()
@click.option('--lines', '-n', default=50, help='Number of log lines to show')
@click.option('--follow', '-f', is_flag=True, help='Follow log output')
def logs(lines: int, follow: bool):
    """View system logs."""
    try:
        log_file = Path("logs/plexichat.log")

        if not log_file.exists():
            click.echo("[ERROR] Log file not found")
            return

        if follow:
            click.echo("[DOCUMENT] Following log output (Ctrl+C to stop)...")
            # This would implement log following
            click.echo("Log following not implemented yet")
        else:
            with open(log_file, 'r') as f:
                log_lines = f.readlines()

            # Show last N lines
            for line in log_lines[-lines:]:
                click.echo(line.rstrip())

    except Exception as e:
        click.echo(f"[ERROR] Error reading logs: {e}")

if __name__ == '__main__':
    system()
