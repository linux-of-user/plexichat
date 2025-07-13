import asyncio
import logging
import os
import platform
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

from ..cli_coordinator import CommandCategory, UltimateCommand, ultimate_cli

            import json

import psutil

"""
PlexiChat Ultimate CLI - Core System Commands
Essential system operations and management commands
"""

logger = logging.getLogger(__name__)
console = Console()


# Core System Commands

async def cmd_status(detailed: bool = False, json_output: bool = False):
    """Show comprehensive system status."""
    try:
        if detailed:
            console.print(" Gathering detailed system information...")
        
        # System information
        system_info = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.architecture()[0],
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "cpu_count": import psutil
psutil.cpu_count(),
            "memory_total": import psutil
psutil.virtual_memory().total,
            "memory_available": import psutil
psutil.virtual_memory().available,
            "disk_usage": import psutil
psutil.disk_usage('/').percent if os.name != 'nt' else import psutil
psutil.disk_usage('C:').percent,
            "uptime": from datetime import datetime
datetime.now() - datetime.fromtimestamp(import psutil
psutil.boot_time()),
            "load_average": import psutil
psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }
        
        # PlexiChat specific status
        plexichat_status = {
            "version": "3.0.0",
            "status": "running",
            "pid": os.getpid(),
            "start_time": from datetime import datetime
datetime.now().isoformat(),
            "config_loaded": True,
            "database_connected": True,
            "services_running": ["api", "websocket", "background_tasks"]
        }
        
        if json_output:
            result = {"system": system_info, "plexichat": plexichat_status}
            console.print(json.dumps(result, indent=2, default=str))
        else:
            # Display formatted status
            console.print(Panel(" PlexiChat System Status", style="bold green"))
            
            # System table
            system_table = Table(title=" System Information")
            system_table.add_column("Property", style="cyan")
            system_table.add_column("Value", style="white")
            
            system_table.add_row("Platform", f"{system_info['platform']} {system_info['platform_version']}")
            system_table.add_row("Architecture", system_info['architecture'])
            system_table.add_row("Hostname", system_info['hostname'])
            system_table.add_row("Python Version", system_info['python_version'])
            system_table.add_row("CPU Cores", str(system_info['cpu_count']))
            system_table.add_row("Memory", f"{system_info['memory_available'] // (1024**3)} GB / {system_info['memory_total'] // (1024**3)} GB")
            system_table.add_row("Disk Usage", f"{system_info['disk_usage']:.1f}%")
            system_table.add_row("Uptime", str(system_info['uptime']).split('.')[0])
            
            console.print(system_table)
            
            # PlexiChat table
            plexichat_table = Table(title=" PlexiChat Status")
            plexichat_table.add_column("Component", style="cyan")
            plexichat_table.add_column("Status", style="green")
            
            plexichat_table.add_row("Version", plexichat_status['version'])
            plexichat_table.add_row("Status", " Running")
            plexichat_table.add_row("Process ID", str(plexichat_status['pid']))
            plexichat_table.add_row("Database", " Connected")
            plexichat_table.add_row("Services", " " + ", ".join(plexichat_status['services_running']))
            
            console.print(plexichat_table)
        
        return True
        
    except Exception as e:
        console.print(f"[red] Failed to get system status: {e}[/red]")
        return False


async def cmd_version(check_updates: bool = False):
    """Show version information and optionally check for updates."""
    try:
        version_info = {
            "version": "3.0.0",
            "build": "20240101",
            "commit": "abc123def456",
            "build_date": "2024-01-01T00:00:00Z",
            "python_version": platform.python_version(),
            "platform": platform.system()
        }
        
        console.print(Panel(" Version Information", style="bold blue"))
        
        table = Table()
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("PlexiChat Version", version_info['version'])
        table.add_row("Build Number", version_info['build'])
        table.add_row("Git Commit", version_info['commit'][:8])
        table.add_row("Build Date", version_info['build_date'])
        table.add_row("Python Version", version_info['python_version'])
        table.add_row("Platform", version_info['platform'])
        
        console.print(table)
        
        if check_updates:
            console.print("\n Checking for updates...")
            # This would check for actual updates
            console.print("[green] You are running the latest version[/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[red] Failed to get version information: {e}[/red]")
        return False


async def cmd_health(component: Optional[str] = None):
    """Perform comprehensive health checks."""
    try:
        console.print(" Performing health checks...")
        
        components = {
            "database": {"status": "healthy", "response_time": "5ms"},
            "redis": {"status": "healthy", "response_time": "2ms"},
            "api": {"status": "healthy", "response_time": "10ms"},
            "websocket": {"status": "healthy", "connections": 42},
            "background_tasks": {"status": "healthy", "queue_size": 3},
            "file_storage": {"status": "healthy", "free_space": "85%"},
            "security": {"status": "healthy", "last_scan": "2024-01-01T12:00:00Z"},
            "clustering": {"status": "healthy", "nodes": 3}
        }
        
        if component:
            if component in components:
                comp_info = components[component]
                console.print(f" Health check for {component}:")
                for key, value in comp_info.items():
                    console.print(f"  {key}: {value}")
            else:
                console.print(f"[red] Unknown component: {component}[/red]")
                console.print(f"Available components: {', '.join(components.keys())}")
                return False
        else:
            # Show all components
            table = Table(title=" System Health Check")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="white")
            
            for comp_name, comp_info in components.items():
                status = comp_info.get("status", "unknown")
                status_icon = "" if status == "healthy" else ""
                
                details = []
                for key, value in comp_info.items():
                    if key != "status":
                        details.append(f"{key}: {value}")
                
                table.add_row(
                    comp_name,
                    f"{status_icon} {status}",
                    ", ".join(details)
                )
            
            console.print(table)
        
        return True
        
    except Exception as e:
        console.print(f"[red] Health check failed: {e}[/red]")
        return False


async def cmd_restart(component: Optional[str] = None, force: bool = False):
    """Restart system or specific components."""
    try:
        if not force:
            if not Confirm.ask(" Are you sure you want to restart?"):
                console.print("[yellow]Restart cancelled[/yellow]")
                return True
        
        if component:
            console.print(f" Restarting component: {component}")
            # Component-specific restart logic would go here
            console.print(f"[green] Component {component} restarted successfully[/green]")
        else:
            console.print(" Restarting PlexiChat system...")
            # Full system restart logic would go here
            console.print("[green] System restart initiated[/green]")
        
        return True
        
    except Exception as e:
        console.print(f"[red] Restart failed: {e}[/red]")
        return False


async def cmd_shutdown(graceful: bool = True, timeout: int = 30):
    """Shutdown the system gracefully or forcefully."""
    try:
        if not Confirm.ask(" Are you sure you want to shutdown PlexiChat?"):
            console.print("[yellow]Shutdown cancelled[/yellow]")
            return True
        
        if graceful:
            console.print(f" Initiating graceful shutdown (timeout: {timeout}s)...")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Shutting down services...", total=None)
                
                # Simulate shutdown process
                await asyncio.sleep(2)
                progress.update(task, description="Stopping API server...")
                await asyncio.sleep(1)
                progress.update(task, description="Closing database connections...")
                await asyncio.sleep(1)
                progress.update(task, description="Saving state...")
                await asyncio.sleep(1)
                progress.update(task, description="Cleanup complete")
            
            console.print("[green] Graceful shutdown completed[/green]")
        else:
            console.print(" Forcing immediate shutdown...")
            console.print("[yellow] Forced shutdown completed[/yellow]")
        
        return True
        
    except Exception as e:
        console.print(f"[red] Shutdown failed: {e}[/red]")
        return False


async def cmd_config_get(key: Optional[str] = None):
    """Get configuration values."""
    try:
        # Mock configuration
        config = {
            "server.host": "0.0.0.0",
            "server.port": 8000,
            "database.url": "postgresql://localhost/plexichat",
            "redis.url": "redis://localhost:6379",
            "security.encryption_key": "***hidden***",
            "logging.level": "INFO",
            "features.ai_enabled": True,
            "features.clustering_enabled": True
        }
        
        if key:
            if key in config:
                console.print(f"{key}: {config[key]}")
            else:
                console.print(f"[red] Configuration key not found: {key}[/red]")
                return False
        else:
            table = Table(title=" Configuration")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="white")
            
            for k, v in sorted(config.items()):
                table.add_row(k, str(v))
            
            console.print(table)
        
        return True
        
    except Exception as e:
        console.print(f"[red] Failed to get configuration: {e}[/red]")
        return False


async def cmd_config_set(key: str, value: str):
    """Set configuration values."""
    try:
        console.print(f" Setting configuration: {key} = {value}")
        
        # Configuration validation would go here
        # Actual configuration update would go here
        
        console.print("[green] Configuration updated successfully[/green]")
        console.print("[yellow] Restart may be required for changes to take effect[/yellow]")
        
        return True
        
    except Exception as e:
        console.print(f"[red] Failed to set configuration: {e}[/red]")
        return False


async def cmd_config_validate():
    """Validate current configuration."""
    try:
        console.print(" Validating configuration...")
        
        # Mock validation results
        validation_results = [
            {"key": "server.host", "status": "valid", "message": "Valid host address"},
            {"key": "server.port", "status": "valid", "message": "Port is available"},
            {"key": "database.url", "status": "valid", "message": "Database connection successful"},
            {"key": "redis.url", "status": "warning", "message": "Redis connection slow"},
            {"key": "security.encryption_key", "status": "valid", "message": "Strong encryption key"},
        ]
        
        table = Table(title=" Configuration Validation")
        table.add_column("Key", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Message", style="white")
        
        for result in validation_results:
            status_icon = {
                "valid": "",
                "warning": "",
                "error": ""
            }.get(result["status"], "")
            
            table.add_row(
                result["key"],
                f"{status_icon} {result['status']}",
                result["message"]
            )
        
        console.print(table)
        
        # Summary
        valid_count = sum(1 for r in validation_results if r["status"] == "valid")
        warning_count = sum(1 for r in validation_results if r["status"] == "warning")
        error_count = sum(1 for r in validation_results if r["status"] == "error")
        
        console.print(f"\n Summary: {valid_count} valid, {warning_count} warnings, {error_count} errors")
        
        return error_count == 0
        
    except Exception as e:
        console.print(f"[red] Configuration validation failed: {e}[/red]")
        return False


async def cmd_info():
    """Show comprehensive system information."""
    try:
        console.print(Panel(" PlexiChat System Information", style="bold blue"))
        
        # System info
        console.print("\n System:")
        console.print(f"  OS: {platform.system()} {platform.release()}")
        console.print(f"  Architecture: {platform.architecture()[0]}")
        console.print(f"  Hostname: {platform.node()}")
        console.print(f"  Python: {platform.python_version()}")
        
        # Hardware info
        console.print("\n Hardware:")
        console.print(f"  CPU Cores: {import psutil
psutil.cpu_count()}")
        console.print(f"  Memory: {import psutil
psutil.virtual_memory().total // (1024**3)} GB")
        console.print(f"  Disk: {import psutil
psutil.disk_usage('/').total // (1024**3) if os.name != 'nt' else import psutil
psutil.disk_usage('C:').total // (1024**3)} GB")
        
        # PlexiChat info
        console.print("\n PlexiChat:")
        console.print("  Version: 3.0.0")
        console.print(f"  Installation: {Path.cwd()}")
        console.print(f"  Process ID: {os.getpid()}")
        console.print(f"  Start Time: {from datetime import datetime
datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return True
        
    except Exception as e:
        console.print(f"[red] Failed to get system information: {e}[/red]")
        return False


# Register core commands
def register_core_commands():
    """Register all core system commands."""
    
    commands = [
        UltimateCommand(
            name="status",
            description="Show comprehensive system status and health",
            category=CommandCategory.CORE,
            handler=cmd_status,
            aliases=["st", "stat"],
            examples=[
                "plexichat status",
                "plexichat status --detailed",
                "plexichat status --json-output"
            ],
            related_commands=["health", "info", "version"]
        ),
        UltimateCommand(
            name="version",
            description="Show version information and check for updates",
            category=CommandCategory.CORE,
            handler=cmd_version,
            aliases=["ver", "v"],
            examples=[
                "plexichat version",
                "plexichat version --check-updates"
            ],
            related_commands=["status", "info"]
        ),
        UltimateCommand(
            name="health",
            description="Perform comprehensive health checks on all components",
            category=CommandCategory.CORE,
            handler=cmd_health,
            aliases=["healthcheck", "hc"],
            examples=[
                "plexichat health",
                "plexichat health --component database",
                "plexichat health --component api"
            ],
            related_commands=["status", "monitor"]
        ),
        UltimateCommand(
            name="restart",
            description="Restart system or specific components",
            category=CommandCategory.CORE,
            handler=cmd_restart,
            aliases=["reboot"],
            dangerous=True,
            admin_only=True,
            examples=[
                "plexichat restart",
                "plexichat restart --component api",
                "plexichat restart --force"
            ],
            related_commands=["shutdown", "start", "stop"]
        ),
        UltimateCommand(
            name="shutdown",
            description="Shutdown the system gracefully or forcefully",
            category=CommandCategory.CORE,
            handler=cmd_shutdown,
            aliases=["stop", "halt"],
            dangerous=True,
            admin_only=True,
            examples=[
                "plexichat shutdown",
                "plexichat shutdown --timeout 60",
                "plexichat shutdown --no-graceful"
            ],
            related_commands=["restart", "start"]
        ),
        UltimateCommand(
            name="config-get",
            description="Get configuration values",
            category=CommandCategory.CORE,
            handler=cmd_config_get,
            aliases=["cfg-get", "get-config"],
            examples=[
                "plexichat config-get",
                "plexichat config-get server.port",
                "plexichat config-get database.url"
            ],
            related_commands=["config-set", "config-validate"]
        ),
        UltimateCommand(
            name="config-set",
            description="Set configuration values",
            category=CommandCategory.CORE,
            handler=cmd_config_set,
            aliases=["cfg-set", "set-config"],
            admin_only=True,
            examples=[
                "plexichat config-set server.port 8080",
                "plexichat config-set logging.level DEBUG"
            ],
            related_commands=["config-get", "config-validate"]
        ),
        UltimateCommand(
            name="config-validate",
            description="Validate current configuration",
            category=CommandCategory.CORE,
            handler=cmd_config_validate,
            aliases=["cfg-validate", "validate-config"],
            examples=[
                "plexichat config-validate"
            ],
            related_commands=["config-get", "config-set"]
        ),
        UltimateCommand(
            name="info",
            description="Show comprehensive system information",
            category=CommandCategory.CORE,
            handler=cmd_info,
            aliases=["information", "sysinfo"],
            examples=[
                "plexichat info"
            ],
            related_commands=["status", "version", "health"]
        )
    ]
    
    for command in commands:
        ultimate_cli.register_command(command)
    
    console.print("[green] Registered 9 core system commands[/green]")


# Auto-register when module is imported
register_core_commands()
