"""
PlexiChat Main CLI

Command-line interface with threading and performance optimization.
"""

import asyncio
import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Union
from pathlib import Path

try:
    import click
except ImportError:
    click = None

try:
    import rich
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.prompt import Prompt
except ImportError:
    rich = None
    Console = None
    Table = None
    Progress = None
    Panel = None
    Prompt = None

try:
    from plexichat.core.plugins.unified_plugin_manager import unified_plugin_manager
except ImportError:
    unified_plugin_manager = None

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import thread_manager, submit_task, get_task_result
except ImportError:
    thread_manager = None
    submit_task = None
    get_task_result = None

try:
    from plexichat.core.messaging.message_processor import message_processor, queue_message
except ImportError:
    message_processor = None
    queue_message = None

# Analytics manager is optional
analytics_manager = None
track_event = None

try:
    from plexichat.interfaces.cli.commands.tests import handle_test_command
except ImportError:
    handle_test_command = None

# Import CLI command groups
# Import CLI commands with fallbacks
admin_cmd: Optional[Any] = None
backup_cmd: Optional[Any] = None
system_cmd: Optional[Any] = None
security_cmd: Optional[Any] = None
database_cmd: Optional[Any] = None
plugins_cmd: Optional[Any] = None
ai_cmd: Optional[Any] = None
logs_cmd: Optional[Any] = None
updates_cmd: Optional[Any] = None

try:
    from plexichat.interfaces.cli.commands.admin import admin as admin_cmd
except ImportError:
    pass

try:
    from plexichat.interfaces.cli.commands.backup import backup as backup_cmd
except ImportError:
    pass

try:
    from plexichat.interfaces.cli.commands.system import system as system_cmd
except ImportError:
    pass

# Security manager is optional
security_manager = None
hash_password = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

# Initialize console
if Console:
    console = Console()
else:
    console = None

def print_message(message: str, style: str = "info"):
    """Print message with styling."""
    if console:
        if style == "error":
            console.print(f"[red]ERROR:[/red] {message}")
        elif style == "warning":
            console.print(f"[yellow]WARNING:[/yellow] {message}")
        elif style == "success":
            console.print(f"[green]SUCCESS:[/green] {message}")
        else:
            console.print(f"[blue]INFO:[/blue] {message}")
    else:
        print(f"{style.upper()}: {message}")

def print_table(data: List[Dict[str, Any]], title: str = "Results"):
    """Print data as table."""
    if not data:
        print_message("No data to display", "warning")
        return

    if console and Table:
        table = Table(title=title)

        # Add columns
        for key in data[0].keys():
            table.add_column(str(key).title())

        # Add rows
        for row in data:
            table.add_row(*[str(value) for value in row.values()])

        console.print(table)
    else:
        # Fallback to simple print
        print(f"\n{title}:")
        for i, row in enumerate(data):
            print(f"{i+1}. {row}")

async def initialize_cli():
    """Initialize CLI components."""
    try:
        # Initialize plugin manager
        if unified_plugin_manager:
            await unified_plugin_manager.initialize()
            print_message("Plugin manager initialized", "success")

        # Initialize database
        if database_manager:
            await database_manager.initialize()
            print_message("Database initialized", "success")

        # Initialize message processor
        if message_processor:
            await message_processor.start_processing()
            print_message("Message processor started", "success")

        # Initialize analytics (currently not available)
        # if analytics_manager and hasattr(analytics_manager, 'start_processing'):
        #     await analytics_manager.start_processing()
        #     print_message("Analytics manager started", "success")

        return True
    except Exception as e:
        print_message(f"Failed to initialize CLI: {e}", "error")
        return False

async def shutdown_cli():
    """Shutdown CLI components."""
    try:
        # Shutdown plugin manager
        if unified_plugin_manager:
            await unified_plugin_manager.shutdown()
            print_message("Plugin manager shut down", "success")

        # Shutdown message processor
        if message_processor:
            await message_processor.stop_processing()
            print_message("Message processor stopped", "success")

        # Shutdown analytics (currently not available)
        # if analytics_manager and hasattr(analytics_manager, 'stop_processing'):
        #     await analytics_manager.stop_processing()
        #     print_message("Analytics manager stopped", "success")

        # Shutdown thread manager
        if thread_manager:
            thread_manager.shutdown(wait=True)
            print_message("Thread manager stopped", "success")

        print_message("CLI shutdown complete", "success")
    except Exception as e:
        print_message(f"Error during CLI shutdown: {e}", "error")

# CLI Commands
if click:
    @click.group()
    @click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
    @click.option('--config', '-c', help='Configuration file path')
    def cli(verbose: bool, config: Optional[str]):
        """PlexiChat CLI - Manage your PlexiChat instance."""
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        # Initialize CLI
        if not asyncio.run(initialize_cli()):
            sys.exit(1)

        print_message("PlexiChat CLI initialized", "success")

    @cli.group()
    def server():
        """Server management commands."""
        pass

    @server.command()
    @click.option('--host', default='0.0.0.0', help='Host to bind to')
    @click.option('--port', default=8000, help='Port to bind to')
    @click.option('--reload', is_flag=True, help='Enable auto-reload')
    def start(host: str, port: int, reload: bool):
        """Start the PlexiChat server."""
        try:
            print_message(f"Starting PlexiChat server on {host}:{port}", "info")

            # Start server
            from plexichat.interfaces.api.main_api import run_server
            run_server(host=host, port=port, reload=reload)

        except Exception as e:
            print_message(f"Failed to start server: {e}", "error")
            sys.exit(1)

    @server.command()
    def stop():
        """Stop the PlexiChat server."""
        try:
            print_message("Stopping PlexiChat server...", "info")
            asyncio.run(shutdown_cli())
        except Exception as e:
            print_message(f"Error stopping server: {e}", "error")

    @server.command()
    def status():
        """Show server status."""
        try:
            print_message("Checking server status...", "info")

            status_data = []

            # Check database
            if database_manager:
                try:
                    asyncio.run(database_manager.execute_query("SELECT 1"))
                    status_data.append({"Component": "Database", "Status": "Healthy"})
                except Exception:
                    status_data.append({"Component": "Database", "Status": "Unhealthy"})
            else:
                status_data.append({"Component": "Database", "Status": "Not Available"})

            # Check plugin manager
            if unified_plugin_manager:
                plugin_stats = unified_plugin_manager.get_stats()
                status_data.append({
                    "Component": "Plugin Manager",
                    "Status": f"Active ({plugin_stats['total_loaded']} plugins loaded)"
                })
            else:
                status_data.append({"Component": "Plugin Manager", "Status": "Not Available"})

            # Check thread manager
            if thread_manager:
                thread_status = thread_manager.get_status()
                status = "Healthy" if not thread_status["shutdown"] else "Stopped"
                status_data.append({"Component": "Thread Manager", "Status": status})
            else:
                status_data.append({"Component": "Thread Manager", "Status": "Not Available"})

            # Check message processor
            if message_processor:
                processor_status = message_processor.get_status()
                status = "Running" if processor_status["processing"] else "Stopped"
                status_data.append({"Component": "Message Processor", "Status": status})
            else:
                status_data.append({"Component": "Message Processor", "Status": "Not Available"})

            print_table(status_data, "Server Status")

        except Exception as e:
            print_message(f"Error checking status: {e}", "error")

    @cli.group()
    def plugins():
        """Plugin management commands."""
        pass

    @plugins.command()
    def list_plugins():
        """List all plugins."""
        try:
            if unified_plugin_manager:
                plugins_info = unified_plugin_manager.get_all_plugins_info()
                plugins_data = [
                    {
                        "Name": info["metadata"]["name"],
                        "Version": info["metadata"]["version"],
                        "Status": info["status"],
                        "Type": info["metadata"]["type"]
                    }
                    for info in plugins_info.values()
                ]
                print_table(plugins_data, "Installed Plugins")
            else:
                print_message("Plugin manager not available", "error")
        except Exception as e:
            print_message(f"Error listing plugins: {e}", "error")

    @plugins.command()
    @click.argument('plugin_name')
    def enable(plugin_name: str):
        """Enable a plugin."""
        try:
            if unified_plugin_manager:
                success = asyncio.run(unified_plugin_manager.enable_plugin(plugin_name))
                if success:
                    print_message(f"Plugin '{plugin_name}' enabled successfully", "success")
                else:
                    print_message(f"Failed to enable plugin '{plugin_name}'", "error")
            else:
                print_message("Plugin manager not available", "error")
        except Exception as e:
            print_message(f"Error enabling plugin: {e}", "error")

    @plugins.command()
    @click.argument('plugin_name')
    def disable(plugin_name: str):
        """Disable a plugin."""
        try:
            if unified_plugin_manager:
                success = asyncio.run(unified_plugin_manager.disable_plugin(plugin_name))
                if success:
                    print_message(f"Plugin '{plugin_name}' disabled successfully", "success")
                else:
                    print_message(f"Failed to disable plugin '{plugin_name}'", "error")
            else:
                print_message("Plugin manager not available", "error")
        except Exception as e:
            print_message(f"Error disabling plugin: {e}", "error")

    @plugins.command()
    @click.argument('plugin_name')
    def info(plugin_name: str):
        """Show plugin information."""
        try:
            if unified_plugin_manager:
                plugin_info = unified_plugin_manager.get_plugin_info(plugin_name)
                if plugin_info:
                    # Get plugin metrics
                    metrics = unified_plugin_manager.get_plugin_metrics(plugin_name)
                    errors = unified_plugin_manager.get_plugin_errors(plugin_name)

                    # Combine information
                    info_data = [
                        {"Property": "Name", "Value": plugin_info["metadata"]["name"]},
                        {"Property": "Version", "Value": plugin_info["metadata"]["version"]},
                        {"Property": "Author", "Value": plugin_info["metadata"]["author"]},
                        {"Property": "Status", "Value": plugin_info["status"]},
                        {"Property": "Type", "Value": plugin_info["metadata"]["type"]},
                        {"Property": "Load Time", "Value": f"{metrics.get(plugin_name, {}).get('load_time', 0):.2f}s"},
                        {"Property": "Memory Usage", "Value": f"{metrics.get(plugin_name, {}).get('memory_usage', 0):.1f}MB"},
                        {"Property": "Components", "Value": metrics.get(plugin_name, {}).get('component_count', 0)},
                        {"Property": "Errors", "Value": len(errors.get(plugin_name, []))}
                    ]

                    print_table(info_data, f"Plugin Information: {plugin_name}")

                    # Show errors if any
                    if plugin_name in errors and errors[plugin_name]:
                        print_message("\nPlugin Errors:", "error")
                        for error in errors[plugin_name]:
                            print_message(f"  - {error}", "error")
                else:
                    print_message(f"Plugin '{plugin_name}' not found", "error")
            else:
                print_message("Plugin manager not available", "error")
        except Exception as e:
            print_message(f"Error getting plugin info: {e}", "error")

    @plugins.command()
    def graph():
        """Show plugin dependency graph."""
        try:
            if unified_plugin_manager:
                graph = unified_plugin_manager.get_dependency_graph()
                if graph:
                    graph_data = [
                        {"Plugin": plugin, "Dependencies": ", ".join(deps) or "None"}
                        for plugin, deps in graph.items()
                    ]
                    print_table(graph_data, "Plugin Dependencies")
                else:
                    print_message("No plugin dependencies found", "info")
            else:
                print_message("Plugin manager not available", "error")
        except Exception as e:
            print_message(f"Error getting dependency graph: {e}", "error")

    @cli.group()
    def test():
        """Test execution commands."""
        pass

    @test.command()
    @click.argument('categories', nargs=-1)
    @click.option('--quick', is_flag=True, help='Run quick smoke tests')
    @click.option('--no-save', is_flag=True, help='Do not save test report')
    @click.option('--quiet', is_flag=True, help='Reduce output verbosity')
    def run(categories, quick, no_save, quiet):
        """Run tests (all or specific categories)."""
        try:
            if handle_test_command:
                if quick:
                    asyncio.run(handle_test_command(['quick']))
                elif categories:
                    asyncio.run(handle_test_command(['run'] + list(categories)))
                else:
                    asyncio.run(handle_test_command(['run', 'all']))
            else:
                print_message("Test system not available", "error")
        except Exception as e:
            print_message(f"Error running tests: {e}", "error")

    @test.command()
    def list_tests():
        """List available test categories."""
        try:
            if handle_test_command:
                asyncio.run(handle_test_command(['list']))
            else:
                print_message("Test system not available", "error")
        except Exception as e:
            print_message(f"Error listing test categories: {e}", "error")

    @cli.command()
    def version():
        """Show version information."""
        version_info = {
            "PlexiChat": "1.0.0",
            "Python": sys.version.split()[0],
            "Platform": sys.platform,
            "Plugins": unified_plugin_manager.get_stats()["total_loaded"] if unified_plugin_manager else 0
        }

        if console and Panel:
            content = "\n".join([f"{k}: {v}" for k, v in version_info.items()])
            panel = Panel(content, title="Version Information", border_style="blue")
            console.print(panel)
        else:
            print("\nVersion Information:")
            for k, v in version_info.items():
                print(f"  {k}: {v}")

else:
    # Fallback CLI without click
    def cli_fallback():
        """Fallback CLI without click."""
        print("PlexiChat CLI")
        print("Click library not available - limited functionality")

        if len(sys.argv) > 1:
            command = sys.argv[1]

            if command == "version":
                print(f"PlexiChat version 1.0.0")
            elif command == "status":
                print("Checking status...")
                # Basic status check
            else:
                print(f"Unknown command: {command}")
        else:
            print("Available commands: version, status")

# Main entry point
def main():
    """Main CLI entry point with enhanced CLI integration."""
    try:
        # Try enhanced CLI first if available
        try:
            from .enhanced_cli import enhanced_cli

            # If no additional arguments, show enhanced help
            if len(sys.argv) <= 1:
                enhanced_cli.show_help()
                return

            # Get command and arguments
            command = sys.argv[1] if len(sys.argv) > 1 else "help"
            args = sys.argv[2:] if len(sys.argv) > 2 else []

            # Run the enhanced CLI
            success = asyncio.run(enhanced_cli.execute_command(command, args))
            if not success:
                sys.exit(1)
            return

        except ImportError:
            # Fallback to original CLI system
            print_message("Enhanced CLI not available, using standard CLI", "info")

        # Original CLI system
        if click:
            cli()
        else:
            cli_fallback()

    except KeyboardInterrupt:
        print_message("\nOperation cancelled by user", "warning")
        # Ensure proper shutdown
        asyncio.run(shutdown_cli())
        sys.exit(0)
    except Exception as e:
        print_message(f"Unexpected error: {e}", "error")
        # Attempt cleanup
        try:
            asyncio.run(shutdown_cli())
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
