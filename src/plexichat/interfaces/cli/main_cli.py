"""
PlexiChat Main CLI

Command-line interface with threading and performance optimization.
"""

import asyncio
import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional

try:
    import click
except ImportError:
    click = None

try:
    import rich
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
    from rich.panel import Panel
except ImportError:
    rich = None
    Console = None
    Table = None
    Progress = None
    Panel = None

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

try:
    from plexichat.core.analytics.analytics_manager import analytics_manager, track_event
except ImportError:
    analytics_manager = None
    track_event = None

try:
    from plexichat.interfaces.cli.commands.tests import handle_test_command
except ImportError:
    handle_test_command = None

# Import CLI command groups
try:
    from plexichat.interfaces.cli.commands.admin import admin
    from plexichat.interfaces.cli.commands.backup import backup
    from plexichat.interfaces.cli.commands.system import system
    from plexichat.interfaces.cli.commands.security import security
    from plexichat.interfaces.cli.commands.database import database
    from plexichat.interfaces.cli.commands.plugins import plugins
    from plexichat.interfaces.cli.commands.ai import ai
    from plexichat.interfaces.cli.commands.logs import logs
    from plexichat.interfaces.cli.commands.updates import updates
except ImportError as e:
    # Individual command imports may fail, that's ok
    pass

try:
    from plexichat.core.security.security_manager import security_manager, hash_password
except ImportError:
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

            # Initialize components
            if database_manager:
                asyncio.run(database_manager.initialize())
                print_message("Database initialized", "success")

            if message_processor:
                asyncio.run(message_processor.start_processing())
                print_message("Message processor started", "success")

            if analytics_manager:
                asyncio.run(analytics_manager.start_processing())
                print_message("Analytics manager started", "success")

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

            # Stop components
            if message_processor:
                asyncio.run(message_processor.stop_processing())
                print_message("Message processor stopped", "success")

            if analytics_manager:
                asyncio.run(analytics_manager.stop_processing())
                print_message("Analytics manager stopped", "success")

            if thread_manager:
                thread_manager.shutdown(wait=True)
                print_message("Thread manager stopped", "success")

            print_message("Server stopped successfully", "success")

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
    def database():
        """Database management commands."""
        pass

    @database.command()
    def init():
        """Initialize the database."""
        try:
            print_message("Initializing database...", "info")

            if database_manager:
                asyncio.run(database_manager.initialize())
                print_message("Database initialized successfully", "success")
            else:
                print_message("Database manager not available", "error")

        except Exception as e:
            print_message(f"Database initialization failed: {e}", "error")
            sys.exit(1)

    @database.command()
    def stats():
        """Show database statistics."""
        try:
            if database_manager:
                stats = database_manager.get_stats()

                stats_data = [
                    {"Metric": "Queries Executed", "Value": stats["queries_executed"]},
                    {"Metric": "Queries Failed", "Value": stats["queries_failed"]},
                    {"Metric": "Total Execution Time", "Value": f"{stats['total_execution_time']:.2f}s"},
                    {"Metric": "Average Execution Time", "Value": f"{stats['average_execution_time']:.4f}s"},
                    {"Metric": "Connection Pool Size", "Value": stats["connection_pool_size"]},
                ]

                print_table(stats_data, "Database Statistics")
            else:
                print_message("Database manager not available", "error")

        except Exception as e:
            print_message(f"Error getting database stats: {e}", "error")

    @cli.group()
    def users():
        """User management commands."""
        pass

    @users.command()
    @click.argument('username')
    @click.argument('email')
    @click.argument('password')
    def create(username: str, email: str, password: str):
        """Create a new user."""
        try:
            print_message(f"Creating user: {username}", "info")

            # Hash password
            if hash_password:
                password_hash = hash_password(password)
            else:
                password_hash = password

            # Create user (threaded)
            if submit_task:
                task_id = f"create_user_{username}_{int(time.time())}"
                submit_task(task_id, _create_user_sync, username, email, password_hash)

                if Progress:
                    with Progress() as progress:
                        task = progress.add_task("Creating user...", total=100)

                        for i in range(100):
                            time.sleep(0.01)
                            progress.update(task, advance=1)

                success = get_task_result(task_id, timeout=10.0)

                if success:
                    print_message(f"User '{username}' created successfully", "success")
                else:
                    print_message("User creation failed", "error")
            else:
                print_message("Threading not available", "error")

        except Exception as e:
            print_message(f"Error creating user: {e}", "error")

    @users.command()
    @click.argument('username')
    def delete(username: str):
        """Delete a user."""
        try:
            # Confirm deletion
            if click.confirm(f"Are you sure you want to delete user '{username}'?"):
                print_message(f"Deleting user: {username}", "info")

                # Delete user (threaded)
                if submit_task:
                    task_id = f"delete_user_{username}_{int(time.time())}"
                    submit_task(task_id, _delete_user_sync, username)
                    success = get_task_result(task_id, timeout=10.0)

                    if success:
                        print_message(f"User '{username}' deleted successfully", "success")
                    else:
                        print_message("User deletion failed", "error")
                else:
                    print_message("Threading not available", "error")
            else:
                print_message("User deletion cancelled", "info")

        except Exception as e:
            print_message(f"Error deleting user: {e}", "error")

    @users.command()
    def list():
        """List all users."""
        try:
            print_message("Fetching users...", "info")

            # Get users (threaded)
            if submit_task:
                task_id = f"list_users_{int(time.time())}"
                submit_task(task_id, _list_users_sync)
                users_data = get_task_result(task_id, timeout=10.0)

                if users_data:
                    print_table(users_data, "Users")
                else:
                    print_message("No users found", "warning")
            else:
                print_message("Threading not available", "error")

        except Exception as e:
            print_message(f"Error listing users: {e}", "error")

    @cli.group()
    def analytics():
        """Analytics commands."""
        pass

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
    def list():
        """List available test categories."""
        try:
            if handle_test_command:
                asyncio.run(handle_test_command(['list']))
            else:
                print_message("Test system not available", "error")
        except Exception as e:
            print_message(f"Error listing test categories: {e}", "error")

    @test.command()
    def config():
        """Show test configuration."""
        try:
            if handle_test_command:
                asyncio.run(handle_test_command(['config']))
            else:
                print_message("Test system not available", "error")
        except Exception as e:
            print_message(f"Error showing test config: {e}", "error")

    @test.command()
    def validate():
        """Validate test environment."""
        try:
            if handle_test_command:
                asyncio.run(handle_test_command(['validate']))
            else:
                print_message("Test system not available", "error")
        except Exception as e:
            print_message(f"Error validating test environment: {e}", "error")

    @analytics.command()
    @click.option('--days', default=7, help='Number of days to analyze')
    def report(days: int):
        """Generate analytics report."""
        try:
            print_message(f"Generating analytics report for last {days} days...", "info")

            if analytics_manager:
                # Get analytics data (threaded)
                if submit_task:
                    task_id = f"analytics_report_{int(time.time())}"
                    submit_task(task_id, _get_analytics_report_sync, days)
                    report_data = get_task_result(task_id, timeout=15.0)

                    if report_data:
                        print_table(report_data, f"Analytics Report ({days} days)")
                    else:
                        print_message("No analytics data available", "warning")
                else:
                    print_message("Threading not available", "error")
            else:
                print_message("Analytics manager not available", "error")

        except Exception as e:
            print_message(f"Error generating report: {e}", "error")

    # Add external command groups
    try:
        cli.add_command(admin)
        cli.add_command(backup)
        cli.add_command(system)
        cli.add_command(security)
        cli.add_command(plugins)
        cli.add_command(ai)
        cli.add_command(logs)
        cli.add_command(updates)
    except NameError:
        # Commands not available, skip
        pass

    @cli.command()
    def version():
        """Show version information."""
        version_info = {
            "PlexiChat": "1.0.0",
            "Python": sys.version.split()[0],
            "Platform": sys.platform
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
    def cli():
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

# Helper functions for threading
def _create_user_sync(username: str, email: str, password_hash: str) -> bool:
    """Create user synchronously."""
    try:
        # Placeholder implementation
        time.sleep(1)  # Simulate work
        return True
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

def _delete_user_sync(username: str) -> bool:
    """Delete user synchronously."""
    try:
        # Placeholder implementation
        time.sleep(0.5)  # Simulate work
        return True
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False

def _list_users_sync() -> List[Dict[str, Any]]:
    """List users synchronously."""
    try:
        # Placeholder implementation
        time.sleep(0.5)  # Simulate work
        return [
            {"ID": 1, "Username": "admin", "Email": "admin@example.com", "Active": True},
            {"ID": 2, "Username": "user1", "Email": "user1@example.com", "Active": True},
        ]
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        return []

def _get_analytics_report_sync(days: int) -> List[Dict[str, Any]]:
    """Get analytics report synchronously."""
    try:
        # Placeholder implementation
        time.sleep(1)  # Simulate work
        return [
            {"Event Type": "user_login", "Count": 150, "Percentage": "45%"},
            {"Event Type": "message_sent", "Count": 120, "Percentage": "36%"},
            {"Event Type": "file_upload", "Count": 63, "Percentage": "19%"},
        ]
    except Exception as e:
        logger.error(f"Error getting analytics report: {e}")
        return []

# Main entry point
def main():
    """Main CLI entry point."""
    try:
        if click:
            cli()
        else:
            cli()
    except KeyboardInterrupt:
        print_message("\nOperation cancelled by user", "warning")
        sys.exit(0)
    except Exception as e:
        print_message(f"Unexpected error: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
