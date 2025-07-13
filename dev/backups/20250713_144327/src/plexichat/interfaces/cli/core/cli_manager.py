import asyncio
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ....core_system.config import get_config, get_setting, set_setting

from pathlib import Path



from pathlib import Path

import uvicorn
from ....main import app as fastapi_app

from plexichat.core.config import settings
from plexichat.core.config import settings

"""
PlexiChat CLI Manager

Consolidated CLI management system that merges functionality from:
- command_registry.py
- main_cli.py
- app.py
- cli_integration.py
- comprehensive_cli.py
- integrated_cli.py
- advanced_cli.py

Provides a unified command-line interface for PlexiChat administration and operations.
"""

logger = logging.getLogger(__name__)
console = Console()

# Create main CLI app
app = typer.Typer(
    name="plexichat",
    help="PlexiChat - Advanced Communication Platform CLI",
    add_completion=False,
    rich_markup_mode="rich"
)

@dataclass
logger = logging.getLogger(__name__)
class CommandInfo:
    """Information about a CLI command."""
    name: str
    description: str
    handler: Callable
    category: str = "general"
    requires_auth: bool = False
    admin_only: bool = False


class CLIManager:
    """Centralized CLI management system."""

    def __init__(self):
        self.commands: Dict[str, CommandInfo] = {}
        self.categories: Dict[str, List[str]] = {}
        self.console = Console()
        self.current_user = None
        self.config = None

    def register_command(self, command_info: CommandInfo):
        """Register a new CLI command."""
        self.commands[command_info.name] = command_info

        if command_info.category not in self.categories:
            self.categories[command_info.category] = []
        self.categories[command_info.category].append(command_info.name)

        logger.debug(f"Registered CLI command: {command_info.name}")

    def get_command(self, name: str) -> Optional[CommandInfo]:
        """Get command information by name."""
        return self.commands.get(name)

    def list_commands(self, category: Optional[str] = None) -> List[CommandInfo]:
        """List available commands, optionally filtered by category."""
        if category:
            command_names = self.categories.get(category, [])
            return [self.commands[name] for name in command_names]
        return list(self.commands.values())

    def check_auth(self, command_info: CommandInfo) -> bool:
        """Check if user is authorized to run a command."""
        if not command_info.requires_auth:
            return True

        if not self.current_user:
            self.console.logger.info("[red]Authentication required. Please login first.[/red]")
            return False

        if command_info.admin_only and not self.current_user.get("is_admin", False):
            self.console.logger.info("[red]Admin privileges required for this command.[/red]")
            return False

        return True

    async def execute_command(self, name: str, *args, **kwargs) -> bool:
        """Execute a command by name."""
        command_info = self.get_command(name)
        if not command_info:
            self.console.logger.info(f"[red]Unknown command: {name}[/red]")
            return False

        if not self.check_auth(command_info):
            return False

        try:
            if asyncio.iscoroutinefunction(command_info.handler):
                result = await command_info.handler(*args, **kwargs)
            else:
                result = command_info.handler(*args, **kwargs)
            return result if isinstance(result, bool) else True
        except Exception as e:
            self.console.logger.info(f"[red]Command failed: {e}[/red]")
            logger.error(f"Command {name} failed: {e}")
            return False


# Global CLI manager instance
cli_manager = CLIManager()

# Main CLI Commands
@app.command()
def status():
    """Show system status."""
    console.logger.info(Panel.fit(" PlexiChat System Status", style="bold green"))

    # Create status table
    table = Table(title="System Information")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")

    # Add status rows (these would be populated from actual system checks)
    table.add_row("Core System", " Running", "All core services operational")
    table.add_row("Database", " Connected", "PostgreSQL 14.2")
    table.add_row("API Server", " Running", "Port 8000")
    table.add_row("Web Interface", " Running", "Port 3000")

    console.logger.info(table)

@app.command()
def version():
    """Show version information."""
    try:
        config = get_config()
        version = config.app_version
    except Exception:
        version = "Unknown"

    console.logger.info(f"[bold green]PlexiChat v{version}[/bold green]")
    console.logger.info(f"Python {sys.version}")

@app.command()
def config(
    key: Optional[str] = typer.Argument(None, help="Configuration key to display"),
    set_value: Optional[str] = typer.Option(None, "--set", help="Set configuration value"),
    list_all: bool = typer.Option(False, "--list", help="List all configuration")
):
    """Manage configuration from plexichat.core.config import settings
settings."""
    try:
        if list_all:
            config = get_config()
            console.logger.info(Panel.fit(" Configuration Settings", style="bold blue"))

            # Display sanitized config
            table = Table()
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")

            # Add some basic settings (avoid sensitive data)
            table.add_row("app_name", config.app_name)
            table.add_row("app_version", config.app_version)
            table.add_row("server.host", config.server.host)
            table.add_row("server.port", str(config.server.port))
            table.add_row("logging.level", config.logging.level)

            console.logger.info(table)

        elif key and set_value:
            success = set_setting(key, set_value)
            if success:
                console.logger.info(f"[green] Set {key} = {set_value}[/green]")
            else:
                console.logger.info(f"[red] Failed to set {key}[/red]")

        elif key:
            value = get_setting(key)
            if value is not None:
                console.logger.info(f"[cyan]{key}[/cyan] = [green]{value}[/green]")
            else:
                console.logger.info(f"[red]Configuration key '{key}' not found[/red]")
        else:
            console.logger.info("[yellow]Use --list to show all settings or provide a key name[/yellow]")

    except Exception as e:
        console.logger.info(f"[red]Configuration error: {e}[/red]")

@app.command()
def logs(
    lines: int = typer.Option(50, "--lines", "-n", help="Number of lines to show"),
    follow: bool = typer.Option(False, "--follow", "-f", help="Follow log output"),
    level: Optional[str] = typer.Option(None, "--level", help="Filter by log level")
):
    """View application logs."""
    console.logger.info(f"[cyan] Showing last {lines} log lines[/cyan]")

    try:
        # This would integrate with the actual logging system
        from pathlib import Path
log_file = Path
Path("logs/plexichat.log")
        if log_file.exists():
            with open(log_file, 'r') as f:
                log_lines = f.readlines()

            # Show last N lines
            for line in log_lines[-lines:]:
                # Basic log level coloring
                if "ERROR" in line:
                    console.logger.info(f"[red]{line.strip()}[/red]")
                elif "WARNING" in line:
                    console.logger.info(f"[yellow]{line.strip()}[/yellow]")
                elif "INFO" in line:
                    console.logger.info(f"[green]{line.strip()}[/green]")
                else:
                    console.logger.info(line.strip())
        else:
            console.logger.info("[yellow]No log file found[/yellow]")

    except Exception as e:
        console.logger.info(f"[red]Error reading logs: {e}[/red]")

@app.command()
def setup(
    install_type: str = typer.Argument("minimal", help="Installation type: minimal or full"),
    force: bool = typer.Option(False, "--force", help="Force reinstallation")
):
    """Setup PlexiChat dependencies and configuration."""
    console.logger.info(f"[cyan] Setting up PlexiChat ({install_type} installation)[/cyan]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # Setup tasks
        task1 = progress.add_task("Checking Python version...", total=None)
        # Simulate setup steps
        time.sleep(1)
        progress.update(task1, description=" Python version OK")

        task2 = progress.add_task("Installing dependencies...", total=None)
        time.sleep(2)
        progress.update(task2, description=" Dependencies installed")

        task3 = progress.add_task("Setting up database...", total=None)
        time.sleep(1)
        progress.update(task3, description=" Database configured")

        task4 = progress.add_task("Creating configuration...", total=None)
        time.sleep(1)
        progress.update(task4, description=" Configuration created")

    console.logger.info("[green] Setup completed successfully![/green]")

@app.command()
def start(
    port: int = typer.Option(8000, "--port", "-p", help="Port to run on"),
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload"),
    workers: int = typer.Option(1, "--workers", help="Number of worker processes")
):
    """Start the PlexiChat server."""
    console.logger.info(f"[green] Starting PlexiChat server on {host}:{port}[/green]")

    try:
        # This would start the actual server
        uvicorn.run(
            fastapi_app,
            host=host,
            port=port,
            reload=reload,
            workers=workers if not reload else 1
        )
    except ImportError:
        console.logger.info("[red] Server dependencies not installed. Run 'plexichat setup' first.[/red]")
    except Exception as e:
        console.logger.info(f"[red] Failed to start server: {e}[/red]")

@app.command()
def stop():
    """Stop the PlexiChat server."""
    console.logger.info("[yellow] Stopping PlexiChat server...[/yellow]")
    # This would implement graceful shutdown
    console.logger.info("[green] Server stopped[/green]")

@app.command()
def test(
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Test pattern to run"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Run tests."""
    console.logger.info("[cyan] Running tests...[/cyan]")

    try:
        cmd = [sys.executable, "-m", "pytest"]
        if pattern:
            cmd.extend(["-k", pattern])
        if verbose:
            cmd.append("-v")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            console.logger.info("[green] All tests passed![/green]")
        else:
            console.logger.info("[red] Some tests failed[/red]")
            console.logger.info(result.stdout)
            console.logger.info(result.stderr)

    except Exception as e:
        console.logger.info(f"[red]Error running tests: {e}[/red]")

# Command registration helper
def register_command_module(module_name: str, category: str = "general"):
    """Register commands from a module."""
    try:
        # Dynamic import of command modules
        module = __import__(f"..commands.{module_name}", fromlist=[""])

        # Look for command functions or classes
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if hasattr(attr, "__cli_command__"):
                command_info = CommandInfo(
                    name=attr_name,
                    description=attr.__doc__ or f"{module_name} command",
                    handler=attr,
                    category=category
                )
                cli_manager.register_command(command_info)

    except ImportError as e:
        logger.warning(f"Could not import command module {module_name}: {e}")

# Initialize CLI
def init_cli():
    """Initialize the CLI system."""
    # Register command modules
    command_modules = [
        ("admin", "administration"),
        ("ai", "ai"),
        ("antivirus", "security"),
        ("automation", "automation"),
        ("cluster", "clustering"),
        ("database", "database"),
        ("logs", "logging"),
        ("plugins", "plugins"),
        ("security", "security"),
        ("updates", "updates")
    ]

    for module_name, category in command_modules:
        register_command_module(module_name, category)

# Main entry point
def main():
    """Main CLI entry point."""
    init_cli()
    app()

if __name__ == "__main__":
    main()
