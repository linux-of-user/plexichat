import asyncio
import csv
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Any

try:
    import typer
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
except ImportError:
    # This will be handled by the main CLI entry point
    pass

logger = logging.getLogger(__name__)
console = Console()

class CommandCategory(Enum):
    """CLI command categories."""
    CORE = "core"
    SYSTEM = "system"
    SECURITY = "security"
    DATABASE = "database"
    PLUGINS = "plugins"
    USERS = "users"
    # ... add other categories as needed

@dataclass
class UltimateCommand:
    """Ultimate CLI command definition."""
    name: str
    description: str
    category: CommandCategory
    handler: Callable
    aliases: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    admin_only: bool = False

class UltimateCLICoordinator:
    """Coordinates all commands for the Ultimate CLI."""

    def __init__(self):
        self.commands: Dict[str, UltimateCommand] = {}
        self.categories: Dict[CommandCategory, List[str]] = {cat: [] for cat in CommandCategory}
        self.aliases: Dict[str, str] = {}
        self.stats = {"total_commands": 0, "commands_by_category": {}}

    def register_command(self, command: UltimateCommand):
        """Register a new ultimate command."""
        self.commands[command.name] = command
        self.categories[command.category].append(command.name)
        for alias in command.aliases:
            self.aliases[alias] = command.name
        self._update_stats()

    def get_command(self, name: str) -> Optional[UltimateCommand]:
        """Get command by name or alias."""
        if name in self.commands:
            return self.commands[name]
        return self.commands.get(self.aliases.get(name))

    def list_commands(self, category_filter: Optional[str] = None):
        """Prints a list of commands, optionally filtered by category."""
        table = Table(title="PlexiChat Ultimate Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Category", style="magenta")
        table.add_column("Description", style="green")

        for cmd in sorted(self.commands.values(), key=lambda c: (c.category.value, c.name)):
            if not category_filter or cmd.category.value == category_filter:
                table.add_row(cmd.name, cmd.category.value, cmd.description)

        console.print(table)

    def get_category_description(self, category: CommandCategory) -> str:
        """Returns a brief description for a command category."""
        descriptions = {
            CommandCategory.CORE: "Core functionalities of the application.",
            CommandCategory.SYSTEM: "System-level commands and management.",
            CommandCategory.SECURITY: "Security-related commands.",
            # ... add other descriptions
        }
        return descriptions.get(category, "No description available.")

    def show_command_help(self, command_name: str):
        """Shows detailed help for a specific command."""
        command = self.get_command(command_name)
        if not command:
            console.print(f"[bold red]Error: Command '{command_name}' not found.[/bold red]")
            return

        panel_content = f"[bold]{command.name}[/bold]\n[dim]{command.description}[/dim]\n\n"
        if command.aliases:
            panel_content += f"[bold]Aliases:[/] {', '.join(command.aliases)}\n"
        if command.examples:
            panel_content += "[bold]Examples:[/]\n" + "\n".join(f"  {ex}" for ex in command.examples)

        console.print(Panel(panel_content, title="Command Help", border_style="blue"))

    async def execute_command(self, command_name: str, *args, **kwargs) -> Any:
        """Executes a registered command."""
        command = self.get_command(command_name)
        if not command:
            console.print(f"[bold red]Error: Command '{command_name}' not found.[/bold red]")
            return

        # Placeholder for permission checks
        if command.admin_only:
            console.print("[bold yellow]Warning: This is an admin-only command.[/bold yellow]")

        console.print(f"Executing command: [bold cyan]{command.name}[/bold cyan]")
        try:
            if asyncio.iscoroutinefunction(command.handler):
                return await command.handler(*args, **kwargs)
            else:
                return command.handler(*args, **kwargs)
        except Exception as e:
            console.print(f"[bold red]An error occurred during execution: {e}[/bold red]")
            logger.exception(f"Error executing command '{command_name}'")

    def _update_stats(self):
        """Updates internal statistics about commands."""
        self.stats["total_commands"] = len(self.commands)
        self.stats["commands_by_category"] = {
            cat.value: len(cmds) for cat, cmds in self.categories.items()
        }

    def register_all_commands(self):
        """Registers all commands for the CLI."""
        # This is a placeholder. In a real app, this would import modules
        # that register their own commands.
        self.register_command(UltimateCommand(
            name="status",
            description="Display the system status.",
            category=CommandCategory.CORE,
            handler=lambda: console.print("[green]System is operational.[/green]"),
            aliases=["info"],
            examples=["plexichat status"]
        ))
        self.register_command(UltimateCommand(
            name="config.show",
            description="Show current configuration.",
            category=CommandCategory.SYSTEM,
            handler=lambda: console.print("[yellow]Configuration details would be shown here.[/yellow]"),
            admin_only=True
        ))
        self.register_command(UltimateCommand(
            name="security.scan",
            description="Run a security scan.",
            category=CommandCategory.SECURITY,
            handler=lambda: console.print("[cyan]Running security scan... done.[/cyan]"),
            admin_only=True
        ))

# Singleton instance
ultimate_cli = UltimateCLICoordinator()
