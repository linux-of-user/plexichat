import sys
import os
from typing import List, Optional

# Add project root to path to allow absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../')))

try:
    from typer import Typer, Argument, Option
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Error: Typer and Rich libraries are required. Please run 'pip install typer rich'.")
    sys.exit(1)

from plexichat.interfaces.cli.ultimate.cli_coordinator import CommandCategory, ultimate_cli

# --- Basic Setup ---
logger = logging.getLogger(__name__)
console = Console()
app = Typer(
    name="plexichat",
    help="PlexiChat Ultimate CLI - 200+ commands for complete system control",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

# --- Command Definitions ---

@app.command()
def help(command: Optional[str] = Argument(None, help="Show help for a specific command.")):
    """Shows help for a command or the main help screen."""
    if command:
        ultimate_cli.show_command_help(command)
    else:
        show_main_help()

@app.command()
def list(category: Optional[str] = Option(None, "--category", "-c", help="Filter by category.")):
    """Lists all available commands, optionally filtered by category."""
    ultimate_cli.list_commands(category)

@app.command()
async def run(command: str, args: List[str] = Argument(None, help="Arguments for the command.")):
    """Executes a plexichat command."""
    await ultimate_cli.execute_command(command, *args)

# --- Helper Functions ---

def show_main_help():
    """Displays the main help screen with categories and examples."""
    console.print(Panel("[bold blue]Welcome to the PlexiChat Ultimate CLI![/]", expand=False))
    console.print("This CLI provides over 200 commands to manage every aspect of your PlexiChat instance.")
    console.print("\n[bold]Available Command Categories:[/bold]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Description")

    for category in CommandCategory:
        table.add_row(category.value, ultimate_cli.get_category_description(category))

    console.print(table)
    console.print("\nUse [bold]'plexichat list --category <category>'[/] to see commands in a category.")
    console.print("Use [bold]'plexichat help <command>'[/] for detailed help on a specific command.")

def initialize_and_register_commands():
    """Initializes the CLI and registers all command modules."""
    console.print("[bold]Initializing Ultimate CLI...[/bold]")
    # In a real application, command modules would be imported here to register themselves.
    # For this example, we'll assume they are already registered in the coordinator.
    ultimate_cli.register_all_commands()
    console.print(f"[green]Initialization complete. {ultimate_cli.stats['total_commands']} commands registered.[/green]")

# --- Main Execution ---

def main():
    """Main entry point for the Ultimate CLI."""
    try:
        initialize_and_register_commands()
        app()
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        logger.exception("CLI Error")

if __name__ == "__main__":
    main()
