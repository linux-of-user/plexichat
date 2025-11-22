import importlib
import logging
from pathlib import Path
import pkgutil
import shlex
from typing import Any, Dict

import click

# The commands directory is relative to this file's location.
COMMANDS_PATH = Path(__file__).parent / "commands"
# The package path to the commands.
COMMANDS_PACKAGE = "plexichat.interfaces.cli.commands"

logger = logging.getLogger(__name__)


class CLIManager:
    """
    A dynamic CLI builder that discovers and loads command groups from a specified directory.
    """

    def _discover_commands(self):
        """
        Dynamically discover and import command groups from the commands directory.
        It iterates over all modules in the commands package, imports them,
        and yields any click.Group objects found within.
        """
        logger.info(f"Discovering CLI commands in: {COMMANDS_PATH}")
        if not COMMANDS_PATH.is_dir():
            logger.error(f"Commands directory not found at {COMMANDS_PATH}")
            return

        for _, name, _ in pkgutil.iter_modules([str(COMMANDS_PATH)]):
            try:
                module_name = f"{COMMANDS_PACKAGE}.{name}"
                module = importlib.import_module(module_name)
                for item_name in dir(module):
                    item = getattr(module, item_name)
                    if isinstance(item, click.Group):
                        logger.info(
                            f"Found command group '{item.name}' in module '{name}'"
                        )
                        yield item
            except Exception as e:
                logger.error(
                    f"Failed to load command module '{name}': {e}", exc_info=True
                )

    def build_cli(self):
        """
        Build the main CLI group and attach all discovered command groups.
        This creates the root of the CLI application.
        """

        @click.group(
            help="PlexiChat CLI System. Use --help on any command for details."
        )
        @click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
        @click.option("--json", "-j", is_flag=True, help="Output in JSON format.")
        @click.option(
            "--quiet", "-q", is_flag=True, help="Suppress all output except for errors."
        )
        @click.pass_context
        def cli(ctx, verbose: bool, json: bool, quiet: bool):
            """CLI entrypoint."""
            ctx.ensure_object(dict)
            ctx.obj["verbose"] = verbose
            ctx.obj["json"] = json
            ctx.obj["quiet"] = quiet

            if quiet:
                logging.getLogger().setLevel(logging.ERROR)
            elif verbose:
                logging.getLogger().setLevel(logging.DEBUG)

        for command_group in self._discover_commands():
            cli.add_command(command_group)

        return cli

    def execute_system_command(
        self, command_str: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a system command via the CLI interface.

        Args:
            command_str: The command string to execute
            context: Execution context (user, ip, etc.)

        Returns:
            Dict containing 'success', 'message', and 'data'
        """
        from click.testing import CliRunner

        try:
            # Security check: ensure command is not empty
            if not command_str or not command_str.strip():
                return {"success": False, "message": "Empty command"}

            # Build the CLI app
            cli = self.build_cli()

            # Parse command string into arguments
            args = shlex.split(command_str)

            # Run the command
            runner = CliRunner()
            result = runner.invoke(cli, args, catch_exceptions=False)

            if result.exit_code == 0:
                return {
                    "success": True,
                    "message": "Command executed successfully",
                    "data": {"output": result.output},
                }
            else:
                return {
                    "success": False,
                    "message": f"Command failed with exit code {result.exit_code}",
                    "data": {"output": result.output, "error": str(result.exception)},
                }

        except Exception as e:
            logger.error(f"Error executing CLI command: {e}")
            return {"success": False, "message": str(e)}


def main():
    """Main entry point for running the CLI directly."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    builder = CLIManager()
    cli = builder.build_cli()
    cli()


if __name__ == "__main__":
    main()
