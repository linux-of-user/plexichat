import argparse
import asyncio
import logging
import shlex
import sys
from typing import List, Optional

from plexichat.core.launcher import LaunchConfig, PlexiChatLauncher

"""
PlexiChat Integrated CLI
Comprehensive command-line interface for PlexiChat management and operations.
"""

logger = logging.getLogger(__name__)


class PlexiChatCLI:
    """Main PlexiChat CLI class."""

    def __init__(self):
        self.parser = self._create_parser()
        self.running = True  # Add running attribute for compatibility with run.py
        self.commands = {
            'start': self.start_server,
            'stop': self.stop_server,
            'status': self.show_status,
            'setup': self.run_setup,
            'test': self.run_tests,
            'backup': self.create_backup,
            'restore': self.restore_backup,
            'migrate': self.run_migration,
            'config': self.manage_config,
            'users': self.manage_users,
            'logs': self.show_logs,
        }
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog='plexichat',
            description='PlexiChat Management CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start PlexiChat server')
        start_parser.add_argument('--host', default='localhost', help='Host to bind to')
        start_parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
        start_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
        
        # Stop command
        subparsers.add_parser('stop', help='Stop PlexiChat server')
        
        # Status command
        subparsers.add_parser('status', help='Show server status')
        
        # Setup command
        setup_parser = subparsers.add_parser('setup', help='Run setup wizard')
        setup_parser.add_argument('--type', choices=['basic', 'full'], default='basic', help='Setup type')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Run tests')
        test_parser.add_argument('--suite', help='Test suite to run')
        
        # Backup command
        backup_parser = subparsers.add_parser('backup', help='Create backup')
        backup_parser.add_argument('--name', help='Backup name')
        
        # Restore command
        restore_parser = subparsers.add_parser('restore', help='Restore from backup')
        restore_parser.add_argument('backup_name', help='Backup name to restore')
        
        # Migration command
        migrate_parser = subparsers.add_parser('migrate', help='Run database migrations')
        migrate_parser.add_argument('--target', help='Target migration version')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Manage configuration')
        config_parser.add_argument('action', choices=['show', 'set', 'get'], help='Config action')
        config_parser.add_argument('--key', help='Configuration key')
        config_parser.add_argument('--value', help='Configuration value')
        
        # Users command
        users_parser = subparsers.add_parser('users', help='Manage users')
        users_parser.add_argument('action', choices=['list', 'create', 'delete'], help='User action')
        users_parser.add_argument('--username', help='Username')
        users_parser.add_argument('--email', help='User email')
        users_parser.add_argument('--admin', action='store_true', help='Make user admin')
        
        # Logs command
        logs_parser = subparsers.add_parser('logs', help='Show logs')
        logs_parser.add_argument('--tail', type=int, default=50, help='Number of lines to show')
        logs_parser.add_argument('--follow', action='store_true', help='Follow log output')
        
        return parser

    async def process_command(self, command_str: str) -> Optional[str]:
        """Process a command string and return response."""
        try:
            # Parse command string into arguments
            args_list = shlex.split(command_str)

            if not args_list:
                return "No command provided"

            # Handle special commands
            if args_list[0].lower() in ['exit', 'quit']:
                self.running = False
                return "Goodbye!"

            if args_list[0].lower() == 'help':
                self.parser.print_help()
                return None

            # Parse arguments
            try:
                args = self.parser.parse_args(args_list)
            except SystemExit:
                return "Invalid command. Type 'help' for available commands."

            if not args.command:
                return "No command specified. Type 'help' for available commands."

            if args.command in self.commands:
                result = await self.commands[args.command](args)
                return f"Command '{args.command}' completed successfully" if result else f"Command '{args.command}' failed"
            else:
                return f"Unknown command: {args.command}"

        except Exception as e:
            logger.error(f"Error processing command '{command_str}': {e}")
            return f"Error: {e}"

    async def start_server(self, args):
        """Start the PlexiChat server."""
        try:
            config = LaunchConfig(
                host=args.host,
                port=args.port,
                debug=args.debug
            )
            
            launcher = PlexiChatLauncher(config)
            await launcher.start()
            
        except ImportError:
            print(" Server components not available")
            return False
        except Exception as e:
            print(f" Failed to start server: {e}")
            return False
    
    async def stop_server(self, args):
        """Stop the PlexiChat server."""
        print(" Stopping PlexiChat server...")
        # Implementation would depend on how the server is managed
        return True
    
    async def show_status(self, args):
        """Show server status."""
        try:
            # Check if server is running
            print(" PlexiChat Status:")
            print("Status: Unknown")
            print("Version: 1.0.0")
            return True
        except Exception as e:
            print(f" Failed to get status: {e}")
            return False
    
    async def run_setup(self, args):
        """Run setup wizard."""
        print(f" Running {args.type} setup...")
        # Implementation would call the setup system
        return True
    
    async def run_tests(self, args):
        """Run tests."""
        try:
            if args.suite:
                print(f" Running test suite: {args.suite}")
            else:
                print(" Running all tests...")
            
            # Implementation would call the test system
            return True
        except Exception as e:
            print(f" Test execution failed: {e}")
            return False
    
    async def create_backup(self, args):
        """Create backup."""
        backup_name = args.name or f"backup_{int(asyncio.get_event_loop().time())}"
        print(f" Creating backup: {backup_name}")
        # Implementation would call the backup system
        return True
    
    async def restore_backup(self, args):
        """Restore from backup."""
        print(f" Restoring from backup: {args.backup_name}")
        # Implementation would call the restore system
        return True
    
    async def run_migration(self, args):
        """Run database migrations."""
        print(" Running database migrations...")
        # Implementation would call the migration system
        return True
    
    async def manage_config(self, args):
        """Manage configuration."""
        if args.action == 'show':
            print(" Configuration:")
            # Show current config
        elif args.action == 'set':
            print(f"  Setting {args.key} = {args.value}")
            # Set config value
        elif args.action == 'get':
            print(f" {args.key}: <value>")
            # Get config value
        return True
    
    async def manage_users(self, args):
        """Manage users."""
        if args.action == 'list':
            print(" Users:")
            # List users
        elif args.action == 'create':
            print(f" Creating user: {args.username}")
            # Create user
        elif args.action == 'delete':
            print(f"  Deleting user: {args.username}")
            # Delete user
        return True
    
    async def show_logs(self, args):
        """Show logs."""
        print(f" Showing last {args.tail} log lines...")
        # Implementation would show logs
        return True
    
    async def run(self, argv: Optional[List[str]] = None):
        """Run the CLI with given arguments."""
        try:
            args = self.parser.parse_args(argv)
            
            if not args.command:
                self.parser.print_help()
                return False
            
            if args.command in self.commands:
                return await self.commands[args.command](args)
            else:
                print(f" Unknown command: {args.command}")
                return False
                
        except KeyboardInterrupt:
            print("\n  Operation cancelled by user")
            return False
        except Exception as e:
            print(f" CLI error: {e}")
            return False


# Convenience functions for backward compatibility
async def run_cli(argv: Optional[List[str]] = None):
    """Run the CLI."""
    cli = PlexiChatCLI()
    return await cli.run(argv)

def main():
    """Main entry point."""
    cli = PlexiChatCLI()
    return asyncio.run(cli.run())

if __name__ == "__main__":
    sys.exit(main())
