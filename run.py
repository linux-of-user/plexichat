#!/usr/bin/env python3
"""
PlexiChat Run Script

Starts PlexiChat server and provides CLI access for testing and management.
This script handles:
- Server startup with proper initialization
- CLI interface for running tests
- Interactive mode for development
- Graceful shutdown handling
"""

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set up basic logging first
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from plexichat.interfaces.cli.test_commands import handle_test_command
    from plexichat.core.logging.unified_logging_manager import get_logger
    # Use unified logger if available
    logger = get_logger(__name__)
except ImportError as e:
    logger.warning(f"Could not import some PlexiChat modules: {e}")
    logger.info("Using basic logging and continuing...")

    # Define fallback function
    def handle_test_command(*args, **kwargs):
        logger.error("Test commands not available - CLI module not imported")
        return False

def setup_environment():
    directories = ['logs', 'data', 'config', 'temp', 'backups', 'uploads']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    os.environ.setdefault('PLEXICHAT_ENV', 'production')
    os.environ.setdefault('PLEXICHAT_CONFIG_DIR', 'config')

def load_configuration():
    try:
        from plexichat.main import config
        return config
    except Exception as e:
        logger.warning(f"Could not load configuration: {e}")
        return None

def run_enhanced_tests():
    """Run the comprehensive test suite."""
    try:
        import asyncio
        from src.plexichat.tests.test_runner import run_tests

        logger.info("🚀 Running PlexiChat comprehensive test suite...")

        # Run all tests
        report = asyncio.run(run_tests(
            categories=None,  # Run all categories
            verbose=True,
            save_report=True
        ))

        # Check results
        if report.get('summary', {}).get('failed', 0) == 0:
            logger.info("✅ All tests passed!")
            return True
        else:
            failed_count = report['summary']['failed']
            total_count = report['summary']['total_tests']
            logger.error(f"❌ {failed_count}/{total_count} tests failed")
            return False

    except ImportError as e:
        logger.error(f"Test system not available: {e}")
        logger.info("Make sure all test dependencies are installed")
        return False
    except Exception as e:
        logger.error(f"Error running tests: {e}")
        return False

def run_splitscreen_cli():
    try:
        from src.plexichat.interfaces.cli.console_manager import EnhancedSplitScreen
        cli = EnhancedSplitScreen(logger=logger)
        if cli and hasattr(cli, "start"): cli.start()
    except Exception as e:
        logger.error(f"Could not start splitscreen CLI: {e}")


def run_api_and_cli():
    # Start the splitscreen CLI in a separate thread
    cli_thread = threading.Thread(target=run_splitscreen_cli, daemon=True)
    if cli_thread and hasattr(cli_thread, "start"): cli_thread.start()
    # Start the API server (blocking)
    run_api_server()


def run_gui():
    logger.info("Launching PlexiChat GUI (not yet implemented, starting API server and splitscreen CLI)...")
    logger.info("Web interface available at: http://localhost:8000")
    logger.info("API documentation at: http://localhost:8000/docs")
    run_api_and_cli()

def run_configuration_wizard():
    logger.info("Starting configuration wizard... (not implemented)")
    return True

def run_api_server():
    try:
        import uvicorn
        config = load_configuration()
        host = "0.0.0.0"
        port = 8000
        if config:
            host = config.get('network', {}).get('host', '0.0.0.0')
            port = config.get('network', {}).get('port', 8000)
        logger.info(f"Starting PlexiChat API server on {host}:{port}")
        logger.info("PlexiChat API server starting...")
        logger.info("Version: a.1.1-12")
        logger.info("API Documentation available at: http://localhost:8000/docs")
        logger.info("Web interface available at: http://localhost:8000")
        logger.info("Health check: http://localhost:8000/health")
        logger.info("Version info: http://localhost:8000/api/v1/version")
        uvicorn.run(
            "plexichat.main:app",
            host=host,
            port=port,
            reload=True,
            log_level="info"
        )
        return True
    except Exception as e:
        logger.error(f"Could not start API server: {e}")
        return False

def run_cli():
    """Run the main CLI interface."""
    try:
        from plexichat.interfaces.cli.main_cli import main as cli_main
        cli_main()
    except Exception as e:
        logger.error(f"Could not start CLI: {e}")

def run_admin_cli():
    """Run admin CLI commands."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to admin commands
        original_argv = sys.argv.copy()

        # If no additional args, show admin help
        if len(sys.argv) <= 2:
            sys.argv = ['plexichat', 'admin', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['plexichat', 'admin'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        logger.error(f"Could not start admin CLI: {e}")
        print("Admin CLI not available. Please check your installation.")

def run_backup_node():
    """Run backup node."""
    try:
        from plexichat.features.backup.nodes.backup_node_main import main as backup_main
        import asyncio
        asyncio.run(backup_main())
    except Exception as e:
        logger.error(f"Could not start backup node: {e}")

def run_plugin_manager():
    """Run plugin management CLI."""
    try:
        # Import the main CLI
        from plexichat.interfaces.cli.main_cli import main as cli_main

        # Modify sys.argv to route to plugin commands
        original_argv = sys.argv.copy()

        # If no additional args, show plugin help
        if len(sys.argv) <= 2:
            sys.argv = ['run.py', 'plugins', '--help']
        else:
            # Pass through additional arguments
            sys.argv = ['run.py', 'plugins'] + sys.argv[2:]

        try:
            cli_main()
        finally:
            sys.argv = original_argv

    except Exception as e:
        logger.error(f"Could not start plugin manager: {e}")
        print("Plugin manager CLI not available. Please check your installation.")

def show_help():
    help_text = """
PlexiChat - Government-Level Secure Communication Platform
=========================================================

Usage: python run.py [command] [options]

Commands:
  (no command)     - Start API server with splitscreen CLI (default)
  api              - Start API server with splitscreen CLI
  gui              - Launch GUI (starts API server and splitscreen CLI)
  cli              - Run comprehensive CLI interface (admin, backup, system, etc.)
  admin            - Run admin CLI commands only
  backup-node      - Start backup node server
  plugin           - Plugin management CLI
  test             - Run enhanced test suite
  config           - Show configuration
  wizard           - Run configuration wizard
  help             - Show this help

Options:
  --verbose, -v    - Enable verbose output
  --debug, -d      - Enable debug mode
  --config FILE    - Use custom config file
  --log-level LEVEL - Set log level (DEBUG, INFO, WARNING, ERROR)
  --port PORT      - Override port number
  --host HOST      - Override host address

Examples:
  python run.py                    # Start API server with splitscreen CLI (default)
  python run.py api                # Start API server with splitscreen CLI
  python run.py gui                # Launch GUI (starts API server and splitscreen CLI)
  python run.py admin create-admin # Create admin user
  python run.py backup-node        # Start backup node
  python run.py test               # Run test suite
  python run.py wizard             # Run configuration wizard
  python run.py --verbose          # Start with verbose logging

Features:
  - API server with comprehensive endpoints
  - Admin management system with CLI and web interface
  - Backup node system with clustering
  - Plugin system with SDK
  - File attachment support for messages
  - Security scanning for uploaded files
  - Real-time messaging capabilities
  - Enhanced splitscreen CLI
  - Comprehensive test suite
  - Configuration management
  - Security features
  - AI integration
  - Monitoring and logging

Version: a.1.1-12 (alpha version 1.1 build 12)
API Version: v1
"""
    print(help_text)

def main():
    setup_environment()

    # Check if this is a CLI command that should be routed to the unified CLI
    if len(sys.argv) > 1 and sys.argv[1] in ['admin', 'test', 'system', 'database', 'users', 'analytics', 'backup', 'server']:
        try:
            from plexichat.interfaces.cli.main_cli import main as cli_main
            # Modify sys.argv to work with Click
            original_argv = sys.argv.copy()
            sys.argv = ['plexichat'] + sys.argv[1:]  # Replace 'run.py' with 'plexichat'

            try:
                cli_main()
                return
            finally:
                sys.argv = original_argv
        except Exception as e:
            logger.error(f"Could not start unified CLI: {e}")
            print("Falling back to basic CLI...")

    parser = argparse.ArgumentParser(
        description="PlexiChat - Government-Level Secure Communication Platform",
        add_help=False
    )
    parser.add_argument('command', nargs='?', default='api',
                       help='Command to run (default: api)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--debug', '-d', action='store_true',
                       help='Enable debug mode')
    parser.add_argument('--config', type=str,
                       help='Custom config file')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Set log level')
    parser.add_argument('--port', type=int, help='Override port number')
    parser.add_argument('--host', type=str, help='Override host address')
    parser.add_argument('--help', '-h', action='store_true',
                       help='Show help information')
    args = parser.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    if args.help or args.command == 'help':
        show_help()
        return
    config = load_configuration()
    if config:
        logger.info("Configuration loaded successfully")
    try:
        if args.command == 'api' or args.command is None:
            logger.info("Starting API server with splitscreen CLI (default)")
            run_api_and_cli()
        elif args.command == 'gui':
            logger.info("Launching GUI (starts API server and splitscreen CLI)")
            run_gui()
        elif args.command == 'cli':
            logger.info("Starting comprehensive CLI interface")
            run_cli()
        elif args.command == 'admin':
            logger.info("Starting admin CLI")
            run_admin_cli()
        elif args.command == 'backup-node':
            logger.info("Starting backup node")
            run_backup_node()
        elif args.command == 'plugin':
            logger.info("Starting plugin manager CLI")
            run_plugin_manager()
        elif args.command == 'test':
            logger.info("Running enhanced test suite")
            success = run_enhanced_tests()
            if success:
                logger.info("All tests passed")
            else:
                logger.error("Some tests failed")
        elif args.command == 'config':
            if config:
                print("Configuration loaded successfully")
                print(f"Version: {config.get('system', {}).get('version', 'a.1.1-12')}")
            else:
                print("Configuration not available")
        elif args.command == 'wizard':
            logger.info("Starting configuration wizard")
            run_configuration_wizard()
        else:
            logger.error(f"Unknown command: {args.command}")
            show_help()
            sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
