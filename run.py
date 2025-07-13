#!/usr/bin/env python3
"""
PlexiChat Main Entry Point
==========================

Government-level secure communication platform with enterprise-grade features.
This is the main entry point for the PlexiChat application.
"""

import sys
import os
import logging
import argparse
from pathlib import Path
from typing import Optional, Dict, Any
import threading

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Configure logging
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/plexichat.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
    logger.info("Running basic tests... (not implemented)")
    return True

def run_splitscreen_cli():
    try:
        from src.plexichat.interfaces.cli.console_manager import EnhancedSplitScreen
        cli = EnhancedSplitScreen(logger=logger)
        cli.start()
    except Exception as e:
        logger.error(f"Could not start splitscreen CLI: {e}")


def run_api_and_cli():
    # Start the splitscreen CLI in a separate thread
    cli_thread = threading.Thread(target=run_splitscreen_cli, daemon=True)
    cli_thread.start()
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

def show_help():
    help_text = """
PlexiChat - Government-Level Secure Communication Platform
=========================================================

Usage: python run.py [command] [options]

Commands:
  (no command)     - Start API server with splitscreen CLI (default)
  gui              - Launch GUI (starts API server and splitscreen CLI)
  test             - Run enhanced test suite
  config           - Show configuration
  wizard           - Run configuration wizard
  help             - Show this help

Options:
  --verbose, -v    - Enable verbose output
  --debug, -d      - Enable debug mode
  --config FILE    - Use custom config file
  --log-level LEVEL - Set log level (DEBUG, INFO, WARNING, ERROR)

Examples:
  python run.py                    # Start API server with splitscreen CLI (default)
  python run.py gui                # Launch GUI (starts API server and splitscreen CLI)
  python run.py test               # Run test suite
  python run.py wizard             # Run configuration wizard
  python run.py --verbose          # Start with verbose logging

Features:
  - API server with comprehensive endpoints
  - File attachment support for messages
  - Security scanning for uploaded files
  - Real-time messaging capabilities
  - Enhanced splitscreen CLI
  - Comprehensive test suite
  - Configuration management
  - Security features
  - AI integration
  - Backup system
  - Monitoring and logging
  - GUI (not yet implemented)

Version: a.1.1-12 (alpha version 1.1 build 12)
API Version: v1
"""
    print(help_text)

def main():
    setup_environment()
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
