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

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Configure logging
# Create logs directory first
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
    """Setup the application environment."""
    # Create necessary directories
    directories = ['logs', 'data', 'config', 'temp', 'backups', 'uploads']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Set up environment variables
    os.environ.setdefault('PLEXICHAT_ENV', 'production')
    os.environ.setdefault('PLEXICHAT_CONFIG_DIR', 'config')

def load_configuration():
    """Load application configuration."""
    try:
        from plexichat.core.config_manager import config_manager
        return config_manager
    except ImportError as e:
        logger.warning(f"Could not load configuration manager: {e}")
        return None

def run_enhanced_tests():
    """Run the enhanced test suite."""
    try:
        from plexichat.tests.test_enhanced_framework import EnhancedTestFramework
        framework = EnhancedTestFramework()
        return framework.run_all_tests()
    except (ImportError, AttributeError) as e:
        logger.error(f"Could not load enhanced test framework: {e}")
        return False

def run_unified_cli():
    """Run the unified CLI system."""
    try:
        from plexichat.interfaces.cli.unified_cli_default import UnifiedCLIDefault
        cli = UnifiedCLIDefault()
        cli.run_terminal()
    except ImportError as e:
        logger.error(f"Could not load unified CLI: {e}")
        return False

def run_enhanced_terminal():
    """Run the enhanced terminal interface."""
    try:
        from plexichat.interfaces.terminal.enhanced_terminal import start_enhanced_terminal
        start_enhanced_terminal()
    except ImportError as e:
        logger.error(f"Could not load enhanced terminal: {e}")
        return False

def run_configuration_wizard():
    """Run the configuration wizard."""
    try:
        from plexichat.core.config_wizard import ConfigurationWizard
        wizard = ConfigurationWizard()
        wizard.run_wizard()
    except ImportError as e:
        logger.error(f"Could not load configuration wizard: {e}")
        return False

def run_web_interface():
    """Run the web interface."""
    try:
        # Web interface implementation would go here
        logger.info("Web interface not yet implemented")
        return False
    except Exception as e:
        logger.error(f"Could not start web interface: {e}")
        return False

def run_api_server():
    """Run the API server."""
    try:
        import uvicorn
        from plexichat.main import app
        
        # Load configuration
        config = load_configuration()
        host = "0.0.0.0"
        port = 8000
        
        if config:
            host = config.get('network', {}).get('host', '0.0.0.0')
            port = config.get('network', {}).get('port', 8000)
        
        logger.info(f"Starting API server on {host}:{port}")
        logger.info("PlexiChat API server starting...")
        logger.info("Version: a.1.1-12")
        logger.info("API Documentation available at: http://localhost:8000/docs")
        
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
    """Show help information."""
    help_text = """
PlexiChat - Government-Level Secure Communication Platform
=========================================================

Usage: python run.py [command] [options]

Commands:
  (no command)     - Start unified CLI (default)
  cli              - Start unified CLI system
  terminal         - Start enhanced terminal interface
  web              - Start web interface
  api              - Start API server
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
  python run.py                    # Start unified CLI
  python run.py cli               # Start CLI system
  python run.py terminal          # Start enhanced terminal
  python run.py api               # Start API server
  python run.py test              # Run test suite
  python run.py wizard            # Run configuration wizard
  python run.py --verbose         # Start with verbose logging

Features:
  - 300+ CLI commands
  - Enhanced terminal with resizable panes
  - Comprehensive test suite
  - Configuration management
  - Security features
  - AI integration
  - Backup system
  - Monitoring and logging
  - File attachment support
  - Real-time messaging
  - API server with comprehensive endpoints

Version: a.1.1-12 (alpha version 1.1 build 12)
API Version: v1
"""
    print(help_text)

def main():
    """Main entry point."""
    # Setup environment
    setup_environment()
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="PlexiChat - Government-Level Secure Communication Platform",
        add_help=False
    )
    parser.add_argument('command', nargs='?', default='cli',
                       help='Command to run (default: cli)')
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
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Show help if requested
    if args.help or args.command == 'help':
        show_help()
        return
    
    # Load configuration
    config = load_configuration()
    if config:
        logger.info("Configuration loaded successfully")
    
    # Execute command
    try:
        if args.command == 'cli':
            logger.info("Starting unified CLI system")
            run_unified_cli()
        elif args.command == 'terminal':
            logger.info("Starting enhanced terminal interface")
            run_enhanced_terminal()
        elif args.command == 'web':
            logger.info("Starting web interface")
            run_web_interface()
        elif args.command == 'api':
            logger.info("Starting API server")
            run_api_server()
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
                print(f"Config file: {config.main_config_file}")
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
