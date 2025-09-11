"""
PlexiChat CLI Interface Module
"""

import logging

logger = logging.getLogger(__name__)

try:
    from plexichat.interfaces.cli.console_manager import EnhancedSplitScreen
    from plexichat.interfaces.cli.main_cli import main

    # Create a simple CLI app reference
    cli_app = True

    logger.info("CLI interface initialized successfully")

except ImportError as e:
    logger.warning(f"CLI interface not fully available: {e}")
    cli_app = None

__all__ = ["EnhancedSplitScreen", "cli_app", "cli_main"]
