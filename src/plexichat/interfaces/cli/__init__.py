"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

CLI Interface Module
"""

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

try:
    from plexichat.interfaces.cli.main_cli import main

    cli_app = True
    logger.info("CLI interface initialized successfully")

except ImportError as e:
    logger.warning(f"CLI interface not fully available: {e}")
    cli_app = None

__all__ = ["cli_app"]
