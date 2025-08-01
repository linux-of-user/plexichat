"""
PlexiChat CLI Interface Module
"""

import logging

logger = logging.getLogger(__name__)

try:
    from .main_cli import main as cli_main
    from .console_manager import EnhancedSplitScreen
    
    # Create a simple CLI app reference
    cli_app = True
    
    logger.info("CLI interface initialized successfully")
    
except ImportError as e:
    logger.warning(f"CLI interface not fully available: {e}")
    cli_app = None

__all__ = ["cli_main", "EnhancedSplitScreen", "cli_app"]
