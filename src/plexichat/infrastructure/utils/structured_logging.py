import logging

from plexichat.core.errors.error_manager import ErrorHandler

def get_enhanced_logger(name=None):
    """Return a logger with enhanced error handling."""
    logger = logging.getLogger(name)
    logger.error_handler = ErrorHandler()
    return logger