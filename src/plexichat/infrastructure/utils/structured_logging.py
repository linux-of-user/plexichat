import logging

from plexichat.core.errors.error_manager import ErrorHandler

def get_logger(name=None):
    """Return a logger with error handling."""
    logger = logging.getLogger(name)
    logger.error_handler = ErrorHandler()
    return logger
