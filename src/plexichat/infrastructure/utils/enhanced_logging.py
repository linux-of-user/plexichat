from .monitoring.error_handler import ErrorHandler
import logging

def get_enhanced_logger(name=None):
    """Return a logger with enhanced error handling."""
    logger = logging.getLogger(name)
    logger.error_handler = ErrorHandler()
    return logger 