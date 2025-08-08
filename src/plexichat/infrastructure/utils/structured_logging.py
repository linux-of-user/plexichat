import logging

try:
    from .monitoring.error_handler import ErrorHandler
except ImportError:
    class ErrorHandler:
        def handle_error(self, error):
            print(f"Error: {error}")

def get_enhanced_logger(name=None):
    """Return a logger with enhanced error handling."""
    logger = logging.getLogger(name)
    logger.error_handler = ErrorHandler()
    return logger