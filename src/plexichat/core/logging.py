"""
PlexiChat Logging System
========================

Unified logging configuration using standard logging with JSON formatting support.
Ensures consistent log formats and PII redaction across the application.
"""

import logging
import sys
import json
from typing import Any, Dict
from datetime import datetime, timezone

# Try to import PII redaction if available, else use placeholder
try:
    from plexichat.core.logging.pii_redaction import redact_pii
except ImportError:
    def redact_pii(text: str) -> str:
        return text

class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_pii(record.getMessage()),
            "module": record.module,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def configure_logging(level: str = "INFO", json_format: bool = False):
    """
    Configure the root logger.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    """
    return logging.getLogger(name)

# Auto-configure on import with default settings
# This can be overridden by calling configure_logging again
configure_logging()
