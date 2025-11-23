"""
PlexiChat Logging System
========================

Unified logging configuration with rotation and JSON support.
"""

import logging
import sys
import json
import os
from typing import Any, Dict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from plexichat.core.config import config

class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def configure_logging():
    """
    Configure the root logger based on global config.
    """
    log_config = config.logging
    system_config = config.system
    
    root_logger = logging.getLogger()
    root_logger.setLevel(system_config.log_level.upper())
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Create formatters
    if log_config.json_format:
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File Handler (Rotating)
    log_path = Path(log_config.file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        filename=log_path,
        maxBytes=log_config.max_bytes,
        backupCount=log_config.backup_count,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    """
    return logging.getLogger(name)

# Auto-configure on import
configure_logging()
