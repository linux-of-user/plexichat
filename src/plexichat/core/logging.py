"""
PlexiChat Core Logging Module

Provides logging management and configuration.


import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


class LoggingManager:
    """Logging manager for PlexiChat."""
        def __init__(self):
        self.loggers: Dict[str, logging.Logger] = {}
        self.configured = False
        self.log_directory = Path("logs")
        self.log_level = logging.INFO
        self.log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.date_format = "%Y-%m-%d %H:%M:%S"
    
    def configure(self, 
                log_level: str = "INFO",
                log_directory: str = "logs",
                log_format: Optional[str] = None,
                enable_console: bool = True,
                enable_file: bool = True) -> bool:
        """Configure logging system."""
        try:
            # Set log level
            self.log_level = getattr(logging, log_level.upper(), logging.INFO)
            
            # Set log directory
            self.log_directory = Path(log_directory)
            self.log_directory.mkdir(parents=True, exist_ok=True)
            
            # Set log format
            if log_format:
                self.log_format = log_format
            
            # Configure root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(self.log_level)
            
            # Clear existing handlers
            root_logger.handlers.clear()
            
            # Create formatter
            formatter = logging.Formatter(self.log_format, self.date_format)
            
            # Console handler with UTF-8 encoding support
            if enable_console:
                # Ensure stdout can handle Unicode characters
                import io
                if hasattr(sys.stdout, 'buffer'):
                    # Use UTF-8 encoding for console output
                    utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
                    console_handler = logging.StreamHandler(utf8_stdout)
                else:
                    console_handler = logging.StreamHandler(sys.stdout)

                console_handler.setLevel(self.log_level)
                console_handler.setFormatter(formatter)
                root_logger.addHandler(console_handler)
            
            # File handler
            if enable_file:
                log_file = self.log_directory / "plexichat.log"
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                )
                file_handler.setLevel(self.log_level)
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)
            
            self.configured = True
            logging.info("Logging system configured successfully")
            return True
            
        except Exception as e:
            print(f"Error configuring logging: {e}")
            return False
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger.
        if name not in self.loggers:
            logger = logging.getLogger(name)
            logger.setLevel(self.log_level)
            self.loggers[name] = logger
        
        return self.loggers[name]
    
    def set_level(self, level: str):
        """Set logging level for all loggers."""
        self.log_level = getattr(logging, level.upper(), logging.INFO)
        
        # Update root logger
        logging.getLogger().setLevel(self.log_level)
        
        # Update all managed loggers
        for logger in self.loggers.values():
            logger.setLevel(self.log_level)
    
    def add_file_handler(self, logger_name: str, filename: str) -> bool:
        Add file handler to specific logger."""
        try:
            logger = self.get_logger(logger_name)
            
            log_file = self.log_directory / filename
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            
            formatter = logging.Formatter(self.log_format, self.date_format)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(self.log_level)
            
            logger.addHandler(file_handler)
            return True
            
        except Exception as e:
            logging.error(f"Error adding file handler: {e}")
            return False
    
    def remove_handlers(self, logger_name: str):
        """Remove all handlers from logger.
        if logger_name in self.loggers:
            logger = self.loggers[logger_name]
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)
    
    def is_configured(self) -> bool:
        """Check if logging is configured."""
        return self.configured
    
    def get_log_files(self) -> list:
        Get list of log files."""
        if not self.log_directory.exists():
            return []
        
        return [f for f in self.log_directory.iterdir() if f.is_file() and f.suffix == '.log']
    
    def cleanup_old_logs(self, days: int = 30):
        """Clean up old log files."""
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
            
            for log_file in self.get_log_files():
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logging.info(f"Removed old log file: {log_file}")
            
        except Exception as e:
            logging.error(f"Error cleaning up old logs: {e}")


# Global logging manager instance
logging_manager = LoggingManager()

# Convenience functions
def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance."""
    if name is None:
        return logging.getLogger()
    return logging_manager.get_logger(name)

def configure_logging(log_level: str = "INFO",
                    log_directory: str = "logs",
                    log_format: Optional[str] = None,
                    enable_console: bool = True,
                    enable_file: bool = True) -> bool:
    """Configure the logging system.
    return logging_manager.configure(log_level, log_directory, log_format, enable_console, enable_file)

def set_log_level(level: str):
    """Set logging level."""
    logging_manager.set_level(level)

def add_file_handler(logger_name: str, filename: str) -> bool:
    Add file handler to logger."""
    return logging_manager.add_file_handler(logger_name, filename)

def cleanup_old_logs(days: int = 30):
    """Clean up old log files.
    logging_manager.cleanup_old_logs(days)

def is_logging_configured() -> bool:
    """Check if logging is configured."""
    return logging_manager.is_configured()

# Auto-configure logging if not already configured
try:
    if not logging_manager.is_configured():
        # Try to get config from environment or use defaults
        import os
        log_level = os.getenv('PLEXICHAT_LOG_LEVEL', 'INFO')
        log_directory = os.getenv('PLEXICHAT_LOG_DIRECTORY', 'logs')
        
        logging_manager.configure(
            log_level=log_level,
            log_directory=log_directory,
            enable_console=True,
            enable_file=True
        )
        
except Exception as e:
    print(f"Error during logging auto-configuration: {e}")

# Export commonly used items
__all__ = [
    'LoggingManager',
    'logging_manager',
    'get_logger',
    'configure_logging',
    'set_log_level',
    'add_file_handler',
    'cleanup_old_logs',
    'is_logging_configured'
]
