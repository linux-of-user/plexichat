import logging
import os
import zipfile
from datetime import datetime
from pathlib import Path

LOGS_DIR = Path("logs")
LATEST_LOG_FILE = LOGS_DIR / "latest.txt"
LOG_RETENTION_DAYS = 30  # Default retention period

class ColorizedFormatter(logging.Formatter):
    """A logging formatter that adds color to the output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[31m\033[1m",  # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record):
        log_message = super().format(record)
        # Ensure message is ascii
        log_message = log_message.encode('ascii', 'ignore').decode('ascii')
        return f"{self.COLORS.get(record.levelname, '')}{log_message}{self.RESET}"

def setup_logging(config=None):
    """Sets up the logging system."""
    LOGS_DIR.mkdir(exist_ok=True)

    # Rotate logs
    if LATEST_LOG_FILE.exists():
        try:
            log_date = datetime.fromtimestamp(LATEST_LOG_FILE.stat().st_mtime)
            archive_name = LOGS_DIR / f"{log_date.strftime('%Y-%m-%d')}.zip"
            with zipfile.ZipFile(archive_name, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(LATEST_LOG_FILE, LATEST_LOG_FILE.name)
            LATEST_LOG_FILE.unlink()
        except Exception as e:
            print(f"Could not rotate log file: {e}")

    # Clean up old logs
    retention_days = config.get("log_retention_days", LOG_RETENTION_DAYS) if config else LOG_RETENTION_DAYS
    if retention_days > 0:
        for item in LOGS_DIR.iterdir():
            if item.is_file() and item.suffix == ".zip":
                try:
                    log_date = datetime.strptime(item.stem, "%Y-%m-%d")
                    if (datetime.now() - log_date).days > retention_days:
                        item.unlink()
                except (ValueError, OSError):
                    continue

    # Set up logging
    logger = logging.getLogger("plexichat")
    logger.setLevel(logging.DEBUG)

    # Remove existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create file handler
    file_handler = logging.FileHandler(LATEST_LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(file_handler)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorizedFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(console_handler)

    logger.info("Logging system initialized.")
    return logger

def get_logger(name="plexichat"):
    """Returns the logger instance."""
    return logging.getLogger(name)
