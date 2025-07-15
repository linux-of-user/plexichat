import sys
from pathlib import Path

from pathlib import Path

from pathlib import Path
import logging
from typing import Optional


#!/usr/bin/env python3
"""
PlexiChat Startup Validation
Ensures all required directories exist before starting the application.
"""

logger = logging.getLogger(__name__)
def validate_directory_structure():
    """Validate that all required directories exist."""

    from pathlib import Path
project_root = Path
Path(__file__).parent.parent

    required_dirs = [
        "config", "data", "backups", "logs", "plugins",
        "databases", "static", "runtime"
    ]

    missing_dirs = []
    for dir_name in required_dirs:
        if not (project_root / dir_name).exists():
            missing_dirs.append(dir_name)

    if missing_dirs:
        logger.info("ERROR: Missing required directories:")
        for dir_name in missing_dirs:
            logger.info(f"   - {dir_name}")
        logger.info("\nRun 'python scripts/auto_setup.py' to create missing directories")
        return False

    return True

if __name__ == "__main__":
    if not validate_directory_structure():
        sys.exit(1)
    logger.info("SUCCESS: Directory structure validation passed")
