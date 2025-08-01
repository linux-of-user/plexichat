"""
PlexiChat Version Utilities

Centralized version loading and management utilities.
All version information should be loaded from version.json.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class VersionManager:
    """Centralized version management."""
    
    def __init__(self):
        self._version_data: Optional[Dict[str, Any]] = None
        self._load_version_data()
    
    def _load_version_data(self) -> None:
        """Load version data from version.json."""
        try:
            # Look for version.json in the project root
            current_file = Path(__file__)
            version_file = current_file.parent.parent.parent.parent / "version.json"
            
            if version_file.exists():
                with open(version_file, 'r', encoding='utf-8') as f:
                    self._version_data = json.load(f)
                logger.debug(f"Version data loaded from {version_file}")
            else:
                logger.warning(f"Version file not found at {version_file}")
                self._version_data = self._get_fallback_version_data()
        except Exception as e:
            logger.error(f"Failed to load version data: {e}")
            self._version_data = self._get_fallback_version_data()
    
    def _get_fallback_version_data(self) -> Dict[str, Any]:
        """Get fallback version data when version.json is not available."""
        return {
            "version": "b.1.1-88",
            "version_type": "beta",
            "major_version": 1,
            "minor_version": 1,
            "build_number": 88,
            "api_version": "v1",
            "release_date": datetime.now().strftime("%Y-%m-%d"),
            "status": "beta"
        }
    
    def get_version(self) -> str:
        """Get the current version string."""
        if self._version_data:
            return self._version_data.get('version', 'b.1.1-88')
        return 'b.1.1-88'
    
    def get_api_version(self) -> str:
        """Get the API version."""
        if self._version_data:
            return self._version_data.get('api_version', 'v1')
        return 'v1'
    
    def get_version_type(self) -> str:
        """Get the version type (alpha, beta, release)."""
        if self._version_data:
            return self._version_data.get('version_type', 'beta')
        return 'beta'
    
    def get_build_number(self) -> int:
        """Get the build number."""
        if self._version_data:
            return self._version_data.get('build_number', 88)
        return 88
    
    def get_release_date(self) -> str:
        """Get the release date."""
        if self._version_data:
            return self._version_data.get('release_date', datetime.now().strftime("%Y-%m-%d"))
        return datetime.now().strftime("%Y-%m-%d")
    
    def get_full_version_info(self) -> Dict[str, Any]:
        """Get complete version information."""
        return {
            "version": self.get_version(),
            "api_version": self.get_api_version(),
            "version_type": self.get_version_type(),
            "build_number": self.get_build_number(),
            "release_date": self.get_release_date(),
            "status": self._version_data.get('status', 'beta') if self._version_data else 'beta',
            "timestamp": datetime.now().isoformat()
        }
    
    def get_health_version_info(self) -> Dict[str, Any]:
        """Get version info suitable for health checks."""
        return {
            "version": self.get_version(),
            "status": "healthy",
            "timestamp": datetime.now().isoformat()
        }
    
    def reload(self) -> None:
        """Reload version data from file."""
        self._load_version_data()

# Global version manager instance
version_manager = VersionManager()

# Convenience functions for backward compatibility
def get_version() -> str:
    """Get current version string."""
    return version_manager.get_version()

def get_api_version() -> str:
    """Get API version string."""
    return version_manager.get_api_version()

def get_version_info() -> Dict[str, Any]:
    """Get complete version information."""
    return version_manager.get_full_version_info()

def get_health_info() -> Dict[str, Any]:
    """Get health check version information."""
    return version_manager.get_health_version_info()
