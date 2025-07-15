import json
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from pathlib import Path

from pathlib import Path

"""
PlexiChat Version Management System
Provides centralized version tracking and management.
"""

logger = logging.getLogger(__name__)


class VersionType(Enum):
    """Version type enumeration."""
    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    PRERELEASE = "prerelease"
    BUILD = "build"


@dataclass
class Version:
    """Version data class."""
    major: int = 1
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None
    build: Optional[str] = None
    
    def __str__(self) -> str:
        """String representation of version."""
        version_str = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            version_str += f"-{self.prerelease}"
        if self.build:
            version_str += f"+{self.build}"
        return version_str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "major": self.major,
            "minor": self.minor,
            "patch": self.patch,
            "prerelease": self.prerelease,
            "build": self.build
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Version":
        """Create from dictionary."""
        return cls(
            major=data.get("major", 1),
            minor=data.get("minor", 0),
            patch=data.get("patch", 0),
            prerelease=data.get("prerelease"),
            build=data.get("build")
        )
    
    @classmethod
    def from_string(cls, version_str: str) -> "Version":
        """Parse version from string."""
        try:
            # Basic parsing - can be enhanced
            parts = version_str.split(".")
            major = int(parts[0]) if len(parts) > 0 else 1
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return cls(major=major, minor=minor, patch=patch)
        except (ValueError, IndexError):
            logger.warning(f"Failed to parse version string: {version_str}")
            return cls()


class VersionManager:
    """Centralized version management system."""
    
    def __init__(self, version_file: str = "version.json"):
        from pathlib import Path
        self.version_file = Path(version_file)
        self.current_version: Optional[Version] = None
        self._load_version()
    
    def _load_version(self):
        """Load version from file."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    data = json.load(f)
                    self.current_version = Version.from_dict(data)
            else:
                # Default version
                self.current_version = Version(1, 0, 0)
                self._save_version()
        except Exception as e:
            logger.error(f"Failed to load version: {e}")
            self.current_version = Version(1, 0, 0)
    
    def _save_version(self):
        """Save version to file."""
        try:
            self.version_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.version_file, 'w') as f:
                json.dump(self.current_version.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save version: {e}")
    
    def get_current_version(self) -> Optional[Version]:
        """Get current version."""
        return self.current_version
    
    def set_current_version(self, version: str):
        """Set current version from string."""
        try:
            self.current_version = Version.from_string(version)
            self._save_version()
        except Exception as e:
            logger.error(f"Failed to set version: {e}")
    
    def bump_version(self, version_type: VersionType) -> Version:
        """Bump version by type."""
        if not self.current_version:
            self.current_version = Version()
        
        if version_type == VersionType.MAJOR:
            self.current_version.major += 1
            self.current_version.minor = 0
            self.current_version.patch = 0
        elif version_type == VersionType.MINOR:
            self.current_version.minor += 1
            self.current_version.patch = 0
        elif version_type == VersionType.PATCH:
            self.current_version.patch += 1
        
        self._save_version()
        return self.current_version


# Global version manager instance
version_manager = VersionManager()
