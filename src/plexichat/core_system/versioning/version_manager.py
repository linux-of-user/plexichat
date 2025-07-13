import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


"""
PlexiChat Advanced Version Management System

New versioning scheme: {major}{type}{minor}
- Types: 'a' (alpha), 'b' (beta), 'r' (release)
- Examples: 0a1, 0b1, 0r1, 0a2, 1r1, etc.

Features:
- Semantic version parsing and comparison
- Version lifecycle management
- Upgrade/downgrade path validation
- Changelog integration
- Database schema versioning
- Configuration migration support
"""

logger = logging.getLogger(__name__)


class VersionType(Enum):
    """Version type enumeration."""
    ALPHA = "a"
    BETA = "b"
    RELEASE = "r"


class VersionStatus(Enum):
    """Version status enumeration."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    END_OF_LIFE = "end_of_life"


@dataclass
class Version:
    """Version representation with new scheme."""
    major: int
    type: VersionType
    minor: int
    build: Optional[str] = None
    
    def __post_init__(self):
        """Validate version components."""
        if self.major < 0:
            raise ValueError("Major version cannot be negative")
        if self.minor < 1:
            raise ValueError("Minor version must be >= 1")
    
    @classmethod
    def parse(cls, version_string: str) -> 'Version':
        """Parse version string into Version object."""
        # Pattern: letter.major.minor-build (e.g., a.1.1-1)
        pattern = r'^([abr])\.(\d+)\.(\d+)-(\d+)$'
        match = re.match(pattern, version_string.strip())

        if not match:
            # Try old format for backward compatibility
            old_pattern = r'^(\d+)([abr])(\d+)(?:\+(.+))?$'
            old_match = re.match(old_pattern, version_string.strip())
            if old_match:
                major, type_char, minor, build = old_match.groups()
                return cls(
                    major=int(major),
                    type=VersionType(type_char),
                    minor=int(minor),
                    build=build or "1"
                )
            raise ValueError(f"Invalid version format: {version_string}")

        type_char, major, minor, build = match.groups()

        return cls(
            major=int(major),
            type=VersionType(type_char),
            minor=int(minor),
            build=build
        )
    
    def __str__(self) -> str:
        """String representation of version."""
        version_str = f"{self.type.value}.{self.major}.{self.minor}-{self.build or '1'}"
        return version_str
    
    def __eq__(self, other) -> bool:
        """Version equality comparison."""
        if not isinstance(other, Version):
            return False
        return (self.major, self.type, self.minor) == (other.major, other.type, other.minor)
    
    def __lt__(self, other) -> bool:
        """Version less than comparison."""
        if not isinstance(other, Version):
            return NotImplemented
        
        # Compare major version first
        if self.major != other.major:
            return self.major < other.major
        
        # Compare type (alpha < beta < release)
        type_order = {VersionType.ALPHA: 0, VersionType.BETA: 1, VersionType.RELEASE: 2}
        if self.type != other.type:
            return type_order[self.type] < type_order[other.type]
        
        # Compare minor version
        return self.minor < other.minor
    
    def __le__(self, other) -> bool:
        return self == other or self < other
    
    def __gt__(self, other) -> bool:
        return not self <= other
    
    def __ge__(self, other) -> bool:
        return not self < other
    
    def is_compatible_with(self, other: 'Version') -> bool:
        """Check if versions are compatible for upgrades."""
        # Same major version is always compatible
        if self.major == other.major:
            return True
        
        # Can upgrade from previous major version
        if other.major == self.major - 1:
            return True
        
        return False
    
    def get_status(self) -> VersionStatus:
        """Get version status based on type."""
        if self.type == VersionType.ALPHA:
            return VersionStatus.DEVELOPMENT
        elif self.type == VersionType.BETA:
            return VersionStatus.TESTING
        else:  # RELEASE
            return VersionStatus.STABLE


@dataclass
class VersionInfo:
    """Complete version information."""
    version: Version
    release_date: datetime
    status: VersionStatus
    changelog: List[str] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)
    migration_required: bool = False
    database_version: Optional[str] = None
    config_version: Optional[str] = None
    dependencies: Dict[str, str] = field(default_factory=dict)
    security_updates: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": str(self.version),
            "release_date": self.release_date.isoformat(),
            "status": self.status.value,
            "changelog": self.changelog,
            "breaking_changes": self.breaking_changes,
            "migration_required": self.migration_required,
            "database_version": self.database_version,
            "config_version": self.config_version,
            "dependencies": self.dependencies,
            "security_updates": self.security_updates
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VersionInfo':
        """Create from dictionary."""
        return cls(
            version=Version.parse(data["version"]),
            release_date=datetime.fromisoformat(data["release_date"]),
            status=VersionStatus(data["status"]),
            changelog=data.get("changelog", []),
            breaking_changes=data.get("breaking_changes", []),
            migration_required=data.get("migration_required", False),
            database_version=data.get("database_version"),
            config_version=data.get("config_version"),
            dependencies=data.get("dependencies", {}),
            security_updates=data.get("security_updates", [])
        )


class VersionManager:
    """Advanced version management system."""
    
    def __init__(self, version_file: Path = None):
        """Initialize version manager."""
        self.version_file = version_file or from pathlib import Path
Path("version.json")
        self.changelog_file = from pathlib import Path
Path("CHANGELOG.md")
        self.current_version: Optional[Version] = None
        self.version_history: List[VersionInfo] = []
        
        # Load current version and history
        self._load_version_info()
    
    def _load_version_info(self):
        """Load version information from files."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    data = json.load(f)
                    self.current_version = Version.parse(data["current_version"])
                    self.version_history = [
                        VersionInfo.from_dict(v) for v in data.get("history", [])
                    ]
            else:
                # Initialize with default version
                self.current_version = Version(1, VersionType.ALPHA, 1, "1")
                self._save_version_info()
        except Exception as e:
            logger.error(f"Failed to load version info: {e}")
            self.current_version = Version(1, VersionType.ALPHA, 1, "1")
    
    def _save_version_info(self):
        """Save version information to file."""
        try:
            data = {
                "current_version": str(self.current_version),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "history": [v.to_dict() for v in self.version_history]
            }
            
            with open(self.version_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save version info: {e}")
    
    def get_current_version(self) -> Version:
        """Get current version."""
        return self.current_version
    
    def get_version_info(self, version: Version) -> Optional[VersionInfo]:
        """Get information for specific version."""
        for info in self.version_history:
            if info.version == version:
                return info
        return None
    
    def get_next_version(self, version_type: VersionType = None) -> Version:
        """Get next version based on current version and type."""
        current = self.current_version
        
        if version_type is None:
            # Auto-increment based on current type
            if current.type == VersionType.ALPHA:
                version_type = VersionType.BETA
            elif current.type == VersionType.BETA:
                version_type = VersionType.RELEASE
            else:  # RELEASE
                version_type = VersionType.ALPHA
        
        if version_type == VersionType.ALPHA:
            if current.type == VersionType.RELEASE:
                # New major version alpha
                return Version(current.major, VersionType.ALPHA, current.minor + 1)
            else:
                # Same major, increment minor
                return Version(current.major, VersionType.ALPHA, current.minor + 1)
        elif version_type == VersionType.BETA:
            if current.type == VersionType.ALPHA:
                # Same version, beta stage
                return Version(current.major, VersionType.BETA, current.minor)
            else:
                # New beta version
                return Version(current.major, VersionType.BETA, current.minor + 1)
        else:  # RELEASE
            if current.type == VersionType.BETA:
                # Same version, release stage
                return Version(current.major, VersionType.RELEASE, current.minor)
            else:
                # New release version
                return Version(current.major, VersionType.RELEASE, current.minor + 1)
    
    def can_upgrade_to(self, target_version: Version) -> Tuple[bool, str]:
        """Check if upgrade to target version is possible."""
        current = self.current_version
        
        if target_version <= current:
            return False, f"Target version {target_version} is not newer than current {current}"
        
        if not target_version.is_compatible_with(current):
            return False, f"Version {target_version} is not compatible with current {current}"
        
        return True, "Upgrade is possible"
    
    def can_downgrade_to(self, target_version: Version) -> Tuple[bool, str]:
        """Check if downgrade to target version is possible."""
        current = self.current_version
        
        if target_version >= current:
            return False, f"Target version {target_version} is not older than current {current}"
        
        # Check if target version exists in history
        target_info = self.get_version_info(target_version)
        if not target_info:
            return False, f"Version {target_version} not found in history"
        
        # Check for breaking changes between versions
        for info in self.version_history:
            if target_version < info.version <= current:
                if info.breaking_changes:
                    return False, f"Breaking changes in {info.version} prevent downgrade"
        
        return True, "Downgrade is possible"
    
    def register_version(self, version_info: VersionInfo):
        """Register a new version in history."""
        # Remove existing entry if present
        self.version_history = [v for v in self.version_history if v.version != version_info.version]
        
        # Add new version info
        self.version_history.append(version_info)
        
        # Sort by version
        self.version_history.sort(key=lambda x: x.version)
        
        # Save to file
        self._save_version_info()
    
    def set_current_version(self, version: Version):
        """Set current version."""
        self.current_version = version
        self._save_version_info()
        logger.info(f"Current version set to {version}")
    
    def get_upgrade_path(self, target_version: Version) -> List[Version]:
        """Get upgrade path from current to target version."""
        self.current_version
        path = []
        
        # Simple path for now - direct upgrade
        # TODO: Implement complex multi-step upgrade paths
        if self.can_upgrade_to(target_version)[0]:
            path.append(target_version)
        
        return path
    
    def get_available_versions(self) -> List[Version]:
        """Get all available versions."""
        return [info.version for info in self.version_history]
    
    def get_latest_stable_version(self) -> Optional[Version]:
        """Get latest stable (release) version."""
        stable_versions = [
            info.version for info in self.version_history
            if info.version.type == VersionType.RELEASE
        ]
        return max(stable_versions) if stable_versions else None


# Global version manager instance
version_manager = VersionManager()
