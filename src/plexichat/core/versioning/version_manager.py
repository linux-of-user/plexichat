# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime  # , timezone  # Unused import
from enum import Enum
# from pathlib import Path  # Unused import
from typing import Any, Dict, List, Optional  # , Tuple  # Unused import
import os
import tempfile
import shutil

"""
import string
import time
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
        # Accept 'main' and other branch/tag names as special versions
        if version_string.strip().lower() in ("main", "master", "latest"):
            return cls(major=0, type=VersionType.ALPHA, minor=0, build="main")
        # Accept v1.2.3 or v1.2.3-4 as valid tags
        vtag_pattern = r'^v(\d+)\.(\d+)\.(\d+)(?:-(\d+))?$'
        vtag_match = re.match(vtag_pattern, version_string.strip())
        if vtag_match:
            major, minor, patch, build = vtag_match.groups()
            return cls(major=int(major), type=VersionType.RELEASE, minor=int(minor), build=build or patch)
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
    """Manages version information and auto-generates version files."""

    def __init__(self):
        # Get current build number from GitHub releases
        self.build_number = self._get_github_release_count()
        self.current_version = f"b.1.1-{self.build_number}"
        self.version_type = "beta"
        self.major_version = 1
        self.minor_version = 1
        self.api_version = "v1"
        self.release_date = datetime.now().strftime("%Y-%m-%d")

        # Parse version components
        self._parse_version()

        # Load additional version info
        self._load_version_info()

        # Auto-generate version files if they don't exist
        self._ensure_version_files_exist()

    def _get_github_release_count(self) -> int:
        """Get current build number from GitHub releases."""
        try:
            import requests

            # Try to get GitHub repo info from git remote
            repo_url = self._get_github_repo_url()
            if repo_url:
                api_url = f"https://api.github.com/repos/{repo_url}/releases"
                response = requests.get(api_url, timeout=10)
                if response.status_code == 200:
                    releases = response.json()
                    if releases:
                        # Get the latest release build number
                        latest_release = releases[0]
                        tag_name = latest_release.get('tag_name', '')
                        if '-' in tag_name:
                            try:
                                build_num = int(tag_name.split('-')[-1])
                                logger.info(f"Found latest GitHub release build: {build_num}")
                                return build_num
                            except ValueError:
                                pass

                        # If no build number in tag, count releases
                        build_num = len(releases) + 81  # Start from 82
                        logger.info(f"Calculated build number from release count: {build_num}")
                        return build_num

        except Exception as e:
            logger.warning(f"Could not get GitHub release count: {e}")

        # Fallback to current build number
        return 82

    def _get_github_repo_url(self) -> str:
        """Get GitHub repository URL from git remote."""
        try:
            import subprocess
            result = subprocess.run(
                ['git', 'remote', 'get-url', 'origin'],
                capture_output=True,
                text=True,
                cwd=os.path.dirname(__file__)
            )
            if result.returncode == 0:
                url = result.stdout.strip()
                # Convert git URL to repo path
                if 'github.com' in url:
                    if url.startswith('git@'):
                        # git@github.com:user/repo.git -> user/repo
                        repo_path = url.split(':')[1].replace('.git', '')
                    elif url.startswith('https://'):
                        # https://github.com/user/repo.git -> user/repo
                        repo_path = '/'.join(url.split('/')[-2:]).replace('.git', '')
                    else:
                        return ""
                    return repo_path
        except Exception as e:
            logger.warning(f"Could not get GitHub repo URL: {e}")
        return ""

    def _load_version_info(self):
        """Load additional version information."""
        try:
            # Load from version.json if it exists
            version_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", "version.json")
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    import json
                    version_data = json.load(f)
                    self.release_date = version_data.get('release_date', self.release_date)
                    self.api_version = version_data.get('api_version', self.api_version)
                    logger.info(f"Loaded version info from {version_file}")
        except Exception as e:
            logger.warning(f"Could not load version info: {e}")

    def _ensure_version_files_exist(self):
        """Ensure version.json and changelog.json exist, create if missing."""
        try:
            root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
            version_file = os.path.join(root_dir, "version.json")
            changelog_file = os.path.join(root_dir, "changelog.json")

            # Create version.json if it doesn't exist
            if not os.path.exists(version_file):
                logger.info("Creating missing version.json file")
                self.auto_generate_files()

            # Create changelog.json if it doesn't exist
            if not os.path.exists(changelog_file):
                logger.info("Creating missing changelog.json file")
                self.auto_generate_files()

        except Exception as e:
            logger.error(f"Error ensuring version files exist: {e}")

    def _parse_version(self):
        """Parse version string into components."""
        try:
            # Format: letter.major.minor-build (e.g., a.1.1-18)
            import re
            pattern = r'^([abr])\.(\d+)\.(\d+)-(\d+)$'
            match = re.match(pattern, self.current_version.strip())
            if not match:
                raise ValueError(f"Invalid version format: {self.current_version}")
            letter, major, minor, build = match.groups()
            self.major_version = int(major)
            self.minor_version = int(minor)
            self.build_number = int(build)
            type_mapping = {
                'a': 'alpha',
                'b': 'beta',
                'r': 'release',
                'c': 'candidate'
            }
            self.version_type = type_mapping.get(letter, 'unknown')
        except Exception as e:
            logger.error(f"Failed to parse version {self.current_version}: {e}")

    def generate_version_json(self) -> Dict[str, Any]:
        """Generate version.json content."""
        return {
            "version": self.current_version,
            "version_type": self.version_type,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "build_number": self.build_number,
            "release_date": self.release_date,
            "api_version": self.api_version,
            "compatibility": {
                "min_client_version": f"a.{self.major_version}.0-0",
                "max_client_version": f"a.{self.major_version + 1}.0-999"
            },
            "features": {
                "file_attachments": True,
                "ai_integration": True,
                "security_scanning": True,
                "backup_system": True,
                "real_time_messaging": True,
                "plugin_system": True
            },
            "changelog": [
                {
                    "version": self.current_version,
                    "date": self.release_date,
                    "changes": [
                        "Implemented new versioning system (letter.majorversion.minorversion-buildnumber)",
                        "Added comprehensive file attachment support",
                        "Enhanced message endpoints with file uploads",
                        "Improved API error handling and validation",
                        "Added security scanning for uploaded files",
                        "Implemented auto-generated version.json and changelog.json",
                        "Enhanced backup system integration",
                        "Added real-time messaging capabilities",
                        "Improved plugin system architecture"
                    ],
                    "breaking_changes": [],
                    "deprecations": []
                }
            ]
        }

    def generate_changelog_json(self) -> Dict[str, Any]:
        """Generate changelog.json content."""
        return {
            "project": "PlexiChat",
            "description": "Government-Level Secure Communication Platform",
            "versions": [
                {
                    "version": self.current_version,
                    "date": self.release_date,
                    "type": self.version_type,
                    "status": "current",
                    "changes": {
                        "added": [
                            "New versioning system (letter.majorversion.minorversion-buildnumber)",
                            "Comprehensive file attachment support for messages",
                            "Enhanced file upload endpoints with validation",
                            "Security scanning for uploaded files",
                            "Auto-generated version.json and changelog.json",
                            "Improved API error handling and validation",
                            "Enhanced backup system integration",
                            "Real-time messaging capabilities",
                            "Plugin system architecture improvements",
                            "File permission management system",
                            "Message threading and replies",
                            "Voice message support",
                            "Advanced search functionality",
                            "User profile management",
                            "Admin dashboard improvements"
                        ],
                        "changed": [
                            "Updated version format throughout codebase",
                            "Improved error handling in main application",
                            "Enhanced router loading system",
                            "Better import error handling",
                            "Updated configuration management",
                            "Improved logging system"
                        ],
                        "fixed": [
                            "Import errors in main.py",
                            "Broken router loading",
                            "Missing file upload endpoints",
                            "Incomplete message attachment functionality",
                            "Version inconsistency across files"
                        ],
                        "deprecated": [],
                        "removed": [],
                        "security": [
                            "File upload validation",
                            "Security scanning for uploaded files",
                            "Enhanced authentication middleware",
                            "Improved permission system"
                        ]
                    },
                    "api_changes": {
                        "added": [
                            "POST /api/v1/files/upload - File upload endpoint",
                            "GET /api/v1/files/{file_id} - File download endpoint",
                            "POST /api/v1/messages/create - Enhanced message creation with attachments",
                            "PUT /api/v1/messages/{message_id} - Message editing with file management",
                            "GET /api/v1/messages/{message_id}/attachments - Get message attachments",
                            "POST /api/v1/security/scan/file - File security scanning",
                            "GET /api/v1/version - Version information endpoint"
                        ],
                        "changed": [
                            "Updated message endpoints to support file attachments",
                            "Enhanced file management endpoints",
                            "Improved error responses"
                        ]
                    },
                    "breaking_changes": [],
                    "migration_notes": "This version introduces a new versioning format. Update any version parsing code to handle the new format."
                },
                {
                    "version": f"a.{self.major_version}.0-15",
                    "date": "2024-12-18",
                    "type": "alpha",
                    "status": "previous",
                    "changes": {
                        "added": [
                            "Basic messaging system",
                            "User authentication",
                            "File management",
                            "Backup system foundation"
                        ],
                        "changed": [],
                        "fixed": [],
                        "deprecated": [],
                        "removed": []
                    }
                }
            ],
            "version_format": {
                "description": "letter.majorversion.minorversion-buildnumber",
                "examples": [
                    f"{self.current_version} (alpha version {self.major_version}.{self.minor_version} build {self.build_number})",
                    "b.2.1-5 (beta version 2.1 build 5)",
                    "r.1.0-10 (release version 1.0 build 10)"
                ],
                "letters": {
                    "a": "alpha",
                    "b": "beta",
                    "r": "release",
                    "c": "candidate"
                }
            }
        }

    def _write_version_file(self):
        """Write the current version to version.json in the repo root atomically."""
        version_data = {
            "current_version": self.current_version,
            "version_type": self.version_type,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "build_number": self.build_number,
            "release_date": self.release_date,
            "api_version": self.api_version
        }
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
        version_file = os.path.join(root_dir, "version.json")
        temp_file = version_file + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(version_data, f, indent=2)
        shutil.move(temp_file, version_file)

    def update_version(self, new_version: str):
        """Update to a new version."""
        self.current_version = new_version
        self._parse_version()
        self.release_date = datetime.now().strftime("%Y-%m-%d")
        logger.info(f"Updated version to {new_version}")
        self._write_version_file()

    def increment_build(self):
        """Increment build number."""
        self.build_number += 1
        self.current_version = f"a.{self.major_version}.{self.minor_version}-{self.build_number}"
        self.release_date = datetime.now().strftime("%Y-%m-%d")
        logger.info(f"Incremented build to {self.current_version}")
        self._write_version_file()

    def increment_minor(self):
        """Increment minor version."""
        self.minor_version += 1
        self.build_number = 0
        self.current_version = f"a.{self.major_version}.{self.minor_version}-{self.build_number}"
        self.release_date = datetime.now().strftime("%Y-%m-%d")
        logger.info(f"Incremented minor version to {self.current_version}")
        self._write_version_file()

    def increment_major(self):
        """Increment major version."""
        self.major_version += 1
        self.minor_version = 0
        self.build_number = 0
        self.current_version = f"a.{self.major_version}.{self.minor_version}-{self.build_number}"
        self.release_date = datetime.now().strftime("%Y-%m-%d")
        logger.info(f"Incremented major version to {self.current_version}")
        self._write_version_file()

    def auto_generate_files(self):
        """Auto-generate version.json and changelog.json files atomically."""
        try:
            root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))

            # Generate version.json
            version_data = self.generate_version_json()
            version_file = os.path.join(root_dir, "version.json")
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", prefix="version-") as tf:
                json.dump(version_data, tf, indent=2)
                temp_version_path = tf.name
            shutil.move(temp_version_path, version_file)
            logger.info(f"Auto-generated version.json at {version_file}")

            # Generate changelog.json
            changelog_data = self.generate_changelog_json()
            changelog_file = os.path.join(root_dir, "changelog.json")
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", prefix="changelog-") as tf:
                json.dump(changelog_data, tf, indent=2)
                temp_changelog_path = tf.name
            shutil.move(temp_changelog_path, changelog_file)
            logger.info(f"Auto-generated changelog.json at {changelog_file}")

        except Exception as e:
            logger.error(f"Failed to auto-generate version files: {e}")

    def get_version_info(self) -> Dict[str, Any]:
        """Get current version information."""
        return {
            "version": self.current_version,
            "version_type": self.version_type,
            "major_version": self.major_version,
            "minor_version": self.minor_version,
            "build_number": self.build_number,
            "api_version": self.api_version,
            "release_date": self.release_date
        }

# Global version manager instance
version_manager = VersionManager()

def get_version_manager() -> VersionManager:
    """Get the global version manager instance."""
    return version_manager

def auto_generate_version_files():
    """Auto-generate version files."""
    version_manager.auto_generate_files()
# Monkey-patch: set_current_version as alias for update_version
VersionManager.set_current_version = VersionManager.update_version
