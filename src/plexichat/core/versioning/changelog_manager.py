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
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
import tempfile
import shutil

from .version_manager import Version

"""
import time
PlexiChat Changelog Management System

Manages changelog generation, parsing, and integration with the version system.
Supports multiple formats and automatic changelog generation from commits.


logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes in changelog."""
        ADDED = "Added"
    CHANGED = "Changed"
    DEPRECATED = "Deprecated"
    REMOVED = "Removed"
    FIXED = "Fixed"
    SECURITY = "Security"
    BREAKING = "Breaking"


@dataclass
class ChangeEntry:
    """Individual change entry.
    type: ChangeType
    description: str
    component: Optional[str] = None
    issue_id: Optional[str] = None
    author: Optional[str] = None
    commit_hash: Optional[str] = None

    def to_markdown(self) -> str:
        """Convert to markdown format."""
        prefix = f"**{self.component}**: " if self.component else ""
        suffix = f" (#{self.issue_id})" if self.issue_id else ""
        return f"- {prefix}{self.description}{suffix}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type.value,
            "description": self.description,
            "component": self.component,
            "issue_id": self.issue_id,
            "author": self.author,
            "commit_hash": self.commit_hash
        }}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChangeEntry':
        """Create from dictionary."""
        return cls(
            type=ChangeType(data["type"]),
            description=data["description"],
            component=data.get("component"),
            issue_id=data.get("issue_id"),
            author=data.get("author"),
            commit_hash=data.get("commit_hash")
        )


@dataclass
class VersionChangelog:
    """Changelog for a specific version.
        version: Version
    release_date: datetime
    changes: Dict[ChangeType, List[ChangeEntry]] = field(default_factory=dict)
    summary: Optional[str] = None
    migration_notes: List[str] = field(default_factory=list)

    def add_change(self, change: ChangeEntry):
        """Add a change entry."""
        if change.type not in self.changes:
            self.changes[change.type] = []
        self.changes[change.type].append(change)

    def get_changes_by_type(self, change_type: ChangeType) -> List[ChangeEntry]:
        Get changes by type."""
        return self.changes.get(change_type, [])

    def has_breaking_changes(self) -> bool:
        """Check if version has breaking changes.
        return ChangeType.BREAKING in self.changes and len(self.changes[ChangeType.BREAKING]) > 0

    def to_markdown(self) -> str:
        """Convert to markdown format."""
        lines = []

        # Version header
        version_str = str(self.version)
        date_str = self.release_date.strftime("%Y-%m-%d")
        lines.append(f"## [{version_str}] - {date_str}")
        lines.append("")

        # Summary
        if self.summary:
            lines.append(self.summary)
            lines.append("")

        # Changes by type
        for change_type in ChangeType:
            if change_type in self.changes and self.changes[change_type]:
                lines.append(f"### {change_type.value}")
                for change in self.changes[change_type]:
                    lines.append(change.to_markdown())
                lines.append("")

        # Migration notes
        if self.migration_notes:
            lines.append("### Migration Notes")
            for note in self.migration_notes:
                lines.append(f"- {note}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": str(self.version),
            "release_date": self.release_date.isoformat(),
            "changes": {
                change_type.value: [change.to_dict() for change in changes]
                for change_type, changes in self.changes.items()
            }},
            "summary": self.summary,
            "migration_notes": self.migration_notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VersionChangelog':
        """Create from dictionary."""
        changelog = cls(
            version=Version.parse(data["version"]),
            release_date=datetime.fromisoformat(data["release_date"]),
            summary=data.get("summary"),
            migration_notes=data.get("migration_notes", [])
        )
        # Parse changes
        for change_type_str, changes_data in data.get("changes", {}).items():
            change_type = ChangeType(change_type_str)
            changelog.changes[change_type] = [
                ChangeEntry.from_dict(change_data) for change_data in changes_data
            ]
        return changelog


class ChangelogManager:
    """Manages changelog generation and parsing.
        def __init__(self, changelog_file: Optional[Path] = None):
        """Initialize changelog manager."""
        self.changelog_file = changelog_file or Path("CHANGELOG.md")
        self.changelog_data_file = Path("changelog.json")
        self.version_changelogs: Dict[str, VersionChangelog] = {}
        # Load existing changelog
        self._load_changelog()

    def _load_changelog(self):
        """Load changelog from files."""
        try:
            # Load from JSON data file if exists
            if self.changelog_data_file.exists() if self.changelog_data_file else False:
                with open(self.changelog_data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                    # Validate data structure
                    if not isinstance(data, dict):
                        logger.warning("Changelog data is not a dictionary, skipping")
                        return

                    for version_str, changelog_data in data.items():
                        try:
                            # Validate changelog_data structure
                            if not isinstance(changelog_data, dict):
                                logger.warning(f"Changelog data for version {version_str} is not a dictionary, skipping")
                                continue

                            changelog = VersionChangelog.from_dict(changelog_data)
                            self.version_changelogs[version_str] = changelog
                        except Exception as e:
                            logger.warning(f"Failed to load changelog for version {version_str}: {e}")
                            continue

            # Parse markdown file if JSON doesn't exist
            elif self.changelog_file.exists() if self.changelog_file else False:
                self._parse_markdown_changelog()
        except Exception as e:
            logger.error(f"Failed to load changelog: {e}")

    def _save_changelog(self):
        """Save changelog to files atomically."""
        try:
            # Save JSON data
            data = {
                version_str: changelog.to_dict()
                for version_str, changelog in self.version_changelogs.items()
            }
            temp_json = str(self.changelog_data_file) + ".tmp"
            with open(temp_json, 'w') as f:
                json.dump(data, f, indent=2)
            shutil.move(temp_json, self.changelog_data_file)

            # Generate markdown
            self._generate_markdown_changelog()
        except Exception as e:
            logger.error(f"Failed to save changelog: {e}")

    def _parse_markdown_changelog(self):
        """Parse existing markdown changelog."""
        try:
            with open(self.changelog_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Simple parsing - extract version headers and changes
            version_pattern = r'## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})'
            versions = re.findall(version_pattern, content)

            for version_str, date_str in versions:
                try:
                    version = Version.parse(version_str)
                    release_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)

                    changelog = VersionChangelog(version=version, release_date=release_date)
                    self.version_changelogs[version_str] = changelog
                except Exception as e:
                    logger.warning(f"Failed to parse version {version_str}: {e}")
        except Exception as e:
            logger.error(f"Failed to parse markdown changelog: {e}")

    def _generate_markdown_changelog(self):
        """Generate markdown changelog file atomically, no emoji or non-standard formatting."""
        try:
            lines = [
                "# Changelog",
                "",
                "All notable changes to PlexiChat will be documented in this file.",
                "",
                "The format is based on Keep a Changelog (https://keepachangelog.com/en/1.0.0/),",
                "and this project adheres to Semantic Versioning (https://semver.org/spec/v2.0.0.html).",
                "",
                "## Version Format",
                "",
                "PlexiChat uses a custom versioning scheme: {major}{type}{minor}",
                "- Types: a (alpha), b (beta), r (release)",
                "- Examples: 0a1, 0b1, 0r1, 0a2, 1r1",
                "",
                "---",
                ""
            ]
            # Sort versions in descending order
            sorted_versions = sorted(
                self.version_changelogs.values(),
                key=lambda x: x.version,
                reverse=True
            )
            for changelog in sorted_versions:
                lines.append(changelog.to_markdown())
            temp_md = str(self.changelog_file) + ".tmp"
            with open(temp_md, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines))
            shutil.move(temp_md, self.changelog_file)
        except Exception as e:
            logger.error(f"Failed to generate markdown changelog: {e}")

    def add_version_changelog(self, changelog: VersionChangelog):
        """Add changelog for a version."""
        version_str = str(changelog.version)
        self.version_changelogs[version_str] = changelog
        self._save_changelog()
        logger.info(f"Added changelog for version {version_str}")

    def get_version_changelog(self, version: Version) -> Optional[VersionChangelog]:
        """Get changelog for specific version.
        return self.version_changelogs.get(str(version))

    def create_version_changelog(self, version: Version, summary: Optional[str] = None) -> VersionChangelog:
        """Create new version changelog."""
        changelog = VersionChangelog(
            version=version,
            release_date=datetime.now(timezone.utc),
            summary=summary
        )
        return changelog

    def add_change(self, version: Version, change: ChangeEntry):
        Add change to version changelog."""
        version_str = str(version)
        if version_str not in self.version_changelogs:
            self.version_changelogs[version_str] = self.create_version_changelog(version)

        self.version_changelogs[version_str].add_change(change)
        self._save_changelog()

    def get_changes_since_version(self, since_version: Version) -> List[VersionChangelog]:
        """Get all changes since a specific version.
        changes = []
        for changelog in self.version_changelogs.values():
            if changelog.version > since_version:
                changes.append(changelog)

        return sorted(changes, key=lambda x: x.version)

    def get_breaking_changes_since_version(self, since_version: Version) -> List[ChangeEntry]:
        """Get breaking changes since a specific version."""
        breaking_changes = []
        for changelog in self.version_changelogs.values():
            if changelog.version > since_version:
                breaking_changes.extend(changelog.get_changes_by_type(ChangeType.BREAKING))

        return breaking_changes

    def generate_release_notes(self, version: Version) -> str:
        Generate release notes for a version."""
        changelog = self.get_version_changelog(version)
        if not changelog:
            return f"No changelog found for version {version}"
        lines = [
            f"# PlexiChat {version} Release Notes",
            "",
            f"Released: {changelog.release_date.strftime('%Y-%m-%d')}",
            ""
        ]
        if changelog.summary:
            lines.extend([changelog.summary, ""])
        # Highlight breaking changes
        breaking_changes = changelog.get_changes_by_type(ChangeType.BREAKING)
        if breaking_changes:
            lines.extend([
                "##  Breaking Changes",
                "",
                "**Important**: This version contains breaking changes that may require manual intervention.",
                ""
            ])
            for change in breaking_changes:
                lines.append(f"- {change.description}")
            lines.append("")
        # Add other changes
        for change_type in [ChangeType.ADDED, ChangeType.CHANGED, ChangeType.FIXED, ChangeType.SECURITY]:
            changes = changelog.get_changes_by_type(change_type)
            if changes:
                lines.extend([
                    f"## {change_type.value}",
                    ""
                ])
                for change in changes:
                    lines.append(change.to_markdown())
                lines.append("")
        # Migration notes
        if changelog.migration_notes:
            lines.extend([
                "##  Migration Notes",
                ""
            ])
            for note in changelog.migration_notes:
                lines.append(f"- {note}")
            lines.append("")
        return "\n".join(lines)

    def auto_generate_changelog_from_commits(self, version: Version, commits: List[Dict[str, Any]]) -> VersionChangelog:
        """Auto-generate changelog from commit messages."""
        changelog = self.create_version_changelog(version)

        # Parse commit messages for conventional commits
        for commit in commits:
            message = commit.get("message", "")
            author = commit.get("author", "")
            hash_val = commit.get("hash", "")

            # Parse conventional commit format
            change_entry = self._parse_commit_message(message, author, hash_val)
            if change_entry:
                changelog.add_change(change_entry)

        return changelog

    def _parse_commit_message(self, message: str, author: Optional[str] = None, commit_hash: Optional[str] = None) -> Optional[ChangeEntry]:
        """Parse commit message for changelog entry."""
        # Conventional commit pattern: type(scope): description
        pattern = r'^(feat|fix|docs|style|refactor|test|chore|security|breaking)(?:\(([^)]+)\))?: (.+)$'
        match = re.match(pattern, message.strip(), re.IGNORECASE)
        if not match:
            return None
        commit_type, scope, description = match.groups()
        # Map commit types to change types
        type_mapping = {
            "feat": ChangeType.ADDED,
            "fix": ChangeType.FIXED,
            "docs": ChangeType.CHANGED,
            "style": ChangeType.CHANGED,
            "refactor": ChangeType.CHANGED,
            "test": ChangeType.CHANGED,
            "chore": ChangeType.CHANGED,
            "security": ChangeType.SECURITY,
            "breaking": ChangeType.BREAKING
        }
        change_type = type_mapping.get(commit_type.lower(), ChangeType.CHANGED)
        return ChangeEntry(
            type=change_type,
            description=description,
            component=scope,
            author=author,
            commit_hash=commit_hash
        )


# Global changelog manager instance
changelog_manager = ChangelogManager()
