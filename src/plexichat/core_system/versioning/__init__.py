# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .changelog_manager import (
from typing import Optional


    Advanced,
    New,
    PlexiChat,
    System,
    Version,
    Versioning,
    """,
    -,
    .update_system,
    .version_manager,
    a.1.1-1,
    b.1.2-1,
    comprehensive,
    e.g.,
    format:,
    from,
    import,
    letter.major.minor-build,
    logging,
    management:,
    r.1.0-1,
    scheme,
    update,
    versioning,
    with,
)

- Types: 'a' (alpha), 'b' (beta), 'r' (release)
- In-place upgrades and downgrades
- Configuration and database migration
- Clustering integration
- Rollback capabilities
- Changelog management

Features:
- Semantic version parsing and comparison
- Version lifecycle management
- Upgrade/downgrade path validation
- Changelog integration
- Database schema versioning
- Configuration migration support
- Dependency management
- Security update detection
- Backup and rollback system
"""

    ChangeEntry,
    ChangelogManager,
    ChangeType,
    VersionChangelog,
    changelog_manager,
)
    UpdatePlan,
    UpdateResult,
    UpdateStatus,
    UpdateSystem,
    UpdateType,
    update_system,
)
    Version,
    VersionInfo,
    VersionManager,
    VersionStatus,
    VersionType,
    version_manager,
)

__version__ = "1.0.0"
__all__ = [
    # Version management
    "Version",
    "VersionType",
    "VersionStatus",
    "VersionInfo",
    "VersionManager",
    "version_manager",

    # Changelog management
    "ChangeType",
    "ChangeEntry",
    "VersionChangelog",
    "ChangelogManager",
    "changelog_manager",

    # Update system
    "UpdateType",
    "UpdateStatus",
    "UpdatePlan",
    "UpdateResult",
    "UpdateSystem",
    "update_system"
]

# Version utilities
def get_current_version() -> Version:
    """Get current PlexiChat version."""
    return version_manager.get_current_version()

def get_version_string() -> str:
    """Get current version as string."""
    return str(version_manager.get_current_version())

def parse_version(version_string: str) -> Version:
    """Parse version string into Version object."""
    return Version.parse(version_string)

def compare_versions(version1: str, version2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    v1 = Version.parse(version1)
    v2 = Version.parse(version2)

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def is_version_compatible(current: str, target: str) -> bool:
    """Check if target version is compatible with current."""
    current_version = Version.parse(current)
    target_version = Version.parse(target)
    return target_version.is_compatible_with(current_version)

# Changelog utilities
def get_changelog(version: Optional[str] = None, since_version: Optional[str] = None) -> str:
    """Get changelog for version or since version."""
    if version:
        v = Version.parse(version)
        return update_system.show_changelog(version=v)
    elif since_version:
        v = Version.parse(since_version)
        return update_system.show_changelog(since_version=v)
    else:
        return update_system.show_changelog()

def get_breaking_changes_since(version: str) -> list:
    """Get breaking changes since specified version."""
    since_version = Version.parse(version)
    return changelog_manager.get_breaking_changes_since_version(since_version)

# Update utilities
async def check_for_updates():
    """Check for available updates."""
    return await update_system.check_for_updates()

async def upgrade_to_version(target_version: str, force: bool = False):
    """Upgrade to specific version."""
    target = Version.parse(target_version)
    plan = await update_system.create_update_plan(target, UpdateType.UPGRADE)

    if not force and plan.breaking_changes:
        raise ValueError(f"Breaking changes detected. Use force=True to proceed: {plan.breaking_changes}")

    return await update_system.execute_update(plan)

async def downgrade_to_version(target_version: str, force: bool = False):
    """Downgrade to specific version."""
    target = Version.parse(target_version)
    plan = await update_system.create_update_plan(target, UpdateType.DOWNGRADE)

    if not force and plan.breaking_changes:
        raise ValueError(f"Breaking changes detected. Use force=True to proceed: {plan.breaking_changes}")

    return await update_system.execute_update(plan)

# Version validation
def validate_version_format(version_string: str) -> bool:
    """Validate version string format."""
    try:
        Version.parse(version_string)
        return True
    except ValueError:
        return False

def get_next_version_suggestion(current_version: Optional[str] = None, version_type: Optional[str] = None) -> str:
    """Get suggested next version."""
    if current_version:
        current = Version.parse(current_version)
        version_manager.current_version = current

    if version_type:
        vtype = VersionType(version_type)
        next_version = version_manager.get_next_version(vtype)
    else:
        next_version = version_manager.get_next_version()

    return str(next_version)

# System integration
def initialize_versioning_system():
    """Initialize the versioning system."""
    try:
        # Load version information
        version_manager._load_version_info()
        changelog_manager._load_changelog()

        # Ensure current version is set
        if not version_manager.current_version:
            initial_version = Version(0, VersionType.ALPHA, 1)
            version_manager.set_current_version(initial_version)

        return True
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to initialize versioning system: {e}")
        return False

# Auto-initialize on import
initialize_versioning_system()
