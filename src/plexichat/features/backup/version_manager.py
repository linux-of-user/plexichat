"""
Version Manager - Backup versioning and differential storage
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class VersionManager:
    """
    Manages backup versions and differential storage.

    Features:
    - Version tracking and metadata
    - Differential backup support
    - Version cleanup and retention policies
    """

    def __init__(self, storage_root: str = "backup_storage"):
        project_root = Path(__file__).parent.parent.parent.parent.parent
        self.storage_root = project_root / storage_root
        self.versions_storage = self.storage_root / "versions"
        self.versions_storage.mkdir(exist_ok=True)
        self.logger = logger

    def create_version(self, backup_id: str, version_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new backup version.

        Args:
            backup_id: Backup identifier
            version_data: Version metadata

        Returns:
            Version information
        """
        try:
            version_id = f"{backup_id}_v{int(datetime.now().timestamp())}"

            version_info = {
                "version_id": version_id,
                "backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "metadata": version_data
            }

            version_path = self.versions_storage / f"{version_id}.json"
            with open(version_path, 'w') as f:
                json.dump(version_info, f, indent=2)

            self.logger.info(f"Created version: {version_id}")
            return version_info

        except Exception as e:
            self.logger.error(f"Failed to create version: {e}")
            raise

    def get_versions(self, backup_id: str) -> List[Dict[str, Any]]:
        """
        Get all versions for a backup.

        Args:
            backup_id: Backup identifier

        Returns:
            List of version information
        """
        try:
            versions = []

            for version_file in self.versions_storage.glob(f"{backup_id}_v*.json"):
                with open(version_file, 'r') as f:
                    version_info = json.load(f)
                versions.append(version_info)

            # Sort by creation time
            versions.sort(key=lambda x: x['created_at'])

            return versions

        except Exception as e:
            self.logger.error(f"Failed to get versions: {e}")
            return []

    def delete_version(self, version_id: str) -> bool:
        """
        Delete a specific version.

        Args:
            version_id: Version identifier

        Returns:
            True if successful, False otherwise
        """
        try:
            version_path = self.versions_storage / f"{version_id}.json"
            if version_path.exists():
                version_path.unlink()
                self.logger.info(f"Deleted version: {version_id}")
                return True
            return False

        except Exception as e:
            self.logger.error(f"Failed to delete version: {e}")
            return False