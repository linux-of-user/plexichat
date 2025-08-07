"""
Backup Repository - Database abstraction for backup metadata
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BackupRepository:
    """
    Repository for backup-related database operations.

    Provides abstraction layer for:
    - Backup metadata management
    - Shard tracking and distribution
    - Recovery operation logging
    - User quota management
    - Backup node management
    """

    def __init__(self, storage_root: str = "backup_storage"):
        project_root = Path(__file__).parent.parent.parent.parent.parent
        self.storage_root = project_root / storage_root
        self.repository_storage = self.storage_root / "repository"
        self.repository_storage.mkdir(exist_ok=True)
        self.logger = logger

        # Initialize storage files
        self.backups_file = self.repository_storage / "backups.json"
        self.shards_file = self.repository_storage / "shards.json"
        self.recovery_logs_file = self.repository_storage / "recovery_logs.json"

        # Initialize empty files if they don't exist
        for file_path in [self.backups_file, self.shards_file, self.recovery_logs_file]:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump([], f)

    # Backup Operations
    async def create_backup(self, backup_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new backup record.

        Args:
            backup_data: Backup metadata

        Returns:
            Created backup record
        """
        try:
            # Add timestamp and ID if not present
            if 'backup_id' not in backup_data:
                backup_data['backup_id'] = f"backup_{int(datetime.now().timestamp())}"

            if 'created_at' not in backup_data:
                backup_data['created_at'] = datetime.now(timezone.utc).isoformat()

            # Load existing backups
            backups = self._load_backups()

            # Add new backup
            backups.append(backup_data)

            # Save updated backups
            self._save_backups(backups)

            self.logger.info(f"Created backup record: {backup_data['backup_id']}")
            return backup_data

        except Exception as e:
            self.logger.error(f"Failed to create backup record: {e}")
            raise

    async def get_backup(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """
        Get backup by ID.

        Args:
            backup_id: Backup identifier

        Returns:
            Backup record if found, None otherwise
        """
        try:
            backups = self._load_backups()

            for backup in backups:
                if backup.get('backup_id') == backup_id:
                    self.logger.info(f"Retrieved backup: {backup_id}")
                    return backup

            self.logger.warning(f"Backup not found: {backup_id}")
            return None

        except Exception as e:
            self.logger.error(f"Failed to get backup {backup_id}: {e}")
            return None

    async def update_backup_status(self, backup_id: str, status: str,
                                 metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update backup status and metadata.

        Args:
            backup_id: Backup identifier
            status: New backup status
            metadata: Optional additional metadata

        Returns:
            True if successful, False otherwise
        """
        try:
            backups = self._load_backups()

            for backup in backups:
                if backup.get('backup_id') == backup_id:
                    backup['status'] = status
                    backup['updated_at'] = datetime.now(timezone.utc).isoformat()

                    if metadata:
                        # Merge metadata
                        current_metadata = backup.get('metadata', {})
                        current_metadata.update(metadata)
                        backup['metadata'] = current_metadata

                    self._save_backups(backups)
                    self.logger.info(f"Updated backup status: {backup_id} -> {status}")
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to update backup status: {e}")
            return False

    async def list_backups(self, user_id: Optional[str] = None,
                         status: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """
        List backups with optional filtering.

        Args:
            user_id: Optional user ID filter
            status: Optional status filter
            limit: Maximum number of results

        Returns:
            List of backup records
        """
        try:
            backups = self._load_backups()

            # Apply filters
            filtered_backups = []
            for backup in backups:
                if user_id and backup.get('user_id') != user_id:
                    continue
                if status and backup.get('status') != status:
                    continue
                filtered_backups.append(backup)

            # Sort by creation time (newest first) and limit
            filtered_backups.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            result = filtered_backups[:limit]

            self.logger.info(f"Listed {len(result)} backups")
            return result

        except Exception as e:
            self.logger.error(f"Failed to list backups: {e}")
            return []

    # Shard Operations
    async def create_shard(self, shard_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new shard record.

        Args:
            shard_data: Shard metadata

        Returns:
            Created shard record
        """
        try:
            # Add timestamp and ID if not present
            if 'shard_id' not in shard_data:
                shard_data['shard_id'] = f"shard_{int(datetime.now().timestamp())}"

            if 'created_at' not in shard_data:
                shard_data['created_at'] = datetime.now(timezone.utc).isoformat()

            # Load existing shards
            shards = self._load_shards()

            # Add new shard
            shards.append(shard_data)

            # Save updated shards
            self._save_shards(shards)

            self.logger.info(f"Created shard: {shard_data['shard_id']}")
            return shard_data

        except Exception as e:
            self.logger.error(f"Failed to create shard: {e}")
            raise

    async def get_backup_shards(self, backup_id: str) -> List[Dict[str, Any]]:
        """
        Get all shards for a backup.

        Args:
            backup_id: Backup identifier

        Returns:
            List of shard records
        """
        try:
            shards = self._load_shards()

            backup_shards = [shard for shard in shards if shard.get('backup_id') == backup_id]
            backup_shards.sort(key=lambda x: x.get('shard_index', 0))

            self.logger.info(f"Retrieved {len(backup_shards)} shards for backup: {backup_id}")
            return backup_shards

        except Exception as e:
            self.logger.error(f"Failed to get shards for backup {backup_id}: {e}")
            return []

    # Recovery Operations
    async def log_recovery_operation(self, recovery_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Log a recovery operation.

        Args:
            recovery_data: Recovery operation metadata

        Returns:
            Created recovery log record
        """
        try:
            # Add timestamp and ID if not present
            if 'recovery_id' not in recovery_data:
                recovery_data['recovery_id'] = f"recovery_{int(datetime.now().timestamp())}"

            if 'recovery_started_at' not in recovery_data:
                recovery_data['recovery_started_at'] = datetime.now(timezone.utc).isoformat()

            # Load existing recovery logs
            recovery_logs = self._load_recovery_logs()

            # Add new recovery log
            recovery_logs.append(recovery_data)

            # Save updated recovery logs
            self._save_recovery_logs(recovery_logs)

            self.logger.info(f"Logged recovery operation: {recovery_data['recovery_id']}")
            return recovery_data

        except Exception as e:
            self.logger.error(f"Failed to log recovery operation: {e}")
            raise

    # Helper methods for file-based storage
    def _load_backups(self) -> List[Dict[str, Any]]:
        """Load backups from JSON file."""
        try:
            with open(self.backups_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load backups: {e}")
            return []

    def _save_backups(self, backups: List[Dict[str, Any]]) -> None:
        """Save backups to JSON file."""
        try:
            with open(self.backups_file, 'w') as f:
                json.dump(backups, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save backups: {e}")
            raise

    def _load_shards(self) -> List[Dict[str, Any]]:
        """Load shards from JSON file."""
        try:
            with open(self.shards_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load shards: {e}")
            return []

    def _save_shards(self, shards: List[Dict[str, Any]]) -> None:
        """Save shards to JSON file."""
        try:
            with open(self.shards_file, 'w') as f:
                json.dump(shards, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save shards: {e}")
            raise

    def _load_recovery_logs(self) -> List[Dict[str, Any]]:
        """Load recovery logs from JSON file."""
        try:
            with open(self.recovery_logs_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load recovery logs: {e}")
            return []

    def _save_recovery_logs(self, recovery_logs: List[Dict[str, Any]]) -> None:
        """Save recovery logs to JSON file."""
        try:
            with open(self.recovery_logs_file, 'w') as f:
                json.dump(recovery_logs, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save recovery logs: {e}")
            raise
