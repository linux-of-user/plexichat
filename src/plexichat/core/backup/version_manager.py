#!/usr/bin/env python3
"""
Version Manager for Distributed Backup System

Handles immutable versioning and diff generation for message edits.
Maintains version chains and provides efficient storage of changes.


import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from uuid import uuid4

# Diff library for efficient change tracking
try:
    import difflib
    DIFF_AVAILABLE = True
except ImportError:
    DIFF_AVAILABLE = False

logger = logging.getLogger(__name__)

class VersionType(Enum):
    """Types of versions."""
        FULL = "full"           # Complete backup
    INCREMENTAL = "incremental"  # Changes since last version
    DIFF = "diff"           # Message edit diff
    SNAPSHOT = "snapshot"   # Point-in-time snapshot

class ChangeType(Enum):
    """Types of changes."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EDIT = "edit"

@dataclass
class VersionInfo:
    """Information about a backup version.
        version_id: str
    backup_id: str
    version_type: VersionType
    parent_version_id: Optional[str]
    created_at: datetime
    size: int
    checksum: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    changes: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version_id": self.version_id,
            "backup_id": self.backup_id,
            "version_type": self.version_type.value,
            "parent_version_id": self.parent_version_id,
            "created_at": self.created_at.isoformat(),
            "size": self.size,
            "checksum": self.checksum,
            "metadata": self.metadata,
            "changes": self.changes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VersionInfo':
        """Create from dictionary."""
        return cls(
            version_id=data["version_id"],
            backup_id=data["backup_id"],
            version_type=VersionType(data["version_type"]),
            parent_version_id=data.get("parent_version_id"),
            created_at=datetime.fromisoformat(data["created_at"]),
            size=data["size"],
            checksum=data["checksum"],
            metadata=data.get("metadata", {}),
            changes=data.get("changes", [])
        )

@dataclass
class MessageDiff:
    """Represents a diff for a message edit.
        message_id: str
    old_content: str
    new_content: str
    edit_timestamp: datetime
    user_id: str
    diff_data: str
    change_type: ChangeType
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_id": self.message_id,
            "old_content": self.old_content,
            "new_content": self.new_content,
            "edit_timestamp": self.edit_timestamp.isoformat(),
            "user_id": self.user_id,
            "diff_data": self.diff_data,
            "change_type": self.change_type.value
        }

@dataclass
class VersionChain:
    """Represents a chain of versions for a backup.
        backup_id: str
    versions: List[VersionInfo]
    head_version_id: str
    created_at: datetime
    
    @property
    def version_count(self) -> int:
        """Get total number of versions."""
        return len(self.versions)
    
    @property
    def total_size(self) -> int:
        Get total size of all versions."""
        return sum(v.size for v in self.versions)
    
    def get_version(self, version_id: str) -> Optional[VersionInfo]:
        """Get version by ID.
        return next((v for v in self.versions if v.version_id == version_id), None)
    
    def get_latest_version(self) -> Optional[VersionInfo]:
        """Get the latest version."""
        return self.get_version(self.head_version_id)

class VersionManager:
    Manages immutable versioning and diff generation."""
        def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Version storage
        self.versions_dir = self.storage_dir / "versions"
        self.diffs_dir = self.storage_dir / "diffs"
        self.versions_dir.mkdir(exist_ok=True)
        self.diffs_dir.mkdir(exist_ok=True)
        
        # In-memory registries
        self.version_chains: Dict[str, VersionChain] = {}
        self.versions: Dict[str, VersionInfo] = {}
        
        # Load existing versions
        self._load_versions()
    
    def create_version(self, backup_id: str, data: bytes, version_type: VersionType = VersionType.FULL,
                    parent_version_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> VersionInfo:
        """Create a new immutable version."""
        try:
            version_id = str(uuid4())
            checksum = hashlib.sha256(data).hexdigest()
            
            version_info = VersionInfo(
                version_id=version_id,
                backup_id=backup_id,
                version_type=version_type,
                parent_version_id=parent_version_id,
                created_at=datetime.now(timezone.utc),
                size=len(data),
                checksum=checksum,
                metadata=metadata or {}
            )
            
            # Save version data
            version_file = self.versions_dir / f"{version_id}.version"
            with open(version_file, 'wb') as f:
                f.write(data)
            
            # Save version metadata
            metadata_file = self.versions_dir / f"{version_id}.meta"
            with open(metadata_file, 'w') as f:
                json.dump(version_info.to_dict(), f, indent=2)
            
            # Update registries
            self.versions[version_id] = version_info
            
            # Update or create version chain
            if backup_id not in self.version_chains:
                self.version_chains[backup_id] = VersionChain(
                    backup_id=backup_id,
                    versions=[version_info],
                    head_version_id=version_id,
                    created_at=datetime.now(timezone.utc)
                )
            else:
                chain = self.version_chains[backup_id]
                chain.versions.append(version_info)
                chain.head_version_id = version_id
            
            logger.info(f"Created version {version_id} for backup {backup_id}")
            return version_info
            
        except Exception as e:
            logger.error(f"Failed to create version: {e}")
            raise
    
    def create_incremental_version(self, backup_id: str, new_data: bytes, 
                                metadata: Optional[Dict[str, Any]] = None) -> Optional[VersionInfo]:
        """Create an incremental version with changes since last version."""
        try:
            chain = self.version_chains.get(backup_id)
            if not chain:
                # No previous version, create full version
                return self.create_version(backup_id, new_data, VersionType.FULL, metadata=metadata)
            
            latest_version = chain.get_latest_version()
            if not latest_version:
                return self.create_version(backup_id, new_data, VersionType.FULL, metadata=metadata)
            
            # Load previous version data
            prev_version_file = self.versions_dir / f"{latest_version.version_id}.version"
            if not prev_version_file.exists():
                logger.warning(f"Previous version file not found: {prev_version_file}")
                return self.create_version(backup_id, new_data, VersionType.FULL, metadata=metadata)
            
            with open(prev_version_file, 'rb') as f:
                prev_data = f.read()
            
            # Generate diff
            diff_data = self._generate_binary_diff(prev_data, new_data)
            
            # Create incremental version with diff data
            incremental_metadata = metadata or {}
            incremental_metadata.update({
                "diff_size": len(diff_data),
                "original_size": len(new_data),
                "compression_ratio": len(diff_data) / len(new_data) if new_data else 0
            })
            
            return self.create_version(
                backup_id=backup_id,
                data=diff_data,
                version_type=VersionType.INCREMENTAL,
                parent_version_id=latest_version.version_id,
                metadata=incremental_metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to create incremental version: {e}")
            return None
    
    def create_message_diff(self, message_id: str, old_content: str, new_content: str, 
                        user_id: str, backup_id: str) -> Optional[VersionInfo]:
        """Create a diff version for a message edit."""
        try:
            # Generate text diff
            if DIFF_AVAILABLE:
                diff_lines = list(difflib.unified_diff(
                    old_content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"message_{message_id}_old",
                    tofile=f"message_{message_id}_new",
                    lineterm=''
                ))
                diff_text = ''.join(diff_lines)
            else:
                # Simple diff fallback
                diff_text = f"OLD: {old_content}\nNEW: {new_content}"
            
            # Create message diff object
            message_diff = MessageDiff(
                message_id=message_id,
                old_content=old_content,
                new_content=new_content,
                edit_timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                diff_data=diff_text,
                change_type=ChangeType.EDIT
            )
            
            # Serialize diff
            diff_data = json.dumps(message_diff.to_dict()).encode('utf-8')
            
            # Create diff version
            metadata = {
                "message_id": message_id,
                "user_id": user_id,
                "change_type": "message_edit",
                "old_length": len(old_content),
                "new_length": len(new_content)
            }
            
            version_info = self.create_version(
                backup_id=backup_id,
                data=diff_data,
                version_type=VersionType.DIFF,
                metadata=metadata
            )
            
            # Save diff separately for quick access
            diff_file = self.diffs_dir / f"{message_id}_{version_info.version_id}.diff"
            with open(diff_file, 'w') as f:
                f.write(diff_text)
            
            logger.info(f"Created message diff for message {message_id}")
            return version_info
            
        except Exception as e:
            logger.error(f"Failed to create message diff: {e}")
            return None
    
    def reconstruct_version(self, version_id: str) -> Optional[bytes]:
        """Reconstruct data for a specific version."""
        try:
            version_info = self.versions.get(version_id)
            if not version_info:
                logger.error(f"Version {version_id} not found")
                return None
            
            if version_info.version_type == VersionType.FULL:
                # Load full version directly
                version_file = self.versions_dir / f"{version_id}.version"
                if version_file.exists():
                    with open(version_file, 'rb') as f:
                        return f.read()
            
            elif version_info.version_type == VersionType.INCREMENTAL:
                # Reconstruct from parent + diff
                if not version_info.parent_version_id:
                    logger.error(f"Incremental version {version_id} has no parent")
                    return None
                
                # Get parent data
                parent_data = self.reconstruct_version(version_info.parent_version_id)
                if parent_data is None:
                    return None
                
                # Load diff data
                version_file = self.versions_dir / f"{version_id}.version"
                if not version_file.exists():
                    return None
                
                with open(version_file, 'rb') as f:
                    diff_data = f.read()
                
                # Apply diff
                return self._apply_binary_diff(parent_data, diff_data)
            
            elif version_info.version_type == VersionType.DIFF:
                # Load diff data directly
                version_file = self.versions_dir / f"{version_id}.version"
                if version_file.exists():
                    with open(version_file, 'rb') as f:
                        return f.read()
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to reconstruct version {version_id}: {e}")
            return None
    
    def _generate_binary_diff(self, old_data: bytes, new_data: bytes) -> bytes:
        """Generate binary diff between two data sets."""
        # Simple diff implementation - in production, use a proper binary diff library
        try:
            # For now, just store the new data if it's small enough
            # In a real implementation, you'd use algorithms like bsdiff or similar
            if len(new_data) < len(old_data) * 0.8:  # If new data is significantly smaller
                return new_data
            else:
                # Store as simple change record
                diff_record = {
                    "type": "binary_diff",
                    "old_size": len(old_data),
                    "new_size": len(new_data),
                    "new_data": new_data.hex()  # Store as hex for JSON compatibility
                }
                return json.dumps(diff_record).encode('utf-8')
        except Exception as e:
            logger.error(f"Failed to generate binary diff: {e}")
            return new_data  # Fallback to storing full data
    
    def _apply_binary_diff(self, old_data: bytes, diff_data: bytes) -> bytes:
        """Apply binary diff to reconstruct new data."""
        try:
            # Try to parse as JSON diff record
            try:
                diff_record = json.loads(diff_data.decode('utf-8'))
                if diff_record.get("type") == "binary_diff":
                    return bytes.fromhex(diff_record["new_data"])
            except (json.JSONDecodeError, KeyError):
                pass
            
            # If not a diff record, assume it's the full new data
            return diff_data
            
        except Exception as e:
            logger.error(f"Failed to apply binary diff: {e}")
            return diff_data  # Fallback
    
    def get_version_chain(self, backup_id: str) -> Optional[VersionChain]:
        """Get version chain for a backup.
        return self.version_chains.get(backup_id)
    
    def get_version_history(self, backup_id: str) -> List[VersionInfo]:
        """Get version history for a backup."""
        chain = self.version_chains.get(backup_id)
        return chain.versions if chain else []
    
    def cleanup_old_versions(self, backup_id: str, keep_count: int = 10) -> int:
        Clean up old versions, keeping only the most recent ones."""
        try:
            chain = self.version_chains.get(backup_id)
            if not chain or len(chain.versions) <= keep_count:
                return 0
            
            # Sort versions by creation date
            sorted_versions = sorted(chain.versions, key=lambda v: v.created_at, reverse=True)
            
            # Keep the most recent versions
            versions_to_keep = sorted_versions[:keep_count]
            versions_to_delete = sorted_versions[keep_count:]
            
            deleted_count = 0
            for version in versions_to_delete:
                try:
                    # Delete version files
                    version_file = self.versions_dir / f"{version.version_id}.version"
                    metadata_file = self.versions_dir / f"{version.version_id}.meta"
                    
                    if version_file.exists():
                        version_file.unlink()
                    if metadata_file.exists():
                        metadata_file.unlink()
                    
                    # Remove from registries
                    if version.version_id in self.versions:
                        del self.versions[version.version_id]
                    
                    deleted_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to delete version {version.version_id}: {e}")
            
            # Update chain
            chain.versions = versions_to_keep
            
            logger.info(f"Cleaned up {deleted_count} old versions for backup {backup_id}")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old versions: {e}")
            return 0
    
    def _load_versions(self):
        """Load existing versions from storage."""
        try:
            for metadata_file in self.versions_dir.glob("*.meta"):
                try:
                    with open(metadata_file, 'r') as f:
                        version_data = json.load(f)
                    
                    version_info = VersionInfo.from_dict(version_data)
                    self.versions[version_info.version_id] = version_info
                    
                    # Add to version chain
                    backup_id = version_info.backup_id
                    if backup_id not in self.version_chains:
                        self.version_chains[backup_id] = VersionChain(
                            backup_id=backup_id,
                            versions=[],
                            head_version_id=version_info.version_id,
                            created_at=version_info.created_at
                        )
                    
                    self.version_chains[backup_id].versions.append(version_info)
                    
                except Exception as e:
                    logger.warning(f"Failed to load version metadata {metadata_file}: {e}")
            
            # Update head versions for each chain
            for chain in self.version_chains.values():
                if chain.versions:
                    latest_version = max(chain.versions, key=lambda v: v.created_at)
                    chain.head_version_id = latest_version.version_id
            
            logger.info(f"Loaded {len(self.versions)} versions across {len(self.version_chains)} backup chains")
            
        except Exception as e:
            logger.error(f"Failed to load versions: {e}")

# Export main classes
__all__ = [
    "VersionManager",
    "VersionInfo",
    "VersionChain",
    "MessageDiff",
    "VersionType",
    "ChangeType"
]
