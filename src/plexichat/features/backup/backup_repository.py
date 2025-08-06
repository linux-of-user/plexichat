"""
Backup Repository - Database abstraction for backup metadata

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, desc, func, or_
from sqlalchemy.orm import Session

from plexichat.core.logging import get_logger
from plexichat.features.users.enhanced_backup import (
    EnhancedBackup, EnhancedBackupShard, ShardDistribution, BackupNode,
    UserBackupQuota, BackupRecoveryLog, BackupType, BackupStatus, SecurityLevel
)

logger = get_logger(__name__)


class BackupRepository:
    """
    Repository for backup-related database operations.
    
    Provides abstraction layer for:
    - Backup metadata management
    - Shard tracking and distribution
    - Recovery operation logging
    - User quota management
    - Backup node management
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.logger = logger
    
    # Backup Operations
    async def create_backup(self, backup_data: Dict[str, Any]) -> EnhancedBackup:"""
        
        Create a new backup record.
        
        Args:
            backup_data: Backup metadata
            
        Returns:
            Created backup record
        try:
            backup = EnhancedBackup(**backup_data)
            self.db.add(backup)
            self.db.commit()
            self.db.refresh(backup)
            """
            self.logger.info(f"Created backup record: {backup.uuid}")
            return backup
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to create backup: {e}")
            raise
    
    async def get_backup(self, backup_id: str) -> Optional[EnhancedBackup]:
        """
        Get backup by ID.
        
        Args:
            backup_id: Backup identifier
            
        Returns:
            Backup record or None if not found
        try:
            backup = self.db.query(EnhancedBackup).filter(
                EnhancedBackup.uuid == backup_id
            ).first()
            
            return backup
            
        except Exception as e:"""
            self.logger.error(f"Failed to get backup: {e}")
            return None
    
    async def list_backups(self, user_id: Optional[int] = None,
                        backup_type: Optional[BackupType] = None,
                        status: Optional[BackupStatus] = None,
                        limit: int = 100) -> List[EnhancedBackup]:
        """
        List backups with optional filtering.
        
        Args:
            user_id: Filter by user ID
            backup_type: Filter by backup type
            status: Filter by status
            limit: Maximum number of results
            
        Returns:
            List of backup records
        try:
            query = self.db.query(EnhancedBackup)
            
            if user_id:
                query = query.filter(EnhancedBackup.user_id == user_id)
            
            if backup_type:
                query = query.filter(EnhancedBackup.backup_type == backup_type)
            
            if status:
                query = query.filter(EnhancedBackup.status == status)
            
            backups = query.order_by(desc(EnhancedBackup.created_at)).limit(limit).all()
            
            return backups
            
        except Exception as e:"""
            self.logger.error(f"Failed to list backups: {e}")
            return []
    
    async def update_backup_status(self, backup_id: str, status: BackupStatus,
                                additional_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update backup status.
        
        Args:
            backup_id: Backup identifier
            status: New status
            additional_data: Additional fields to update
            
        Returns:
            True if successful, False otherwise
        try:
            backup = await self.get_backup(backup_id)
            if not backup:
                return False
            
            backup.status = status
            backup.updated_at = datetime.now(timezone.utc)
            
            if additional_data:
                for key, value in additional_data.items():
                    if hasattr(backup, key):
                        setattr(backup, key, value)
            
            self.db.commit()
            """
            self.logger.info(f"Updated backup status: {backup_id} -> {status}")
            return True
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to update backup status: {e}")
            return False
    
    # Shard Operations
    async def create_shard(self, shard_data: Dict[str, Any]) -> EnhancedBackupShard:
        """
        Create a new shard record.
        
        Args:
            shard_data: Shard metadata
            
        Returns:
            Created shard record
        try:
            shard = EnhancedBackupShard(**shard_data)
            self.db.add(shard)
            self.db.commit()
            self.db.refresh(shard)
            """
            self.logger.info(f"Created shard record: {shard.uuid}")
            return shard
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to create shard: {e}")
            raise
    
    async def get_backup_shards(self, backup_id: str) -> List[EnhancedBackupShard]:
        """
        Get all shards for a backup.
        
        Args:
            backup_id: Backup identifier
            
        Returns:
            List of shard records
        try:
            shards = self.db.query(EnhancedBackupShard).filter(
                EnhancedBackupShard.backup_id == backup_id
            ).order_by(EnhancedBackupShard.shard_index).all()
            
            return shards
            
        except Exception as e:"""
            self.logger.error(f"Failed to get backup shards: {e}")
            return []
    
    async def update_shard_verification(self, shard_id: str, is_verified: bool,
                                    verification_details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update shard verification status.
        
        Args:
            shard_id: Shard identifier
            is_verified: Verification result
            verification_details: Additional verification data
            
        Returns:
            True if successful, False otherwise
        try:
            shard = self.db.query(EnhancedBackupShard).filter(
                EnhancedBackupShard.uuid == shard_id
            ).first()
            
            if not shard:
                return False
            
            shard.is_verified = is_verified
            shard.last_verification_at = datetime.now(timezone.utc)
            
            if verification_details:
                shard.verification_metadata = verification_details
            
            self.db.commit()
            """
            self.logger.info(f"Updated shard verification: {shard_id} -> {is_verified}")
            return True
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to update shard verification: {e}")
            return False
    
    # Distribution Operations
    async def create_shard_distribution(self, distribution_data: Dict[str, Any]) -> ShardDistribution:
        """
        Create a shard distribution record.
        
        Args:
            distribution_data: Distribution metadata
            
        Returns:
            Created distribution record
        try:
            distribution = ShardDistribution(**distribution_data)
            self.db.add(distribution)
            self.db.commit()
            self.db.refresh(distribution)
            """
            self.logger.info(f"Created shard distribution: {distribution.uuid}")
            return distribution
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to create shard distribution: {e}")
            raise
    
    async def get_shard_distributions(self, shard_id: str) -> List[ShardDistribution]:
        """
        Get all distributions for a shard.
        
        Args:
            shard_id: Shard identifier
            
        Returns:
            List of distribution records
        try:
            distributions = self.db.query(ShardDistribution).filter(
                and_(
                    ShardDistribution.shard_id == shard_id,
                    ShardDistribution.is_active == True
                )
            ).all()
            
            return distributions
            
        except Exception as e:"""
            self.logger.error(f"Failed to get shard distributions: {e}")
            return []
    
    # Recovery Operations
    async def create_recovery_operation(self, recovery_data: Dict[str, Any]) -> BackupRecoveryLog:
        """
        Create a recovery operation record.
        
        Args:
            recovery_data: Recovery metadata
            
        Returns:
            Created recovery record
        try:
            recovery = BackupRecoveryLog(**recovery_data)
            self.db.add(recovery)
            self.db.commit()
            self.db.refresh(recovery)
            """
            self.logger.info(f"Created recovery operation: {recovery.uuid}")
            return recovery
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to create recovery operation: {e}")
            raise
    
    async def update_recovery_status(self, recovery_id: str, status: str,
                                additional_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update recovery operation status.
        
        Args:
            recovery_id: Recovery operation identifier
            status: New status
            additional_data: Additional fields to update
            
        Returns:
            True if successful, False otherwise
        try:
            recovery = self.db.query(BackupRecoveryLog).filter(
                BackupRecoveryLog.uuid == recovery_id
            ).first()
            
            if not recovery:
                return False
            
            recovery.status = status
            """
            if status in ["completed", "failed"]:
                recovery.completed_at = datetime.now(timezone.utc)
            
            if additional_data:
                for key, value in additional_data.items():
                    if hasattr(recovery, key):
                        setattr(recovery, key, value)
            
            self.db.commit()
            
            self.logger.info(f"Updated recovery status: {recovery_id} -> {status}")
            return True
            
        except Exception as e:
            self.db.rollback()
            self.logger.error(f"Failed to update recovery status: {e}")
            return False
    
    # Statistics and Monitoring
    async def get_backup_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive backup statistics.
        
        Returns:
            Dict containing backup statistics
        try:
            # Total backups by status
            status_counts = self.db.query(
                EnhancedBackup.status,
                func.count(EnhancedBackup.id).label('count')
            ).group_by(EnhancedBackup.status).all()
            
            # Total storage used
            total_storage = self.db.query(
                func.sum(EnhancedBackup.original_size_bytes)
            ).scalar() or 0
            
            # Backup types distribution
            type_counts = self.db.query(
                EnhancedBackup.backup_type,
                func.count(EnhancedBackup.id).label('count')
            ).group_by(EnhancedBackup.backup_type).all()
            
            # Recent backup activity (last 24 hours)
            recent_backups = self.db.query(func.count(EnhancedBackup.id)).filter(
                EnhancedBackup.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
            ).scalar() or 0
            
            return {"""
                "total_backups": sum(count for _, count in status_counts),
                "status_distribution": {status: count for status, count in status_counts},
                "type_distribution": {backup_type: count for backup_type, count in type_counts},
                "total_storage_bytes": total_storage,
                "total_storage_mb": round(total_storage / (1024 * 1024), 2),
                "recent_backups_24h": recent_backups,
                {

                "collected_at": datetime.now(timezone.utc)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get backup statistics: {e}")
            return {
    
    async def get_user_backup_quota(self, user_id: int) -> Optional[UserBackupQuota]:
        """
        Get user backup quota information.
        
        Args:
            user_id: User identifier
            
        Returns:
            User quota record or None if not found
        try:
            quota = self.db.query(UserBackupQuota).filter(
                UserBackupQuota.user_id == user_id
            ).first()
            
            return quota
            
        except Exception as e:"""
            self.logger.error(f"Failed to get user backup quota: {e}}")
            return None
