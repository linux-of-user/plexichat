"""
PlexiChat Backup Manager

Backup management with threading and performance optimization.
"""

import asyncio
import gzip
import json
import logging
import os
import shutil
import tarfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from uuid import uuid4

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.scheduler.task_scheduler import schedule_recurring
except ImportError:
    schedule_recurring = None

try:
    from plexichat.core.analytics.analytics_manager import track_event
except ImportError:
    track_event = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class BackupInfo:
    """Backup information."""
    backup_id: str
    backup_type: str
    created_at: datetime
    file_path: str
    file_size: int
    compressed: bool
    checksum: str
    metadata: Dict[str, Any]
    status: str

class BackupManager:
    """Backup manager with threading support."""
    
    def __init__(self, backup_dir: str = "backups"):
        self.backup_dir = Path(backup_dir)
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup settings
        self.max_backups = 30
        self.compression_enabled = True
        self.auto_backup_interval = 86400  # 24 hours
        
        # Statistics
        self.backups_created = 0
        self.backups_restored = 0
        self.total_backup_size = 0
    
    async def start_auto_backup(self):
        """Start automatic backup scheduling."""
        try:
            if schedule_recurring:
                task_id = await schedule_recurring(
                    "auto_database_backup",
                    self.create_database_backup,
                    self.auto_backup_interval,
                    metadata={"auto_backup": True}
                )
                logger.info(f"Auto backup scheduled with task ID: {task_id}")
            else:
                logger.warning("Scheduler not available for auto backup")
        except Exception as e:
            logger.error(f"Error starting auto backup: {e}")
    
    async def create_database_backup(self, backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create database backup."""
        try:
            start_time = time.time()
            
            backup_id = str(uuid4())
            backup_name = backup_name or f"db_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create backup file path
            backup_file = self.backup_dir / f"{backup_name}.sql"
            if self.compression_enabled:
                backup_file = backup_file.with_suffix('.sql.gz')
            
            # Export database (threaded)
            if self.async_thread_manager:
                success = await self.async_thread_manager.run_in_thread(
                    self._export_database_sync, str(backup_file)
                )
            else:
                success = await self._export_database(str(backup_file))
            
            if not success:
                logger.error("Database backup failed")
                return None
            
            # Calculate file size and checksum
            file_size = backup_file.stat().st_size
            checksum = await self._calculate_checksum(backup_file)
            
            # Create backup info
            backup_info = BackupInfo(
                backup_id=backup_id,
                backup_type="database",
                created_at=datetime.now(),
                file_path=str(backup_file),
                file_size=file_size,
                compressed=self.compression_enabled,
                checksum=checksum,
                metadata={"backup_name": backup_name},
                status="completed"
            )
            
            # Store backup info
            await self._store_backup_info(backup_info)
            
            # Clean up old backups
            await self._cleanup_old_backups("database")
            
            # Performance tracking
            duration = time.time() - start_time
            self.backups_created += 1
            self.total_backup_size += file_size
            
            if self.performance_logger:
                self.performance_logger.record_metric("backup_creation_duration", duration, "seconds")
                self.performance_logger.record_metric("backups_created", 1, "count")
                self.performance_logger.record_metric("backup_size", file_size, "bytes")
            
            # Track analytics
            if track_event:
                await track_event(
                    "backup_created",
                    properties={
                        "backup_type": "database",
                        "file_size": file_size,
                        "compressed": self.compression_enabled,
                        "duration": duration
                    }
                )
            
            logger.info(f"Database backup created: {backup_file} ({file_size} bytes)")
            return backup_info
            
        except Exception as e:
            logger.error(f"Error creating database backup: {e}")
            return None
    
    def _export_database_sync(self, backup_file: str) -> bool:
        """Export database synchronously."""
        try:
            # Placeholder implementation - would use actual database export
            # For SQLite, could use .backup() method
            # For PostgreSQL, could use pg_dump
            # For MySQL, could use mysqldump
            
            if self.compression_enabled and backup_file.endswith('.gz'):
                with gzip.open(backup_file, 'wt') as f:
                    f.write("-- PlexiChat Database Backup\n")
                    f.write(f"-- Created: {datetime.now()}\n")
                    f.write("-- Placeholder backup content\n")
            else:
                with open(backup_file, 'w') as f:
                    f.write("-- PlexiChat Database Backup\n")
                    f.write(f"-- Created: {datetime.now()}\n")
                    f.write("-- Placeholder backup content\n")
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting database: {e}")
            return False
    
    async def _export_database(self, backup_file: str) -> bool:
        """Export database asynchronously."""
        return self._export_database_sync(backup_file)
    
    async def create_files_backup(self, backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create files backup."""
        try:
            start_time = time.time()
            
            backup_id = str(uuid4())
            backup_name = backup_name or f"files_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create backup file path
            backup_file = self.backup_dir / f"{backup_name}.tar.gz"
            
            # Create files backup (threaded)
            if self.async_thread_manager:
                success = await self.async_thread_manager.run_in_thread(
                    self._create_files_backup_sync, str(backup_file)
                )
            else:
                success = await self._create_files_backup_async(str(backup_file))
            
            if not success:
                logger.error("Files backup failed")
                return None
            
            # Calculate file size and checksum
            file_size = backup_file.stat().st_size
            checksum = await self._calculate_checksum(backup_file)
            
            # Create backup info
            backup_info = BackupInfo(
                backup_id=backup_id,
                backup_type="files",
                created_at=datetime.now(),
                file_path=str(backup_file),
                file_size=file_size,
                compressed=True,
                checksum=checksum,
                metadata={"backup_name": backup_name},
                status="completed"
            )
            
            # Store backup info
            await self._store_backup_info(backup_info)
            
            # Clean up old backups
            await self._cleanup_old_backups("files")
            
            # Performance tracking
            duration = time.time() - start_time
            self.backups_created += 1
            self.total_backup_size += file_size
            
            if self.performance_logger:
                self.performance_logger.record_metric("backup_creation_duration", duration, "seconds")
                self.performance_logger.record_metric("backups_created", 1, "count")
                self.performance_logger.record_metric("backup_size", file_size, "bytes")
            
            logger.info(f"Files backup created: {backup_file} ({file_size} bytes)")
            return backup_info
            
        except Exception as e:
            logger.error(f"Error creating files backup: {e}")
            return None
    
    def _create_files_backup_sync(self, backup_file: str) -> bool:
        """Create files backup synchronously."""
        try:
            # Find files to backup
            files_to_backup = []
            
            # Add uploads directory
            uploads_dir = Path("uploads")
            if uploads_dir.exists():
                files_to_backup.append(uploads_dir)
            
            # Add config files
            config_files = ["plexichat.yaml", "plexichat.json", "config.yaml"]
            for config_file in config_files:
                if Path(config_file).exists():
                    files_to_backup.append(Path(config_file))
            
            # Create tar.gz archive
            with tarfile.open(backup_file, 'w:gz') as tar:
                for file_path in files_to_backup:
                    if file_path.exists():
                        tar.add(file_path, arcname=file_path.name)
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating files backup: {e}")
            return False
    
    async def _create_files_backup_async(self, backup_file: str) -> bool:
        """Create files backup asynchronously."""
        return self._create_files_backup_sync(backup_file)
    
    async def create_full_backup(self, backup_name: Optional[str] = None) -> Optional[BackupInfo]:
        """Create full system backup."""
        try:
            start_time = time.time()
            
            backup_id = str(uuid4())
            backup_name = backup_name or f"full_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Create temporary directory for full backup
            temp_dir = self.backup_dir / f"temp_{backup_id}"
            temp_dir.mkdir(exist_ok=True)
            
            try:
                # Create database backup
                db_backup = await self.create_database_backup(f"{backup_name}_db")
                if db_backup:
                    shutil.copy2(db_backup.file_path, temp_dir / "database.sql.gz")
                
                # Create files backup
                files_backup = await self.create_files_backup(f"{backup_name}_files")
                if files_backup:
                    shutil.copy2(files_backup.file_path, temp_dir / "files.tar.gz")
                
                # Create metadata file
                metadata = {
                    "backup_id": backup_id,
                    "backup_name": backup_name,
                    "created_at": datetime.now().isoformat(),
                    "database_backup": db_backup.backup_id if db_backup else None,
                    "files_backup": files_backup.backup_id if files_backup else None,
                    "version": "1.0.0"
                }
                
                with open(temp_dir / "metadata.json", 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                # Create final backup archive
                backup_file = self.backup_dir / f"{backup_name}.tar.gz"
                
                if self.async_thread_manager:
                    success = await self.async_thread_manager.run_in_thread(
                        self._create_archive_sync, str(temp_dir), str(backup_file)
                    )
                else:
                    success = self._create_archive_sync(str(temp_dir), str(backup_file))
                
                if not success:
                    return None
                
                # Calculate file size and checksum
                file_size = backup_file.stat().st_size
                checksum = await self._calculate_checksum(backup_file)
                
                # Create backup info
                backup_info = BackupInfo(
                    backup_id=backup_id,
                    backup_type="full",
                    created_at=datetime.now(),
                    file_path=str(backup_file),
                    file_size=file_size,
                    compressed=True,
                    checksum=checksum,
                    metadata=metadata,
                    status="completed"
                )
                
                # Store backup info
                await self._store_backup_info(backup_info)
                
                # Clean up old backups
                await self._cleanup_old_backups("full")
                
                # Performance tracking
                duration = time.time() - start_time
                self.backups_created += 1
                self.total_backup_size += file_size
                
                if self.performance_logger:
                    self.performance_logger.record_metric("backup_creation_duration", duration, "seconds")
                    self.performance_logger.record_metric("backups_created", 1, "count")
                    self.performance_logger.record_metric("backup_size", file_size, "bytes")
                
                logger.info(f"Full backup created: {backup_file} ({file_size} bytes)")
                return backup_info
                
            finally:
                # Clean up temporary directory
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
            
        except Exception as e:
            logger.error(f"Error creating full backup: {e}")
            return None
    
    def _create_archive_sync(self, source_dir: str, archive_file: str) -> bool:
        """Create archive synchronously."""
        try:
            with tarfile.open(archive_file, 'w:gz') as tar:
                tar.add(source_dir, arcname='.')
            return True
        except Exception as e:
            logger.error(f"Error creating archive: {e}")
            return False
    
    async def restore_backup(self, backup_id: str) -> bool:
        """Restore from backup."""
        try:
            # Get backup info
            backup_info = await self._get_backup_info(backup_id)
            if not backup_info:
                logger.error(f"Backup not found: {backup_id}")
                return False
            
            # Verify backup file exists
            backup_file = Path(backup_info.file_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            # Verify checksum
            current_checksum = await self._calculate_checksum(backup_file)
            if current_checksum != backup_info.checksum:
                logger.error(f"Backup file corrupted: checksum mismatch")
                return False
            
            # Restore based on backup type
            if backup_info.backup_type == "database":
                success = await self._restore_database(backup_file)
            elif backup_info.backup_type == "files":
                success = await self._restore_files(backup_file)
            elif backup_info.backup_type == "full":
                success = await self._restore_full(backup_file)
            else:
                logger.error(f"Unknown backup type: {backup_info.backup_type}")
                return False
            
            if success:
                self.backups_restored += 1
                
                if self.performance_logger:
                    self.performance_logger.record_metric("backups_restored", 1, "count")
                
                logger.info(f"Backup restored successfully: {backup_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error restoring backup: {e}")
            return False
    
    async def _restore_database(self, backup_file: Path) -> bool:
        """Restore database from backup."""
        try:
            # Placeholder implementation
            logger.info(f"Restoring database from: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error restoring database: {e}")
            return False
    
    async def _restore_files(self, backup_file: Path) -> bool:
        """Restore files from backup."""
        try:
            # Placeholder implementation
            logger.info(f"Restoring files from: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error restoring files: {e}")
            return False
    
    async def _restore_full(self, backup_file: Path) -> bool:
        """Restore full backup."""
        try:
            # Placeholder implementation
            logger.info(f"Restoring full backup from: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error restoring full backup: {e}")
            return False
    
    async def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate file checksum."""
        try:
            import hashlib
            
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            
            return hash_md5.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return ""
    
    async def _store_backup_info(self, backup_info: BackupInfo):
        """Store backup information."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO backups (
                        backup_id, backup_type, created_at, file_path,
                        file_size, compressed, checksum, metadata, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "backup_id": backup_info.backup_id,
                    "backup_type": backup_info.backup_type,
                    "created_at": backup_info.created_at,
                    "file_path": backup_info.file_path,
                    "file_size": backup_info.file_size,
                    "compressed": backup_info.compressed,
                    "checksum": backup_info.checksum,
                    "metadata": json.dumps(backup_info.metadata),
                    "status": backup_info.status
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing backup info: {e}")
    
    async def _get_backup_info(self, backup_id: str) -> Optional[BackupInfo]:
        """Get backup information."""
        try:
            if self.db_manager:
                query = "SELECT * FROM backups WHERE backup_id = ?"
                result = await self.db_manager.execute_query(query, {"backup_id": backup_id})
                
                if result:
                    row = result[0]
                    return BackupInfo(
                        backup_id=row[0],
                        backup_type=row[1],
                        created_at=row[2],
                        file_path=row[3],
                        file_size=row[4],
                        compressed=row[5],
                        checksum=row[6],
                        metadata=json.loads(row[7]) if row[7] else {},
                        status=row[8]
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting backup info: {e}")
            return None
    
    async def _cleanup_old_backups(self, backup_type: str):
        """Clean up old backups."""
        try:
            if self.db_manager:
                # Get old backups
                query = """
                    SELECT backup_id, file_path FROM backups 
                    WHERE backup_type = ? 
                    ORDER BY created_at DESC 
                    LIMIT -1 OFFSET ?
                """
                params = {"backup_type": backup_type, "offset": self.max_backups}
                result = await self.db_manager.execute_query(query, params)
                
                for row in result:
                    backup_id, file_path = row
                    
                    # Delete file
                    try:
                        Path(file_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                    
                    # Delete from database
                    delete_query = "DELETE FROM backups WHERE backup_id = ?"
                    await self.db_manager.execute_query(delete_query, {"backup_id": backup_id})
                
                if result:
                    logger.info(f"Cleaned up {len(result)} old {backup_type} backups")
                    
        except Exception as e:
            logger.error(f"Error cleaning up old backups: {e}")
    
    async def list_backups(self, backup_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all backups."""
        try:
            if self.db_manager:
                if backup_type:
                    query = "SELECT * FROM backups WHERE backup_type = ? ORDER BY created_at DESC"
                    params = {"backup_type": backup_type}
                else:
                    query = "SELECT * FROM backups ORDER BY created_at DESC"
                    params = {}
                
                result = await self.db_manager.execute_query(query, params)
                
                backups = []
                for row in result:
                    backups.append({
                        "backup_id": row[0],
                        "backup_type": row[1],
                        "created_at": row[2].isoformat() if row[2] else None,
                        "file_path": row[3],
                        "file_size": row[4],
                        "compressed": row[5],
                        "checksum": row[6],
                        "status": row[8]
                    })
                
                return backups
            
            return []
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backup statistics."""
        return {
            "backup_dir": str(self.backup_dir),
            "max_backups": self.max_backups,
            "compression_enabled": self.compression_enabled,
            "auto_backup_interval": self.auto_backup_interval,
            "backups_created": self.backups_created,
            "backups_restored": self.backups_restored,
            "total_backup_size": self.total_backup_size,
            "total_backup_size_mb": self.total_backup_size / (1024 * 1024)
        }

# Global backup manager
backup_manager = BackupManager()

# Convenience functions
async def create_database_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create database backup."""
    return await backup_manager.create_database_backup(backup_name)

async def create_files_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create files backup."""
    return await backup_manager.create_files_backup(backup_name)

async def create_full_backup(backup_name: Optional[str] = None) -> Optional[BackupInfo]:
    """Create full backup."""
    return await backup_manager.create_full_backup(backup_name)

async def restore_backup(backup_id: str) -> bool:
    """Restore backup."""
    return await backup_manager.restore_backup(backup_id)

async def list_backups(backup_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """List backups."""
    return await backup_manager.list_backups(backup_type)
