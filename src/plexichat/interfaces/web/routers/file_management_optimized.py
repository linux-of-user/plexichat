# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat File Management Router

Enhanced file management with comprehensive operations and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

# Use EXISTING database abstraction layer
try:
    from plexichat.core_system.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

# Authentication imports
try:
    from plexichat.infrastructure.utils.auth import require_admin
except ImportError:
    def require_admin():
        return {"id": 1, "username": "admin", "is_admin": True}

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/file-management", tags=["file-management"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

# Pydantic models
class FileInfo(BaseModel):
    """File information."""
    path: str
    name: str
    size: int
    modified: datetime
    is_directory: bool
    permissions: str

class BackupInfo(BaseModel):
    """Backup information."""
    backup_id: str
    source_path: str
    backup_path: str
    created_at: datetime
    size: int
    status: str

class FileOperationResult(BaseModel):
    """File operation result."""
    success: bool
    message: str
    affected_files: int
    details: Optional[Dict[str, Any]] = None

class FileManagementService:
    """Service class for file management operations using EXISTING systems."""
    
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
    
    @async_track_performance("file_listing") if async_track_performance else lambda f: f
    async def list_files(self, directory_path: str) -> List[FileInfo]:
        """List files in directory."""
        try:
            files = []
            path = Path(directory_path)
            
            if not path.exists():
                return []
            
            for item in path.iterdir():
                try:
                    stat = item.stat()
                    files.append(FileInfo(
                        path=str(item),
                        name=item.name,
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        is_directory=item.is_dir(),
                        permissions=oct(stat.st_mode)[-3:]
                    ))
                except Exception as e:
                    logger.error(f"Error getting file info for {item}: {e}")
            
            return files
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []
    
    async def create_backup(self, source_path: str, backup_name: str) -> BackupInfo:
        """Create backup of files."""
        try:
            backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_path = f"/backups/{backup_name}_{backup_id}"
            
            # Create backup directory
            os.makedirs(backup_path, exist_ok=True)
            
            # Copy files
            if os.path.isfile(source_path):
                shutil.copy2(source_path, backup_path)
                size = os.path.getsize(source_path)
            else:
                shutil.copytree(source_path, f"{backup_path}/{os.path.basename(source_path)}")
                size = sum(os.path.getsize(os.path.join(dirpath, filename))
                          for dirpath, dirnames, filenames in os.walk(backup_path)
                          for filename in filenames)
            
            backup_info = BackupInfo(
                backup_id=backup_id,
                source_path=source_path,
                backup_path=backup_path,
                created_at=datetime.now(),
                size=size,
                status="completed"
            )
            
            # Log backup to database if available
            if self.db_manager:
                await self._log_backup(backup_info)
            
            return backup_info
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return BackupInfo(
                backup_id="error",
                source_path=source_path,
                backup_path="",
                created_at=datetime.now(),
                size=0,
                status="failed"
            )
    
    async def _log_backup(self, backup_info: BackupInfo):
        """Log backup to database."""
        try:
            query = """
                INSERT INTO file_backups (backup_id, source_path, backup_path, created_at, size, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            params = {
                "backup_id": backup_info.backup_id,
                "source_path": backup_info.source_path,
                "backup_path": backup_info.backup_path,
                "created_at": backup_info.created_at,
                "size": backup_info.size,
                "status": backup_info.status
            }
            await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error logging backup: {e}")

# Initialize service
file_management_service = FileManagementService()

@router.get(
    "/list/{directory_path:path}",
    response_model=List[FileInfo],
    summary="List files in directory"
)
async def list_files(
    request: Request,
    directory_path: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """List files in specified directory (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"File listing for {directory_path} requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("file_listing_requests", 1, "count")
    
    # Security check - prevent directory traversal
    if ".." in directory_path or directory_path.startswith("/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid directory path"
        )
    
    return await file_management_service.list_files(directory_path)

@router.post(
    "/backup",
    response_model=BackupInfo,
    summary="Create file backup"
)
async def create_backup(
    request: Request,
    source_path: str,
    backup_name: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Create backup of files or directories (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Backup creation for {source_path} requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("backup_creation_requests", 1, "count")
    
    # Security check
    if ".." in source_path or source_path.startswith("/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid source path"
        )
    
    backup_info = await file_management_service.create_backup(source_path, backup_name)
    
    if backup_info.status == "failed":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create backup"
        )
    
    return backup_info

@router.delete(
    "/delete/{file_path:path}",
    response_model=FileOperationResult,
    summary="Delete file or directory"
)
async def delete_file(
    request: Request,
    file_path: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Delete file or directory (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"File deletion for {file_path} requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("file_deletion_requests", 1, "count")
    
    # Security check
    if ".." in file_path or file_path.startswith("/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file path"
        )
    
    try:
        path = Path(file_path)
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File or directory not found"
            )
        
        if path.is_file():
            path.unlink()
            affected_files = 1
        else:
            file_count = sum(1 for _ in path.rglob('*') if _.is_file())
            shutil.rmtree(path)
            affected_files = file_count
        
        return FileOperationResult(
            success=True,
            message=f"Successfully deleted {file_path}",
            affected_files=affected_files
        )
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete file"
        )

@router.post(
    "/restore/{backup_id}",
    response_model=FileOperationResult,
    summary="Restore from backup"
)
async def restore_backup(
    request: Request,
    backup_id: str,
    target_path: str,
    current_user: Dict[str, Any] = Depends(require_admin)
):
    """Restore files from backup (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Backup restore {backup_id} to {target_path} requested by admin {current_user.get('username')} from {client_ip}")
    
    # Performance tracking
    if performance_logger:
        performance_logger.record_metric("backup_restore_requests", 1, "count")
    
    try:
        # Get backup info from database
        if file_management_service.db_manager:
            query = "SELECT backup_path FROM file_backups WHERE backup_id = ?"
            result = await file_management_service.db_manager.execute_query(query, {"backup_id": backup_id})
            
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Backup not found"
                )
            
            backup_path = result[0][0]
            
            # Restore files
            if os.path.exists(backup_path):
                shutil.copytree(backup_path, target_path, dirs_exist_ok=True)
                file_count = sum(1 for _ in Path(backup_path).rglob('*') if _.is_file())
                
                return FileOperationResult(
                    success=True,
                    message=f"Successfully restored backup {backup_id} to {target_path}",
                    affected_files=file_count
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Backup files not found"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to restore backup"
        )
