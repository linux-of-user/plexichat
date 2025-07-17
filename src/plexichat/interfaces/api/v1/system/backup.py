# pyright: strict
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field

from plexichat.features.users.user import User
from plexichat.infrastructure.utils.auth import require_admin
from plexichat.core.backup.backup_manager import backup_manager
from plexichat.core.security.input_validation import get_input_validator  # type: ignore
from plexichat.core.security.unified_audit_system import (
    get_unified_audit_system, SecurityEventType, SecuritySeverity, ThreatLevel
)
from plexichat.core.auth.unified_auth_manager import get_unified_auth_manager, SecurityLevel as AuthSecurityLevel  # type: ignore

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/backup", tags=["backup"])
security = HTTPBearer()

auth_manager = None
try:
    auth_manager = get_unified_auth_manager()  # type: ignore
except ImportError:
    logger.warning("Unified auth manager not available.")
audit_system = get_unified_audit_system()
input_validator = get_input_validator()  # type: ignore

async def require_backup_auth(request: Request, token: str = Depends(security)) -> dict:  # type: ignore
    if not auth_manager:
        raise HTTPException(status_code=500, detail="Authentication system unavailable")
    try:
        auth_result = await auth_manager.require_authentication(token.credentials, AuthSecurityLevel.HIGH)  # type: ignore
        if not auth_result.get('authenticated'):
            audit_system.log_security_event(  # type: ignore
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Failed backup authentication from {request.client.host if request.client else 'unknown'}",
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM,
                source_ip=request.client.host if request.client else None,
                resource="/api/v1/system/backup",
                details={"error": auth_result.get('error')}
            )
            raise HTTPException(status_code=401, detail="Authentication required")
        permissions = auth_result.get('permissions', [])
        if not any(perm in permissions for perm in ['admin', 'super_admin', 'backup_admin']):
            audit_system.log_security_event(  # type: ignore
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Insufficient permissions for backup operations: {permissions}",
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM,
                user_id=auth_result.get('user_id'),
                source_ip=request.client.host if request.client else None,
                resource="/api/v1/system/backup"
            )
            raise HTTPException(status_code=403, detail="Backup privileges required")
        return auth_result  # type: ignore
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup authentication error: {e}")
        raise HTTPException(status_code=500, detail="Authentication system error")

class CreateBackupRequest(BaseModel):
    description: str = Field("", description="Backup description")
    password: Optional[str] = Field(None, description="Encryption password (auto-generated if not provided)")

class RecoverBackupRequest(BaseModel):
    backup_id: str = Field(..., description="Backup ID to recover")
    password: str = Field(..., description="Decryption password")

class BackupResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

@router.get("/status")
async def get_backup_status(request: Request, current_user: dict = Depends(require_backup_auth)) -> Dict[str, Any]:  # type: ignore
    try:
        audit_system.log_security_event(  # type: ignore
            SecurityEventType.DATA_ACCESS,
            "Backup system status requested",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user['user_id'],
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/status",
            action="GET"
        )
        status = backup_manager.get_stats()
        audit_system.log_security_event(  # type: ignore
            SecurityEventType.DATA_ACCESS,
            "Backup system status accessed successfully",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user['user_id'],
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/status",
            details={"total_backups": status["backups_created"]}
        )
        return {"success": True, "data": status}
    except Exception as e:
        logger.error(f"Failed to get backup status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup status")

@router.get("/list")
async def list_backups(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    try:
        logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} listing backups")
        backups = await backup_manager.list_backups()
        return {"success": True, "data": {"backups": backups, "total_count": len(backups)}}
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list backups")

@router.post("/create")
async def create_backup(request: CreateBackupRequest, background_tasks: BackgroundTasks, current_user: User = Depends(require_admin)) -> BackupResponse:
    try:
        logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} creating backup")
        # Add background task for cleanup if needed
        background_tasks.add_task(lambda: logger.info("Backup creation task completed"))

        backup_info = await backup_manager.create_database_backup(request.description)
        if not backup_info:
            raise HTTPException(status_code=500, detail="Failed to create backup")
        return BackupResponse(success=True, message="Backup created successfully", data={"backup_id": backup_info.backup_id, "description": request.description})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to create backup")

@router.post("/recover")
async def recover_backup(request: RecoverBackupRequest, current_user: User = Depends(require_admin)) -> BackupResponse:
    try:
        logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} recovering backup {request.backup_id}")
        success = await backup_manager.restore_backup(request.backup_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to recover backup")
        return BackupResponse(success=True, message="Backup recovered successfully", data={"backup_id": request.backup_id})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to recover backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to recover backup")

@router.delete("/{backup_id}")
async def delete_backup(backup_id: str, current_user: User = Depends(require_admin)) -> BackupResponse:
    logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} attempting to delete backup {backup_id}")
    raise HTTPException(status_code=501, detail="Delete backup not implemented in backup_manager")

@router.get("/user/{user_id}/storage")
async def get_user_storage(user_id: int, current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} getting storage for user {user_id}")
    raise HTTPException(status_code=501, detail="Get user storage not implemented in backup_manager")

@router.get("/health")
async def backup_health_check() -> Dict[str, Any]:
    raise HTTPException(status_code=501, detail="Backup health check not implemented in backup_manager")

@router.post("/maintenance/cleanup")
async def run_maintenance_cleanup(current_user: User = Depends(require_admin)) -> BackupResponse:
    logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} running maintenance cleanup")
    raise HTTPException(status_code=501, detail="Maintenance cleanup not implemented in backup_manager")

@router.get("/shards/orphaned")
async def get_orphaned_shards(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} getting orphaned shards")
    raise HTTPException(status_code=501, detail="Orphaned shards not implemented in backup_manager")

@router.get("/statistics")
async def get_backup_statistics(current_user: User = Depends(require_admin)) -> Dict[str, Any]:
    logger.info(f"User {current_user.id if hasattr(current_user, 'id') else 'unknown'} getting backup statistics")
    raise HTTPException(status_code=501, detail="Backup statistics not implemented in backup_manager")

# Additional endpoints for shard management, user preferences, and universal backup can be added here following the same robust, type-safe, and thread-safe patterns.
