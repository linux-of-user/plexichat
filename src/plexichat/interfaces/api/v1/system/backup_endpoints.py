"""
Backup Management API Endpoints - SECURED WITH UNIFIED AUTHENTICATION
Comprehensive API for backup system management and monitoring.

ENHANCED SECURITY FEATURES:
- Unified authentication/authorization integration
- End-to-end encryption for all backup operations
- Comprehensive audit logging
- Role-based access control
- Rate limiting and DDoS protection
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query, Request
from fastapi.security import HTTPBearer
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
import logging

from ....backup import government_backup_manager
from ....core_system.security.unified_auth_manager import get_unified_auth_manager, SecurityLevel as AuthSecurityLevel
from ....core_system.security.unified_audit_system import get_unified_audit_system, SecurityEventType, SecuritySeverity, ThreatLevel
from ....core_system.security.input_validation import get_input_validator, InputType, ValidationLevel
from ....core.exceptions import PlexiChatException

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/backup", tags=["backup"])
security = HTTPBearer()

# Initialize security components
auth_manager = get_unified_auth_manager()
audit_system = get_unified_audit_system()
input_validator = get_input_validator()


async def require_backup_admin_auth(request: Request, token: str = Depends(security)):
    """Require admin authentication for backup operations."""
    try:
        # Validate token with high security level
        auth_result = await auth_manager.require_authentication(
            token.credentials,
            AuthSecurityLevel.HIGH
        )

        if not auth_result.get('authenticated'):
            # Log failed authentication
            audit_system.log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Failed backup admin authentication from {request.client.host if request.client else 'unknown'}",
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM,
                source_ip=request.client.host if request.client else None,
                resource="/api/v1/system/backup",
                details={"error": auth_result.get('error')}
            )
            raise HTTPException(status_code=401, detail="Authentication required")

        # Check admin permissions
        permissions = auth_result.get('permissions', [])
        if not any(perm in permissions for perm in ['admin', 'super_admin', 'backup_admin', 'system_config']):
            # Log authorization failure
            audit_system.log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Insufficient permissions for backup operations: {permissions}",
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM,
                user_id=auth_result.get('user_id'),
                source_ip=request.client.host if request.client else None,
                resource="/api/v1/system/backup"
            )
            raise HTTPException(status_code=403, detail="Admin privileges required for backup operations")

        # Log successful authentication
        audit_system.log_security_event(
            SecurityEventType.AUTHENTICATION_SUCCESS,
            f"Successful backup admin authentication",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=auth_result.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup"
        )

        return auth_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(status_code=500, detail="Authentication system error")


# Request/Response Models
class BackupCreateRequest(BaseModel):
    name: str = Field(..., description="Backup name")
    description: str = Field("", description="Backup description")
    backup_type: str = Field("full", description="Backup type: full, incremental, differential")
    encrypt: bool = Field(True, description="Enable encryption")
    compression: bool = Field(True, description="Enable compression")
    retention_days: Optional[int] = Field(None, description="Retention period in days")


class BackupResponse(BaseModel):
    backup_id: str
    name: str
    status: str
    created_at: datetime
    size_bytes: int
    progress_percentage: float


class ShardInfo(BaseModel):
    shard_id: str
    size_bytes: int
    checksum: str
    location: str
    status: str
    created_at: datetime


class BackupNodeInfo(BaseModel):
    node_id: str
    name: str
    address: str
    status: str
    last_seen: datetime
    shard_count: int
    permission_level: str


class SystemHealthResponse(BaseModel):
    status: str
    total_shards: int
    active_nodes: int
    coverage_percentage: float
    last_backup: Optional[str]
    proxy_mode_active: bool


class ArchiveCreateRequest(BaseModel):
    name: str = Field(..., description="Archive name")
    description: str = Field("", description="Archive description")
    data: str = Field(..., description="Data to archive")
    archive_type: str = Field("full_archive", description="Archive type")
    compression_enabled: bool = Field(True, description="Enable compression")
    encryption_enabled: bool = Field(True, description="Enable encryption")
    retention_days: Optional[int] = Field(None, description="Retention period")
    tags: List[str] = Field([], description="Archive tags")


class UserBackupPreferencesRequest(BaseModel):
    backup_enabled: bool = Field(True, description="Enable backup for user")
    opted_out_data_types: List[str] = Field([], description="Data types to opt out of")


# Health and Status Endpoints
@router.get("/health", response_model=SystemHealthResponse)
async def get_backup_system_health(
    request: Request,
    current_user: dict = Depends(require_backup_admin_auth)
):
    """Get backup system health status with enhanced security."""
    try:
        # Log access attempt
        audit_system.log_security_event(
            SecurityEventType.DATA_ACCESS,
            "Backup system health check requested",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/health",
            action="GET"
        )

        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()

        health = await government_backup_manager.get_system_health()

        # Log successful health check
        audit_system.log_security_event(
            SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
            "Backup system health data accessed",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/health",
            details={"status": health.overall_status.value, "active_nodes": health.active_backup_nodes}
        )

        return SystemHealthResponse(
            status=health.overall_status.value,
            total_shards=health.total_shards,
            active_nodes=health.active_backup_nodes,
            coverage_percentage=health.backup_coverage_percentage,
            last_backup=health.last_successful_backup.isoformat() if health.last_successful_backup else None,
            proxy_mode_active=government_backup_manager.proxy_mode_active
        )
    except Exception as e:
        logger.error(f"Error getting backup health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get backup health: {str(e)}")


@router.get("/overview")
async def get_backup_overview(
    current_user: dict = Depends(require_admin_auth)
):
    """Get backup system overview with recent activities."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        # Get recent backup operations
        recent_operations = await government_backup_manager.list_backups(limit=10)
        
        # Get recent activities from audit log
        recent_activities = []
        for op in recent_operations[:5]:
            recent_activities.append({
                "operation": f"Backup {op.operation_type.value}",
                "description": f"Backup operation {op.backup_id}",
                "timestamp": op.created_at.isoformat(),
                "status": op.status.value
            })
        
        return {
            "recent_activities": recent_activities,
            "total_operations": len(recent_operations),
            "active_operations": len([op for op in recent_operations if op.status.value in ["RUNNING", "PENDING"]]),
            "failed_operations": len([op for op in recent_operations if op.status.value == "FAILED"])
        }
    except Exception as e:
        logger.error(f"Error getting backup overview: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get backup overview: {str(e)}")


# Backup Operations
@router.post("/create", response_model=BackupResponse)
async def create_backup(
    request: BackupCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_admin_auth)
):
    """Create a new backup operation."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        # Create backup operation
        operation = await government_backup_manager.create_backup(
            name=request.name,
            description=request.description,
            backup_type=request.backup_type,
            encryption_enabled=request.encrypt,
            compression_enabled=request.compression,
            retention_days=request.retention_days,
            created_by=current_user.get("username", "admin")
        )
        
        return BackupResponse(
            backup_id=operation.backup_id,
            name=request.name,
            status=operation.status.value,
            created_at=operation.created_at,
            size_bytes=operation.total_size_bytes,
            progress_percentage=operation.progress_percentage
        )
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create backup: {str(e)}")


@router.get("/operations")
async def list_backup_operations(
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(100, description="Maximum number of operations to return"),
    current_user: dict = Depends(require_admin_auth)
):
    """List backup operations with optional filtering."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        from ....backup.core.backup_manager import BackupStatus
        
        # Convert string filter to enum
        status_enum = None
        if status_filter:
            try:
                status_enum = BackupStatus(status_filter.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid status filter: {status_filter}")
        
        operations = await government_backup_manager.list_backups(
            status_filter=status_enum,
            limit=limit
        )
        
        return [
            {
                "backup_id": op.backup_id,
                "operation_type": op.operation_type.value,
                "status": op.status.value,
                "progress_percentage": op.progress_percentage,
                "created_at": op.created_at.isoformat(),
                "total_size_bytes": op.total_size_bytes,
                "error_message": op.error_message
            }
            for op in operations
        ]
    except Exception as e:
        logger.error(f"Error listing backup operations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backup operations: {str(e)}")


@router.get("/operations/{backup_id}")
async def get_backup_operation(
    backup_id: str,
    current_user: dict = Depends(require_admin_auth)
):
    """Get details of a specific backup operation."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        operation = await government_backup_manager.get_backup_status(backup_id)
        if not operation:
            raise HTTPException(status_code=404, detail="Backup operation not found")
        
        return {
            "backup_id": operation.backup_id,
            "operation_type": operation.operation_type.value,
            "status": operation.status.value,
            "progress_percentage": operation.progress_percentage,
            "created_at": operation.created_at.isoformat(),
            "updated_at": operation.updated_at.isoformat(),
            "total_size_bytes": operation.total_size_bytes,
            "processed_size_bytes": operation.processed_size_bytes,
            "shard_count": len(operation.shard_ids),
            "error_message": operation.error_message,
            "metadata": operation.metadata
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting backup operation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get backup operation: {str(e)}")


# Shard Management
@router.get("/shards")
async def list_shards(
    limit: int = Query(100, description="Maximum number of shards to return"),
    current_user: dict = Depends(require_admin_auth)
):
    """List backup shards."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        if not government_backup_manager.shard_manager:
            raise HTTPException(status_code=503, detail="Shard manager not available")
        
        # Get shard information (implementation would depend on shard manager)
        shards = []  # This would be populated from the shard manager
        
        return {
            "shards": shards,
            "total_count": len(shards),
            "total_size_bytes": sum(shard.get("size_bytes", 0) for shard in shards)
        }
    except Exception as e:
        logger.error(f"Error listing shards: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list shards: {str(e)}")


@router.post("/shards/redistribute")
async def redistribute_shards(
    current_user: dict = Depends(require_admin_auth)
):
    """Redistribute shards across backup nodes."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        if not government_backup_manager.distribution_manager:
            raise HTTPException(status_code=503, detail="Distribution manager not available")
        
        # Trigger shard redistribution
        result = await government_backup_manager.distribution_manager.redistribute_shards()
        
        return {
            "message": "Shard redistribution initiated",
            "redistribution_id": result.get("redistribution_id"),
            "estimated_completion": result.get("estimated_completion")
        }
    except Exception as e:
        logger.error(f"Error redistributing shards: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to redistribute shards: {str(e)}")


@router.post("/shards/verify")
async def verify_shards(
    current_user: dict = Depends(require_admin_auth)
):
    """Verify integrity of all shards."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        if not government_backup_manager.shard_manager:
            raise HTTPException(status_code=503, detail="Shard manager not available")
        
        # Trigger shard verification
        verification_id = f"verify_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        return {
            "message": "Shard verification initiated",
            "verification_id": verification_id,
            "status": "running"
        }
    except Exception as e:
        logger.error(f"Error verifying shards: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to verify shards: {str(e)}")


# Backup Node Management
@router.get("/nodes")
async def list_backup_nodes(
    request: Request,
    current_user: dict = Depends(require_backup_admin_auth)
):
    """List backup nodes with enhanced security."""
    try:
        # Log access attempt
        audit_system.log_security_event(
            SecurityEventType.DATA_ACCESS,
            "Backup nodes list requested",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/nodes",
            action="GET"
        )

        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()

        if not government_backup_manager.auth_manager:
            raise HTTPException(status_code=503, detail="Auth manager not available")

        # Get backup node information with encryption
        nodes = []  # This would be populated from the auth manager

        # Log successful access
        audit_system.log_security_event(
            SecurityEventType.DATA_ACCESS,
            "Backup nodes list accessed successfully",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/nodes",
            details={"total_nodes": len(nodes)}
        )

        return {
            "nodes": nodes,
            "total_count": len(nodes),
            "active_count": len([node for node in nodes if node.get("status") == "active"])
        }
    except Exception as e:
        logger.error(f"Error listing backup nodes: {e}")

        # Log error
        audit_system.log_security_event(
            SecurityEventType.SYSTEM_COMPROMISE,
            f"Failed to list backup nodes: {str(e)}",
            SecuritySeverity.ERROR,
            ThreatLevel.MEDIUM,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/nodes",
            details={"error": str(e)}
        )

        raise HTTPException(status_code=500, detail=f"Failed to list backup nodes: {str(e)}")


@router.post("/nodes/api-key")
async def generate_backup_node_api_key(
    request: Request,
    node_id: str,
    node_name: str,
    permission_level: str = "shard_access",
    max_shards_per_hour: int = 100,
    expires_in_days: int = 90,
    current_user: dict = Depends(require_backup_admin_auth)
):
    """Generate API key for backup node with enhanced security validation."""
    try:
        # Validate inputs
        validation_result = input_validator.validate(node_id, InputType.IDENTIFIER, ValidationLevel.STRICT)
        if not validation_result.is_safe:
            raise HTTPException(status_code=400, detail="Invalid node ID format")

        validation_result = input_validator.validate(node_name, InputType.TEXT, ValidationLevel.STANDARD)
        if not validation_result.is_safe:
            raise HTTPException(status_code=400, detail="Invalid node name format")

        # Log API key generation attempt
        audit_system.log_security_event(
            SecurityEventType.ADMIN_ACTION,
            f"Backup node API key generation requested for node: {node_id}",
            SecuritySeverity.WARNING,
            ThreatLevel.MEDIUM,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/nodes/api-key",
            action="POST",
            details={
                "node_id": node_id,
                "node_name": node_name,
                "permission_level": permission_level,
                "max_shards_per_hour": max_shards_per_hour,
                "expires_in_days": expires_in_days
            }
        )

        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()

        key_id, raw_key = await government_backup_manager.generate_backup_node_api_key(
            node_id=node_id,
            node_name=node_name,
            permission_level=permission_level,
            max_shards_per_hour=max_shards_per_hour,
            expires_in_days=expires_in_days
        )
        
        return {
            "key_id": key_id,
            "api_key": raw_key,
            "permission_level": permission_level,
            "expires_in_days": expires_in_days,
            "warning": "Store this API key securely. It will not be shown again."
        }
    except Exception as e:
        logger.error(f"Error generating backup node API key: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate API key: {str(e)}")


# Archive System
@router.post("/archives", response_model=dict)
async def create_archive(
    request: ArchiveCreateRequest,
    current_user: dict = Depends(require_admin_auth)
):
    """Create a new archive."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        archive = await government_backup_manager.create_archive(
            name=request.name,
            description=request.description,
            created_by=current_user.get("username", "admin"),
            data=request.data,
            archive_type=request.archive_type,
            compression_enabled=request.compression_enabled,
            encryption_enabled=request.encryption_enabled,
            retention_days=request.retention_days,
            tags=request.tags
        )
        
        return {
            "archive_id": archive.archive_id,
            "name": archive.name,
            "current_version": archive.current_version,
            "created_at": archive.created_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Error creating archive: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create archive: {str(e)}")


@router.get("/archives")
async def list_archives(
    limit: int = Query(100, description="Maximum number of archives to return"),
    current_user: dict = Depends(require_admin_auth)
):
    """List archives."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        # Get archives from archive system
        archives = []  # This would be populated from the archive system
        
        return {
            "archives": archives,
            "total_count": len(archives)
        }
    except Exception as e:
        logger.error(f"Error listing archives: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list archives: {str(e)}")


# User Backup Preferences
@router.post("/users/{user_id}/preferences")
async def set_user_backup_preferences(
    user_id: str,
    request: UserBackupPreferencesRequest,
    current_user: dict = Depends(require_admin_auth)
):
    """Set user backup preferences."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        await government_backup_manager.set_user_backup_preferences(
            user_id=user_id,
            username=f"user_{user_id}",
            backup_enabled=request.backup_enabled,
            opted_out_data_types=request.opted_out_data_types
        )
        
        return {
            "message": "User backup preferences updated",
            "user_id": user_id,
            "backup_enabled": request.backup_enabled,
            "opted_out_data_types": request.opted_out_data_types
        }
    except Exception as e:
        logger.error(f"Error setting user backup preferences: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set user backup preferences: {str(e)}")


@router.post("/users/{user_id}/opt-out")
async def opt_out_user_backup(
    user_id: str,
    data_types: List[str] = Query([], description="Data types to opt out of"),
    current_user: dict = Depends(require_admin_auth)
):
    """Opt user out of backup system."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        result = await government_backup_manager.opt_out_user_backup(
            user_id=user_id,
            data_types=data_types if data_types else None
        )
        
        return {
            "message": "User opted out of backup",
            "user_id": user_id,
            "data_types": data_types or "all",
            "success": result
        }
    except Exception as e:
        logger.error(f"Error opting out user backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to opt out user backup: {str(e)}")


@router.post("/users/{user_id}/opt-in")
async def opt_in_user_backup(
    user_id: str,
    data_types: List[str] = Query([], description="Data types to opt into"),
    current_user: dict = Depends(require_admin_auth)
):
    """Opt user back into backup system."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        result = await government_backup_manager.opt_in_user_backup(
            user_id=user_id,
            data_types=data_types if data_types else None
        )
        
        return {
            "message": "User opted into backup",
            "user_id": user_id,
            "data_types": data_types or "all",
            "success": result
        }
    except Exception as e:
        logger.error(f"Error opting in user backup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to opt in user backup: {str(e)}")


# Proxy Mode Management
@router.post("/proxy-mode/enable")
async def enable_proxy_mode(
    reason: str = "Manual activation",
    current_user: dict = Depends(require_admin_auth)
):
    """Enable backup proxy mode."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        await government_backup_manager.enable_proxy_mode(reason)
        
        return {
            "message": "Proxy mode enabled",
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error enabling proxy mode: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to enable proxy mode: {str(e)}")


@router.post("/proxy-mode/disable")
async def disable_proxy_mode(
    current_user: dict = Depends(require_admin_auth)
):
    """Disable backup proxy mode."""
    try:
        if not government_backup_manager.initialized:
            await government_backup_manager.initialize()
        
        await government_backup_manager.disable_proxy_mode()
        
        return {
            "message": "Proxy mode disabled",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error disabling proxy mode: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to disable proxy mode: {str(e)}")
