import logging
from typing import Any, Dict, List, Optional

from app.core.backup.distributed_backup import distributed_backup

from ....core_system.security.input_validation import get_input_validator
from ....core_system.security.unified_audit_system import (
    API,
    AUTHENTICATION,
    ENHANCED,
    FEATURES:,
    SECURED,
    SECURITY,
    UNIFIED,
    WITH,
    APIRouter,
    BackgroundTasks,
    Backup,
    BackupDataType,
    BaseModel,
    Comprehensive,
    DDoS,
    Depends,
    End-to-end,
    Field,
    HTTPBearer,
    HTTPException,
    Input,
    Path,
    Provides,
    Rate,
    Request,
    Role-based,
    SecurityEventType,
)
from ....core_system.security.unified_audit_system import SecurityLevel as AuthSecurityLevel
from ....core_system.security.unified_audit_system import (
    SecuritySeverity,
    ThreatLevel,
    Unified,
    UniversalBackupService,
    """,
    -,
    ....core_system.security.unified_auth_manager,
    ..services.universal_backup_service,
    access,
    all,
    and,
    audit,
    authentication/authorization,
    backup,
    control,
    distributed,
    encryption,
    endpoints,
    fastapi,
    fastapi.security,
    for,
    from,
    functionality.,
    get_unified_audit_system,
    get_unified_auth_manager,
    import,
    integration,
    limiting,
    logging,
    management,
    operations,
    pathlib,
    protection,
    pydantic,
    sanitization,
    system,
    to,
    validation,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/backup", tags=["backup"])
security = HTTPBearer()

# Initialize security components
auth_manager = get_unified_auth_manager()
audit_system = get_unified_audit_system()
input_validator = get_input_validator()


async def require_backup_auth(request: Request, token: str = Depends(security)):
    """Require authentication for backup operations."""
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
                f"Failed backup authentication from {request.client.host if request.client else 'unknown'}",
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM,
                source_ip=request.client.host if request.client else None,
                resource="/api/v1/system/backup",
                details={"error": auth_result.get('error')}
            )
            raise HTTPException(status_code=401, detail="Authentication required")

        # Check backup permissions
        permissions = auth_result.get('permissions', [])
        if not any(perm in permissions for perm in ['admin', 'super_admin', 'backup_admin']):
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
            raise HTTPException(status_code=403, detail="Backup privileges required")

        return auth_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup authentication error: {e}")
        raise HTTPException(status_code=500, detail="Authentication system error")

class CreateBackupRequest(BaseModel):
    """Request model for creating a backup."""
    description: str = Field("", description="Backup description")
    password: Optional[str] = Field(None, description="Encryption password (auto-generated if not provided)")

class RecoverBackupRequest(BaseModel):
    """Request model for recovering a backup."""
    backup_id: str = Field(..., description="Backup ID to recover")
    password: str = Field(..., description="Decryption password")

class BackupResponse(BaseModel):
    """Response model for backup operations."""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

@router.get("/status")
async def get_backup_status(
    request: Request,
    current_user: dict = Depends(require_backup_auth)
) -> Dict[str, Any]:
    """
    Get overall backup system status with enhanced security.

    **Admin only endpoint with comprehensive audit logging**

    Returns:
    - Total number of backups
    - System health metrics
    - Storage usage statistics
    - Redundancy information
    """
    try:
        # Log access attempt
        audit_system.log_security_event(
            SecurityEventType.DATA_ACCESS,
            "Backup system status requested",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/status",
            action="GET"
        )

        status = await distributed_backup.get_backup_status()

        # Log successful access
        audit_system.log_security_event(
            SecurityEventType.DATA_ACCESS,
            "Backup system status accessed successfully",
            SecuritySeverity.INFO,
            ThreatLevel.LOW,
            user_id=current_user.get('user_id'),
            source_ip=request.client.host if request.client else None,
            resource="/api/v1/system/backup/status",
            details={"total_backups": status.get("total_backups", 0)}
        )

        return {
            "success": True,
            "data": status
        }
    except Exception as e:
        logger.error(f"Failed to get backup status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup status")

@router.get("/list")
async def list_backups(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)) -> Dict[str, Any]:
    """
    List all available backups.
    
    **Admin only endpoint**
    
    Returns:
    - List of all backups with metadata
    - Health status for each backup
    - Recovery information
    """
    try:
        backups = await distributed_backup.list_backups()
        return {
            "success": True,
            "data": {
                "backups": backups,
                "total_count": len(backups)
            }
        }
    except Exception as e:
        logger.error(f"Failed to list backups: {e}")
        raise HTTPException(status_code=500, detail="Failed to list backups")

@router.post("/create")
async def create_backup(
    request: CreateBackupRequest,
    background_tasks: BackgroundTasks,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
) -> BackupResponse:
    """
    Create a new distributed backup.
    
    **Admin only endpoint**
    
    This creates an encrypted, compressed backup of critical database data
    and distributes it across multiple users for redundancy.
    
    **Process:**
    1. Export critical database tables (users, guilds, channels, recent messages)
    2. Compress the data using gzip
    3. Encrypt using Fernet encryption with provided/generated password
    4. Split into shards (1MB each)
    5. Distribute shards across users with redundancy
    
    **Security:**
    - Data is encrypted before distribution
    - Users cannot access the raw backup data
    - Each shard is checksummed for integrity
    - Requires majority of shards for recovery
    
    **Example:**
    ```bash
    curl -X POST "https://api.example.com/v1/backup/create" \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{
        "description": "Weekly backup",
        "password": "secure_password_123"
      }'
    ```
    """
    try:
        # Create backup in background to avoid timeout
        backup_id = await distributed_backup.create_distributed_backup(
            description=request.description,
            password=request.password
        )
        
        return BackupResponse(
            success=True,
            message="Backup created successfully",
            data={
                "backup_id": backup_id,
                "description": request.description
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to create backup")

@router.post("/recover")
async def recover_backup(
    request: RecoverBackupRequest,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
) -> BackupResponse:
    """
    Recover data from a distributed backup.
    
    **Admin only endpoint**
    
    This recovers and decrypts a backup from the distributed storage system.
    
    **Process:**
    1. Locate and verify backup shards
    2. Check if enough shards are available for recovery
    3. Reconstruct the encrypted backup data
    4. Decrypt using provided password
    5. Decompress and return the backup data
    
    **Requirements:**
    - Must have at least 51% of shards available
    - Correct decryption password
    - Valid backup ID
    
    **Example:**
    ```bash
    curl -X POST "https://api.example.com/v1/backup/recover" \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{
        "backup_id": "550e8400-e29b-41d4-a716-446655440000",
        "password": "secure_password_123"
      }'
    ```
    """
    try:
        backup_data = await distributed_backup.recover_backup(
            backup_id=request.backup_id,
            password=request.password
        )
        
        # In a real implementation, you might want to save this to a file
        # or provide a download link instead of returning the raw data
        
        return BackupResponse(
            success=True,
            message="Backup recovered successfully",
            data={
                "backup_id": request.backup_id,
                "size": len(backup_data),
                "recovered_at": "2024-01-01T12:00:00Z"  # Current timestamp
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to recover backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to recover backup")

@router.delete("/{backup_id}")
async def delete_backup(
    backup_id: str,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
) -> BackupResponse:
    """
    Delete a backup and all its distributed shards.
    
    **Admin only endpoint**
    
    **Warning:** This action is irreversible!
    
    **Example:**
    ```bash
    curl -X DELETE "https://api.example.com/v1/backup/550e8400-e29b-41d4-a716-446655440000" \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
    ```
    """
    try:
        success = await distributed_backup.delete_backup(backup_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Backup not found")
        
        return BackupResponse(
            success=True,
            message="Backup deleted successfully",
            data={"backup_id": backup_id}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete backup")

@router.get("/user/{user_id}/storage")
async def get_user_storage(
    user_id: int,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
) -> Dict[str, Any]:
    """
    Get storage information for a specific user.
    
    **Admin only endpoint**
    
    Shows how much backup storage space a user has allocated
    and how much they're currently using.
    
    **Example:**
    ```bash
    curl -X GET "https://api.example.com/v1/backup/user/123/storage" \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
    ```
    """
    try:
        storage_info = await distributed_backup.get_user_storage_info(user_id)
        return {
            "success": True,
            "data": {
                "user_id": user_id,
                **storage_info
            }
        }
    except Exception as e:
        logger.error(f"Failed to get user storage info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get storage information")

@router.get("/health")
async def backup_health_check() -> Dict[str, Any]:
    """
    Check the health of the backup system.
    
    **Public endpoint** - No authentication required
    
    Returns basic health information about the backup system
    without exposing sensitive details.
    
    **Example:**
    ```bash
    curl -X GET "https://api.example.com/v1/backup/health"
    ```
    """
    try:
        status = await distributed_backup.get_backup_status()
        
        # Return limited health information
        return {
            "success": True,
            "data": {
                "system_operational": True,
                "total_backups": status["total_backups"],
                "healthy_backups": status["healthy_backups"],
                "health_percentage": (status["healthy_backups"] / status["total_backups"] * 100) if status["total_backups"] > 0 else 100,
                "redundancy_factor": status["redundancy_factor"]
            }
        }
    except Exception as e:
        logger.error(f"Backup health check failed: {e}")
        return {
            "success": False,
            "data": {
                "system_operational": False,
                "error": "Health check failed"
            }
        }

@router.post("/maintenance/cleanup")
async def run_maintenance_cleanup(
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
) -> BackupResponse:
    """
    Manually trigger maintenance cleanup.
    
    **Admin only endpoint**
    
    This removes expired shards and optimizes storage usage.
    Normally runs automatically every hour.
    
    **Example:**
    ```bash
    curl -X POST "https://api.example.com/v1/backup/maintenance/cleanup" \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
    ```
    """
    try:
        await distributed_backup.cleanup_expired_shards()
        
        return BackupResponse(
            success=True,
            message="Maintenance cleanup completed successfully"
        )
        
    except Exception as e:
        logger.error(f"Maintenance cleanup failed: {e}")
        raise HTTPException(status_code=500, detail="Maintenance cleanup failed")

# Additional utility endpoints for monitoring and debugging

@router.get("/shards/orphaned")
async def get_orphaned_shards(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)) -> Dict[str, Any]:
    """
    Get list of orphaned shards (shards without valid backup metadata).
    
    **Admin only endpoint**
    
    Useful for debugging and cleanup operations.
    """
    try:
        orphaned_shards = []
        
        for shard_id, shard in distributed_backup.shard_registry.items():
            if shard.backup_id not in distributed_backup.backup_metadata:
                orphaned_shards.append({
                    "shard_id": shard_id,
                    "backup_id": shard.backup_id,
                    "size": shard.size,
                    "created_at": shard.created_at.isoformat()
                })
        
        return {
            "success": True,
            "data": {
                "orphaned_shards": orphaned_shards,
                "count": len(orphaned_shards)
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get orphaned shards: {e}")
        raise HTTPException(status_code=500, detail="Failed to get orphaned shards")

@router.get("/statistics")
async def get_backup_statistics(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)) -> Dict[str, Any]:
    """
    Get detailed backup system statistics.

    **Admin only endpoint**

    Provides comprehensive statistics for monitoring and analysis.
    """
    try:
        status = await distributed_backup.get_backup_status()
        backups = await distributed_backup.list_backups()

        # Calculate additional statistics
        total_backup_size = sum(backup["total_size"] for backup in backups)
        avg_backup_size = total_backup_size / len(backups) if backups else 0

        # Health distribution
        health_distribution = {"healthy": 0, "degraded": 0, "critical": 0}
        for backup in backups:
            if backup["health_percentage"] >= 80:
                health_distribution["healthy"] += 1
            elif backup["health_percentage"] >= 50:
                health_distribution["degraded"] += 1
            else:
                health_distribution["critical"] += 1

        return {
            "success": True,
            "data": {
                **status,
                "backup_statistics": {
                    "total_backup_size": total_backup_size,
                    "average_backup_size": avg_backup_size,
                    "health_distribution": health_distribution
                }
            }
        }

    except Exception as e:
        logger.error(f"Failed to get backup statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup statistics")

# Shard Distribution Endpoints

@router.post("/shards/request")
async def request_shard(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)) -> Dict[str, Any]:
    """
    Request a backup shard to store.

    **User endpoint** - Users can request shards to contribute storage

    This endpoint allows users to participate in the distributed backup system
    by storing encrypted backup shards. Users receive rewards for storage.

    **Process:**
    1. System finds shards that need more redundancy
    2. Selects appropriate shard based on user's available storage
    3. Assigns shard to user with storage tracking
    4. Returns shard metadata and storage reward information

    **Rewards:**
    - Points based on storage size and duration
    - Contribution to system resilience
    - Priority access during system recovery

    **Example:**
    ```bash
    curl -X POST "https://api.example.com/v1/backup/shards/request" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        shard_info = await distributed_backup.request_shard_for_user(current_user.id)

        if not shard_info:
            return {
                "success": False,
                "message": "No shards available for storage at this time",
                "data": None
            }

        return {
            "success": True,
            "message": "Shard assigned successfully",
            "data": shard_info
        }

    except Exception as e:
        logger.error(f"Failed to request shard for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to request shard")

@router.get("/shards/my")
async def get_my_shards(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)) -> Dict[str, Any]:
    """
    Get all shards stored by the current user.

    **User endpoint**

    Returns information about all backup shards currently stored by the user,
    including storage rewards and expiration dates.

    **Example:**
    ```bash
    curl -X GET "https://api.example.com/v1/backup/shards/my" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        user_shards = await distributed_backup.get_user_shards(current_user.id)

        return {
            "success": True,
            "data": {
                "shards": user_shards,
                "total_shards": len(user_shards),
                "total_storage_mb": sum(shard["size"] for shard in user_shards) / (1024 * 1024),
                "total_rewards": sum(shard["reward"]["points"] for shard in user_shards)
            }
        }

    except Exception as e:
        logger.error(f"Failed to get shards for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user shards")

@router.post("/shards/{shard_id}/verify")
async def verify_shard_storage(
    shard_id: str,
    checksum: str,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> Dict[str, Any]:
    """
    Verify that a shard is correctly stored.

    **User endpoint**

    Users must periodically verify they still have their assigned shards
    by providing the correct checksum. This ensures data integrity.

    **Example:**
    ```bash
    curl -X POST "https://api.example.com/v1/backup/shards/abc123/verify" \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"checksum": "sha256_hash_here"}'
    ```
    """
    try:
        is_valid = await distributed_backup.verify_user_shard(
            current_user.id, shard_id, checksum
        )

        if is_valid:
            return {
                "success": True,
                "message": "Shard verification successful",
                "data": {"verified": True, "shard_id": shard_id}
            }
        else:
            return {
                "success": False,
                "message": "Shard verification failed",
                "data": {"verified": False, "shard_id": shard_id}
            }

    except Exception as e:
        logger.error(f"Failed to verify shard {shard_id} for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify shard")

@router.delete("/shards/{shard_id}")
async def release_shard(
    shard_id: str,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> Dict[str, Any]:
    """
    Release a shard from user storage.

    **User endpoint**

    Allows users to stop storing a particular shard. The system will
    automatically redistribute the shard to maintain redundancy.

    **Example:**
    ```bash
    curl -X DELETE "https://api.example.com/v1/backup/shards/abc123" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        success = await distributed_backup.release_user_shard(current_user.id, shard_id)

        if success:
            return {
                "success": True,
                "message": "Shard released successfully",
                "data": {"shard_id": shard_id}
            }
        else:
            raise HTTPException(status_code=404, detail="Shard not found or not owned by user")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to release shard {shard_id} for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to release shard")

@router.get("/shards/available")
async def get_available_shards(current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)) -> Dict[str, Any]:
    """
    Get information about shards available for storage.

    **User endpoint**

    Shows how many shards are available for storage and potential rewards.
    Helps users understand the current system needs.

    **Example:**
    ```bash
    curl -X GET "https://api.example.com/v1/backup/shards/available" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        # Count shards that need more redundancy
        available_count = 0
        total_reward_potential = 0

        user_storage = distributed_backup.user_storage.get(current_user.id)
        user_shards = user_storage.stored_shards if user_storage else []

        for shard_id, shard in distributed_backup.shard_registry.items():
            if shard_id in user_shards:
                continue  # User already has this shard

            current_copies = sum(
                1 for storage in distributed_backup.user_storage.values()
                if shard_id in storage.stored_shards
            )

            if current_copies < shard.redundancy_level:
                if distributed_backup._can_store_shard(current_user.id, shard):
                    available_count += 1
                    reward = distributed_backup._calculate_storage_reward(shard)
                    total_reward_potential += reward["points"]

        return {
            "success": True,
            "data": {
                "available_shards": available_count,
                "potential_rewards": round(total_reward_potential, 2),
                "storage_limit_mb": distributed_backup.user_storage_limit / (1024 * 1024),
                "current_usage": await distributed_backup.get_user_storage_info(current_user.id)
            }
        }

    except Exception as e:
        logger.error(f"Failed to get available shards for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get available shards")


# Universal Backup Endpoints with Opt-out Support

class UserBackupPreferencesRequest(BaseModel):
    """Request model for setting user backup preferences."""
    opt_out_level: str = Field(..., description="Backup opt-out level")
    excluded_data_types: List[str] = Field(default_factory=list, description="Data types to exclude")
    retention_days: int = Field(365, description="Data retention period in days")
    allow_cross_server: bool = Field(True, description="Allow cross-server backup")

class BackupUserDataRequest(BaseModel):
    """Request model for backing up user data."""
    user_ids: List[str] = Field(..., description="User IDs to backup")
    data_types: Optional[List[str]] = Field(None, description="Specific data types to backup")
    backup_node_api_key: Optional[str] = Field(None, description="Backup node API key")

class BackupMessagesRequest(BaseModel):
    """Request model for backing up messages."""
    channel_ids: Optional[List[str]] = Field(None, description="Channel IDs to backup")
    date_range: Optional[Dict[str, str]] = Field(None, description="Date range for messages")
    backup_node_api_key: Optional[str] = Field(None, description="Backup node API key")


@router.post("/users/preferences")
async def set_user_backup_preferences(
    request: UserBackupPreferencesRequest,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
):
    """
    Set user backup preferences including opt-out options.

    Users can control what data is backed up and how:
    - full_participation: All data backed up
    - metadata_only: Only metadata, no content
    - minimal_backup: Only essential data
    - complete_opt_out: No backup at all
    """
    try:
            BackupDataType,
            BackupOptOutLevel,
            UniversalBackupService,
            UserBackupPreferences,
        )

        # Initialize service (in production, this would be a singleton)
        backup_service = UniversalBackupService(from pathlib import Path
Path("data"))
        await backup_service.initialize()

        # Parse excluded data types
        excluded_types = set()
        for dt_str in request.excluded_data_types:
            try:
                excluded_types.add(BackupDataType(dt_str))
            except ValueError:
                logger.warning(f"Invalid data type: {dt_str}")

        # Create preferences
        preferences = UserBackupPreferences(
            user_id=current_user.id,
            opt_out_level=BackupOptOutLevel(request.opt_out_level),
            excluded_data_types=excluded_types,
            retention_days=request.retention_days,
            allow_cross_server=request.allow_cross_server
        )

        # Save preferences
        success = await backup_service.set_user_backup_preferences(current_user.id, preferences)

        if success:
            return {
                "success": True,
                "message": "Backup preferences updated successfully",
                "preferences": {
                    "opt_out_level": preferences.opt_out_level.value,
                    "excluded_data_types": [dt.value for dt in preferences.excluded_data_types],
                    "retention_days": preferences.retention_days,
                    "allow_cross_server": preferences.allow_cross_server
                }
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update backup preferences")

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid preference value: {e}")
    except Exception as e:
        logger.error(f"Failed to set backup preferences for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update backup preferences")


@router.get("/users/preferences")
async def get_user_backup_preferences(
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
):
    """Get current user's backup preferences."""
    try:
        backup_service = UniversalBackupService(from pathlib import Path
Path("data"))
        await backup_service.initialize()

        preferences = await backup_service.get_user_backup_preferences(current_user.id)

        return {
            "success": True,
            "preferences": {
                "opt_out_level": preferences.opt_out_level.value,
                "excluded_data_types": [dt.value for dt in preferences.excluded_data_types],
                "retention_days": preferences.retention_days,
                "allow_cross_server": preferences.allow_cross_server,
                "encryption_preference": preferences.encryption_preference,
                "last_updated": preferences.last_updated.isoformat()
            }
        }

    except Exception as e:
        logger.error(f"Failed to get backup preferences for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup preferences")


@router.post("/users/backup")
async def backup_user_data(
    request: BackupUserDataRequest,
    background_tasks: BackgroundTasks,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Backup user data with respect to opt-out preferences.

    **Admin only endpoint**

    This endpoint respects user backup preferences and only backs up
    data that users have consented to backup.
    """
    try:
        backup_service = UniversalBackupService(from pathlib import Path
Path("data"))
        await backup_service.initialize()

        # Get users to backup (implementation depends on your user model)
        # This is a placeholder - you'd need to implement user retrieval

        backup_results = []

        for user_id in request.user_ids:
            # Get user object (placeholder)
            user = None  # Get user by ID

            if user:
                data_types = None
                if request.data_types:
                    data_types = [BackupDataType(dt) for dt in request.data_types]

                backup_id = await backup_service.backup_user_data(
                    user=user,
                    data_types=data_types,
                    backup_node_api_key=request.backup_node_api_key
                )

                backup_results.append({
                    "user_id": user_id,
                    "backup_id": backup_id,
                    "success": backup_id is not None
                })

        return {
            "success": True,
            "message": f"Backup initiated for {len(request.user_ids)} users",
            "results": backup_results
        }

    except Exception as e:
        logger.error(f"Failed to backup user data: {e}")
        raise HTTPException(status_code=500, detail="Failed to backup user data")


@router.post("/messages/backup")
async def backup_message_data(
    request: BackupMessagesRequest,
    background_tasks: BackgroundTasks,
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Backup message data with respect to user opt-out preferences.

    **Admin only endpoint**

    This endpoint respects user backup preferences for message content.
    Users who have opted out will have their messages excluded or
    only metadata backed up based on their preferences.
    """
    try:
        backup_service = UniversalBackupService(from pathlib import Path
Path("data"))
        await backup_service.initialize()

        # Get messages to backup (implementation depends on your message model)
        # This is a placeholder - you'd need to implement message retrieval
        messages_to_backup = []  # Get messages by criteria

        if not messages_to_backup:
            return {
                "success": True,
                "message": "No messages found to backup",
                "backup_id": None
            }

        backup_id = await backup_service.backup_message_data(
            messages=messages_to_backup,
            backup_node_api_key=request.backup_node_api_key
        )

        return {
            "success": True,
            "message": f"Message backup {'completed' if backup_id else 'failed'}",
            "backup_id": backup_id,
            "message_count": len(messages_to_backup)
        }

    except Exception as e:
        logger.error(f"Failed to backup message data: {e}")
        raise HTTPException(status_code=500, detail="Failed to backup message data")


@router.get("/statistics")
async def get_backup_statistics(
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import require_admin)
):
    """
    Get comprehensive backup system statistics.

    **Admin only endpoint**
    """
    try:
        backup_service = UniversalBackupService(from pathlib import Path
Path("data"))
        await backup_service.initialize()

        stats = backup_service.get_statistics()

        return {
            "success": True,
            "statistics": stats
        }

    except Exception as e:
        logger.error(f"Failed to get backup statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup statistics")
