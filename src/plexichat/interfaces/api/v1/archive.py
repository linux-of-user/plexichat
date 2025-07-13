"""
Archive System API Endpoints

Provides API access to the archive system plugin for versioning functionality.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...core.auth.dependencies import get_current_user, require_admin
from ...logger_config import logger
from ...models.user import User

router = APIRouter(prefix="/archive", tags=["archive"])


class ServerArchiveConfigRequest(BaseModel):
    """Request model for server archive configuration."""
    archive_enabled: bool = Field(..., description="Enable archive system for server")
    enabled_types: List[str] = Field(default_factory=list, description="Archive types to enable")
    retention_days: int = Field(365, description="Archive retention period in days")
    max_versions_per_item: int = Field(100, description="Maximum versions per item")
    premium_only_access: bool = Field(False, description="Restrict access to premium users")
    auto_archive_edits: bool = Field(True, description="Automatically archive edits")
    auto_archive_deletions: bool = Field(True, description="Automatically archive deletions")
    compression_enabled: bool = Field(True, description="Enable compression")
    encryption_level: str = Field("quantum-resistant", description="Encryption level")


class CreateArchiveRequest(BaseModel):
    """Request model for creating archive versions."""
    original_id: str = Field(..., description="ID of original object")
    archive_type: str = Field(..., description="Type of archive")
    server_id: str = Field(..., description="Server ID")
    data: Dict[str, Any] = Field(..., description="Data to archive")
    change_description: str = Field("", description="Description of changes")
    access_level: str = Field("public", description="Access level for archive")
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")


class ArchiveResponse(BaseModel):
    """Response model for archive operations."""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


async def get_archive_plugin():
    """Get the archive system plugin instance."""
    try:
        from ....plugins.archive_system.archive_plugin import ArchiveSystemPlugin
        
        plugin = ArchiveSystemPlugin(Path("data"))
        await plugin.initialize()
        return plugin
    except Exception as e:
        logger.error(f"Failed to initialize archive plugin: {e}")
        raise HTTPException(status_code=500, detail="Archive system not available")


@router.get("/config/{server_id}")
async def get_server_archive_config(
    server_id: str,
    current_user: User = Depends(require_admin)
):
    """
    Get archive configuration for a server.
    
    **Admin only endpoint**
    """
    try:
        plugin = await get_archive_plugin()
        
        config = plugin.server_configs.get(server_id)
        if not config:
            return ArchiveResponse(
                success=False,
                message="Archive configuration not found for server",
                data={"server_id": server_id, "configured": False}
            )
        
        return ArchiveResponse(
            success=True,
            message="Archive configuration retrieved",
            data={
                "server_id": server_id,
                "archive_enabled": config.archive_enabled,
                "enabled_types": [t.value for t in config.enabled_types],
                "retention_days": config.retention_days,
                "max_versions_per_item": config.max_versions_per_item,
                "premium_only_access": config.premium_only_access,
                "auto_archive_edits": config.auto_archive_edits,
                "auto_archive_deletions": config.auto_archive_deletions,
                "compression_enabled": config.compression_enabled,
                "encryption_level": config.encryption_level
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to get archive config for server {server_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get archive configuration")


@router.post("/config/{server_id}")
async def set_server_archive_config(
    server_id: str,
    request: ServerArchiveConfigRequest,
    current_user: User = Depends(require_admin)
):
    """
    Set archive configuration for a server.
    
    **Admin only endpoint**
    """
    try:
        from ....plugins.archive_system.archive_plugin import ArchiveType, ServerArchiveConfig
        
        plugin = await get_archive_plugin()
        
        # Parse enabled types
        enabled_types = set()
        for type_str in request.enabled_types:
            try:
                enabled_types.add(ArchiveType(type_str))
            except ValueError:
                logger.warning(f"Invalid archive type: {type_str}")
        
        # Create configuration
        config = ServerArchiveConfig(
            server_id=server_id,
            archive_enabled=request.archive_enabled,
            enabled_types=enabled_types,
            retention_days=request.retention_days,
            max_versions_per_item=request.max_versions_per_item,
            premium_only_access=request.premium_only_access,
            auto_archive_edits=request.auto_archive_edits,
            auto_archive_deletions=request.auto_archive_deletions,
            compression_enabled=request.compression_enabled,
            encryption_level=request.encryption_level
        )
        
        # Save configuration
        success = await plugin.enable_server_archive(server_id, config)
        
        if success:
            return ArchiveResponse(
                success=True,
                message=f"Archive system {'enabled' if request.archive_enabled else 'configured'} for server",
                data={"server_id": server_id, "archive_enabled": request.archive_enabled}
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to save archive configuration")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid configuration: {e}")
    except Exception as e:
        logger.error(f"Failed to set archive config for server {server_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to set archive configuration")


@router.get("/versions/{original_id}")
async def get_archive_versions(
    original_id: str,
    archive_type: str = Query(..., description="Type of archive"),
    current_user: User = Depends(get_current_user)
):
    """
    Get all archive versions for an object.
    
    Returns versions based on user's access level and premium status.
    """
    try:
        from ....plugins.archive_system.archive_plugin import ArchiveType
        
        plugin = await get_archive_plugin()
        
        # Parse archive type
        try:
            arch_type = ArchiveType(archive_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid archive type: {archive_type}")
        
        # Get user permissions (placeholder - implement based on your user model)
        is_premium = getattr(current_user, 'is_premium', False)
        is_admin = getattr(current_user, 'is_admin', False)
        
        # Get versions
        versions = await plugin.get_archive_versions(
            original_id=original_id,
            archive_type=arch_type,
            user_id=current_user.id,
            is_premium=is_premium,
            is_admin=is_admin
        )
        
        # Format response
        version_data = []
        for version in versions:
            version_data.append({
                "archive_id": version.archive_id,
                "version_number": version.version_number,
                "created_at": version.created_at.isoformat(),
                "created_by": version.created_by,
                "change_description": version.change_description,
                "access_level": version.access_level.value,
                "tags": list(version.tags),
                "metadata": version.metadata
            })
        
        return ArchiveResponse(
            success=True,
            message=f"Found {len(versions)} archive versions",
            data={
                "original_id": original_id,
                "archive_type": archive_type,
                "versions": version_data,
                "total_versions": len(versions)
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get archive versions for {original_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get archive versions")


@router.post("/create")
async def create_archive_version(
    request: CreateArchiveRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Create a new archive version.
    
    Archives the provided data with versioning and access control.
    """
    try:
        from ....plugins.archive_system.archive_plugin import ArchiveAccessLevel, ArchiveType
        
        plugin = await get_archive_plugin()
        
        # Parse types
        try:
            arch_type = ArchiveType(request.archive_type)
            access_level = ArchiveAccessLevel(request.access_level)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid type or access level: {e}")
        
        # Convert tags
        tags = set(request.tags) if request.tags else None
        
        # Create archive version
        archive_id = await plugin.create_archive_version(
            original_id=request.original_id,
            archive_type=arch_type,
            server_id=request.server_id,
            created_by=current_user.id,
            data=request.data,
            change_description=request.change_description,
            access_level=access_level,
            tags=tags
        )
        
        if archive_id:
            return ArchiveResponse(
                success=True,
                message="Archive version created successfully",
                data={
                    "archive_id": archive_id,
                    "original_id": request.original_id,
                    "archive_type": request.archive_type,
                    "server_id": request.server_id
                }
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to create archive version")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create archive version: {e}")
        raise HTTPException(status_code=500, detail="Failed to create archive version")


@router.post("/restore/{archive_id}")
async def restore_archive_version(
    archive_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Restore data from an archive version.
    
    Returns the archived data if user has access permissions.
    """
    try:
        plugin = await get_archive_plugin()
        
        # Get user permissions
        is_premium = getattr(current_user, 'is_premium', False)
        is_admin = getattr(current_user, 'is_admin', False)
        
        # Restore data
        restored_data = await plugin.restore_archive_version(
            archive_id=archive_id,
            user_id=current_user.id,
            is_premium=is_premium,
            is_admin=is_admin
        )
        
        if restored_data is not None:
            return ArchiveResponse(
                success=True,
                message="Archive version restored successfully",
                data={
                    "archive_id": archive_id,
                    "restored_data": restored_data
                }
            )
        else:
            raise HTTPException(status_code=404, detail="Archive not found or access denied")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore archive version {archive_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to restore archive version")


@router.get("/statistics")
async def get_archive_statistics(
    current_user: User = Depends(require_admin)
):
    """
    Get comprehensive archive system statistics.
    
    **Admin only endpoint**
    """
    try:
        plugin = await get_archive_plugin()
        
        plugin_info = plugin.get_plugin_info()
        
        return ArchiveResponse(
            success=True,
            message="Archive statistics retrieved",
            data=plugin_info
        )
        
    except Exception as e:
        logger.error(f"Failed to get archive statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get archive statistics")


@router.get("/servers")
async def list_configured_servers(
    current_user: User = Depends(require_admin)
):
    """
    List all servers with archive configuration.
    
    **Admin only endpoint**
    """
    try:
        plugin = await get_archive_plugin()
        
        servers = []
        for server_id, config in plugin.server_configs.items():
            servers.append({
                "server_id": server_id,
                "archive_enabled": config.archive_enabled,
                "enabled_types": [t.value for t in config.enabled_types],
                "retention_days": config.retention_days,
                "max_versions_per_item": config.max_versions_per_item,
                "premium_only_access": config.premium_only_access
            })
        
        return ArchiveResponse(
            success=True,
            message=f"Found {len(servers)} configured servers",
            data={
                "servers": servers,
                "total_servers": len(servers)
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to list configured servers: {e}")
        raise HTTPException(status_code=500, detail="Failed to list configured servers")
