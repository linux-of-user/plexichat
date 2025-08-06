#!/usr/bin/env python3
"""
API Endpoints for Distributed Backup System

Provides REST API endpoints for shard management, distribution status,
and backup operations in the distributed backup system.
"""

import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends, BackgroundTasks, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from pathlib import Path
import io

# Import backup components
try:
    from . import get_backup_manager
    from .shard_manager import ShardType, ShardStatus
    from .distribution_manager import NodeType, NodeStatus, DistributionStrategy
    from .version_manager import VersionType, ChangeType
    BACKUP_AVAILABLE = True
except ImportError as e:
    BACKUP_AVAILABLE = False
    logger.warning(f"Backup components not available: {e}")

    # Create a dummy get_backup_manager for fallback
    def get_backup_manager():
        return None

# Import authentication
try:
    from plexichat.interfaces.api.v1.auth import get_current_user
    AUTH_AVAILABLE = True
except ImportError:
    AUTH_AVAILABLE = False
    async def get_current_user(): return {"id": "admin", "username": "admin", "is_admin": True}

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/backup/shards", tags=["Distributed Backup"])

# Request models
class ShardUploadRequest(BaseModel):
    """Shard upload request.
        shard_id: str
    backup_id: str
    shard_type: str
    metadata: Optional[Dict[str, Any]] = None

class NodeRegistrationRequest(BaseModel):
    """Storage node registration request."""
        node_id: str
    node_type: str
    capacity_mb: int
    location: str
    user_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class MessageDiffRequest(BaseModel):
    Message diff backup request."""
        message_id: str
    old_content: str
    new_content: str
    user_id: str

class DistributionRequest(BaseModel):
    """Distribution plan request."""
        backup_id: str
    strategy: Optional[str] = "load_balanced"

@router.get("/status")
async def get_shard_system_status(current_user: dict = Depends(get_current_user)):
    """Get overall shard system status."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'distribution_manager'):
            raise HTTPException(status_code=503, detail="Distributed backup not available")
        
        # Get system status
        nodes = list(backup_manager.distribution_manager.nodes.values())
        total_capacity = sum(node.capacity_mb for node in nodes)
        total_used = sum(node.used_mb for node in nodes)
        
        status = {
            "system_status": "operational",
            "distributed_enabled": backup_manager.distributed_enabled,
            "total_nodes": len(nodes),
            "online_nodes": len([n for n in nodes if n.status == NodeStatus.ONLINE]),
            "total_capacity_mb": total_capacity,
            "total_used_mb": total_used,
            "usage_percent": (total_used / total_capacity * 100) if total_capacity > 0 else 0,
            "total_backups": len(backup_manager.backups),
            "shard_sets": len(backup_manager.shard_manager.shard_sets) if backup_manager.shard_manager else 0
        }
        
        return JSONResponse(content=status)
        
    except Exception as e:
        logger.error(f"Failed to get shard system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")

@router.get("/nodes")
async def list_storage_nodes(current_user: dict = Depends(get_current_user)):
    """List all storage nodes."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'distribution_manager'):
            raise HTTPException(status_code=503, detail="Distributed backup not available")
        
        nodes = []
        for node in backup_manager.distribution_manager.nodes.values():
            nodes.append(node.to_dict())
        
        return JSONResponse(content={"nodes": nodes})
        
    except Exception as e:
        logger.error(f"Failed to list storage nodes: {e}")
        raise HTTPException(status_code=500, detail="Failed to list nodes")

@router.post("/nodes/register")
async def register_storage_node(
    request: NodeRegistrationRequest,
    current_user: dict = Depends(get_current_user)
):
    """Register a new storage node."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'distribution_manager'):
            raise HTTPException(status_code=503, detail="Distributed backup not available")
        
        # Validate node type
        try:
            node_type = NodeType(request.node_type)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid node type")
        
        # Register node
        node = backup_manager.distribution_manager.register_node(
            node_id=request.node_id,
            node_type=node_type,
            capacity_mb=request.capacity_mb,
            location=request.location,
            user_id=request.user_id,
            metadata=request.metadata
        )
        
        logger.info(f"Storage node registered by {current_user['username']}: {request.node_id}")
        
        return JSONResponse(content={
            "success": True,
            "message": "Storage node registered successfully",
            "node": node.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Failed to register storage node: {e}")
        raise HTTPException(status_code=500, detail="Failed to register node")

@router.delete("/nodes/{node_id}")
async def unregister_storage_node(
    node_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Unregister a storage node."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'distribution_manager'):
            raise HTTPException(status_code=503, detail="Distributed backup not available")
        
        success = backup_manager.distribution_manager.unregister_node(node_id)
        
        if success:
            logger.info(f"Storage node unregistered by {current_user['username']}: {node_id}")
            return JSONResponse(content={
                "success": True,
                "message": "Storage node unregistered successfully"
            })
        else:
            raise HTTPException(status_code=400, detail="Cannot unregister node (may have shards)")
        
    except Exception as e:
        logger.error(f"Failed to unregister storage node: {e}")
        raise HTTPException(status_code=500, detail="Failed to unregister node")

@router.get("/distribution/{backup_id}")
async def get_distribution_status(
    backup_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get distribution status for a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'distribution_manager'):
            raise HTTPException(status_code=503, detail="Distributed backup not available")
        
        status = backup_manager.distribution_manager.get_distribution_status(backup_id)
        
        return JSONResponse(content=status)
        
    except Exception as e:
        logger.error(f"Failed to get distribution status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get distribution status")

@router.get("/shards/{backup_id}")
async def get_backup_shards(
    backup_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get shard information for a backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'shard_manager'):
            raise HTTPException(status_code=503, detail="Shard manager not available")
        
        shard_set = backup_manager.shard_manager.get_shard_set(backup_id)
        
        if not shard_set:
            raise HTTPException(status_code=404, detail="Backup shards not found")
        
        shards_info = {
            "backup_id": shard_set.backup_id,
            "version_id": shard_set.version_id,
            "total_size": shard_set.total_size,
            "created_at": shard_set.created_at.isoformat(),
            "redundancy_level": shard_set.redundancy_level,
            "min_shards_required": shard_set.min_shards_required,
            "can_restore": shard_set.can_restore,
            "data_shards": [shard.to_dict() for shard in shard_set.data_shards],
            "parity_shards": [shard.to_dict() for shard in shard_set.parity_shards],
            "metadata_shard": shard_set.metadata_shard.to_dict() if shard_set.metadata_shard else None
        }
        
        return JSONResponse(content=shards_info)
        
    except Exception as e:
        logger.error(f"Failed to get backup shards: {e}")
        raise HTTPException(status_code=500, detail="Failed to get backup shards")

@router.post("/verify/{backup_id}")
async def verify_backup_shards(
    backup_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Verify integrity of backup shards."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    try:
        backup_manager = get_backup_manager()
        
        if not hasattr(backup_manager, 'shard_manager'):
            raise HTTPException(status_code=503, detail="Shard manager not available")
        
        shard_set = backup_manager.shard_manager.get_shard_set(backup_id)
        
        if not shard_set:
            raise HTTPException(status_code=404, detail="Backup shards not found")
        
        verification_results = backup_manager.shard_manager.verify_shards(shard_set)
        
        logger.info(f"Shard verification performed by {current_user['username']} for backup {backup_id}")
        
        return JSONResponse(content=verification_results)
        
    except Exception as e:
        logger.error(f"Failed to verify backup shards: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify shards")

@router.post("/message-diff")
async def create_message_diff_backup(
    request: MessageDiffRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create a backup for a message edit diff."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")
    
    try:
        backup_manager = get_backup_manager()
        
        # Start message diff backup in background
        background_tasks.add_task(
            backup_manager.create_message_diff_backup,
            request.message_id,
            request.old_content,
            request.new_content,
            request.user_id
        )
        
        logger.info(f"Message diff backup started by {current_user['username']} for message {request.message_id}")
        
        return JSONResponse(content={
            "success": True,
            "message": "Message diff backup started successfully"
        })
        
    except Exception as e:
        logger.error(f"Failed to create message diff backup: {e}")
        raise HTTPException(status_code=500, detail="Failed to create message diff backup")

# Enhanced P2P and Massive Scale Endpoints

@router.post("/nodes/register")
async def register_node(
    node_id: str,
    endpoint: str,
    capacity_gb: float,
    location: str,
    current_user: dict = Depends(get_current_user)
):
    """Register a storage node in the P2P network."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        if not hasattr(backup_manager, 'register_storage_node'):
            raise HTTPException(status_code=503, detail="P2P network not available")

        success = await backup_manager.register_storage_node(
            node_id=node_id,
            endpoint=endpoint,
            capacity_gb=capacity_gb,
            location=location,
            user_id=current_user.get('user_id')
        )

        if success:
            logger.info(f"Node {node_id} registered by {current_user.get('username', 'unknown')}")
            return JSONResponse(content={
                "success": True,
                "message": "Node registered successfully",
                "node_id": node_id,
                "capacity_gb": capacity_gb,
                "location": location
            })
        else:
            raise HTTPException(status_code=400, detail="Failed to register node")

    except Exception as e:
        logger.error(f"Node registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/network")
async def get_network_status(current_user: dict = Depends(get_current_user)):
    """Get P2P network status."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        if not hasattr(backup_manager, 'get_network_status'):
            return JSONResponse(content={
                "available": False,
                "reason": "P2P network not initialized"
            })

        status = backup_manager.get_network_status()
        return JSONResponse(content=status)

    except Exception as e:
        logger.error(f"Failed to get network status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/massive")
async def create_massive_backup(
    name: Optional[str] = None,
    streaming: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Create a massive scale database backup."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        # Check if massive scale backup is available
        if not hasattr(backup_manager, 'create_massive_database_backup'):
            # Fallback to regular backup
            backup_info = await backup_manager.create_database_backup(name)
        else:
            backup_info = await backup_manager.create_massive_database_backup(
                name=name,
                streaming=streaming
            )

        if backup_info:
            logger.info(f"Backup started by {current_user.get('username', 'unknown')}: {backup_info.backup_id}")
            return JSONResponse(content={
                "success": True,
                "message": "Backup started successfully",
                "backup_id": backup_info.backup_id,
                "name": backup_info.name,
                "size_mb": round(backup_info.size / (1024**2), 2),
                "streaming": streaming,
                "type": "massive" if hasattr(backup_manager, 'create_massive_database_backup') else "standard"
            })
        else:
            raise HTTPException(status_code=500, detail="Failed to start backup")

    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/restore/{backup_id}")
async def restore_massive_backup(
    backup_id: str,
    target_path: Optional[str] = None,
    verify: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """Restore a backup (massive scale if available)."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        # Check if massive scale restore is available
        if hasattr(backup_manager, 'restore_massive_backup'):
            result_path = await backup_manager.restore_massive_backup(
                backup_id=backup_id,
                target_path=target_path,
                verify_integrity=verify
            )
            restore_type = "massive"
        else:
            # Fallback to regular restore
            success = await backup_manager.restore_backup(backup_id, target_path)
            result_path = target_path if success else None
            restore_type = "standard"

        if result_path:
            logger.info(f"Backup {backup_id} restored by {current_user.get('username', 'unknown')}")
            return JSONResponse(content={
                "success": True,
                "message": "Backup restored successfully",
                "backup_id": backup_id,
                "restored_path": result_path,
                "verified": verify,
                "type": restore_type
            })
        else:
            raise HTTPException(status_code=500, detail="Restore failed")

    except Exception as e:
        logger.error(f"Restore failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_backup_stats(current_user: dict = Depends(get_current_user)):
    """Get backup system statistics."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()
        stats = backup_manager.get_backup_stats()

        return JSONResponse(content={
            "timestamp": datetime.now().isoformat(),
            "stats": stats
        })

    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def get_system_health(current_user: dict = Depends(get_current_user)):
    """Get system health information."""
    if not BACKUP_AVAILABLE:
        raise HTTPException(status_code=503, detail="Backup system not available")

    try:
        backup_manager = get_backup_manager()

        health_info = {
            "timestamp": datetime.now().isoformat(),
            "distributed_enabled": getattr(backup_manager, 'distributed_enabled', False),
            "components": {
                "basic_backup": True,
                "distributed_backup": hasattr(backup_manager, 'shard_manager'),
                "p2p_network": hasattr(backup_manager, 'p2p_manager'),
                "massive_scale": hasattr(backup_manager, 'recovery_manager'),
                "key_management": hasattr(backup_manager, 'key_manager')
            }
        }

        # Add component stats if available
        if hasattr(backup_manager, 'shard_manager') and backup_manager.shard_manager:
            try:
                health_info["shard_stats"] = backup_manager.shard_manager.get_enhanced_stats()
            except:
                health_info["shard_stats"] = {"error": "Stats unavailable"}

        if hasattr(backup_manager, 'p2p_manager') and backup_manager.p2p_manager:
            try:
                health_info["network_stats"] = backup_manager.p2p_manager.get_network_stats()
            except:
                health_info["network_stats"] = {"error": "Stats unavailable"}

        return JSONResponse(content=health_info)

    except Exception as e:
        logger.error(f"Failed to get health info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Export router
__all__ = ["router"]
