from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlmodel import Session, func, select







from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from plexichat.app.db import get_session
from plexichat.app.logger_config import logger
from plexichat.app.models.device_management import (
from plexichat.app.models.enhanced_models import EnhancedUser
from plexichat.app.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user, get_optional_current_user
        from plexichat.app.services.backup_status_monitor import get_backup_status_monitor
        from plexichat.app.services.backup_status_monitor import get_backup_status_monitor
        from plexichat.app.services.backup_status_monitor import get_backup_status_monitor

"""
Device management API for intelligent shard distribution.
Handles device registration, status reporting, and shard management.
"""

    ConnectionType,
    DeviceCapabilityReport,
    DeviceShardAssignment,
    DeviceStatus,
    DeviceType,
    StorageDevice,
)
# Pydantic models for API
class DeviceRegistrationRequest(BaseModel):
    device_name: str
    device_type: DeviceType
    hardware_id: str
    total_storage_gb: float
    connection_type: ConnectionType = ConnectionType.WIFI
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    prefer_own_messages: bool = True
    allow_critical_data: bool = True
    storage_priority: int = 5
    geographic_region: Optional[str] = None
    capabilities: Optional[Dict[str, Any]] = None


class DeviceStatusUpdate(BaseModel):
    status: DeviceStatus
    available_storage_gb: Optional[float] = None
    upload_speed_mbps: Optional[float] = None
    download_speed_mbps: Optional[float] = None
    average_latency_ms: Optional[float] = None
    uptime_percentage: Optional[float] = None


class DeviceCapabilityReportRequest(BaseModel):
    cpu_usage_percent: Optional[float] = None
    memory_usage_percent: Optional[float] = None
    disk_usage_percent: Optional[float] = None
    network_usage_mbps: Optional[float] = None
    upload_speed_mbps: Optional[float] = None
    download_speed_mbps: Optional[float] = None
    latency_ms: Optional[float] = None
    temperature_celsius: Optional[float] = None
    battery_level_percent: Optional[float] = None
    uptime_hours: Optional[float] = None
    custom_metrics: Optional[Dict[str, Any]] = None


class ShardDeletionRequest(BaseModel):
    shard_id: int
    reason: str = "cleanup"


router = APIRouter(prefix="/api/v1/devices", tags=["Device Management"])


@router.post("/register")
async def register_device(
    request: DeviceRegistrationRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Register a new storage device."""
    try:
        # Check if device already exists
        existing_device = session.exec(
            select(StorageDevice).where(StorageDevice.hardware_id == request.hardware_id)
        ).first()
        
        if existing_device:
            # Update existing device
            existing_device.device_name = request.device_name
            existing_device.device_type = request.device_type
            existing_device.user_id = current_user.id
            existing_device.total_storage_bytes = int(request.total_storage_gb * 1024**3)
            existing_device.available_storage_bytes = int(request.total_storage_gb * 1024**3) - existing_device.used_storage_bytes
            existing_device.connection_type = request.connection_type
            existing_device.ip_address = request.ip_address
            existing_device.hostname = request.hostname
            existing_device.port = request.port
            existing_device.prefer_own_messages = request.prefer_own_messages
            existing_device.allow_critical_data = request.allow_critical_data
            existing_device.storage_priority = request.storage_priority
            existing_device.geographic_region = request.geographic_region
            existing_device.capabilities = request.capabilities
            existing_device.status = DeviceStatus.ONLINE
            existing_device.last_seen_at = from datetime import datetime
datetime.utcnow()
            existing_device.last_updated_at = from datetime import datetime
datetime.utcnow()
            
            session.commit()
            session.refresh(existing_device)
            
            return JSONResponse({
                "success": True,
                "message": "Device updated successfully",
                "device_id": existing_device.id,
                "device_uuid": existing_device.uuid
            })
        
        # Create new device
        device = StorageDevice(
            device_name=request.device_name,
            device_type=request.device_type,
            hardware_id=request.hardware_id,
            user_id=current_user.id,
            total_storage_bytes=int(request.total_storage_gb * 1024**3),
            available_storage_bytes=int(request.total_storage_gb * 1024**3),
            connection_type=request.connection_type,
            ip_address=request.ip_address,
            hostname=request.hostname,
            port=request.port,
            prefer_own_messages=request.prefer_own_messages,
            allow_critical_data=request.allow_critical_data,
            storage_priority=request.storage_priority,
            geographic_region=request.geographic_region,
            capabilities=request.capabilities,
            status=DeviceStatus.ONLINE,
            last_seen_at=from datetime import datetime
datetime.utcnow()
        )
        
        session.add(device)
        session.commit()
        session.refresh(device)
        
        logger.info(f"Registered new device: {device.device_name} ({device.hardware_id}) for user {current_user.id}")
        
        return JSONResponse({
            "success": True,
            "message": "Device registered successfully",
            "device_id": device.id,
            "device_uuid": device.uuid
        })
        
    except Exception as e:
        logger.error(f"Failed to register device: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{device_id}/heartbeat")
async def device_heartbeat(
    device_id: int,
    update: DeviceStatusUpdate,
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> JSONResponse:
    """Update device status and send heartbeat."""
    try:
        device = session.get(StorageDevice, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Verify device ownership (if user is authenticated)
        if current_user and device.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Update device status
        device.status = update.status
        device.last_heartbeat_at = from datetime import datetime
datetime.utcnow()
        device.last_seen_at = from datetime import datetime
datetime.utcnow()
        
        if update.available_storage_gb is not None:
            device.available_storage_bytes = int(update.available_storage_gb * 1024**3)
        
        if update.upload_speed_mbps is not None:
            device.upload_speed_mbps = update.upload_speed_mbps
        
        if update.download_speed_mbps is not None:
            device.download_speed_mbps = update.download_speed_mbps
        
        if update.average_latency_ms is not None:
            device.average_latency_ms = update.average_latency_ms
        
        if update.uptime_percentage is not None:
            device.uptime_percentage = update.uptime_percentage
            # Update reliability score based on uptime
            device.reliability_score = min(1.0, update.uptime_percentage / 100)
        
        session.commit()
        
        return JSONResponse({
            "success": True,
            "message": "Heartbeat received",
            "device_status": device.status.value,
            "last_seen": device.last_seen_at.isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process heartbeat for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{device_id}/capability-report")
async def submit_capability_report(
    device_id: int,
    report: DeviceCapabilityReportRequest,
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> JSONResponse:
    """Submit device capability report."""
    try:
        device = session.get(StorageDevice, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Verify device ownership (if user is authenticated)
        if current_user and device.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Count current shards
        shard_counts = session.exec(
            select(
                func.count(DeviceShardAssignment.id).label("total"),
                func.count(DeviceShardAssignment.id).filter(DeviceShardAssignment.is_verified).label("verified")
            ).where(
                (DeviceShardAssignment.device_id == device_id) &
                (DeviceShardAssignment.is_active)
            )
        ).first()
        
        stored_shards = shard_counts.total if shard_counts else 0
        verified_shards = shard_counts.verified if shard_counts else 0
        
        # Create capability report
        capability_report = DeviceCapabilityReport(
            device_id=device_id,
            cpu_usage_percent=report.cpu_usage_percent,
            memory_usage_percent=report.memory_usage_percent,
            disk_usage_percent=report.disk_usage_percent,
            network_usage_mbps=report.network_usage_mbps,
            upload_speed_mbps=report.upload_speed_mbps,
            download_speed_mbps=report.download_speed_mbps,
            latency_ms=report.latency_ms,
            temperature_celsius=report.temperature_celsius,
            battery_level_percent=report.battery_level_percent,
            uptime_hours=report.uptime_hours,
            stored_shards_count=stored_shards,
            verified_shards_count=verified_shards,
            custom_metrics=report.custom_metrics
        )
        
        session.add(capability_report)
        
        # Update device with latest performance metrics
        if report.upload_speed_mbps is not None:
            device.upload_speed_mbps = report.upload_speed_mbps
        if report.download_speed_mbps is not None:
            device.download_speed_mbps = report.download_speed_mbps
        if report.latency_ms is not None:
            device.average_latency_ms = report.latency_ms
        
        device.last_seen_at = from datetime import datetime
datetime.utcnow()
        
        session.commit()
        
        return JSONResponse({
            "success": True,
            "message": "Capability report submitted",
            "stored_shards": stored_shards,
            "verified_shards": verified_shards
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit capability report for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/my-devices")
async def get_my_devices(
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> List[Dict[str, Any]]:
    """Get devices owned by the current user."""
    try:
        devices = session.exec(
            select(StorageDevice).where(StorageDevice.user_id == current_user.id)
        ).all()
        
        result = []
        for device in devices:
            # Get shard assignments
            shard_assignments = session.exec(
                select(DeviceShardAssignment).where(
                    (DeviceShardAssignment.device_id == device.id) &
                    (DeviceShardAssignment.is_active)
                )
            ).all()
            
            # Get latest capability report
            latest_report = session.exec(
                select(DeviceCapabilityReport)
                .where(DeviceCapabilityReport.device_id == device.id)
                .order_by(DeviceCapabilityReport.reported_at.desc())
                .limit(1)
            ).first()
            
            device_info = {
                "id": device.id,
                "uuid": device.uuid,
                "device_name": device.device_name,
                "device_type": device.device_type.value,
                "hardware_id": device.hardware_id,
                "status": device.status.value,
                "storage": {
                    "total_gb": device.total_storage_bytes / (1024**3),
                    "available_gb": device.available_storage_bytes / (1024**3),
                    "used_gb": device.used_storage_bytes / (1024**3),
                    "utilization_percent": (device.used_storage_bytes / device.total_storage_bytes * 100) if device.total_storage_bytes > 0 else 0
                },
                "shards": {
                    "count": len(shard_assignments),
                    "max_count": device.max_shard_count,
                    "verified_count": len([a for a in shard_assignments if a.is_verified])
                },
                "performance": {
                    "upload_speed_mbps": device.upload_speed_mbps,
                    "download_speed_mbps": device.download_speed_mbps,
                    "average_latency_ms": device.average_latency_ms,
                    "reliability_score": device.reliability_score,
                    "uptime_percentage": device.uptime_percentage
                },
                "network": {
                    "connection_type": device.connection_type.value,
                    "ip_address": device.ip_address,
                    "hostname": device.hostname,
                    "port": device.port
                },
                "preferences": {
                    "prefer_own_messages": device.prefer_own_messages,
                    "allow_critical_data": device.allow_critical_data,
                    "storage_priority": device.storage_priority
                },
                "timestamps": {
                    "registered_at": device.registered_at.isoformat(),
                    "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
                    "last_heartbeat_at": device.last_heartbeat_at.isoformat() if device.last_heartbeat_at else None
                },
                "latest_report": {
                    "cpu_usage_percent": latest_report.cpu_usage_percent if latest_report else None,
                    "memory_usage_percent": latest_report.memory_usage_percent if latest_report else None,
                    "disk_usage_percent": latest_report.disk_usage_percent if latest_report else None,
                    "reported_at": latest_report.reported_at.isoformat() if latest_report else None
                }
            }
            
            result.append(device_info)
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get user devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{device_id}/shards")
async def get_device_shards(
    device_id: int,
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> Dict[str, Any]:
    """Get shards stored on a specific device."""
    try:
        device = session.get(StorageDevice, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Verify device ownership
        if device.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get shard assignments
        assignments = session.exec(
            select(DeviceShardAssignment)
            .where(DeviceShardAssignment.device_id == device_id)
            .order_by(DeviceShardAssignment.assigned_at.desc())
            .offset(offset)
            .limit(limit)
        ).all()
        
        shard_info = []
        for assignment in assignments:
            shard_info.append({
                "assignment_id": assignment.id,
                "shard_id": assignment.shard_id,
                "backup_id": assignment.backup_id,
                "local_path": assignment.local_path,
                "storage_size_bytes": assignment.storage_size_bytes,
                "is_active": assignment.is_active,
                "is_verified": assignment.is_verified,
                "last_verified_at": assignment.last_verified_at.isoformat() if assignment.last_verified_at else None,
                "assigned_at": assignment.assigned_at.isoformat(),
                "assignment_reason": assignment.assignment_reason,
                "priority_level": assignment.priority_level
            })
        
        return {
            "device_id": device_id,
            "device_name": device.device_name,
            "shards": shard_info,
            "total_shards": len(assignments),
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device shards: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{device_id}/shards/{shard_id}")
async def delete_device_shard(
    device_id: int,
    shard_id: int,
    request: ShardDeletionRequest,
    session: Session = Depends(get_session),
    current_user: Enhancedfrom plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
) -> JSONResponse:
    """Delete a specific shard from a device."""
    try:
        device = session.get(StorageDevice, device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Verify device ownership
        if device.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Find shard assignment
        assignment = session.exec(
            select(DeviceShardAssignment).where(
                (DeviceShardAssignment.device_id == device_id) &
                (DeviceShardAssignment.shard_id == shard_id) &
                (DeviceShardAssignment.is_active)
            )
        ).first()
        
        if not assignment:
            raise HTTPException(status_code=404, detail="Shard assignment not found")
        
        # Mark assignment as inactive
        assignment.is_active = False
        
        # Update device storage
        device.current_shard_count = max(0, device.current_shard_count - 1)
        device.used_storage_bytes = max(0, device.used_storage_bytes - assignment.storage_size_bytes)
        device.available_storage_bytes += assignment.storage_size_bytes
        
        session.commit()
        
        logger.info(f"Deleted shard {shard_id} from device {device_id} (reason: {request.reason})")
        
        return JSONResponse({
            "success": True,
            "message": "Shard deleted successfully",
            "shard_id": shard_id,
            "device_id": device_id,
            "reason": request.reason
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete shard {shard_id} from device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/network-status")
async def get_network_status(
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get real-time network status of all devices."""
    try:
        monitor = get_backup_status_monitor(session)
        network_status = await monitor.get_device_network_status()

        return network_status

    except Exception as e:
        logger.error(f"Failed to get network status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/backup-coverage")
async def get_backup_coverage(
    force_refresh: bool = Query(False, description="Force refresh of cached data"),
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get comprehensive backup coverage report."""
    try:
        monitor = get_backup_status_monitor(session)
        coverage_report = await monitor.get_real_time_status(force_refresh=force_refresh)

        return {
            "backup_coverage": {
                "total_backups": coverage_report.total_backups,
                "fully_available_backups": coverage_report.fully_available_backups,
                "partially_available_backups": coverage_report.partially_available_backups,
                "unavailable_backups": coverage_report.unavailable_backups,
                "overall_availability_percentage": coverage_report.overall_availability_percentage
            },
            "shard_statistics": {
                "total_shards": coverage_report.total_shards,
                "available_shards": coverage_report.available_shards,
                "availability_percentage": (coverage_report.available_shards / coverage_report.total_shards * 100) if coverage_report.total_shards > 0 else 100
            },
            "device_statistics": {
                "total_devices": coverage_report.total_devices,
                "online_devices": coverage_report.online_devices,
                "device_availability_percentage": (coverage_report.online_devices / coverage_report.total_devices * 100) if coverage_report.total_devices > 0 else 0
            },
            "health_status": {
                "critical_issues": coverage_report.critical_issues,
                "warnings": coverage_report.warnings,
                "overall_health": "critical" if coverage_report.critical_issues else ("warning" if coverage_report.warnings else "healthy")
            },
            "timestamp": from datetime import datetime
datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Failed to get backup coverage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/shard-distribution")
async def get_shard_distribution(
    session: Session = Depends(get_session),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get visual shard distribution map."""
    try:
        monitor = get_backup_status_monitor(session)
        distribution_map = await monitor.get_shard_distribution_map()

        return distribution_map

    except Exception as e:
        logger.error(f"Failed to get shard distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))
