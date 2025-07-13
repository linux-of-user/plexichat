import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlmodel import Session, func, select




from plexichat.app.logger_config import logger
from plexichat.app.models.device_management import (

    DeviceShardAssignment,
    DeviceStatus,
    EnhancedBackupShard,
    PlexiChat.,
    Real-time,
    StorageDevice,
    Tracks,
    """,
    and,
    availability,
    backup,
    coverage.,
    database,
    device,
    distribution,
    for,
    from,
    import,
    monitoring,
    plexichat.app.models.enhanced_backup,
    service,
    shard,
    status,
)


@dataclass
class DeviceAvailabilityStatus:
    """Device availability information."""
    device_id: int
    device_name: str
    device_type: str
    user_id: int
    status: str
    is_online: bool
    last_seen_minutes_ago: Optional[int]
    stored_shards: int
    verified_shards: int
    storage_utilization_percent: float
    reliability_score: float


@dataclass
class ShardAvailabilityStatus:
    """Shard availability across devices."""
    shard_id: int
    backup_id: int
    total_assignments: int
    online_assignments: int
    verified_assignments: int
    availability_percentage: float
    redundancy_level: str  # "critical", "low", "adequate", "excellent"
    geographic_distribution: bool


@dataclass
class BackupCoverageReport:
    """Overall backup coverage status."""
    total_backups: int
    fully_available_backups: int
    partially_available_backups: int
    unavailable_backups: int
    overall_availability_percentage: float
    total_shards: int
    available_shards: int
    online_devices: int
    total_devices: int
    critical_issues: List[str]
    warnings: List[str]


class BackupStatusMonitor:
    """Real-time backup status monitoring service."""

    def __init__(self, session: Session):
        self.session = session
        self.monitoring_active = False
        self.last_update = None
        self.cached_status = None
        self.cache_duration_seconds = 30  # Cache status for 30 seconds

        # Thresholds for status classification
        self.redundancy_thresholds = {
            "critical": 1,    # Only 1 copy available
            "low": 2,         # 2 copies available
            "adequate": 3,    # 3+ copies available
            "excellent": 5    # 5+ copies available
        }

    async def get_real_time_status(self, force_refresh: bool = False) -> BackupCoverageReport:
        """Get comprehensive real-time backup status."""
        try:
            # Check cache
            if (not force_refresh and
                self.cached_status and
                self.last_update and
                (datetime.now(timezone.utc) - self.last_update).total_seconds() < self.cache_duration_seconds):
                return self.cached_status

            logger.info(" Generating real-time backup status report...")

            # Get device availability
            device_statuses = await self._get_device_availability_statuses()

            # Get shard availability
            shard_statuses = await self._get_shard_availability_statuses()

            # Calculate overall coverage
            coverage_report = await self._calculate_backup_coverage(device_statuses, shard_statuses)

            # Cache the result
            self.cached_status = coverage_report
            self.last_update = datetime.now(timezone.utc)

            logger.info(f" Backup status: {coverage_report.overall_availability_percentage:.1f}% available")

            return coverage_report

        except Exception as e:
            logger.error(f"Failed to get real-time backup status: {e}")
            raise

    async def _get_device_availability_statuses(self) -> List[DeviceAvailabilityStatus]:
        """Get availability status for all devices."""
        devices = self.session.exec(select(StorageDevice)).all()
        device_statuses = []

        for device in devices:
            # Calculate time since last seen
            last_seen_minutes = None
            if device.last_seen_at:
                time_diff = datetime.now(timezone.utc) - device.last_seen_at.replace(tzinfo=timezone.utc)
                last_seen_minutes = int(time_diff.total_seconds() / 60)

            # Determine if device is considered online
            is_online = (
                device.status == DeviceStatus.ONLINE and
                last_seen_minutes is not None and
                last_seen_minutes <= 5  # Consider online if seen within 5 minutes
            )

            # Get shard counts
            shard_counts = self.session.exec(
                select(
                    func.count(DeviceShardAssignment.id).label("total"),
                    func.count(DeviceShardAssignment.id).filter(DeviceShardAssignment.is_verified).label("verified")
                ).where(
                    (DeviceShardAssignment.device_id == device.id) &
                    (DeviceShardAssignment.is_active)
                )
            ).first()

            stored_shards = shard_counts.total if shard_counts else 0
            verified_shards = shard_counts.verified if shard_counts else 0

            # Calculate storage utilization
            storage_utilization = 0.0
            if device.total_storage_bytes > 0:
                storage_utilization = (device.used_storage_bytes / device.total_storage_bytes) * 100

            device_status = DeviceAvailabilityStatus(
                device_id=device.id,
                device_name=device.device_name,
                device_type=device.device_type.value,
                user_id=device.user_id or 0,
                status=device.status.value,
                is_online=is_online,
                last_seen_minutes_ago=last_seen_minutes,
                stored_shards=stored_shards,
                verified_shards=verified_shards,
                storage_utilization_percent=storage_utilization,
                reliability_score=device.reliability_score
            )

            device_statuses.append(device_status)

        return device_statuses

    async def _get_shard_availability_statuses(self) -> List[ShardAvailabilityStatus]:
        """Get availability status for all shards."""
        # Get all shards with their assignments
        shards_query = self.session.exec(
            select(EnhancedBackupShard).order_by(EnhancedBackupShard.id)
        ).all()

        shard_statuses = []

        for shard in shards_query:
            # Get assignments for this shard
            assignments = self.session.exec(
                select(DeviceShardAssignment, StorageDevice)
                .join(StorageDevice, DeviceShardAssignment.device_id == StorageDevice.id)
                .where(
                    (DeviceShardAssignment.shard_id == shard.id) &
                    (DeviceShardAssignment.is_active)
                )
            ).all()

            total_assignments = len(assignments)
            online_assignments = 0
            verified_assignments = 0

            for assignment, device in assignments:
                # Check if device is online (last seen within 5 minutes)
                if device.last_seen_at:
                    time_diff = datetime.now(timezone.utc) - device.last_seen_at.replace(tzinfo=timezone.utc)
                    if time_diff.total_seconds() <= 300 and device.status == DeviceStatus.ONLINE:
                        online_assignments += 1

                if assignment.is_verified:
                    verified_assignments += 1

            # Calculate availability percentage
            availability_percentage = (online_assignments / total_assignments * 100) if total_assignments > 0 else 0

            # Determine redundancy level
            redundancy_level = "critical"
            if online_assignments >= self.redundancy_thresholds["excellent"]:
                redundancy_level = "excellent"
            elif online_assignments >= self.redundancy_thresholds["adequate"]:
                redundancy_level = "adequate"
            elif online_assignments >= self.redundancy_thresholds["low"]:
                redundancy_level = "low"

            # Check geographic distribution (simplified)
            geographic_distribution = total_assignments >= 3

            shard_status = ShardAvailabilityStatus(
                shard_id=shard.id,
                backup_id=shard.backup_id,
                total_assignments=total_assignments,
                online_assignments=online_assignments,
                verified_assignments=verified_assignments,
                availability_percentage=availability_percentage,
                redundancy_level=redundancy_level,
                geographic_distribution=geographic_distribution
            )

            shard_statuses.append(shard_status)

        return shard_statuses

    async def _calculate_backup_coverage(
        self,
        device_statuses: List[DeviceAvailabilityStatus],
        shard_statuses: List[ShardAvailabilityStatus]
    ) -> BackupCoverageReport:
        """Calculate overall backup coverage report."""

        # Device statistics
        total_devices = len(device_statuses)
        online_devices = len([d for d in device_statuses if d.is_online])

        # Shard statistics
        total_shards = len(shard_statuses)
        available_shards = len([s for s in shard_statuses if s.online_assignments > 0])

        # Backup statistics
        backup_coverage = {}
        for shard_status in shard_statuses:
            backup_id = shard_status.backup_id
            if backup_id not in backup_coverage:
                backup_coverage[backup_id] = {
                    "total_shards": 0,
                    "available_shards": 0,
                    "fully_available": True
                }

            backup_coverage[backup_id]["total_shards"] += 1
            if shard_status.online_assignments > 0:
                backup_coverage[backup_id]["available_shards"] += 1
            else:
                backup_coverage[backup_id]["fully_available"] = False

        # Calculate backup availability
        total_backups = len(backup_coverage)
        fully_available_backups = len([b for b in backup_coverage.values() if b["fully_available"]])
        partially_available_backups = len([
            b for b in backup_coverage.values()
            if not b["fully_available"] and b["available_shards"] > 0
        ])
        unavailable_backups = len([
            b for b in backup_coverage.values()
            if b["available_shards"] == 0
        ])

        # Calculate overall availability percentage
        if total_shards > 0:
            overall_availability = (available_shards / total_shards) * 100
        else:
            overall_availability = 100.0

        # Identify critical issues and warnings
        critical_issues = []
        warnings = []

        # Check for critical shards (redundancy level "critical")
        critical_shards = [s for s in shard_statuses if s.redundancy_level == "critical"]
        if critical_shards:
            critical_issues.append(f"{len(critical_shards)} shards have critical redundancy (only 1 copy available)")

        # Check for unavailable backups
        if unavailable_backups > 0:
            critical_issues.append(f"{unavailable_backups} backups are completely unavailable")

        # Check for low device availability
        if total_devices > 0:
            device_availability = (online_devices / total_devices) * 100
            if device_availability < 50:
                critical_issues.append(f"Low device availability: {device_availability:.1f}%")
            elif device_availability < 80:
                warnings.append(f"Moderate device availability: {device_availability:.1f}%")

        # Check for low redundancy shards
        low_redundancy_shards = [s for s in shard_statuses if s.redundancy_level == "low"]
        if low_redundancy_shards:
            warnings.append(f"{len(low_redundancy_shards)} shards have low redundancy (only 2 copies available)")

        # Check for unverified shards
        unverified_shards = [s for s in shard_statuses if s.verified_assignments < s.total_assignments]
        if unverified_shards:
            warnings.append(f"{len(unverified_shards)} shards have unverified copies")

        return BackupCoverageReport(
            total_backups=total_backups,
            fully_available_backups=fully_available_backups,
            partially_available_backups=partially_available_backups,
            unavailable_backups=unavailable_backups,
            overall_availability_percentage=overall_availability,
            total_shards=total_shards,
            available_shards=available_shards,
            online_devices=online_devices,
            total_devices=total_devices,
            critical_issues=critical_issues,
            warnings=warnings
        )

    async def get_device_network_status(self) -> Dict[str, Any]:
        """Get network status of all devices."""
        try:
            device_statuses = await self._get_device_availability_statuses()

            # Group devices by status
            status_groups = {
                "online": [],
                "offline": [],
                "maintenance": [],
                "unreachable": []
            }

            for device in device_statuses:
                if device.is_online:
                    status_groups["online"].append({
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "device_type": device.device_type,
                        "stored_shards": device.stored_shards,
                        "verified_shards": device.verified_shards,
                        "storage_utilization_percent": device.storage_utilization_percent,
                        "reliability_score": device.reliability_score,
                        "last_seen_minutes_ago": device.last_seen_minutes_ago
                    })
                else:
                    status_key = "offline" if device.status == "offline" else "unreachable"
                    status_groups[status_key].append({
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "device_type": device.device_type,
                        "stored_shards": device.stored_shards,
                        "last_seen_minutes_ago": device.last_seen_minutes_ago
                    })

            return {
                "network_status": status_groups,
                "summary": {
                    "total_devices": len(device_statuses),
                    "online_devices": len(status_groups["online"]),
                    "offline_devices": len(status_groups["offline"]),
                    "unreachable_devices": len(status_groups["unreachable"]),
                    "maintenance_devices": len(status_groups["maintenance"]),
                    "network_health_percentage": (len(status_groups["online"]) / len(device_statuses) * 100) if device_statuses else 0
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get device network status: {e}")
            raise

    async def get_shard_distribution_map(self) -> Dict[str, Any]:
        """Get visual representation of shard distribution across devices."""
        try:
            shard_statuses = await self._get_shard_availability_statuses()
            device_statuses = await self._get_device_availability_statuses()

            # Create device map
            device_map = {d.device_id: d for d in device_statuses}

            # Create distribution visualization data
            distribution_data = {
                "nodes": [],
                "links": [],
                "statistics": {
                    "total_shards": len(shard_statuses),
                    "redundancy_levels": {
                        "critical": 0,
                        "low": 0,
                        "adequate": 0,
                        "excellent": 0
                    }
                }
            }

            # Add device nodes
            for device in device_statuses:
                distribution_data["nodes"].append({
                    "id": f"device_{device.device_id}",
                    "type": "device",
                    "name": device.device_name,
                    "device_type": device.device_type,
                    "is_online": device.is_online,
                    "stored_shards": device.stored_shards,
                    "storage_utilization": device.storage_utilization_percent,
                    "reliability_score": device.reliability_score
                })

            # Add shard nodes and links
            for shard in shard_statuses:
                # Count redundancy levels
                distribution_data["statistics"]["redundancy_levels"][shard.redundancy_level] += 1

                # Add shard node
                distribution_data["nodes"].append({
                    "id": f"shard_{shard.shard_id}",
                    "type": "shard",
                    "backup_id": shard.backup_id,
                    "availability_percentage": shard.availability_percentage,
                    "redundancy_level": shard.redundancy_level,
                    "online_assignments": shard.online_assignments,
                    "total_assignments": shard.total_assignments
                })

                # Add links to devices storing this shard
                assignments = self.session.exec(
                    select(DeviceShardAssignment)
                    .where(
                        (DeviceShardAssignment.shard_id == shard.shard_id) &
                        (DeviceShardAssignment.is_active)
                    )
                ).all()

                for assignment in assignments:
                    device = device_map.get(assignment.device_id)
                    if device:
                        distribution_data["links"].append({
                            "source": f"shard_{shard.shard_id}",
                            "target": f"device_{assignment.device_id}",
                            "is_verified": assignment.is_verified,
                            "is_online": device.is_online,
                            "assignment_reason": assignment.assignment_reason,
                            "priority_level": assignment.priority_level
                        })

            return distribution_data

        except Exception as e:
            logger.error(f"Failed to get shard distribution map: {e}")
            raise

    async def start_monitoring(self):
        """Start continuous monitoring service."""
        self.monitoring_active = True
        logger.info(" Started backup status monitoring service")

        while self.monitoring_active:
            try:
                # Update status every 30 seconds
                await self.get_real_time_status(force_refresh=True)
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f"Error in backup monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    def stop_monitoring(self):
        """Stop monitoring service."""
        self.monitoring_active = False
        logger.info(" Stopped backup status monitoring service")


# Global monitor instance
backup_status_monitor = None

def get_backup_status_monitor(session: Session) -> BackupStatusMonitor:
    """Get or create backup status monitor instance."""
    global backup_status_monitor
    if backup_status_monitor is None:
        backup_status_monitor = BackupStatusMonitor(session)
    return backup_status_monitor
