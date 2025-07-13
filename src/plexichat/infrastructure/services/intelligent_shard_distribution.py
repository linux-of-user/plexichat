"""
Intelligent shard distribution service for NetLink.
Implements device-based shard placement with smart algorithms and user preferences.
"""

from dataclasses import dataclass
from typing import List, Optional

from netlink.app.logger_config import logger
from netlink.app.models.device_management import (
    DeviceCapabilityReport,
    DeviceShardAssignment,
    DeviceStatus,
    ShardDistributionStrategy,
    StorageDevice,
)
from netlink.app.models.enhanced_backup import EnhancedBackup, EnhancedBackupShard
from netlink.app.models.enhanced_models import EnhancedUser
from netlink.app.models.message import Message
from sqlmodel import Session, select


@dataclass
class DeviceScore:
    """Scoring information for device selection."""
    device_id: int
    total_score: float
    reliability_score: float
    performance_score: float
    preference_score: float
    geographic_score: float
    load_score: float
    network_score: float
    reasons: List[str]


@dataclass
class ShardPlacementPlan:
    """Plan for placing a shard across multiple devices."""
    shard_id: int
    target_devices: List[DeviceScore]
    redundancy_achieved: int
    geographic_distribution: bool
    user_preference_satisfied: bool
    estimated_reliability: float


class IntelligentShardDistribution:
    """Advanced shard distribution service with intelligent placement algorithms."""
    
    def __init__(self, session: Session):
        self.session = session
        self.default_strategy = self._get_default_strategy()
        
        # Scoring weights for device selection
        self.scoring_weights = {
            "reliability": 0.25,
            "performance": 0.20,
            "preference": 0.20,
            "geographic": 0.15,
            "load": 0.15,
            "network": 0.05
        }
    
    async def distribute_shard_intelligently(
        self,
        shard: EnhancedBackupShard,
        backup: EnhancedBackup,
        strategy_name: Optional[str] = None
    ) -> ShardPlacementPlan:
        """Intelligently distribute a shard to optimal devices."""
        try:
            # Get distribution strategy
            strategy = await self._get_strategy(strategy_name)
            
            # Get available devices
            available_devices = await self._get_available_devices(strategy)
            
            # Score devices for this shard
            device_scores = await self._score_devices_for_shard(
                shard, backup, available_devices, strategy
            )
            
            # Select optimal devices
            selected_devices = await self._select_optimal_devices(
                device_scores, strategy.redundancy_factor, strategy
            )
            
            # Create placement plan
            placement_plan = ShardPlacementPlan(
                shard_id=shard.id,
                target_devices=selected_devices,
                redundancy_achieved=len(selected_devices),
                geographic_distribution=await self._check_geographic_distribution(selected_devices),
                user_preference_satisfied=await self._check_user_preferences(shard, backup, selected_devices),
                estimated_reliability=await self._calculate_placement_reliability(selected_devices)
            )
            
            # Execute placement
            await self._execute_placement_plan(shard, placement_plan)
            
            logger.info(f"Intelligently distributed shard {shard.id} to {len(selected_devices)} devices")
            return placement_plan
            
        except Exception as e:
            logger.error(f"Failed to distribute shard {shard.id}: {e}")
            raise
    
    async def _get_available_devices(self, strategy: ShardDistributionStrategy) -> List[StorageDevice]:
        """Get devices available for shard storage based on strategy criteria."""
        statement = select(StorageDevice).where(
            (StorageDevice.status == DeviceStatus.ONLINE) &
            (StorageDevice.available_storage_bytes > 0) &
            (StorageDevice.current_shard_count < StorageDevice.max_shard_count) &
            (StorageDevice.reliability_score >= strategy.min_reliability_score)
        )
        
        # Apply storage requirements
        if strategy.min_storage_gb > 0:
            min_storage_bytes = strategy.min_storage_gb * 1024 * 1024 * 1024
            statement = statement.where(StorageDevice.total_storage_bytes >= min_storage_bytes)
        
        # Apply latency requirements
        if strategy.max_latency_ms:
            statement = statement.where(
                (StorageDevice.average_latency_ms.is_(None)) |
                (StorageDevice.average_latency_ms <= strategy.max_latency_ms)
            )
        
        # Apply device type preferences
        if strategy.preferred_device_types:
            statement = statement.where(StorageDevice.device_type.in_(strategy.preferred_device_types))
        
        devices = self.session.exec(statement).all()
        
        # Filter by performance thresholds if specified
        filtered_devices = []
        for device in devices:
            if strategy.min_upload_speed_mbps and device.upload_speed_mbps:
                if device.upload_speed_mbps < strategy.min_upload_speed_mbps:
                    continue
            
            if strategy.min_download_speed_mbps and device.download_speed_mbps:
                if device.download_speed_mbps < strategy.min_download_speed_mbps:
                    continue
            
            # Check recent capability reports for CPU/memory usage
            if strategy.max_cpu_usage_percent or strategy.max_memory_usage_percent:
                recent_report = self.session.exec(
                    select(DeviceCapabilityReport)
                    .where(DeviceCapabilityReport.device_id == device.id)
                    .order_by(DeviceCapabilityReport.reported_at.desc())
                    .limit(1)
                ).first()
                
                if recent_report:
                    if (strategy.max_cpu_usage_percent and 
                        recent_report.cpu_usage_percent and 
                        recent_report.cpu_usage_percent > strategy.max_cpu_usage_percent):
                        continue
                    
                    if (strategy.max_memory_usage_percent and 
                        recent_report.memory_usage_percent and 
                        recent_report.memory_usage_percent > strategy.max_memory_usage_percent):
                        continue
            
            filtered_devices.append(device)
        
        logger.info(f"Found {len(filtered_devices)} available devices for shard distribution")
        return filtered_devices
    
    async def _score_devices_for_shard(
        self,
        shard: EnhancedBackupShard,
        backup: EnhancedBackup,
        devices: List[StorageDevice],
        strategy: ShardDistributionStrategy
    ) -> List[DeviceScore]:
        """Score devices for optimal shard placement."""
        device_scores = []
        
        # Get backup owner information
        backup_owner = self.session.get(EnhancedUser, backup.created_by) if backup.created_by else None
        
        # Get messages in this shard to determine user preferences
        shard_messages = await self._get_shard_messages(shard, backup)
        
        for device in devices:
            score = await self._calculate_device_score(
                device, shard, backup, backup_owner, shard_messages, strategy
            )
            device_scores.append(score)
        
        # Sort by total score (descending)
        device_scores.sort(key=lambda x: x.total_score, reverse=True)
        
        return device_scores
    
    async def _calculate_device_score(
        self,
        device: StorageDevice,
        shard: EnhancedBackupShard,
        backup: EnhancedBackup,
        backup_owner: Optional[EnhancedUser],
        shard_messages: List[Message],
        strategy: ShardDistributionStrategy
    ) -> DeviceScore:
        """Calculate comprehensive score for device suitability."""
        reasons = []
        
        # 1. Reliability Score (0-1)
        reliability_score = device.reliability_score
        if device.uptime_percentage:
            reliability_score = min(reliability_score, device.uptime_percentage / 100)
        
        # 2. Performance Score (0-1)
        performance_score = 0.5  # Base score
        
        if device.upload_speed_mbps and device.download_speed_mbps:
            # Normalize speeds (assume 100 Mbps is excellent)
            upload_norm = min(device.upload_speed_mbps / 100, 1.0)
            download_norm = min(device.download_speed_mbps / 100, 1.0)
            performance_score = (upload_norm + download_norm) / 2
        
        if device.average_latency_ms:
            # Lower latency is better (assume 50ms is excellent, 500ms is poor)
            latency_score = max(0, 1 - (device.average_latency_ms - 50) / 450)
            performance_score = (performance_score + latency_score) / 2
        
        # 3. User Preference Score (0-1)
        preference_score = 0.5  # Base score
        
        if strategy.prefer_user_devices and backup_owner and device.user_id == backup_owner.id:
            preference_score = 1.0
            reasons.append("Owner's device")
        elif device.prefer_own_messages and shard_messages:
            # Check if any messages in shard belong to device owner
            device_owner_messages = [msg for msg in shard_messages if msg.sender_id == device.user_id]
            if device_owner_messages:
                preference_score = 0.8
                reasons.append("Contains user's own messages")
        
        # 4. Geographic Distribution Score (0-1)
        geographic_score = 0.5  # Base score
        
        if strategy.geographic_distribution and device.geographic_region:
            # This would be enhanced with actual geographic distribution logic
            geographic_score = 0.7
            reasons.append("Good geographic distribution")
        
        # 5. Load Balance Score (0-1)
        load_score = 1.0
        
        if device.total_storage_bytes > 0:
            utilization = device.used_storage_bytes / device.total_storage_bytes
            load_score = max(0, 1 - utilization)  # Lower utilization is better
        
        shard_utilization = device.current_shard_count / device.max_shard_count
        load_score = (load_score + max(0, 1 - shard_utilization)) / 2
        
        # 6. Network Score (0-1)
        network_score = 0.5  # Base score
        
        if device.connection_type:
            connection_scores = {
                "ethernet": 1.0,
                "wifi": 0.8,
                "cellular": 0.6,
                "satellite": 0.4,
                "direct": 1.0
            }
            network_score = connection_scores.get(device.connection_type.value, 0.5)
        
        # Calculate weighted total score
        total_score = (
            reliability_score * self.scoring_weights["reliability"] +
            performance_score * self.scoring_weights["performance"] +
            preference_score * self.scoring_weights["preference"] +
            geographic_score * self.scoring_weights["geographic"] +
            load_score * self.scoring_weights["load"] +
            network_score * self.scoring_weights["network"]
        )
        
        # Add device priority bonus
        priority_bonus = (device.storage_priority - 5) * 0.02  # -8% to +10%
        total_score = min(1.0, total_score + priority_bonus)
        
        if device.storage_priority > 7:
            reasons.append("High priority device")
        
        return DeviceScore(
            device_id=device.id,
            total_score=total_score,
            reliability_score=reliability_score,
            performance_score=performance_score,
            preference_score=preference_score,
            geographic_score=geographic_score,
            load_score=load_score,
            network_score=network_score,
            reasons=reasons
        )
    
    async def _select_optimal_devices(
        self,
        device_scores: List[DeviceScore],
        target_redundancy: int,
        strategy: ShardDistributionStrategy
    ) -> List[DeviceScore]:
        """Select optimal devices ensuring diversity and redundancy."""
        selected_devices = []
        used_device_ids = set()
        
        # First pass: Select top-scoring devices
        for score in device_scores:
            if len(selected_devices) >= target_redundancy:
                break
            
            if score.device_id not in used_device_ids:
                selected_devices.append(score)
                used_device_ids.add(score.device_id)
        
        # Second pass: Ensure geographic diversity if enabled
        if strategy.geographic_distribution and len(selected_devices) < target_redundancy:
            # This would implement geographic diversity logic
            pass
        
        # Third pass: Fill remaining slots with best available devices
        remaining_needed = target_redundancy - len(selected_devices)
        if remaining_needed > 0:
            for score in device_scores:
                if remaining_needed <= 0:
                    break
                
                if score.device_id not in used_device_ids:
                    selected_devices.append(score)
                    used_device_ids.add(score.device_id)
                    remaining_needed -= 1
        
        logger.info(f"Selected {len(selected_devices)} devices for shard placement")
        return selected_devices
    
    async def _execute_placement_plan(
        self,
        shard: EnhancedBackupShard,
        plan: ShardPlacementPlan
    ):
        """Execute the shard placement plan by creating assignments."""
        for device_score in plan.target_devices:
            assignment = DeviceShardAssignment(
                device_id=device_score.device_id,
                shard_id=shard.id,
                backup_id=shard.backup_id,
                assignment_reason="intelligent_placement",
                priority_level=min(10, int(device_score.total_score * 10)),
                local_path=f"/backup_storage/shard_{shard.uuid}.data",
                storage_size_bytes=shard.size_bytes
            )
            
            self.session.add(assignment)
            
            # Update device shard count
            device = self.session.get(StorageDevice, device_score.device_id)
            if device:
                device.current_shard_count += 1
                device.used_storage_bytes += shard.size_bytes
                device.available_storage_bytes = max(0, device.available_storage_bytes - shard.size_bytes)
        
        self.session.commit()
    
    async def _get_shard_messages(
        self,
        shard: EnhancedBackupShard,
        backup: EnhancedBackup
    ) -> List[Message]:
        """Get messages that are contained in this shard (simplified)."""
        # This is a simplified implementation
        # In practice, you'd need to track which messages are in which shards
        return []
    
    async def _check_geographic_distribution(self, devices: List[DeviceScore]) -> bool:
        """Check if devices provide good geographic distribution."""
        # Simplified implementation
        return len(devices) >= 3
    
    async def _check_user_preferences(
        self,
        shard: EnhancedBackupShard,
        backup: EnhancedBackup,
        devices: List[DeviceScore]
    ) -> bool:
        """Check if user preferences are satisfied."""
        # Simplified implementation
        return True
    
    async def _calculate_placement_reliability(self, devices: List[DeviceScore]) -> float:
        """Calculate overall reliability of the placement."""
        if not devices:
            return 0.0
        
        # Calculate combined reliability (probability that at least one device is available)
        failure_probability = 1.0
        for device_score in devices:
            failure_probability *= (1 - device_score.reliability_score)
        
        return 1 - failure_probability
    
    def _get_default_strategy(self) -> ShardDistributionStrategy:
        """Get default distribution strategy."""
        return ShardDistributionStrategy(
            strategy_name="default_intelligent",
            description="Default intelligent distribution strategy",
            is_active=True,
            redundancy_factor=5,
            prefer_user_devices=True,
            geographic_distribution=True,
            network_topology_aware=True,
            load_balancing_enabled=True,
            min_reliability_score=0.8,
            min_storage_gb=1.0,
            enable_smart_placement=True,
            enable_predictive_scaling=True,
            enable_automatic_rebalancing=True,
            created_by=1  # System user
        )
    
    async def _get_strategy(self, strategy_name: Optional[str]) -> ShardDistributionStrategy:
        """Get distribution strategy by name or return default."""
        if strategy_name:
            strategy = self.session.exec(
                select(ShardDistributionStrategy).where(
                    (ShardDistributionStrategy.strategy_name == strategy_name) &
                    (ShardDistributionStrategy.is_active)
                )
            ).first()
            
            if strategy:
                return strategy
        
        return self.default_strategy
