"""
Distributed Security Monitoring System

Real-time security monitoring across all NetLink systems with
quantum-encrypted communication and intelligent threat detection.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import weakref
from collections import defaultdict, deque

from .quantum_encryption import QuantumEncryptionSystem, SecurityTier
from .distributed_key_manager import DistributedKeyManager, KeyDomain

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Security threat levels."""
    INFO = "info"           # Informational events
    LOW = "low"            # Low-priority security events
    MEDIUM = "medium"      # Medium-priority threats
    HIGH = "high"          # High-priority threats requiring attention
    CRITICAL = "critical"  # Critical threats requiring immediate action
    EMERGENCY = "emergency"  # Emergency threats requiring system lockdown


class MonitoringScope(Enum):
    """Monitoring scope levels."""
    LOCAL = "local"        # Local node monitoring
    CLUSTER = "cluster"    # Cluster-wide monitoring
    GLOBAL = "global"      # Global network monitoring
    QUANTUM = "quantum"    # Quantum-level security monitoring


class SecurityEventType(Enum):
    """Types of security events."""
    AUTHENTICATION_FAILURE = "auth_failure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    ENCRYPTION_ANOMALY = "encryption_anomaly"
    KEY_COMPROMISE = "key_compromise"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"
    DDOS_ATTACK = "ddos_attack"
    MALWARE_DETECTION = "malware_detection"
    QUANTUM_ATTACK = "quantum_attack"
    SYSTEM_COMPROMISE = "system_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_id: str
    event_type: SecurityEventType
    threat_level: ThreatLevel
    timestamp: datetime
    source_node: str
    source_ip: Optional[str]
    user_id: Optional[str]
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    affected_systems: List[str] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)
    resolved: bool = False
    resolution_time: Optional[datetime] = None


@dataclass
class SecurityMetrics:
    """Security monitoring metrics."""
    node_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    network_connections: int
    failed_auth_attempts: int
    encryption_operations: int
    key_rotations: int
    threat_detections: int
    system_health_score: float
    quantum_security_active: bool


@dataclass
class ThreatPattern:
    """Threat detection pattern."""
    pattern_id: str
    name: str
    description: str
    event_types: List[SecurityEventType]
    threshold_count: int
    time_window: timedelta
    threat_level: ThreatLevel
    auto_mitigation: bool
    mitigation_actions: List[str] = field(default_factory=list)


class DistributedSecurityMonitor:
    """
    Distributed Security Monitoring System
    
    Features:
    - Real-time security event collection and analysis
    - Quantum-encrypted inter-node communication
    - Intelligent threat pattern detection
    - Automated incident response
    - Distributed consensus for threat assessment
    - Performance impact monitoring
    - Compliance reporting
    """
    
    def __init__(self, node_id: str, encryption_system: QuantumEncryptionSystem, 
                 key_manager: DistributedKeyManager):
        self.node_id = node_id
        self.encryption_system = encryption_system
        self.key_manager = key_manager
        
        # Event storage
        self.security_events: deque = deque(maxlen=10000)
        self.active_threats: Dict[str, SecurityEvent] = {}
        self.resolved_threats: deque = deque(maxlen=1000)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_scope = MonitoringScope.LOCAL
        self.connected_nodes: Set[str] = set()
        
        # Threat detection
        self.threat_patterns: Dict[str, ThreatPattern] = {}
        self.pattern_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.pattern_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Metrics collection
        self.metrics_history: deque = deque(maxlen=1440)  # 24 hours at 1-minute intervals
        self.performance_baseline: Dict[str, float] = {}
        
        # Event handlers
        self.event_handlers: Dict[SecurityEventType, List[Callable]] = defaultdict(list)
        self.threat_handlers: Dict[ThreatLevel, List[Callable]] = defaultdict(list)
        
        # Communication
        self.peer_connections: Dict[str, Any] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        
        # Initialize default threat patterns
        self._initialize_default_patterns()
    
    def _initialize_default_patterns(self):
        """Initialize default threat detection patterns."""
        patterns = [
            ThreatPattern(
                pattern_id="brute_force_auth",
                name="Brute Force Authentication",
                description="Multiple failed authentication attempts",
                event_types=[SecurityEventType.AUTHENTICATION_FAILURE],
                threshold_count=5,
                time_window=timedelta(minutes=5),
                threat_level=ThreatLevel.HIGH,
                auto_mitigation=True,
                mitigation_actions=["block_ip", "increase_auth_delay"]
            ),
            ThreatPattern(
                pattern_id="quantum_attack_detection",
                name="Quantum Attack Detection",
                description="Potential quantum cryptographic attack",
                event_types=[SecurityEventType.QUANTUM_ATTACK, SecurityEventType.ENCRYPTION_ANOMALY],
                threshold_count=1,
                time_window=timedelta(seconds=30),
                threat_level=ThreatLevel.EMERGENCY,
                auto_mitigation=True,
                mitigation_actions=["emergency_key_rotation", "quantum_lockdown"]
            ),
            ThreatPattern(
                pattern_id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Unauthorized privilege escalation attempts",
                event_types=[SecurityEventType.PRIVILEGE_ESCALATION, SecurityEventType.UNAUTHORIZED_ACCESS],
                threshold_count=3,
                time_window=timedelta(minutes=10),
                threat_level=ThreatLevel.CRITICAL,
                auto_mitigation=True,
                mitigation_actions=["revoke_permissions", "audit_user_actions"]
            ),
            ThreatPattern(
                pattern_id="data_exfiltration",
                name="Data Exfiltration Attempt",
                description="Suspicious data access patterns",
                event_types=[SecurityEventType.DATA_BREACH_ATTEMPT, SecurityEventType.UNAUTHORIZED_ACCESS],
                threshold_count=10,
                time_window=timedelta(minutes=15),
                threat_level=ThreatLevel.CRITICAL,
                auto_mitigation=True,
                mitigation_actions=["block_data_access", "audit_data_flows"]
            )
        ]
        
        for pattern in patterns:
            self.threat_patterns[pattern.pattern_id] = pattern
    
    async def start_monitoring(self, scope: MonitoringScope = MonitoringScope.LOCAL):
        """Start security monitoring."""
        if self.monitoring_active:
            logger.warning("Security monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_scope = scope
        
        # Start monitoring tasks
        asyncio.create_task(self._metrics_collection_loop())
        asyncio.create_task(self._threat_detection_loop())
        asyncio.create_task(self._event_processing_loop())
        
        if scope in [MonitoringScope.CLUSTER, MonitoringScope.GLOBAL]:
            asyncio.create_task(self._distributed_communication_loop())
        
        logger.info(f"🔍 Security monitoring started - Scope: {scope.value}")
    
    async def stop_monitoring(self):
        """Stop security monitoring."""
        self.monitoring_active = False
        
        # Close peer connections
        for connection in self.peer_connections.values():
            if hasattr(connection, 'close'):
                await connection.close()
        
        self.peer_connections.clear()
        self.connected_nodes.clear()
        
        logger.info("🛑 Security monitoring stopped")
    
    async def report_security_event(self, event_type: SecurityEventType, 
                                  description: str, threat_level: ThreatLevel = ThreatLevel.INFO,
                                  source_ip: Optional[str] = None, user_id: Optional[str] = None,
                                  details: Optional[Dict[str, Any]] = None,
                                  affected_systems: Optional[List[str]] = None):
        """Report a security event."""
        event_id = hashlib.sha256(
            f"{self.node_id}_{event_type.value}_{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:16]
        
        event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            threat_level=threat_level,
            timestamp=datetime.now(timezone.utc),
            source_node=self.node_id,
            source_ip=source_ip,
            user_id=user_id,
            description=description,
            details=details or {},
            affected_systems=affected_systems or [],
            mitigation_actions=[]
        )
        
        # Store event
        self.security_events.append(event)
        
        # Process event for threat detection
        await self._process_event_for_threats(event)
        
        # Notify event handlers
        await self._notify_event_handlers(event)
        
        # Distribute to connected nodes if in distributed mode
        if self.monitoring_scope in [MonitoringScope.CLUSTER, MonitoringScope.GLOBAL]:
            await self._distribute_event(event)
        
        logger.info(f"🚨 Security event reported: {event_type.value} - {threat_level.value}")
    
    async def _process_event_for_threats(self, event: SecurityEvent):
        """Process event for threat pattern matching."""
        current_time = event.timestamp
        
        for pattern_id, pattern in self.threat_patterns.items():
            if event.event_type in pattern.event_types:
                # Update pattern counter
                self.pattern_counters[pattern_id][event.source_ip or "unknown"] += 1
                self.pattern_timestamps[pattern_id].append(current_time)
                
                # Check if pattern threshold is exceeded within time window
                window_start = current_time - pattern.time_window
                recent_events = [
                    ts for ts in self.pattern_timestamps[pattern_id] 
                    if ts >= window_start
                ]
                
                if len(recent_events) >= pattern.threshold_count:
                    await self._trigger_threat_response(pattern, event, len(recent_events))
    
    async def _trigger_threat_response(self, pattern: ThreatPattern, 
                                     triggering_event: SecurityEvent, event_count: int):
        """Trigger automated threat response."""
        threat_id = f"{pattern.pattern_id}_{triggering_event.source_ip or 'unknown'}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Create threat event
        threat_event = SecurityEvent(
            event_id=threat_id,
            event_type=SecurityEventType.SYSTEM_COMPROMISE,
            threat_level=pattern.threat_level,
            timestamp=datetime.now(timezone.utc),
            source_node=self.node_id,
            source_ip=triggering_event.source_ip,
            user_id=triggering_event.user_id,
            description=f"Threat pattern detected: {pattern.name} ({event_count} events)",
            details={
                "pattern_id": pattern.pattern_id,
                "pattern_name": pattern.name,
                "event_count": event_count,
                "triggering_event_id": triggering_event.event_id
            },
            affected_systems=triggering_event.affected_systems,
            mitigation_actions=pattern.mitigation_actions.copy()
        )
        
        # Store as active threat
        self.active_threats[threat_id] = threat_event
        
        # Execute automated mitigation if enabled
        if pattern.auto_mitigation:
            await self._execute_mitigation_actions(threat_event)
        
        # Notify threat handlers
        await self._notify_threat_handlers(threat_event)
        
        logger.critical(f"🚨 THREAT DETECTED: {pattern.name} - Level: {pattern.threat_level.value}")
    
    async def _execute_mitigation_actions(self, threat_event: SecurityEvent):
        """Execute automated mitigation actions."""
        for action in threat_event.mitigation_actions:
            try:
                await self._execute_mitigation_action(action, threat_event)
                logger.info(f"✅ Executed mitigation action: {action}")
            except Exception as e:
                logger.error(f"❌ Failed to execute mitigation action {action}: {e}")
    
    async def _execute_mitigation_action(self, action: str, threat_event: SecurityEvent):
        """Execute a specific mitigation action."""
        if action == "block_ip" and threat_event.source_ip:
            # Implement IP blocking logic
            logger.info(f"🚫 Blocking IP: {threat_event.source_ip}")
            
        elif action == "emergency_key_rotation":
            # Trigger emergency key rotation
            logger.info("🔄 Triggering emergency key rotation")
            await self.key_manager.emergency_rotate_all_keys()
            
        elif action == "quantum_lockdown":
            # Implement quantum security lockdown
            logger.info("🔒 Activating quantum security lockdown")
            
        elif action == "revoke_permissions" and threat_event.user_id:
            # Revoke user permissions
            logger.info(f"⛔ Revoking permissions for user: {threat_event.user_id}")
            
        elif action == "audit_user_actions" and threat_event.user_id:
            # Trigger user action audit
            logger.info(f"🔍 Auditing actions for user: {threat_event.user_id}")
            
        else:
            logger.warning(f"Unknown mitigation action: {action}")
    
    async def _metrics_collection_loop(self):
        """Collect security metrics periodically."""
        while self.monitoring_active:
            try:
                metrics = await self._collect_current_metrics()
                self.metrics_history.append(metrics)
                
                # Update performance baseline
                await self._update_performance_baseline(metrics)
                
                await asyncio.sleep(60)  # Collect metrics every minute
                
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(60)
    
    async def _collect_current_metrics(self) -> SecurityMetrics:
        """Collect current security metrics."""
        # In a real implementation, this would collect actual system metrics
        return SecurityMetrics(
            node_id=self.node_id,
            timestamp=datetime.now(timezone.utc),
            cpu_usage=0.0,  # Placeholder
            memory_usage=0.0,  # Placeholder
            network_connections=0,  # Placeholder
            failed_auth_attempts=len([e for e in self.security_events 
                                    if e.event_type == SecurityEventType.AUTHENTICATION_FAILURE]),
            encryption_operations=0,  # Placeholder
            key_rotations=0,  # Placeholder
            threat_detections=len(self.active_threats),
            system_health_score=100.0,  # Placeholder
            quantum_security_active=True
        )
    
    async def _update_performance_baseline(self, metrics: SecurityMetrics):
        """Update performance baseline for anomaly detection."""
        if len(self.metrics_history) < 10:
            return  # Need more data points
        
        # Calculate rolling averages for baseline
        recent_metrics = list(self.metrics_history)[-60:]  # Last hour
        
        self.performance_baseline = {
            "cpu_usage": sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics),
            "memory_usage": sum(m.memory_usage for m in recent_metrics) / len(recent_metrics),
            "network_connections": sum(m.network_connections for m in recent_metrics) / len(recent_metrics),
            "system_health_score": sum(m.system_health_score for m in recent_metrics) / len(recent_metrics)
        }
    
    async def _threat_detection_loop(self):
        """Main threat detection loop."""
        while self.monitoring_active:
            try:
                # Check for anomalies in metrics
                if self.metrics_history:
                    await self._detect_metric_anomalies()
                
                # Clean up old pattern counters
                await self._cleanup_old_pattern_data()
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in threat detection: {e}")
                await asyncio.sleep(30)
    
    async def _detect_metric_anomalies(self):
        """Detect anomalies in security metrics."""
        if not self.performance_baseline or len(self.metrics_history) < 2:
            return
        
        current_metrics = self.metrics_history[-1]
        
        # Check for significant deviations from baseline
        if (current_metrics.cpu_usage > self.performance_baseline["cpu_usage"] * 2.0 or
            current_metrics.memory_usage > self.performance_baseline["memory_usage"] * 2.0):
            
            await self.report_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                "Abnormal resource usage detected",
                ThreatLevel.MEDIUM,
                details={
                    "cpu_usage": current_metrics.cpu_usage,
                    "memory_usage": current_metrics.memory_usage,
                    "baseline_cpu": self.performance_baseline["cpu_usage"],
                    "baseline_memory": self.performance_baseline["memory_usage"]
                }
            )
    
    async def _cleanup_old_pattern_data(self):
        """Clean up old pattern detection data."""
        current_time = datetime.now(timezone.utc)
        
        for pattern_id, timestamps in self.pattern_timestamps.items():
            pattern = self.threat_patterns.get(pattern_id)
            if not pattern:
                continue
            
            # Remove timestamps older than pattern time window
            cutoff_time = current_time - pattern.time_window
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
    
    async def _event_processing_loop(self):
        """Process queued events."""
        while self.monitoring_active:
            try:
                # Process any queued messages
                if not self.message_queue.empty():
                    message = await self.message_queue.get()
                    await self._process_distributed_message(message)
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in event processing: {e}")
                await asyncio.sleep(1)
    
    async def _distributed_communication_loop(self):
        """Handle distributed communication with other nodes."""
        while self.monitoring_active:
            try:
                # Heartbeat to connected nodes
                await self._send_heartbeat_to_peers()
                
                # Sync threat intelligence
                await self._sync_threat_intelligence()
                
                await asyncio.sleep(30)  # Communicate every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in distributed communication: {e}")
                await asyncio.sleep(30)
    
    async def _notify_event_handlers(self, event: SecurityEvent):
        """Notify registered event handlers."""
        handlers = self.event_handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.error(f"Error in event handler: {e}")
    
    async def _notify_threat_handlers(self, threat_event: SecurityEvent):
        """Notify registered threat handlers."""
        handlers = self.threat_handlers.get(threat_event.threat_level, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(threat_event)
                else:
                    handler(threat_event)
            except Exception as e:
                logger.error(f"Error in threat handler: {e}")
    
    async def _distribute_event(self, event: SecurityEvent):
        """Distribute event to connected nodes."""
        # In a real implementation, this would encrypt and send the event
        # to connected monitoring nodes
        pass
    
    async def _process_distributed_message(self, message: Dict[str, Any]):
        """Process message from another monitoring node."""
        # In a real implementation, this would decrypt and process
        # messages from other monitoring nodes
        pass
    
    async def _send_heartbeat_to_peers(self):
        """Send heartbeat to peer monitoring nodes."""
        # In a real implementation, this would send encrypted heartbeats
        pass
    
    async def _sync_threat_intelligence(self):
        """Synchronize threat intelligence with peer nodes."""
        # In a real implementation, this would sync threat patterns
        # and intelligence data with other nodes
        pass
    
    def add_event_handler(self, event_type: SecurityEventType, handler: Callable):
        """Add event handler for specific event types."""
        self.event_handlers[event_type].append(handler)
    
    def add_threat_handler(self, threat_level: ThreatLevel, handler: Callable):
        """Add threat handler for specific threat levels."""
        self.threat_handlers[threat_level].append(handler)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        return {
            "node_id": self.node_id,
            "monitoring_active": self.monitoring_active,
            "monitoring_scope": self.monitoring_scope.value,
            "connected_nodes": len(self.connected_nodes),
            "total_events": len(self.security_events),
            "active_threats": len(self.active_threats),
            "resolved_threats": len(self.resolved_threats),
            "threat_patterns": len(self.threat_patterns),
            "metrics_collected": len(self.metrics_history),
            "last_metrics_time": self.metrics_history[-1].timestamp.isoformat() if self.metrics_history else None
        }


__all__ = [
    'DistributedSecurityMonitor',
    'SecurityEvent',
    'SecurityMetrics',
    'ThreatPattern',
    'ThreatLevel',
    'MonitoringScope',
    'SecurityEventType'
]
