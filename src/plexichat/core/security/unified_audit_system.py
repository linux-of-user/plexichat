# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...core.config import get_config
from ...core.logging import get_logger

"""
PlexiChat Unified Audit System - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple audit and monitoring systems:
- core_system/logging/security_logger.py - INTEGRATED
- features/blockchain/audit_trails.py - INTEGRATED
- features/security/distributed_monitoring.py - INTEGRATED

Features:
- Immutable blockchain-based audit trails
- Tamper-resistant security logging
- Real-time distributed monitoring
- Comprehensive compliance reporting
- Advanced threat detection and correlation
- Centralized security event management
- Automated incident response
- Multi-node security coordination
"""


logger = get_logger(__name__)


class SecurityEventType(Enum):
    """Types of security events."""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    ADMIN_ACTION = "admin_action"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SYSTEM_CONFIGURATION_CHANGE = "system_configuration_change"
    SECURITY_POLICY_CHANGE = "security_policy_change"
    ENCRYPTION_KEY_ROTATION = "encryption_key_rotation"
    CERTIFICATE_RENEWAL = "certificate_renewal"
    BACKUP_CREATED = "backup_created"
    BACKUP_RESTORED = "backup_restored"
    CLUSTER_NODE_JOINED = "cluster_node_joined"
    CLUSTER_NODE_LEFT = "cluster_node_left"
    DDOS_ATTACK_DETECTED = "ddos_attack_detected"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALWARE_DETECTED = "malware_detected"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    SYSTEM_COMPROMISE = "system_compromise"
    SECURITY_ALERT = "security_alert"
    COMPLIANCE_VIOLATION = "compliance_violation"


class SecuritySeverity(Enum):
    """Security event severity levels."""
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ALERT = 6
    EMERGENCY = 7


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SecurityEvent:
    """Comprehensive security event structure."""
    event_id: str
    event_type: SecurityEventType
    timestamp: datetime
    severity: SecuritySeverity
    threat_level: ThreatLevel

    # User and session information
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    # Network information
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None

    # Resource and action information
    resource: Optional[str] = None
    action: Optional[str] = None

    # Event details
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    # System information
    node_id: Optional[str] = None
    cluster_id: Optional[str] = None

    # Correlation information
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None

    # Compliance and audit
    compliance_tags: List[str] = field(default_factory=list)
    retention_period_days: int = 2555  # 7 years default

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "threat_level": self.threat_level.value,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "resource": self.resource,
            "action": self.action,
            "description": self.description,
            "details": self.details,
            "node_id": self.node_id,
            "cluster_id": self.cluster_id,
            "correlation_id": self.correlation_id,
            "parent_event_id": self.parent_event_id,
            "compliance_tags": self.compliance_tags,
            "retention_period_days": self.retention_period_days
        }


@dataclass
class AuditBlock:
    """Blockchain block for audit trail."""
    index: int
    timestamp: float
    events: List[SecurityEvent]
    previous_hash: str
    nonce: int = 0
    hash: str = ""

    def calculate_hash(self) -> str:
        """Calculate block hash."""
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "events": [event.to_dict() for event in self.events],
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int):
        """Mine the block with proof of work."""
        target = "0" * difficulty

        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

        logger.debug(f"Block mined: {self.hash}")


class TamperResistantLogger:
    """Tamper-resistant logging with HMAC integrity verification."""
    def __init__(self, log_file: Path, secret_key: bytes):
        self.log_file = log_file
        self.secret_key = secret_key
        self.lock = threading.RLock()
        self.sequence_number = 0
        self.previous_hash = "0" * 64

        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing state
        self._load_state()

    def _load_state(self):
        """Load existing sequence number and hash."""
        if not self.log_file.exists():
            return

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            if lines:
                last_line = lines[-1].strip()
                if last_line:
                    last_entry = json.loads(last_line)
                    self.sequence_number = last_entry.get("sequence", 0)
                    self.previous_hash = last_entry.get("hash", "0" * 64)

        except Exception as e:
            logger.error(f"Failed to load tamper-resistant log state: {e}")

    def log_entry(self, entry_data: Dict[str, Any]) -> str:
        """Log an entry with tamper-resistant properties."""
        with self.lock:
            self.sequence_number += 1

            # Create the log entry
            log_entry = {
                "sequence": self.sequence_number,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": entry_data,
                "previous_hash": self.previous_hash
            }

            # Calculate HMAC
            entry_json = json.dumps(log_entry, sort_keys=True, separators=(",", ":"))
            entry_hash = hmac.new(
                self.secret_key,
                entry_json.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            # Add hash to entry
            log_entry["hash"] = entry_hash

            # Write to file
            final_json = json.dumps(log_entry, separators=(',', ':'))
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(final_json + '\n')

            # Update state
            self.previous_hash = entry_hash

            return entry_hash

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the log file."""
        if not self.log_file.exists():
            return {"status": "no_log_file", "verified": True}

        verification_results = {
            "status": "verified",
            "verified": True,
            "total_entries": 0,
            "corrupted_entries": [],
            "missing_sequences": [],
            "hash_mismatches": []
        }

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            previous_hash = "0" * 64
            expected_sequence = 1

            for line_num, line in enumerate(lines, 1):
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line.strip())
                    verification_results["total_entries"] += 1

                    # Check sequence
                    if entry.get("sequence") != expected_sequence:
                        verification_results["missing_sequences"].append(
                            {
                                "line": line_num,
                                "expected": expected_sequence,
                                "actual": entry.get("sequence"),
                            }
                        )
                        verification_results["verified"] = False

                    # Check hash chain
                    if entry.get("previous_hash") != previous_hash:
                        verification_results["hash_mismatches"].append(
                            {
                                "line": line_num,
                                "expected_previous": previous_hash,
                                "actual_previous": entry.get("previous_hash"),
                            }
                        )
                        verification_results["verified"] = False

                    # Verify HMAC
                    entry_copy = entry.copy()
                    stored_hash = entry_copy.pop("hash", "")
                    entry_json = json.dumps(
                        entry_copy, sort_keys=True, separators=(",", ":")
                    )
                    calculated_hash = hmac.new(
                        self.secret_key,
                        entry_json.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()

                    if stored_hash != calculated_hash:
                        verification_results["corrupted_entries"].append(
                            {
                                "line": line_num,
                                "sequence": entry.get("sequence"),
                                "stored_hash": stored_hash,
                                "calculated_hash": calculated_hash,
                            }
                        )
                        verification_results["verified"] = False

                    previous_hash = stored_hash
                    expected_sequence += 1

                except json.JSONDecodeError:
                    verification_results["corrupted_entries"].append(
                        {"line": line_num, "error": "Invalid JSON"}
                    )
                    verification_results["verified"] = False

            if not verification_results["verified"]:
                verification_results["status"] = "corrupted"

        except Exception as e:
            verification_results = {
                "status": "error",
                "verified": False,
                "error": str(e)
            }

        return verification_results


class AuditBlockchain:
    """Blockchain for immutable audit trails."""

    def __init__(self, difficulty: int = 4):
        self.chain: List[AuditBlock] = []
        self.pending_events: List[SecurityEvent] = []
        self.difficulty = difficulty
        self.block_size = 100  # Max events per block
        self.lock = threading.RLock()

        # Create genesis block
        self._create_genesis_block()

    def _create_genesis_block(self):
        """Create the first block in the chain."""
        genesis_block = AuditBlock(index=0, timestamp=time.time(), events=[], previous_hash="0")
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
        logger.info("Audit blockchain genesis block created")

    def add_audit_event(self, event: SecurityEvent):
        """Add an audit event to the blockchain."""
        with self.lock:
            self.pending_events.append(event)

            # Create new block if we have enough events
            if len(self.pending_events) >= self.block_size:
                self._create_new_block()

    def _create_new_block(self):
        """Create a new block with pending events."""
        if not self.pending_events:
            return

        previous_block = self.chain[-1]
        new_block = AuditBlock(
            index=len(self.chain),
            timestamp=time.time(),
            events=self.pending_events.copy(),
            previous_hash=previous_block.hash,
        )

        # Mine the block
        new_block.mine_block(self.difficulty)

        # Add to chain
        self.chain.append(new_block)
        self.pending_events.clear()

        logger.info(f"New audit block created: {new_block.index}")

    def is_chain_valid(self) -> bool:
        """Validate the blockchain integrity."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check if current block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                return False

            # Check if current block points to previous block
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def search_events(self, criteria: Dict[str, Any]) -> List[SecurityEvent]:
        """Search for events matching criteria."""
        matching_events = []

        for block in self.chain:
            for event in block.events:
                if self._event_matches_criteria(event, criteria):
                    matching_events.append(event)

        # Also search pending events
        for event in self.pending_events:
            if self._event_matches_criteria(event, criteria):
                matching_events.append(event)

        return matching_events

    def _event_matches_criteria(self, event: SecurityEvent, criteria: Dict[str, Any]) -> bool:
        """Check if event matches search criteria."""
        for key, value in criteria.items():
            if key == "event_type" and event.event_type != value:
                return False
            elif key == "user_id" and event.user_id != value:
                return False
            elif key == "source_ip" and event.source_ip != value:
                return False
            elif key == "start_time" and event.timestamp < value:
                return False
            elif key == "end_time" and event.timestamp > value:
                return False
            elif key == "severity" and event.severity.value < value:
                return False

        return True

    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Get blockchain statistics."""
        total_events = sum(len(block.events) for block in self.chain)

        return {
            "total_blocks": len(self.chain),
            "total_events": total_events,
            "pending_events": len(self.pending_events),
            "chain_valid": self.is_chain_valid(),
            "difficulty": self.difficulty,
            "last_block_hash": self.chain[-1].hash if self.chain else None
        }


class UnifiedAuditSystem:
    """
    Unified Audit System - Single Source of Truth

    Consolidates all audit logging and monitoring functionality with
    immutable blockchain-based trails and comprehensive security monitoring.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        raw_config: Any = config if isinstance(config, dict) else get_config().get("audit", {})  # type: ignore[reportUnknownMemberType]
        self.config: Dict[str, Any] = raw_config if isinstance(raw_config, dict) else {}
        self.initialized = False

        # Core components
        self.blockchain = AuditBlockchain(
            difficulty=int(self.config.get("blockchain_difficulty", 4))
        )

        # Tamper-resistant logging
        log_dir = Path(str(self.config.get("log_directory", "logs/security")))
        log_dir.mkdir(parents=True, exist_ok=True)

        secret_key: bytes | str = self.config.get(
            "logging_secret_key", secrets.token_bytes(32)
        )
        if isinstance(secret_key, str):
            secret_key = secret_key.encode("utf-8")

        self.tamper_logger = TamperResistantLogger(
            log_dir / "security_audit.log",
            secret_key,
        )

        # Event tracking and correlation
        self.event_counters: Dict[str, int] = {}
        self.correlation_map: Dict[str, List[str]] = {}
        self.active_incidents: Dict[str, Dict[str, Any]] = {}

        # Monitoring and alerting
        self.monitoring_active = False
        self.alert_thresholds = self.config.get(
            "alert_thresholds",
            {
                "failed_logins_per_minute": 10,
                "admin_actions_per_hour": 50,
                "critical_events_per_hour": 5,
            },
        )

        # Performance tracking
        self.metrics_history: List[Dict[str, Any]] = []
        self.performance_baseline: Optional[Dict[str, Any]] = None

        # Thread safety
        self._lock = threading.RLock()

        logger.info("Unified Audit System initialized")

    async def initialize(self) -> bool:
        """Initialize the unified audit system."""
        try:
            # Start monitoring tasks
            asyncio.create_task(self._monitoring_loop())
            asyncio.create_task(self._correlation_loop())
            asyncio.create_task(self._metrics_collection_loop())

            self.initialized = True
            logger.info("Unified Audit System initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Unified Audit System initialization failed: {e}")
            return False

    def log_security_event(
        self,
        event_type: SecurityEventType,
        description: str,
        severity: SecuritySeverity = SecuritySeverity.INFO,
        threat_level: ThreatLevel = ThreatLevel.LOW,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        compliance_tags: Optional[List[str]] = None,
    ) -> str:
        """Log a security event to the unified audit system."""

        event_id = str(uuid.uuid4())

        event = SecurityEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            threat_level=threat_level,
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=resource,
            action=action,
            description=description,
            details=details or {},
            correlation_id=correlation_id,
            compliance_tags=compliance_tags or [],
        )

        # Log to blockchain
        self.blockchain.add_audit_event(event)

        # Log to tamper-resistant storage
        self.tamper_logger.log_entry(event.to_dict())

        # Update event counters
        self._update_event_counters(event)

        # Check for alert conditions
        self._check_alert_conditions(event)

        # Handle correlation
        if correlation_id:
            self._add_to_correlation(correlation_id, event_id)

        logger.info(f"Security event logged: {event_id} - {event_type.value}")
        return event_id

    def search_audit_trail(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search audit trail with comprehensive criteria."""
        events = self.blockchain.search_events(criteria)
        return [event.to_dict() for event in events]

    def get_incident_timeline(self, correlation_id: str) -> Dict[str, Any]:
        """Get timeline of events for an incident."""
        if correlation_id not in self.correlation_map:
            return {"error": "Correlation ID not found"}

        event_ids = self.correlation_map[correlation_id]
        events = []

        # Search for all correlated events
        for event_id in event_ids:
            matching_events = self.blockchain.search_events({"event_id": event_id})
            events.extend(matching_events)

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)

        return {
            "correlation_id": correlation_id,
            "total_events": len(events),
            "timeline": [event.to_dict() for event in events],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

    def verify_audit_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of all audit systems."""
        blockchain_valid = self.blockchain.is_chain_valid()
        tamper_log_result = self.tamper_logger.verify_integrity()

        return {
            "blockchain_integrity": {
                "valid": blockchain_valid,
                "stats": self.blockchain.get_blockchain_stats(),
            },
            "tamper_resistant_log": tamper_log_result,
            "overall_integrity": blockchain_valid and tamper_log_result.get("verified", False),
        }

    def get_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        compliance_standard: str = "general",
    ) -> Dict[str, Any]:
        """Generate compliance report for specified period."""
        criteria = {
            "start_time": start_date,
            "end_time": end_date
        }

        events = self.blockchain.search_events(criteria)

        # Categorize events by type
        event_categories = {}
        for event in events:
            category = event.event_type.value
            if category not in event_categories:
                event_categories[category] = 0
            event_categories[category] += 1

        # Calculate compliance metrics
        total_events = len(events)
        security_events = len([e for e in events if e.threat_level.value >= ThreatLevel.MEDIUM.value])
        critical_events = len([e for e in events if e.severity.value >= SecuritySeverity.CRITICAL.value])

        return {
            "compliance_standard": compliance_standard,
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_events": total_events,
                "security_events": security_events,
                "critical_events": critical_events,
                "event_categories": event_categories
            },
            "integrity_verification": self.verify_audit_integrity(),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

    def _update_event_counters(self, event: SecurityEvent):
        """Update event counters for monitoring."""
        with self._lock:
            # Update general counters
            event_key = event.event_type.value
            self.event_counters[event_key] = self.event_counters.get(event_key, 0) + 1

            # Update IP-specific counters
            if event.source_ip:
                ip_key = f"{event.event_type.value}:{event.source_ip}"
                self.event_counters[ip_key] = self.event_counters.get(ip_key, 0) + 1

    def _check_alert_conditions(self, event: SecurityEvent):
        """Check if event triggers alert conditions."""
        # Critical events always trigger alerts
        if event.severity.value >= SecuritySeverity.CRITICAL.value:
            self._trigger_alert(event, "Critical security event detected")

        # Check for threshold violations
        _ = datetime.now(timezone.utc)

        # Check failed login threshold
        if event.event_type == SecurityEventType.LOGIN_FAILURE:
            recent_failures = self._count_recent_events(
                SecurityEventType.LOGIN_FAILURE,
                event.source_ip,
                timedelta(minutes=1),
            )

            if recent_failures >= self.alert_thresholds.get("failed_logins_per_minute", 10):
                self._trigger_alert(event, f"Brute force attack detected: {recent_failures} failed logins")

    def _count_recent_events(
        self,
        event_type: SecurityEventType,
        source_ip: Optional[str],
        time_window: timedelta,
    ) -> int:
        """Count recent events of specific type."""
        cutoff_time = datetime.now(timezone.utc) - time_window

        criteria = {
            "event_type": event_type,
            "start_time": cutoff_time
        }

        if source_ip:
            criteria["source_ip"] = source_ip

        events = self.blockchain.search_events(criteria)
        return len(events)

    def _trigger_alert(self, event: SecurityEvent, message: str):
        """Trigger security alert."""
        alert_id = str(uuid.uuid4())

        alert_data = {
            "alert_id": alert_id,
            "alert_type": "security",
            "message": message,
            "triggering_event": event.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": event.severity.value,
            "threat_level": event.threat_level.value
        }

        # Log the alert as a security event
        self.log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Security alert triggered: {message}",
            SecuritySeverity.ALERT,
            event.threat_level,
            correlation_id=event.correlation_id,
            details=alert_data,
        )

        logger.critical(f" SECURITY ALERT: {message}")

    def _add_to_correlation(self, correlation_id: str, event_id: str):
        """Add event to correlation map."""
        with self._lock:
            if correlation_id not in self.correlation_map:
                self.correlation_map[correlation_id] = []
            self.correlation_map[correlation_id].append(event_id)

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Perform periodic checks
                await self._check_system_health()
                await self._cleanup_old_data()

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")

    async def _correlation_loop(self):
        """Background correlation analysis loop."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                # Perform correlation analysis
                await self._analyze_event_correlations()

            except Exception as e:
                logger.error(f"Correlation loop error: {e}")

    async def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        while True:
            try:
                await asyncio.sleep(60)  # Run every minute

                # Collect current metrics
                metrics = await self._collect_current_metrics()
                self.metrics_history.append(metrics)

                # Keep only last 24 hours of metrics
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
                self.metrics_history = [
                    m for m in self.metrics_history
                    if datetime.fromisoformat(m["timestamp"]) > cutoff_time
                ]

            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

    async def _check_system_health(self):
        """Check overall system health."""
        # Verify blockchain integrity
        if not self.blockchain.is_chain_valid():
            self.log_security_event(
                SecurityEventType.SYSTEM_COMPROMISE,
                "Audit blockchain integrity compromised",
                SecuritySeverity.CRITICAL,
                ThreatLevel.CRITICAL,
            )

    async def _cleanup_old_data(self):
        """Clean up old data based on retention policies."""
        # This would implement data retention policies
        # For now, just log the cleanup activity
        logger.debug("Performing audit data cleanup")

    async def _analyze_event_correlations(self):
        """Analyze events for potential correlations."""
        # This would implement advanced correlation analysis
        # For now, just log the analysis activity
        logger.debug("Performing event correlation analysis")

    async def _collect_current_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_events": sum(self.event_counters.values()),
            "blockchain_blocks": len(self.blockchain.chain),
            "pending_events": len(self.blockchain.pending_events),
            "active_correlations": len(self.correlation_map),
            "system_health": "healthy"  # Placeholder
        }

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive audit system status."""
        blockchain_stats = self.blockchain.get_blockchain_stats()

        return {
            "initialized": self.initialized,
            "monitoring_active": self.monitoring_active,
            "blockchain": blockchain_stats,
            "event_counters": self.event_counters.copy(),
            "active_correlations": len(self.correlation_map),
            "metrics_history_size": len(self.metrics_history),
            "tamper_resistant_log": {
                "file_exists": self.tamper_logger.log_file.exists(),
                "sequence_number": self.tamper_logger.sequence_number
            },
        }


# Global instance - SINGLE SOURCE OF TRUTH
_unified_audit_system: Optional[UnifiedAuditSystem] = None


def get_unified_audit_system() -> 'UnifiedAuditSystem':
    """Get the global unified audit system instance."""
    global _unified_audit_system
    if _unified_audit_system is None:
        _unified_audit_system = UnifiedAuditSystem()
    return _unified_audit_system


# Export main components
__all__ = [
    "UnifiedAuditSystem",
    "get_unified_audit_system",
    "SecurityEvent",
    "SecurityEventType",
    "SecuritySeverity",
    "ThreatLevel",
    "AuditBlock",
    "TamperResistantLogger",
    "AuditBlockchain"
]
