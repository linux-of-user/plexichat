"""
NetLink Blockchain Audit Trails

Immutable audit logging using blockchain technology for
government-level compliance and forensic analysis.
"""

import hashlib
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CONFIGURATION = "system_configuration"
    SECURITY_EVENT = "security_event"
    ADMIN_ACTION = "admin_action"
    API_CALL = "api_call"
    FILE_OPERATION = "file_operation"
    NETWORK_EVENT = "network_event"


class Severity(Enum):
    """Event severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AuditEvent:
    """Individual audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: str
    resource: str
    action: str
    details: Dict[str, Any]
    severity: Severity = Severity.MEDIUM
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for hashing."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action,
            "details": self.details,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent
        }
    
    def get_hash(self) -> str:
        """Get SHA-256 hash of the event."""
        event_json = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(event_json.encode()).hexdigest()


@dataclass
class Block:
    """Blockchain block containing audit events."""
    index: int
    timestamp: float
    events: List[AuditEvent]
    previous_hash: str
    nonce: int = 0
    hash: str = ""
    
    def calculate_hash(self) -> str:
        """Calculate block hash."""
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "events": [event.to_dict() for event in self.events],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        block_json = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_json.encode()).hexdigest()
    
    def mine_block(self, difficulty: int = 4):
        """Mine block with proof-of-work."""
        target = "0" * difficulty
        
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        logger.info(f"Block mined: {self.hash} (nonce: {self.nonce})")


class AuditBlockchain:
    """Blockchain for immutable audit trails."""
    
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.pending_events: List[AuditEvent] = []
        self.difficulty = difficulty
        self.block_size = 100  # Max events per block
        
        # Create genesis block
        self._create_genesis_block()
    
    def _create_genesis_block(self):
        """Create the first block in the chain."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            events=[],
            previous_hash="0"
        )
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
        logger.info("Genesis block created")
    
    def add_audit_event(self, event: AuditEvent):
        """Add audit event to pending events."""
        self.pending_events.append(event)
        logger.debug(f"Added audit event: {event.event_id}")
        
        # Auto-mine block if we have enough events
        if len(self.pending_events) >= self.block_size:
            self.mine_pending_events()
    
    def mine_pending_events(self) -> Block:
        """Mine pending events into a new block."""
        if not self.pending_events:
            logger.warning("No pending events to mine")
            return None
        
        # Create new block
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            events=self.pending_events.copy(),
            previous_hash=self.get_latest_block().hash
        )
        
        # Mine the block
        new_block.mine_block(self.difficulty)
        
        # Add to chain and clear pending events
        self.chain.append(new_block)
        self.pending_events.clear()
        
        logger.info(f"Mined block {new_block.index} with {len(new_block.events)} events")
        return new_block
    
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain."""
        return self.chain[-1]
    
    def is_chain_valid(self) -> bool:
        """Validate the entire blockchain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if current block hash is valid
            if current_block.hash != current_block.calculate_hash():
                logger.error(f"Invalid hash at block {i}")
                return False
            
            # Check if previous hash matches
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Invalid previous hash at block {i}")
                return False
        
        return True
    
    def search_events(self, criteria: Dict[str, Any]) -> List[AuditEvent]:
        """Search for events matching criteria."""
        results = []
        
        # Search in all blocks
        for block in self.chain:
            for event in block.events:
                if self._event_matches_criteria(event, criteria):
                    results.append(event)
        
        # Search in pending events
        for event in self.pending_events:
            if self._event_matches_criteria(event, criteria):
                results.append(event)
        
        return results
    
    def _event_matches_criteria(self, event: AuditEvent, criteria: Dict[str, Any]) -> bool:
        """Check if event matches search criteria."""
        for key, value in criteria.items():
            if key == "event_type" and event.event_type.value != value:
                return False
            elif key == "user_id" and event.user_id != value:
                return False
            elif key == "resource" and value not in event.resource:
                return False
            elif key == "severity" and event.severity.value < value:
                return False
            elif key == "start_time" and event.timestamp < value:
                return False
            elif key == "end_time" and event.timestamp > value:
                return False
        
        return True
    
    def get_user_activity(self, user_id: str, limit: int = 100) -> List[AuditEvent]:
        """Get recent activity for a specific user."""
        return self.search_events({"user_id": user_id})[-limit:]
    
    def get_resource_access_log(self, resource: str, limit: int = 100) -> List[AuditEvent]:
        """Get access log for a specific resource."""
        return self.search_events({"resource": resource})[-limit:]
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        """Get blockchain statistics."""
        total_events = sum(len(block.events) for block in self.chain)
        
        return {
            "total_blocks": len(self.chain),
            "total_events": total_events,
            "pending_events": len(self.pending_events),
            "chain_valid": self.is_chain_valid(),
            "latest_block_hash": self.get_latest_block().hash,
            "difficulty": self.difficulty
        }


class ComplianceReporter:
    """Generate compliance reports from audit trails."""
    
    def __init__(self, blockchain: AuditBlockchain):
        self.blockchain = blockchain
    
    def generate_user_activity_report(self, user_id: str, 
                                    start_date: datetime, 
                                    end_date: datetime) -> Dict[str, Any]:
        """Generate user activity report for compliance."""
        events = self.blockchain.search_events({
            "user_id": user_id,
            "start_time": start_date,
            "end_time": end_date
        })
        
        # Categorize events
        event_summary = {}
        for event in events:
            event_type = event.event_type.value
            event_summary[event_type] = event_summary.get(event_type, 0) + 1
        
        # Security events
        security_events = [e for e in events if e.event_type == AuditEventType.SECURITY_EVENT]
        
        return {
            "user_id": user_id,
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_events": len(events),
            "event_summary": event_summary,
            "security_events_count": len(security_events),
            "high_severity_events": len([e for e in events if e.severity.value >= 3]),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    
    def generate_system_access_report(self, start_date: datetime, 
                                    end_date: datetime) -> Dict[str, Any]:
        """Generate system-wide access report."""
        events = self.blockchain.search_events({
            "start_time": start_date,
            "end_time": end_date
        })
        
        # Analyze access patterns
        unique_users = set(event.user_id for event in events)
        resources_accessed = set(event.resource for event in events)
        
        # Failed access attempts
        failed_logins = [e for e in events 
                        if e.event_type == AuditEventType.USER_LOGIN 
                        and e.details.get("success") == False]
        
        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_events": len(events),
            "unique_users": len(unique_users),
            "resources_accessed": len(resources_accessed),
            "failed_login_attempts": len(failed_logins),
            "security_events": len([e for e in events if e.event_type == AuditEventType.SECURITY_EVENT]),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    
    def generate_forensic_timeline(self, incident_id: str, 
                                 start_date: datetime, 
                                 end_date: datetime) -> Dict[str, Any]:
        """Generate forensic timeline for incident investigation."""
        events = self.blockchain.search_events({
            "start_time": start_date,
            "end_time": end_date
        })
        
        # Sort events chronologically
        events.sort(key=lambda x: x.timestamp)
        
        # Create timeline
        timeline = []
        for event in events:
            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "user_id": event.user_id,
                "resource": event.resource,
                "action": event.action,
                "severity": event.severity.value,
                "details": event.details,
                "event_hash": event.get_hash()
            })
        
        return {
            "incident_id": incident_id,
            "timeline_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "total_events": len(timeline),
            "timeline": timeline,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "blockchain_verified": self.blockchain.is_chain_valid()
        }


class AuditTrailManager:
    """Main audit trail management system."""
    
    def __init__(self):
        self.blockchain = AuditBlockchain()
        self.compliance_reporter = ComplianceReporter(self.blockchain)
        
        # Event counters
        self.event_counters = {
            "total_events": 0,
            "security_events": 0,
            "failed_logins": 0,
            "admin_actions": 0
        }
    
    def log_event(self, event_type: AuditEventType, user_id: str, 
                 resource: str, action: str, details: Dict[str, Any],
                 severity: Severity = Severity.MEDIUM,
                 source_ip: Optional[str] = None,
                 user_agent: Optional[str] = None) -> str:
        """Log an audit event to the blockchain."""
        import uuid
        
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            resource=resource,
            action=action,
            details=details,
            severity=severity,
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        # Add to blockchain
        self.blockchain.add_audit_event(event)
        
        # Update counters
        self.event_counters["total_events"] += 1
        if event_type == AuditEventType.SECURITY_EVENT:
            self.event_counters["security_events"] += 1
        elif event_type == AuditEventType.USER_LOGIN and not details.get("success", True):
            self.event_counters["failed_logins"] += 1
        elif event_type == AuditEventType.ADMIN_ACTION:
            self.event_counters["admin_actions"] += 1
        
        logger.info(f"Logged audit event: {event.event_id}")
        return event.event_id
    
    def search_audit_trail(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search audit trail with criteria."""
        events = self.blockchain.search_events(criteria)
        return [event.to_dict() for event in events]
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify blockchain integrity."""
        is_valid = self.blockchain.is_chain_valid()
        stats = self.blockchain.get_blockchain_stats()
        
        return {
            "integrity_verified": is_valid,
            "blockchain_stats": stats,
            "verification_timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    def get_audit_status(self) -> Dict[str, Any]:
        """Get comprehensive audit system status."""
        blockchain_stats = self.blockchain.get_blockchain_stats()
        
        return {
            "audit_trails": {
                "blockchain_enabled": True,
                "total_blocks": blockchain_stats["total_blocks"],
                "total_events": blockchain_stats["total_events"],
                "pending_events": blockchain_stats["pending_events"],
                "chain_integrity": blockchain_stats["chain_valid"],
                "event_counters": self.event_counters,
                "mining_difficulty": blockchain_stats["difficulty"]
            }
        }


# Global audit trail manager
audit_trail_manager = AuditTrailManager()
