"""
Enhanced Audit Logging System
Provides comprehensive audit logging with tamper-resistant features and compliance support.
"""

import json
import logging
import hashlib
import time
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from queue import Queue
from cryptography.fernet import Fernet
import gzip

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Audit event types for compliance tracking."""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_REGISTRATION = "user_registration"
    USER_DELETION = "user_deletion"
    PASSWORD_CHANGE = "password_change"
    PERMISSION_CHANGE = "permission_change"
    DATA_ACCESS = "data_access"
    DATA_CREATION = "data_creation"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    SYSTEM_CONFIGURATION = "system_configuration"
    SECURITY_EVENT = "security_event"
    API_ACCESS = "api_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    ADMIN_ACTION = "admin_action"
    BACKUP_OPERATION = "backup_operation"
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"


class ComplianceStandard(Enum):
    """Compliance standards supported."""
    SOX = "sox"  # Sarbanes-Oxley
    HIPAA = "hipaa"  # Health Insurance Portability and Accountability Act
    GDPR = "gdpr"  # General Data Protection Regulation
    PCI_DSS = "pci_dss"  # Payment Card Industry Data Security Standard
    ISO27001 = "iso27001"  # ISO/IEC 27001
    NIST = "nist"  # NIST Cybersecurity Framework


@dataclass
class AuditEvent:
    """Audit event data structure."""
    timestamp: datetime
    event_id: str
    event_type: AuditEventType
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: str
    user_agent: str
    resource: str
    action: str
    outcome: str  # success, failure, error
    details: Dict[str, Any]
    compliance_tags: List[ComplianceStandard]
    risk_level: str  # low, medium, high, critical
    data_classification: str  # public, internal, confidential, restricted
    retention_period: int  # days
    hash_chain: Optional[str] = None  # For tamper detection


class EnhancedAuditLogger:
    """Enhanced audit logging system with tamper-resistant features."""

    def __init__(self, log_directory: str = "audit_logs", encryption_key: Optional[bytes] = None):
        self.log_directory = Path(log_directory)
        self.log_directory.mkdir(exist_ok=True)
        
        # Encryption for sensitive logs
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Hash chain for tamper detection
        self.last_hash = "0" * 64  # Genesis hash
        self.hash_chain_file = self.log_directory / "hash_chain.json"
        
        # Async logging queue
        self.log_queue = Queue()
        self.logging_active = True
        
        # Compliance configurations
        self.compliance_configs = {
            ComplianceStandard.SOX: {
                "retention_days": 2555,  # 7 years
                "encryption_required": True,
                "immutable_storage": True,
                "access_controls": True
            },
            ComplianceStandard.HIPAA: {
                "retention_days": 2190,  # 6 years
                "encryption_required": True,
                "access_logging": True,
                "data_integrity": True
            },
            ComplianceStandard.GDPR: {
                "retention_days": 1095,  # 3 years (configurable)
                "right_to_erasure": True,
                "data_portability": True,
                "consent_tracking": True
            },
            ComplianceStandard.PCI_DSS: {
                "retention_days": 365,  # 1 year minimum
                "encryption_required": True,
                "access_controls": True,
                "network_monitoring": True
            }
        }
        
        # Statistics
        self.stats = {
            "total_events": 0,
            "events_by_type": {},
            "events_by_user": {},
            "events_by_compliance": {},
            "integrity_checks": 0,
            "tamper_attempts": 0
        }
        
        # Load existing hash chain
        self._load_hash_chain()
        
        # Start background logging thread
        self.log_thread = threading.Thread(target=self._background_logger, daemon=True)
        self.log_thread.start()

    async def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str],
        session_id: Optional[str],
        source_ip: str,
        user_agent: str,
        resource: str,
        action: str,
        outcome: str,
        details: Dict[str, Any] = None,
        compliance_tags: List[ComplianceStandard] = None,
        risk_level: str = "low",
        data_classification: str = "internal"
    ):
        """Log an audit event."""
        event_id = self._generate_event_id()
        
        # Determine retention period based on compliance requirements
        retention_period = self._calculate_retention_period(compliance_tags or [])
        
        # Create audit event
        audit_event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_id=event_id,
            event_type=event_type,
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=resource,
            action=action,
            outcome=outcome,
            details=details or {},
            compliance_tags=compliance_tags or [],
            risk_level=risk_level,
            data_classification=data_classification,
            retention_period=retention_period
        )
        
        # Add to hash chain for tamper detection
        audit_event.hash_chain = self._calculate_hash_chain(audit_event)
        
        # Queue for background processing
        self.log_queue.put(audit_event)
        
        # Update statistics
        self._update_statistics(audit_event)

    def _background_logger(self):
        """Background thread for processing audit logs."""
        while self.logging_active:
            try:
                # Process queued events
                if not self.log_queue.empty():
                    event = self.log_queue.get(timeout=1)
                    self._write_audit_event(event)
                    self.log_queue.task_done()
                else:
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Audit logging error: {e}")
                time.sleep(1)

    def _write_audit_event(self, event: AuditEvent):
        """Write audit event to storage."""
        try:
            # Determine log file based on date and compliance requirements
            log_file = self._get_log_file(event)
            
            # Serialize event
            event_data = asdict(event)
            event_data['timestamp'] = event.timestamp.isoformat()
            event_data['event_type'] = event.event_type.value
            event_data['compliance_tags'] = [tag.value for tag in event.compliance_tags]
            
            # Encrypt if required
            if self._requires_encryption(event):
                event_json = json.dumps(event_data)
                encrypted_data = self.cipher.encrypt(event_json.encode())
                log_entry = {
                    "encrypted": True,
                    "data": encrypted_data.decode()
                }
            else:
                log_entry = event_data
            
            # Write to file
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Update hash chain
            self._update_hash_chain(event)
            
        except Exception as e:
            logger.error(f"Failed to write audit event: {e}")

    def _get_log_file(self, event: AuditEvent) -> Path:
        """Get appropriate log file for event."""
        date_str = event.timestamp.strftime("%Y-%m-%d")
        
        # Separate files for different compliance standards
        if event.compliance_tags:
            compliance_str = "_".join([tag.value for tag in event.compliance_tags])
            filename = f"audit_{compliance_str}_{date_str}.log"
        else:
            filename = f"audit_{date_str}.log"
        
        return self.log_directory / filename

    def _requires_encryption(self, event: AuditEvent) -> bool:
        """Check if event requires encryption."""
        # High-risk events always encrypted
        if event.risk_level in ["high", "critical"]:
            return True
        
        # Confidential/restricted data always encrypted
        if event.data_classification in ["confidential", "restricted"]:
            return True
        
        # Check compliance requirements
        for tag in event.compliance_tags:
            config = self.compliance_configs.get(tag, {})
            if config.get("encryption_required", False):
                return True
        
        return False

    def _calculate_retention_period(self, compliance_tags: List[ComplianceStandard]) -> int:
        """Calculate retention period based on compliance requirements."""
        if not compliance_tags:
            return 365  # Default 1 year
        
        # Use the longest retention period required
        max_retention = 365
        for tag in compliance_tags:
            config = self.compliance_configs.get(tag, {})
            retention = config.get("retention_days", 365)
            max_retention = max(max_retention, retention)
        
        return max_retention

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        timestamp = str(int(time.time() * 1000000))  # microseconds
        random_part = os.urandom(8).hex()
        return f"AUD-{timestamp}-{random_part}"

    def _calculate_hash_chain(self, event: AuditEvent) -> str:
        """Calculate hash chain for tamper detection."""
        # Create hash input from event data and previous hash
        event_data = f"{event.timestamp.isoformat()}{event.event_id}{event.event_type.value}{event.user_id}{event.action}{event.outcome}"
        hash_input = f"{self.last_hash}{event_data}"
        
        # Calculate SHA-256 hash
        current_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        self.last_hash = current_hash
        
        return current_hash

    def _update_hash_chain(self, event: AuditEvent):
        """Update hash chain file."""
        try:
            hash_entry = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "hash": event.hash_chain,
                "previous_hash": self.last_hash
            }
            
            with open(self.hash_chain_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(hash_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to update hash chain: {e}")

    def _load_hash_chain(self):
        """Load existing hash chain."""
        try:
            if self.hash_chain_file.exists():
                with open(self.hash_chain_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if lines:
                        last_entry = json.loads(lines[-1].strip())
                        self.last_hash = last_entry["hash"]
        except Exception as e:
            logger.warning(f"Could not load hash chain: {e}")

    def _update_statistics(self, event: AuditEvent):
        """Update audit statistics."""
        self.stats["total_events"] += 1
        
        # By event type
        event_type = event.event_type.value
        self.stats["events_by_type"][event_type] = self.stats["events_by_type"].get(event_type, 0) + 1
        
        # By user
        if event.user_id:
            self.stats["events_by_user"][event.user_id] = self.stats["events_by_user"].get(event.user_id, 0) + 1
        
        # By compliance
        for tag in event.compliance_tags:
            tag_value = tag.value
            self.stats["events_by_compliance"][tag_value] = self.stats["events_by_compliance"].get(tag_value, 0) + 1

    def verify_integrity(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """Verify audit log integrity."""
        self.stats["integrity_checks"] += 1
        
        try:
            # Read hash chain
            if not self.hash_chain_file.exists():
                return {"status": "error", "message": "Hash chain file not found"}
            
            with open(self.hash_chain_file, 'r', encoding='utf-8') as f:
                hash_entries = [json.loads(line.strip()) for line in f.readlines()]
            
            # Verify chain integrity
            verification_results = {
                "status": "success",
                "total_entries": len(hash_entries),
                "verified_entries": 0,
                "tamper_detected": False,
                "broken_chains": []
            }
            
            previous_hash = "0" * 64  # Genesis hash
            
            for i, entry in enumerate(hash_entries):
                # Verify hash chain
                if entry.get("previous_hash") != previous_hash:
                    verification_results["tamper_detected"] = True
                    verification_results["broken_chains"].append({
                        "entry_index": i,
                        "event_id": entry.get("event_id"),
                        "expected_previous": previous_hash,
                        "actual_previous": entry.get("previous_hash")
                    })
                else:
                    verification_results["verified_entries"] += 1
                
                previous_hash = entry.get("hash")
            
            if verification_results["tamper_detected"]:
                self.stats["tamper_attempts"] += len(verification_results["broken_chains"])
                logger.critical(f"Audit log tampering detected! {len(verification_results['broken_chains'])} broken chains found")
            
            return verification_results
            
        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return {"status": "error", "message": str(e)}

    def export_compliance_report(self, compliance_standard: ComplianceStandard, 
                                start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Export compliance report for specific standard."""
        try:
            report = {
                "compliance_standard": compliance_standard.value,
                "report_period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "events": [],
                "summary": {
                    "total_events": 0,
                    "events_by_type": {},
                    "users_active": set(),
                    "integrity_verified": False
                }
            }
            
            # Read relevant log files
            current_date = start_date.date()
            end_date_only = end_date.date()
            
            while current_date <= end_date_only:
                log_file = self.log_directory / f"audit_{compliance_standard.value}_{current_date.strftime('%Y-%m-%d')}.log"
                
                if log_file.exists():
                    with open(log_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            try:
                                log_entry = json.loads(line.strip())
                                
                                # Decrypt if necessary
                                if log_entry.get("encrypted"):
                                    decrypted_data = self.cipher.decrypt(log_entry["data"].encode())
                                    event_data = json.loads(decrypted_data.decode())
                                else:
                                    event_data = log_entry
                                
                                # Check if event is in date range
                                event_time = datetime.fromisoformat(event_data["timestamp"])
                                if start_date <= event_time <= end_date:
                                    report["events"].append(event_data)
                                    report["summary"]["total_events"] += 1
                                    
                                    # Update summary
                                    event_type = event_data["event_type"]
                                    report["summary"]["events_by_type"][event_type] = \
                                        report["summary"]["events_by_type"].get(event_type, 0) + 1
                                    
                                    if event_data.get("user_id"):
                                        report["summary"]["users_active"].add(event_data["user_id"])
                                        
                            except Exception as e:
                                logger.error(f"Error processing log entry: {e}")
                
                current_date += timedelta(days=1)
            
            # Convert set to list for JSON serialization
            report["summary"]["users_active"] = list(report["summary"]["users_active"])
            
            # Verify integrity
            integrity_result = self.verify_integrity(start_date, end_date)
            report["summary"]["integrity_verified"] = integrity_result["status"] == "success" and not integrity_result.get("tamper_detected", True)
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to export compliance report: {e}")
            return {"error": str(e)}

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics."""
        return dict(self.stats)

    def stop_logging(self):
        """Stop the audit logging system."""
        self.logging_active = False
        if self.log_thread.is_alive():
            self.log_thread.join(timeout=5)


# Global audit logger instance
_audit_logger = None


def get_audit_logger() -> EnhancedAuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = EnhancedAuditLogger()
    return _audit_logger
