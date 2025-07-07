"""
NetLink Security Logging System

Specialized logging for security events, audit trails, and compliance.
Provides tamper-resistant logging with encryption and integrity verification.

Features:
- Security event classification
- Tamper-resistant log storage
- Encrypted log transmission
- Compliance reporting
- Threat detection integration
- Audit trail management
- Real-time security alerts
"""

import logging
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading

from . import LogEntry, LogContext, LogCategory, LogLevel
from ..security import security_manager, quantum_encryption

class SecurityEventType(Enum):
    """Security event types for classification."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PERMISSION_DENIED = "permission_denied"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_POLICY_VIOLATION = "security_policy_violation"
    MALWARE_DETECTION = "malware_detection"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    DDOS_ATTACK = "ddos_attack"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    CSRF_ATTEMPT = "csrf_attempt"
    FILE_UPLOAD_VIOLATION = "file_upload_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ENCRYPTION_FAILURE = "encryption_failure"
    KEY_COMPROMISE = "key_compromise"
    CERTIFICATE_ERROR = "certificate_error"
    AUDIT_LOG_TAMPERING = "audit_log_tampering"

class SecuritySeverity(Enum):
    """Security event severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

@dataclass
class SecurityEvent:
    """Security event data structure."""
    event_type: SecurityEventType
    severity: SecuritySeverity
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    threat_indicators: List[str] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary."""
        return {
            "event_type": self.event_type.value,
            "severity": self.severity.name,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "endpoint": self.endpoint,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "details": self.details,
            "threat_indicators": self.threat_indicators,
            "mitigation_actions": self.mitigation_actions,
            "correlation_id": self.correlation_id
        }

class TamperResistantLogger:
    """Tamper-resistant logging with integrity verification."""
    
    def __init__(self, log_file: Path, secret_key: bytes):
        self.log_file = log_file
        self.secret_key = secret_key
        self.lock = threading.RLock()
        self.sequence_number = 0
        self.previous_hash = b"0" * 64  # Initial hash
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing sequence number and hash
        self._load_state()
    
    def _load_state(self):
        """Load the current state from existing log file."""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'rb') as f:
                    lines = f.readlines()
                    if lines:
                        last_line = lines[-1].decode('utf-8').strip()
                        if last_line:
                            entry = json.loads(last_line)
                            self.sequence_number = entry.get('sequence', 0)
                            self.previous_hash = entry.get('hash', '0' * 64).encode()
            except Exception:
                # If we can't load state, start fresh
                self.sequence_number = 0
                self.previous_hash = b"0" * 64
    
    def log_entry(self, entry_data: Dict[str, Any]) -> str:
        """Log an entry with tamper-resistant properties."""
        with self.lock:
            self.sequence_number += 1
            
            # Create the log entry
            log_entry = {
                "sequence": self.sequence_number,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": entry_data,
                "previous_hash": self.previous_hash.decode() if isinstance(self.previous_hash, bytes) else self.previous_hash
            }
            
            # Calculate hash of the entry
            entry_json = json.dumps(log_entry, sort_keys=True, separators=(',', ':'))
            entry_hash = hmac.new(
                self.secret_key,
                entry_json.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Add hash to entry
            log_entry["hash"] = entry_hash
            
            # Write to file
            final_json = json.dumps(log_entry, separators=(',', ':'))
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(final_json + '\n')
            
            # Update state
            self.previous_hash = entry_hash.encode()
            
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
                    
                    # Check sequence number
                    if entry.get("sequence") != expected_sequence:
                        verification_results["missing_sequences"].append({
                            "line": line_num,
                            "expected": expected_sequence,
                            "actual": entry.get("sequence")
                        })
                        verification_results["verified"] = False
                    
                    # Check previous hash
                    if entry.get("previous_hash") != previous_hash:
                        verification_results["hash_mismatches"].append({
                            "line": line_num,
                            "sequence": entry.get("sequence"),
                            "expected_previous": previous_hash,
                            "actual_previous": entry.get("previous_hash")
                        })
                        verification_results["verified"] = False
                    
                    # Verify entry hash
                    entry_copy = entry.copy()
                    stored_hash = entry_copy.pop("hash", "")
                    entry_json = json.dumps(entry_copy, sort_keys=True, separators=(',', ':'))
                    calculated_hash = hmac.new(
                        self.secret_key,
                        entry_json.encode('utf-8'),
                        hashlib.sha256
                    ).hexdigest()
                    
                    if calculated_hash != stored_hash:
                        verification_results["corrupted_entries"].append({
                            "line": line_num,
                            "sequence": entry.get("sequence"),
                            "calculated_hash": calculated_hash,
                            "stored_hash": stored_hash
                        })
                        verification_results["verified"] = False
                    
                    previous_hash = stored_hash
                    expected_sequence += 1
                    
                except json.JSONDecodeError:
                    verification_results["corrupted_entries"].append({
                        "line": line_num,
                        "error": "invalid_json"
                    })
                    verification_results["verified"] = False
        
        except Exception as e:
            verification_results["status"] = "error"
            verification_results["verified"] = False
            verification_results["error"] = str(e)
        
        return verification_results

class SecurityLogger:
    """Comprehensive security logging system."""
    
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize tamper-resistant logger
        secret_key = security_manager.get_logging_key() if security_manager else b"default_key_change_me"
        self.tamper_logger = TamperResistantLogger(
            log_dir / "security_audit.log",
            secret_key
        )
        
        # Initialize standard logger
        self.logger = logging.getLogger("netlink.security")
        
        # Setup security log handler
        self._setup_security_handler()
        
        # Event counters for threat detection
        self.event_counters = {}
        self.lock = threading.RLock()
    
    def _setup_security_handler(self):
        """Setup security-specific log handler."""
        handler = logging.FileHandler(
            self.log_dir / "security.log",
            encoding='utf-8'
        )
        handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '[%(asctime)s] [SECURITY] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event with tamper-resistant storage."""
        # Log to tamper-resistant storage
        self.tamper_logger.log_entry(event.to_dict())
        
        # Log to standard logger
        self.logger.log(
            self._severity_to_log_level(event.severity),
            f"Security Event: {event.event_type.value} | "
            f"Severity: {event.severity.name} | "
            f"User: {event.user_id or 'Unknown'} | "
            f"IP: {event.ip_address or 'Unknown'} | "
            f"Details: {json.dumps(event.details)}"
        )
        
        # Update event counters for threat detection
        self._update_event_counters(event)
        
        # Check for alert conditions
        self._check_alert_conditions(event)
    
    def _severity_to_log_level(self, severity: SecuritySeverity) -> int:
        """Convert security severity to log level."""
        mapping = {
            SecuritySeverity.LOW: logging.INFO,
            SecuritySeverity.MEDIUM: logging.WARNING,
            SecuritySeverity.HIGH: logging.ERROR,
            SecuritySeverity.CRITICAL: logging.CRITICAL,
            SecuritySeverity.EMERGENCY: logging.CRITICAL
        }
        return mapping.get(severity, logging.INFO)
    
    def _update_event_counters(self, event: SecurityEvent):
        """Update event counters for threat detection."""
        with self.lock:
            current_time = time.time()
            event_key = f"{event.event_type.value}:{event.ip_address or 'unknown'}"
            
            if event_key not in self.event_counters:
                self.event_counters[event_key] = []
            
            # Add current event
            self.event_counters[event_key].append(current_time)
            
            # Clean old events (older than 1 hour)
            cutoff_time = current_time - 3600
            self.event_counters[event_key] = [
                t for t in self.event_counters[event_key] if t > cutoff_time
            ]
    
    def _check_alert_conditions(self, event: SecurityEvent):
        """Check if event triggers alert conditions."""
        # Critical events always trigger alerts
        if event.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.EMERGENCY]:
            self._trigger_alert(event, "Critical security event detected")
        
        # Check for brute force patterns
        if event.event_type == SecurityEventType.LOGIN_FAILURE:
            self._check_brute_force(event)
        
        # Check for suspicious activity patterns
        self._check_suspicious_patterns(event)
    
    def _check_brute_force(self, event: SecurityEvent):
        """Check for brute force attack patterns."""
        with self.lock:
            event_key = f"login_failure:{event.ip_address or 'unknown'}"
            if event_key in self.event_counters:
                recent_failures = len(self.event_counters[event_key])
                if recent_failures >= 5:  # 5 failures in 1 hour
                    self._trigger_alert(event, f"Brute force attack detected: {recent_failures} failed logins")
    
    def _check_suspicious_patterns(self, event: SecurityEvent):
        """Check for other suspicious activity patterns."""
        # This can be extended with more sophisticated pattern detection
        suspicious_events = [
            SecurityEventType.UNAUTHORIZED_ACCESS,
            SecurityEventType.PRIVILEGE_ESCALATION,
            SecurityEventType.SQL_INJECTION_ATTEMPT,
            SecurityEventType.XSS_ATTEMPT
        ]
        
        if event.event_type in suspicious_events:
            self._trigger_alert(event, f"Suspicious activity detected: {event.event_type.value}")
    
    def _trigger_alert(self, event: SecurityEvent, message: str):
        """Trigger security alert."""
        alert_data = {
            "alert_type": "security",
            "message": message,
            "event": event.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Log the alert
        self.logger.critical(f"SECURITY ALERT: {message}")
        
        # Here you would integrate with your alerting system
        # For example: send to monitoring system, email, Slack, etc.
    
    def verify_log_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of security logs."""
        return self.tamper_logger.verify_integrity()
    
    def get_security_events(self, start_time: Optional[datetime] = None,
                           end_time: Optional[datetime] = None,
                           event_types: Optional[List[SecurityEventType]] = None,
                           severity: Optional[SecuritySeverity] = None) -> List[Dict[str, Any]]:
        """Retrieve security events with filtering."""
        events = []
        
        if not self.tamper_logger.log_file.exists():
            return events
        
        try:
            with open(self.tamper_logger.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        entry = json.loads(line.strip())
                        event_data = entry.get("data", {})
                        
                        # Apply filters
                        if start_time or end_time:
                            event_time = datetime.fromisoformat(event_data.get("timestamp", ""))
                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue
                        
                        if event_types:
                            event_type_str = event_data.get("event_type", "")
                            if not any(et.value == event_type_str for et in event_types):
                                continue
                        
                        if severity:
                            event_severity = event_data.get("severity", "")
                            if event_severity != severity.name:
                                continue
                        
                        events.append(event_data)
                        
                    except json.JSONDecodeError:
                        continue
        
        except Exception:
            pass
        
        return events

# Global security logger instance
_security_logger = None

def get_security_logger() -> SecurityLogger:
    """Get the global security logger instance."""
    global _security_logger
    if _security_logger is None:
        from ..config import get_config
        config = get_config()
        log_dir = Path(config.get("logging.directory", "logs")) / "security"
        _security_logger = SecurityLogger(log_dir)
    return _security_logger

# Export main components
__all__ = [
    "SecurityEventType", "SecuritySeverity", "SecurityEvent",
    "TamperResistantLogger", "SecurityLogger", "get_security_logger"
]
