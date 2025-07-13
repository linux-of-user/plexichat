import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.enhanced_ddos_service import enhanced_ddos_service
from app.services.security_service import SecurityService
from app.utils.rate_limiting import rate_limiter

from plexichat.antivirus.core.message_scanner import MessageAntivirusScanner

"""
Unified Security Integration Layer

Coordinates all security systems including:
- SQL injection detection and progressive blocking
- Message antivirus scanning
- Rate limiting and DDoS protection
- Input validation and sanitization
- Threat intelligence and reporting
- Security metrics and monitoring
"""

logger = logging.getLogger(__name__)

class SecurityAction(Enum):
    """Security actions that can be taken."""
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"

class SecurityThreatType(Enum):
    """Types of security threats."""
    CLEAN = "clean"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    MALICIOUS_CONTENT = "malicious_content"
    RATE_LIMIT_VIOLATION = "rate_limit_violation"
    DDOS_ATTACK = "ddos_attack"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"

@dataclass
class SecurityAssessment:
    """Comprehensive security assessment result."""
    request_id: str
    client_ip: str
    user_id: Optional[str]
    endpoint: str
    method: str
    timestamp: datetime
    
    # Overall assessment
    threat_detected: bool
    threat_type: SecurityThreatType
    threat_level: int  # 0-10 scale
    confidence_score: float  # 0.0-1.0
    recommended_action: SecurityAction
    
    # Individual system results
    sql_injection_result: Optional[Dict[str, Any]] = None
    antivirus_result: Optional[Dict[str, Any]] = None
    rate_limit_result: Optional[Dict[str, Any]] = None
    ddos_result: Optional[Dict[str, Any]] = None
    input_validation_result: Optional[Dict[str, Any]] = None
    
    # Response information
    witty_response: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    block_duration: Optional[int] = None
    retry_after: Optional[int] = None
    
    # Metadata
    scan_duration_ms: int = 0
    systems_checked: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class UnifiedSecurityService:
    """
    Unified security service that coordinates all security systems.
    
    This service acts as the central coordinator for:
    - SQL injection detection
    - Antivirus scanning
    - Rate limiting
    - DDoS protection
    - Input validation
    - Threat intelligence
    """
    
    def __init__(self):
        self.enabled = True
        
        # Initialize security services
        self._initialize_security_services()
        
        # Security policy configuration
        self.security_policy = {
            "sql_injection": {
                "enabled": True,
                "progressive_blocking": True,
                "allow_quoted_sql": True
            },
            "antivirus": {
                "enabled": True,
                "scan_messages": True,
                "scan_uploads": True
            },
            "rate_limiting": {
                "enabled": True,
                "progressive_blocking": True,
                "adaptive_limits": True
            },
            "ddos_protection": {
                "enabled": True,
                "dynamic_thresholds": True,
                "behavioral_analysis": True
            },
            "input_validation": {
                "enabled": True,
                "strict_mode": False,
                "sanitize_input": True
            }
        }
        
        # Threat correlation rules
        self.correlation_rules = {
            "multiple_violations": {
                "threshold": 3,
                "window_minutes": 15,
                "action": SecurityAction.ESCALATE
            },
            "high_confidence_threat": {
                "confidence_threshold": 0.9,
                "action": SecurityAction.BLOCK
            },
            "suspicious_pattern": {
                "pattern_count": 5,
                "action": SecurityAction.WARN
            }
        }
        
        # Witty response templates
        self.witty_responses = {
            SecurityThreatType.SQL_INJECTION: [
                "SQL injection detected!  Nice try, but we're not that easy!",
                "Injection attempt blocked!  Our database is well protected!",
                "SQL shenanigans detected!  Try using proper quotes: \"[SQL]\"",
                "Database attack thwarted!  Our castle walls are strong!"
            ],
            SecurityThreatType.XSS_ATTEMPT: [
                "XSS attempt blocked!  Keep your scripts to yourself!",
                "Cross-site scripting detected!  We don't fall for that!",
                "Script injection stopped!  Nice try, hacker!",
                "XSS attack prevented!  Our users are safe!"
            ],
            SecurityThreatType.MALICIOUS_CONTENT: [
                "Malicious content detected!  Our antivirus is on duty!",
                "Threat neutralized!  Security systems working perfectly!",
                "Suspicious content blocked!  We see everything!",
                "Malware attempt stopped!  Nice try, but no dice!"
            ],
            SecurityThreatType.RATE_LIMIT_VIOLATION: [
                "Rate limit exceeded!  Slow down, speed racer!",
                "Too many requests!  Patience is a virtue!",
                "Request flood detected!  Let's keep it reasonable!",
                "Slow down there!  Quality over quantity!"
            ],
            SecurityThreatType.DDOS_ATTACK: [
                "DDoS attack detected!  Our shields are up!",
                "Attack repelled!  You shall not pass!",
                "Flood attack blocked!  We're unsinkable!",
                "DDoS protection active!  System secured!"
            ]
        }
        
        logger.info(" Unified Security Service initialized")
    
    def _initialize_security_services(self):
        """Initialize all security service components."""
        # Import and initialize security services
        try:
            self.security_service = SecurityService()
        except ImportError:
            logger.warning("Security service not available")
            self.security_service = None
        
        try:
            self.message_scanner = MessageAntivirusScanner(from pathlib import Path
Path("data"))
        except ImportError:
            logger.warning("Message antivirus scanner not available")
            self.message_scanner = None
        
        try:
            self.ddos_service = enhanced_ddos_service
        except ImportError:
            logger.warning("Enhanced DDoS service not available")
            self.ddos_service = None
        
        try:
            self.rate_limiter = rate_limiter
        except ImportError:
            logger.warning("Rate limiter not available")
            self.rate_limiter = None
    
    async def assess_request_security(self, 
                                    request_data: Dict[str, Any],
                                    content: Optional[str] = None) -> SecurityAssessment:
        """
        Perform comprehensive security assessment of a request.
        
        Args:
            request_data: Request information (IP, endpoint, method, etc.)
            content: Optional content to scan (message, file, etc.)
            
        Returns:
            SecurityAssessment with comprehensive results
        """
        start_time = datetime.now(timezone.utc)
        
        # Extract request information
        client_ip = request_data.get('client_ip', 'unknown')
        user_id = request_data.get('user_id')
        endpoint = request_data.get('endpoint', '/')
        method = request_data.get('method', 'GET')
        request_data.get('user_agent', '')
        
        # Create assessment object
        assessment = SecurityAssessment(
            request_id=f"sec_{int(start_time.timestamp())}_{hash(client_ip) % 10000}",
            client_ip=client_ip,
            user_id=user_id,
            endpoint=endpoint,
            method=method,
            timestamp=start_time,
            threat_detected=False,
            threat_type=SecurityThreatType.CLEAN,
            threat_level=0,
            confidence_score=0.0,
            recommended_action=SecurityAction.ALLOW
        )
        
        # Run security checks
        await self._check_ddos_protection(assessment, request_data)
        await self._check_rate_limiting(assessment, request_data)
        
        if content:
            await self._check_sql_injection(assessment, content, client_ip)
            await self._check_antivirus(assessment, content, request_data)
            await self._check_input_validation(assessment, content)
        
        # Correlate results and determine final action
        self._correlate_threats(assessment)
        
        # Calculate scan duration
        end_time = datetime.now(timezone.utc)
        assessment.scan_duration_ms = int((end_time - start_time).total_seconds() * 1000)
        
        # Log assessment if threat detected
        if assessment.threat_detected:
            logger.warning(f"Security threat detected: {assessment.threat_type.value} "
                         f"from {client_ip} on {endpoint} "
                         f"(confidence: {assessment.confidence_score:.2f})")
        
        return assessment
    
    async def _check_ddos_protection(self, assessment: SecurityAssessment, 
                                   request_data: Dict[str, Any]):
        """Check DDoS protection."""
        if not self.security_policy["ddos_protection"]["enabled"] or not self.ddos_service:
            return
        
        assessment.systems_checked.append("ddos_protection")
        
        try:
            allowed, reason, metadata = await self.ddos_service.check_request(
                assessment.client_ip,
                request_data.get('user_agent', ''),
                assessment.endpoint,
                assessment.method
            )
            
            assessment.ddos_result = {
                "allowed": allowed,
                "reason": reason,
                "metadata": metadata
            }
            
            if not allowed:
                assessment.threat_detected = True
                assessment.threat_type = SecurityThreatType.DDOS_ATTACK
                assessment.threat_level = max(assessment.threat_level, 8)
                assessment.confidence_score = max(assessment.confidence_score, 0.9)
                assessment.recommended_action = SecurityAction.BLOCK
                assessment.witty_response = self._get_witty_response(SecurityThreatType.DDOS_ATTACK)
                assessment.retry_after = metadata.get("retry_after", 300)
                
        except Exception as e:
            logger.error(f"DDoS protection check failed: {e}")
    
    async def _check_rate_limiting(self, assessment: SecurityAssessment, 
                                 request_data: Dict[str, Any]):
        """Check rate limiting."""
        if not self.security_policy["rate_limiting"]["enabled"] or not self.rate_limiter:
            return
        
        assessment.systems_checked.append("rate_limiting")
        
        try:
            # Check rate limit
            rate_limit_key = f"ip:{assessment.client_ip}"
            allowed = self.rate_limiter.check_rate_limit(
                key=rate_limit_key,
                max_attempts=100,  # Default limit
                window_minutes=1,
                algorithm="sliding_window"
            )
            
            assessment.rate_limit_result = {
                "allowed": allowed,
                "key": rate_limit_key
            }
            
            if not allowed:
                assessment.threat_detected = True
                assessment.threat_type = SecurityThreatType.RATE_LIMIT_VIOLATION
                assessment.threat_level = max(assessment.threat_level, 5)
                assessment.confidence_score = max(assessment.confidence_score, 0.8)
                assessment.recommended_action = SecurityAction.BLOCK
                assessment.witty_response = self._get_witty_response(SecurityThreatType.RATE_LIMIT_VIOLATION)
                assessment.retry_after = 60
                
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
    
    async def _check_sql_injection(self, assessment: SecurityAssessment, 
                                 content: str, client_ip: str):
        """Check for SQL injection."""
        if not self.security_policy["sql_injection"]["enabled"] or not self.security_service:
            return
        
        assessment.systems_checked.append("sql_injection")
        
        try:
            is_detected, threat = self.security_service.detect_sql_injection(content, client_ip)
            
            assessment.sql_injection_result = {
                "detected": is_detected,
                "threat": threat.to_dict() if threat else None
            }
            
            if is_detected and threat:
                assessment.threat_detected = True
                assessment.threat_type = SecurityThreatType.SQL_INJECTION
                assessment.threat_level = max(assessment.threat_level, 9)
                assessment.confidence_score = max(assessment.confidence_score, 0.95)
                assessment.recommended_action = SecurityAction.BLOCK
                assessment.witty_response = threat.witty_response
                assessment.block_duration = threat.metadata.get('block_duration')
                
        except Exception as e:
            logger.error(f"SQL injection check failed: {e}")
    
    async def _check_antivirus(self, assessment: SecurityAssessment, 
                             content: str, request_data: Dict[str, Any]):
        """Check antivirus scanning."""
        if not self.security_policy["antivirus"]["enabled"] or not self.message_scanner:
            return
        
        assessment.systems_checked.append("antivirus")
        
        try:
            scan_result = await self.message_scanner.scan_message(
                content,
                sender_info={"ip": assessment.client_ip, "user_agent": request_data.get('user_agent', '')}
            )
            
            assessment.antivirus_result = {
                "threat_type": scan_result.threat_type.value,
                "threat_level": scan_result.threat_level.value,
                "confidence": scan_result.confidence_score,
                "description": scan_result.description
            }
            
            if scan_result.threat_level.value >= 2:  # Medium or higher
                assessment.threat_detected = True
                assessment.threat_type = SecurityThreatType.MALICIOUS_CONTENT
                assessment.threat_level = max(assessment.threat_level, scan_result.threat_level.value + 3)
                assessment.confidence_score = max(assessment.confidence_score, scan_result.confidence_score)
                assessment.recommended_action = SecurityAction.QUARANTINE
                assessment.witty_response = self._get_witty_response(SecurityThreatType.MALICIOUS_CONTENT)
                
        except Exception as e:
            logger.error(f"Antivirus check failed: {e}")
    
    async def _check_input_validation(self, assessment: SecurityAssessment, content: str):
        """Check input validation."""
        if not self.security_policy["input_validation"]["enabled"]:
            return
        
        assessment.systems_checked.append("input_validation")
        
        try:
            # Basic input validation checks
            validation_issues = []
            
            # Check for extremely long input
            if len(content) > 100000:  # 100KB limit
                validation_issues.append("content_too_long")
            
            # Check for null bytes
            if '\x00' in content:
                validation_issues.append("null_bytes_detected")
            
            # Check for control characters
            control_chars = sum(1 for c in content if ord(c) < 32 and c not in '\t\n\r')
            if control_chars > 10:
                validation_issues.append("excessive_control_characters")
            
            assessment.input_validation_result = {
                "issues": validation_issues,
                "content_length": len(content)
            }
            
            if validation_issues:
                assessment.threat_detected = True
                assessment.threat_type = SecurityThreatType.INPUT_VALIDATION_FAILURE
                assessment.threat_level = max(assessment.threat_level, 4)
                assessment.confidence_score = max(assessment.confidence_score, 0.7)
                assessment.recommended_action = SecurityAction.WARN
                
        except Exception as e:
            logger.error(f"Input validation check failed: {e}")
    
    def _correlate_threats(self, assessment: SecurityAssessment):
        """Correlate threat results and determine final action."""
        # If multiple systems detected threats, escalate
        threat_systems = sum(1 for system in assessment.systems_checked 
                           if getattr(assessment, f"{system}_result", {}).get("detected") or
                              getattr(assessment, f"{system}_result", {}).get("threat_level", 0) > 0)
        
        if threat_systems >= 2:
            assessment.threat_level = min(10, assessment.threat_level + 2)
            assessment.confidence_score = min(1.0, assessment.confidence_score + 0.1)
            if assessment.recommended_action == SecurityAction.WARN:
                assessment.recommended_action = SecurityAction.BLOCK
        
        # Apply correlation rules
        if assessment.confidence_score >= self.correlation_rules["high_confidence_threat"]["confidence_threshold"]:
            assessment.recommended_action = self.correlation_rules["high_confidence_threat"]["action"]
    
    def _get_witty_response(self, threat_type: SecurityThreatType) -> str:
        """Get a witty response for the threat type."""
        responses = self.witty_responses.get(threat_type, ["Security violation detected! "])
        return random.choice(responses)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get overall security system status."""
        return {
            "enabled": self.enabled,
            "services": {
                "security_service": self.security_service is not None,
                "message_scanner": self.message_scanner is not None,
                "ddos_service": self.ddos_service is not None,
                "rate_limiter": self.rate_limiter is not None
            },
            "policy": self.security_policy,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    async def handle_security_response(self, assessment: SecurityAssessment) -> Dict[str, Any]:
        """
        Generate appropriate response based on security assessment.

        Args:
            assessment: Security assessment result

        Returns:
            Response data for the client
        """
        if not assessment.threat_detected:
            return {
                "status": "allowed",
                "message": "Request processed successfully"
            }

        # Generate response based on recommended action
        if assessment.recommended_action == SecurityAction.ALLOW:
            return {
                "status": "allowed",
                "message": "Request allowed with warnings",
                "warnings": [assessment.threat_type.value]
            }

        elif assessment.recommended_action == SecurityAction.WARN:
            return {
                "status": "warning",
                "message": "Security warning issued",
                "threat_type": assessment.threat_type.value,
                "witty_response": assessment.witty_response,
                "confidence": assessment.confidence_score
            }

        elif assessment.recommended_action in [SecurityAction.BLOCK, SecurityAction.QUARANTINE]:
            response = {
                "status": "blocked",
                "error": f"Security Violation: {assessment.threat_type.value.replace('_', ' ').title()}",
                "message": "Request blocked by security systems",
                "witty_response": assessment.witty_response,
                "threat_level": assessment.threat_level,
                "confidence": assessment.confidence_score,
                "systems_triggered": assessment.systems_checked
            }

            if assessment.retry_after:
                response["retry_after"] = assessment.retry_after

            if assessment.block_duration:
                response["block_duration"] = assessment.block_duration

            return response

        elif assessment.recommended_action == SecurityAction.ESCALATE:
            return {
                "status": "escalated",
                "error": "Critical Security Violation",
                "message": "Request escalated to security team",
                "witty_response": " Security team has been notified! This incident will be reported!",
                "threat_level": assessment.threat_level,
                "confidence": assessment.confidence_score,
                "request_id": assessment.request_id
            }

        # Default response
        return {
            "status": "blocked",
            "error": "Security Violation",
            "message": "Request blocked by security systems"
        }

# Global unified security service
unified_security_service = UnifiedSecurityService()
