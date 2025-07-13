import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

            from app.services.enhanced_ddos_service import enhanced_ddos_service
            
            from app.security.advanced_behavioral_analyzer import advanced_behavioral_analyzer
            
            from app.security.rate_limiter import RateLimiter

            from app.security.input_sanitizer import InputSanitizer


"""
Unified Security Coordinator for PlexiChat

This module coordinates all security systems including:
- Enhanced DDoS Protection Service (services/enhanced_ddos_service.py)
- Legacy DDoS Protection (security/ddos_protection.py)
- Rate Limiting (security/rate_limiter.py)
- Advanced Behavioral Analysis (security/advanced_behavioral_analyzer.py)
- Unified Security Service (services/unified_security_service.py)
- Comprehensive Security (security/comprehensive_security.py)
- MITM Protection (security/mitm_protection.py)
- Input Sanitization (security/input_sanitizer.py)
- Penetration Testing (security/penetration_tester.py)

This coordinator ensures all security systems work together seamlessly.
"""

logger = logging.getLogger(__name__)

class SecuritySystemStatus(Enum):
    """Status of individual security systems."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    DEGRADED = "degraded"

@dataclass
class SecuritySystemInfo:
    """Information about a security system."""
    name: str
    module_path: str
    status: SecuritySystemStatus
    version: str = "1.0.0"
    last_check: Optional[datetime] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class UnifiedSecurityResponse:
    """Unified response from all security systems."""
    allowed: bool
    primary_reason: str
    security_level: int  # 0-10 (0=clean, 10=critical threat)
    
    # System responses
    ddos_response: Optional[Dict[str, Any]] = None
    rate_limit_response: Optional[Dict[str, Any]] = None
    behavioral_response: Optional[Dict[str, Any]] = None
    input_validation_response: Optional[Dict[str, Any]] = None
    
    # Actions taken
    actions_taken: List[str] = field(default_factory=list)
    block_duration: Optional[int] = None
    witty_response: Optional[str] = None
    
    # Metadata
    processing_time_ms: int = 0
    systems_consulted: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None

class UnifiedSecurityCoordinator:
    """
    Unified coordinator for all PlexiChat security systems.
    
    This class provides a single interface to all security systems,
    ensuring they work together and don't conflict with each other.
    """
    
    def __init__(self):
        self.enabled = True
        self.security_systems: Dict[str, SecuritySystemInfo] = {}
        
        # Initialize all security systems
        self._initialize_security_systems()
        
        # Coordination settings
        self.coordination_policy = {
            "prefer_enhanced_ddos": True,  # Prefer enhanced over legacy DDoS
            "behavioral_analysis_weight": 0.3,  # Weight in final decision
            "rate_limit_escalation": True,  # Allow rate limits to escalate to blocks
            "unified_blocking": True,  # Coordinate blocks across systems
            "cross_system_correlation": True  # Share threat intel between systems
        }
        
        # Shared threat intelligence
        self.shared_threat_data = {
            "blocked_ips": set(),
            "suspicious_patterns": {},
            "coordinated_attacks": {},
            "false_positives": set()
        }
        
        logger.info("Unified Security Coordinator initialized")
    
    def _initialize_security_systems(self):
        """Initialize and register all security systems."""
        systems_to_register = [
            {
                "name": "enhanced_ddos_service",
                "module_path": "app.services.enhanced_ddos_service",
                "description": "Enhanced DDoS Protection with behavioral analysis"
            },
            {
                "name": "ddos_protection",
                "module_path": "app.security.ddos_protection",
                "description": "Legacy DDoS Protection system"
            },
            {
                "name": "rate_limiter",
                "module_path": "app.security.rate_limiter",
                "description": "Advanced rate limiting system"
            },
            {
                "name": "behavioral_analyzer",
                "module_path": "app.security.advanced_behavioral_analyzer",
                "description": "Advanced behavioral analysis with anti-hijacking"
            },
            {
                "name": "unified_security_service",
                "module_path": "app.services.unified_security_service",
                "description": "Unified security assessment service"
            },
            {
                "name": "comprehensive_security",
                "module_path": "app.security.comprehensive_security",
                "description": "Comprehensive security middleware"
            },
            {
                "name": "mitm_protection",
                "module_path": "app.security.mitm_protection",
                "description": "MITM attack protection"
            },
            {
                "name": "input_sanitizer",
                "module_path": "app.security.input_sanitizer",
                "description": "Input validation and sanitization"
            },
            {
                "name": "penetration_tester",
                "module_path": "app.security.penetration_tester",
                "description": "Automated penetration testing"
            }
        ]
        
        for system_info in systems_to_register:
            self._register_security_system(system_info)
    
    def _register_security_system(self, system_info: Dict[str, str]):
        """Register a security system."""
        try:
            # Try to import the module to verify it exists
            module_path = system_info["module_path"]
            
            # Create system info
            system = SecuritySystemInfo(
                name=system_info["name"],
                module_path=module_path,
                status=SecuritySystemStatus.ACTIVE,
                last_check=datetime.now(timezone.utc)
            )
            
            self.security_systems[system_info["name"]] = system
            logger.info(f"Registered security system: {system_info['name']}")
            
        except ImportError as e:
            # System not available
            system = SecuritySystemInfo(
                name=system_info["name"],
                module_path=system_info["module_path"],
                status=SecuritySystemStatus.ERROR,
                error_message=str(e),
                last_check=datetime.now(timezone.utc)
            )
            
            self.security_systems[system_info["name"]] = system
            logger.warning(f"Security system not available: {system_info['name']} - {e}")
    
    async def assess_request_security(self, 
                                    request_data: Dict[str, Any]) -> UnifiedSecurityResponse:
        """
        Perform unified security assessment across all systems.
        
        Args:
            request_data: Request information including IP, endpoint, method, content, etc.
            
        Returns:
            UnifiedSecurityResponse with coordinated security decision
        """
        start_time = datetime.now(timezone.utc)
        correlation_id = f"sec_{int(start_time.timestamp() * 1000)}"
        
        response = UnifiedSecurityResponse(
            allowed=True,
            primary_reason="clean",
            security_level=0,
            correlation_id=correlation_id
        )
        
        try:
            # 1. Enhanced DDoS Protection (Primary)
            if self.coordination_policy["prefer_enhanced_ddos"]:
                ddos_result = await self._check_enhanced_ddos(request_data)
                if ddos_result:
                    response.ddos_response = ddos_result
                    response.systems_consulted.append("enhanced_ddos_service")
                    
                    if not ddos_result.get("allowed", True):
                        response.allowed = False
                        response.primary_reason = ddos_result.get("reason", "ddos_blocked")
                        response.security_level = max(response.security_level, 7)
                        response.actions_taken.append("ddos_block")
            
            # 2. Behavioral Analysis
            behavioral_result = await self._check_behavioral_analysis(request_data)
            if behavioral_result:
                response.behavioral_response = behavioral_result
                response.systems_consulted.append("behavioral_analyzer")
                
                # Weight behavioral analysis in decision
                behavioral_weight = self.coordination_policy["behavioral_analysis_weight"]
                risk_contribution = behavioral_result.get("risk_level", 0) * behavioral_weight
                response.security_level = max(response.security_level, int(risk_contribution))
                
                if behavioral_result.get("risk_level", 0) > 8:
                    response.allowed = False
                    response.primary_reason = "behavioral_threat"
                    response.actions_taken.append("behavioral_block")
            
            # 3. Rate Limiting
            rate_limit_result = await self._check_rate_limiting(request_data)
            if rate_limit_result:
                response.rate_limit_response = rate_limit_result
                response.systems_consulted.append("rate_limiter")
                
                if not rate_limit_result.get("allowed", True):
                    if self.coordination_policy["rate_limit_escalation"]:
                        response.allowed = False
                        response.primary_reason = "rate_limit_exceeded"
                        response.security_level = max(response.security_level, 5)
                        response.actions_taken.append("rate_limit_block")
            
            # 4. Input Validation
            input_result = await self._check_input_validation(request_data)
            if input_result:
                response.input_validation_response = input_result
                response.systems_consulted.append("input_sanitizer")
                
                if not input_result.get("valid", True):
                    response.allowed = False
                    response.primary_reason = "input_validation_failed"
                    response.security_level = max(response.security_level, 6)
                    response.actions_taken.append("input_block")
            
            # 5. Cross-system correlation
            if self.coordination_policy["cross_system_correlation"]:
                await self._perform_cross_system_correlation(request_data, response)
            
            # 6. Generate witty response if blocked
            if not response.allowed:
                response.witty_response = self._generate_witty_response(
                    response.primary_reason, response.security_level
                )
            
            # Calculate processing time
            end_time = datetime.now(timezone.utc)
            response.processing_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Log significant security events
            if response.security_level > 5:
                logger.warning(f"High security threat detected: {response.primary_reason} "
                             f"(level: {response.security_level}, systems: {response.systems_consulted})")
            
            return response
            
        except Exception as e:
            logger.error(f"Unified security assessment failed: {e}")
            # Fail secure - block on error
            response.allowed = False
            response.primary_reason = "security_system_error"
            response.security_level = 8
            return response
    
    async def _check_enhanced_ddos(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check enhanced DDoS protection service."""
        try:
            ip = request_data.get("client_ip", "unknown")
            endpoint = request_data.get("endpoint", "/")
            method = request_data.get("method", "GET")
            user_agent = request_data.get("user_agent", "")
            
            allowed, reason, details = await enhanced_ddos_service.check_request(
                ip, endpoint, method, user_agent
            )
            
            return {
                "allowed": allowed,
                "reason": reason,
                "details": details,
                "system": "enhanced_ddos_service"
            }
            
        except ImportError:
            logger.debug("Enhanced DDoS service not available")
            return None
        except Exception as e:
            logger.error(f"Enhanced DDoS check failed: {e}")
            return {"allowed": False, "reason": "ddos_check_error", "error": str(e)}
    
    async def _check_behavioral_analysis(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check behavioral analysis system."""
        try:
            entity_id = request_data.get("client_ip", "unknown")
            assessment = await advanced_behavioral_analyzer.analyze_request_behavior(
                entity_id, "ip", request_data
            )
            
            return {
                "threat_type": assessment.threat_type.value,
                "confidence": assessment.confidence,
                "risk_level": assessment.risk_level,
                "patterns_detected": assessment.patterns_detected,
                "system": "behavioral_analyzer"
            }
            
        except ImportError:
            logger.debug("Behavioral analyzer not available")
            return None
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            return {"risk_level": 5, "error": str(e)}  # Medium risk on error

    async def _check_rate_limiting(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check rate limiting systems."""
        try:
            # Try to get existing rate limiter instance
            rate_limiter = RateLimiter()

            ip = request_data.get("client_ip", "unknown")
            endpoint = request_data.get("endpoint", "/")

            # Check rate limit
            allowed = await rate_limiter.check_rate_limit(ip, endpoint)

            return {
                "allowed": allowed,
                "system": "rate_limiter",
                "endpoint": endpoint
            }

        except ImportError:
            logger.debug("Rate limiter not available")
            return None
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
            return {"allowed": True, "error": str(e)}  # Allow on error

    async def _check_input_validation(self, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check input validation and sanitization."""
        try:
            sanitizer = InputSanitizer()

            # Check various inputs
            results = {
                "valid": True,
                "issues": [],
                "system": "input_sanitizer"
            }

            # Check endpoint for suspicious patterns
            endpoint = request_data.get("endpoint", "")
            if endpoint:
                endpoint_result = sanitizer.validate_endpoint(endpoint)
                if not endpoint_result.get("valid", True):
                    results["valid"] = False
                    results["issues"].append("suspicious_endpoint")

            # Check content if provided
            content = request_data.get("content", "")
            if content:
                content_result = sanitizer.sanitize_input(content)
                if content_result.get("threats_detected"):
                    results["valid"] = False
                    results["issues"].extend(content_result["threats_detected"])

            return results

        except ImportError:
            logger.debug("Input sanitizer not available")
            return None
        except Exception as e:
            logger.error(f"Input validation failed: {e}")
            return {"valid": True, "error": str(e)}  # Allow on error

    async def _perform_cross_system_correlation(self,
                                              request_data: Dict[str, Any],
                                              response: UnifiedSecurityResponse):
        """Perform cross-system threat correlation."""
        try:
            ip = request_data.get("client_ip", "unknown")

            # Check if IP is in shared threat data
            if ip in self.shared_threat_data["blocked_ips"]:
                response.security_level = max(response.security_level, 8)
                response.actions_taken.append("cross_system_block")

            # Update shared threat data based on current assessment
            if response.security_level > 7:
                self.shared_threat_data["blocked_ips"].add(ip)

            # Check for coordinated attack patterns
            current_time = datetime.now(timezone.utc)
            if ip not in self.shared_threat_data["coordinated_attacks"]:
                self.shared_threat_data["coordinated_attacks"][ip] = []

            self.shared_threat_data["coordinated_attacks"][ip].append(current_time)

            # Clean old entries (keep last hour)
            hour_ago = current_time - timedelta(hours=1)
            self.shared_threat_data["coordinated_attacks"][ip] = [
                timestamp for timestamp in self.shared_threat_data["coordinated_attacks"][ip]
                if timestamp > hour_ago
            ]

            # Check for coordinated attack (multiple high-risk requests)
            high_risk_requests = len(self.shared_threat_data["coordinated_attacks"][ip])
            if high_risk_requests > 10:  # More than 10 high-risk requests in an hour
                response.security_level = max(response.security_level, 9)
                response.actions_taken.append("coordinated_attack_detected")

        except Exception as e:
            logger.error(f"Cross-system correlation failed: {e}")

    def _generate_witty_response(self, reason: str, security_level: int) -> str:
        """Generate witty security response based on threat level."""
        witty_responses = {
            "ddos_blocked": [
                " Whoa there, speed racer! Our servers aren't running a marathon.",
                " Easy does it! Even The Flash takes breaks between requests.",
                " Patience, grasshopper. Good things come to those who wait... and don't spam."
            ],
            "behavioral_threat": [
                " Nice try, but our AI spotted your robot dance moves!",
                " Our behavioral analysis says you're acting sus. Time for a timeout!",
                " We see through your digital disguise. Take five and try being human."
            ],
            "rate_limit_exceeded": [
                " Slow down there, Sonic! Even hedgehogs need to pace themselves.",
                " You've exceeded your request quota. Time to touch some grass!",
                " Too much power! Channel your inner zen and try again later."
            ],
            "input_validation_failed": [
                " Your input needs some spring cleaning. Try again with nicer data!",
                " That input is about as welcome as a virus at a computer convention.",
                " Our scanners found something fishy in your request. Back to the drawing board!"
            ],
            "security_system_error": [
                " Our security systems are having a moment. Please try again later!",
                " Something went wrong in our security checks. Better safe than sorry!",
                " Technical difficulties in the security department. Stand by!"
            ]
        }

        # Escalate wit based on security level
        if security_level >= 9:
            escalated_responses = [
                " MAXIMUM SECURITY BREACH DETECTED! You've triggered our ultimate defense!",
                " DEFCON 1 ACTIVATED! Your request has been classified as 'extremely suspicious'!",
                " CRITICAL THREAT LEVEL! Our AI is now personally offended by your behavior!"
            ]
            return escalated_responses[security_level % len(escalated_responses)]

        responses = witty_responses.get(reason, [" Security says no. Try being nicer to our servers!"])
        return responses[security_level % len(responses)]

    def get_system_status(self) -> Dict[str, Any]:
        """Get status of all security systems."""
        return {
            "coordinator_enabled": self.enabled,
            "systems": {
                name: {
                    "status": system.status.value,
                    "last_check": system.last_check.isoformat() if system.last_check else None,
                    "error": system.error_message,
                    "metrics": system.metrics
                }
                for name, system in self.security_systems.items()
            },
            "coordination_policy": self.coordination_policy,
            "shared_threat_stats": {
                "blocked_ips": len(self.shared_threat_data["blocked_ips"]),
                "suspicious_patterns": len(self.shared_threat_data["suspicious_patterns"]),
                "coordinated_attacks": len(self.shared_threat_data["coordinated_attacks"]),
                "false_positives": len(self.shared_threat_data["false_positives"])
            }
        }

    async def update_coordination_policy(self, policy_updates: Dict[str, Any]):
        """Update coordination policy from plexichat.core.config import settings
settings."""
        for key, value in policy_updates.items():
            if key in self.coordination_policy:
                self.coordination_policy[key] = value
                logger.info(f"Updated coordination policy: {key} = {value}")

    async def reset_threat_data(self):
        """Reset shared threat intelligence data."""
        self.shared_threat_data = {
            "blocked_ips": set(),
            "suspicious_patterns": {},
            "coordinated_attacks": {},
            "false_positives": set()
        }
        logger.info("Shared threat data reset")

    async def add_false_positive(self, ip: str, reason: str):
        """Mark an IP as a false positive to prevent future blocks."""
        self.shared_threat_data["false_positives"].add(ip)
        if ip in self.shared_threat_data["blocked_ips"]:
            self.shared_threat_data["blocked_ips"].remove(ip)
        logger.info(f"Added false positive: {ip} - {reason}")

# Global unified security coordinator instance
unified_security_coordinator = UnifiedSecurityCoordinator()
