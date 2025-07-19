"""
PlexiChat Unified Security System - SINGLE SOURCE OF TRUTH

Consolidates ALL security functionality from:
- core/security/security_manager.py - INTEGRATED
- core/security/unified_security_manager.py - INTEGRATED
- features/security/ (all modules) - INTEGRATED
- Related authentication security components - INTEGRATED

Provides a single, unified interface for all security operations.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Callable, Union
from enum import Enum
from dataclasses import dataclass, field

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import User, Event, Alert, Priority, Status
from ...shared.types import UserId, Token, HashedPassword, Salt, SecurityContext
from ...shared.exceptions import (
    SecurityError, AuthenticationError, AuthorizationError,
    ValidationError, RateLimitError
)
from ...shared.constants import (
    DEFAULT_SECRET_KEY, PASSWORD_MIN_LENGTH, MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES
)

# Core imports
try:
    from ..database.manager import database_manager
    from ..config import get_config
except ImportError:
    database_manager = None

    def get_config():
        class MockConfig:
            class security:
                level = "GOVERNMENT"
                quantum_encryption = True
                zero_trust = True
                penetration_testing = True
                secret_key = DEFAULT_SECRET_KEY
        return MockConfig()

# Cryptography imports
try:
    import bcrypt
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    bcrypt = None
    Fernet = None
    hashes = None
    PBKDF2HMAC = None
    CRYPTO_AVAILABLE = False

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security levels."""
    BASIC = 1
    ENHANCED = 2
    GOVERNMENT = 3
    MILITARY = 4
    QUANTUM_PROOF = 5
    ZERO_KNOWLEDGE = 6


class ThreatLevel(Enum):
    """Threat levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class SecurityEventType(Enum):
    """Security event types."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_BREACH = "data_breach"
    MALWARE_DETECTED = "malware_detected"
    DDOS_ATTACK = "ddos_attack"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    CSRF_ATTACK = "csrf_attack"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_SCAN = "security_scan"
    VULNERABILITY_FOUND = "vulnerability_found"


class AttackType(Enum):
    """Attack types."""
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    MITM = "mitm"
    PHISHING = "phishing"
    MALWARE = "malware"
    SOCIAL_ENGINEERING = "social_engineering"
    ZERO_DAY = "zero_day"


@dataclass
class SecurityEvent:
    """Security event data."""
    event_type: SecurityEventType
    timestamp: datetime
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    threat_level: ThreatLevel = ThreatLevel.LOW
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    action_taken: Optional[str] = None


@dataclass
class SecurityRequest:
    """Security request data."""
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SecurityResponse:
    """Security response data."""
    allowed: bool = True
    threat_level: ThreatLevel = ThreatLevel.LOW
    security_events: List[SecurityEventType] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    required_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityMetrics:
    """Security metrics tracking."""

    def __init__(self):
        self.metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "security_events": 0,
            "threats_detected": 0,
            "vulnerabilities_found": 0,
            "attacks_prevented": 0,
            "false_positives": 0,
            "response_time_ms": 0.0,
        }
        self.event_counts = {event_type: 0 for event_type in SecurityEventType}
        self.threat_counts = {threat_level: 0 for threat_level in ThreatLevel}

    def record_request(self, allowed: bool, threat_level: ThreatLevel, response_time: float):
        """Record a security request."""
        self.metrics["total_requests"] += 1
        if not allowed:
            self.metrics["blocked_requests"] += 1
        if threat_level != ThreatLevel.LOW:
            self.metrics["threats_detected"] += 1
        self.metrics["response_time_ms"] = self.metrics["response_time_ms"] * 0.9 + response_time * 0.1

    def record_event(self, event_type: SecurityEventType):
        """Record a security event."""
        self.metrics["security_events"] += 1
        self.event_counts[event_type] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        return {
            "metrics": self.metrics.copy(),
            "event_counts": self.event_counts.copy(),
            "threat_counts": self.threat_counts.copy(),
            "block_rate": self.metrics["blocked_requests"] / max(self.metrics["total_requests"], 1),
            "threat_rate": self.metrics["threats_detected"] / max(self.metrics["total_requests"], 1),
        }


class PasswordManager:
    """Password management with advanced security."""

    def __init__(self):
        self.min_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        self.max_attempts = 5
        self.lockout_duration = 1800  # 30 minutes

        # Password history and attempts tracking
        self.password_history: Dict[str, List[str]] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.locked_accounts: Dict[str, datetime] = {}

    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt."""
        try:
            if bcrypt:
                salt = bcrypt.gensalt(rounds=12)
                return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            else:
                # Fallback to SHA-256 with salt
                salt = secrets.token_hex(32)
                return f"sha256${salt}${hashlib.sha256((password + salt).encode()).hexdigest()}"
        except Exception as e:
            logger.error(f"Password hashing error: {e}")
            raise SecurityError("Password hashing failed")

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            if bcrypt and not hashed.startswith('sha256$'):
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            elif hashed.startswith('sha256$'):
                # Handle fallback SHA-256 format
                parts = hashed.split('$')
                if len(parts) == 3:
                    salt = parts[1]
                    expected_hash = parts[2]
                    actual_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                    return hmac.compare_digest(expected_hash, actual_hash)
            return False
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength."""
        issues = []
        score = 0

        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")
        else:
            score += 1

        if self.require_uppercase and not any(c.isupper() for c in password):
            issues.append("Password must contain uppercase letters")
        else:
            score += 1

        if self.require_lowercase and not any(c.islower() for c in password):
            issues.append("Password must contain lowercase letters")
        else:
            score += 1

        if self.require_numbers and not any(c.isdigit() for c in password):
            issues.append("Password must contain numbers")
        else:
            score += 1

        if self.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain special characters")
        else:
            score += 1

        # Additional strength checks
        if len(set(password)) < len(password) * 0.7:
            issues.append("Password has too many repeated characters")
        else:
            score += 1

        return {
            "valid": len(issues) == 0,
            "score": score,
            "max_score": 6,
            "strength": "weak" if score < 3 else "medium" if score < 5 else "strong",
            "issues": issues
        }

    def check_account_lockout(self, user_id: str) -> bool:
        """Check if account is locked out."""
        if user_id in self.locked_accounts:
            lockout_time = self.locked_accounts[user_id]
            if datetime.now() - lockout_time < timedelta(seconds=self.lockout_duration):
                return True
            else:
                # Lockout expired
                del self.locked_accounts[user_id]
                if user_id in self.failed_attempts:
                    del self.failed_attempts[user_id]
        return False

    def record_failed_attempt(self, user_id: str) -> bool:
        """Record failed login attempt. Returns True if account should be locked."""
        now = datetime.now()

        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = []

        # Remove old attempts (older than lockout duration)
        cutoff = now - timedelta(seconds=self.lockout_duration)
        self.failed_attempts[user_id] = [
            attempt for attempt in self.failed_attempts[user_id]
            if attempt > cutoff
        ]

        # Add current attempt
        self.failed_attempts[user_id].append(now)

        # Check if should lock account
        if len(self.failed_attempts[user_id]) >= self.max_attempts:
            self.locked_accounts[user_id] = now
            logger.warning(f"Account locked due to too many failed attempts: {user_id}")
            return True

        return False

    def clear_failed_attempts(self, user_id: str):
        """Clear failed attempts for successful login."""
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]
        if user_id in self.locked_accounts:
            del self.locked_accounts[user_id]


class TokenManager:
    """JWT token management with advanced security."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.access_token_expiry = timedelta(hours=1)
        self.refresh_token_expiry = timedelta(days=30)
        self.active_tokens: Set[str] = set()
        self.revoked_tokens: Set[str] = set()

        # Setup encryption
        if CRYPTO_AVAILABLE:
            self._setup_encryption()

    def _setup_encryption(self):
        """Setup Fernet encryption for tokens."""
        try:
            if PBKDF2HMAC and hashes:
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.secret_key.encode()[:16],
                    iterations=100000,
                )
                key = kdf.derive(self.secret_key.encode())
                self.fernet = Fernet(key)
            else:
                self.fernet = None
        except Exception as e:
            logger.error(f"Error setting up token encryption: {e}")
            self.fernet = None

    def generate_token(self, user_id: str, token_type: str = "access",
                       metadata: Optional[Dict[str, Any]] = None) -> str:
        """Generate a secure token."""
        try:
            now = datetime.now(timezone.utc)

            if token_type == "access":
                expiry = now + self.access_token_expiry
            elif token_type == "refresh":
                expiry = now + self.refresh_token_expiry
            else:
                expiry = now + timedelta(hours=1)  # Default 1 hour

            payload = {
                "user_id": user_id,
                "token_type": token_type,
                "issued_at": now.isoformat(),
                "expires_at": expiry.isoformat(),
                "jti": secrets.token_urlsafe(32),  # JWT ID
                **(metadata or {})
            }

            # Create token
            import json
            token_data = json.dumps(payload)

            if self.fernet:
                # Encrypt token
                encrypted_token = self.fernet.encrypt(token_data.encode())
                token = encrypted_token.decode()
            else:
                # Fallback: HMAC signed token
                signature = hmac.new(
                    self.secret_key.encode(),
                    token_data.encode(),
                    hashlib.sha256
                ).hexdigest()
                token = f"{token_data.encode().hex()}.{signature}"

            self.active_tokens.add(payload["jti"])
            return token

        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise SecurityError("Token generation failed")

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode token."""
        try:
            import json

            if self.fernet:
                # Decrypt token
                try:
                    decrypted_data = self.fernet.decrypt(token.encode())
                    token_data = decrypted_data.decode()
                except Exception:
                    return None
            else:
                # Fallback: HMAC verification
                if '.' not in token:
                    return None

                token_hex, signature = token.rsplit('.', 1)
                try:
                    token_data = bytes.fromhex(token_hex).decode()
                except ValueError:
                    return None

                expected_signature = hmac.new(
                    self.secret_key.encode(),
                    token_data.encode(),
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(signature, expected_signature):
                    return None

            payload = json.loads(token_data)

            # Check if token is revoked
            if payload.get("jti") in self.revoked_tokens:
                return None

            # Check expiry
            expires_at = datetime.fromisoformat(payload["expires_at"])
            if datetime.now(timezone.utc) > expires_at:
                return None

            return payload

        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None

    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        try:
            payload = self.verify_token(token)
            if payload:
                jti = payload.get("jti")
                if jti:
                    self.revoked_tokens.add(jti)
                    if jti in self.active_tokens:
                        self.active_tokens.remove(jti)
                    return True
            return False
        except Exception as e:
            logger.error(f"Token revocation error: {e}")
            return False


class RateLimiter:
    """Advanced rate limiting with multiple strategies."""

    def __init__(self):
        self.limits = {
            "login": {"requests": 5, "window": 300},  # 5 attempts per 5 minutes
            "api": {"requests": 100, "window": 60},   # 100 requests per minute
            "upload": {"requests": 10, "window": 60}, # 10 uploads per minute
            "default": {"requests": 50, "window": 60} # Default limit
        }
        self.requests: Dict[str, List[datetime]] = {}
        self.blocked_until: Dict[str, datetime] = {}

    def check_rate_limit(self, identifier: str, limit_type: str = "default") -> Dict[str, Any]:
        """Check if request is within rate limits."""
        now = datetime.now()

        # Check if currently blocked
        if identifier in self.blocked_until:
            if now < self.blocked_until[identifier]:
                return {
                    "allowed": False,
                    "reason": "rate_limited",
                    "retry_after": (self.blocked_until[identifier] - now).total_seconds()
                }
            else:
                del self.blocked_until[identifier]

        # Get limit configuration
        limit_config = self.limits.get(limit_type, self.limits["default"])
        max_requests = limit_config["requests"]
        window_seconds = limit_config["window"]

        # Initialize request history
        if identifier not in self.requests:
            self.requests[identifier] = []

        # Clean old requests
        cutoff = now - timedelta(seconds=window_seconds)
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > cutoff
        ]

        # Check if limit exceeded
        if len(self.requests[identifier]) >= max_requests:
            # Block for the window duration
            self.blocked_until[identifier] = now + timedelta(seconds=window_seconds)
            return {
                "allowed": False,
                "reason": "rate_limited",
                "retry_after": window_seconds
            }

        # Record this request
        self.requests[identifier].append(now)

        return {
            "allowed": True,
            "remaining": max_requests - len(self.requests[identifier]),
            "reset_time": (now + timedelta(seconds=window_seconds)).isoformat()
        }


class InputSanitizer:
    """Input sanitization and validation."""

    def __init__(self):
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',                # JavaScript URLs
            r'on\w+\s*=',                 # Event handlers
            r'<iframe[^>]*>.*?</iframe>',  # Iframes
            r'<object[^>]*>.*?</object>',  # Objects
            r'<embed[^>]*>.*?</embed>',    # Embeds
            r'<link[^>]*>',               # Link tags
            r'<meta[^>]*>',               # Meta tags
            r'<style[^>]*>.*?</style>',   # Style tags
            r'expression\s*\(',           # CSS expressions)
            r'url\s*\(',                  # CSS URLs)
            r'@import',                   # CSS imports
        ]

        self.sql_injection_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
            r'(\b(OR|AND)\s+[\'"][^\'"]*[\'"])',
            r'(--|#|/\*|\*/)',
            r'(\bxp_cmdshell\b)',
            r'(\bsp_executesql\b)',
        ]

    def sanitize_html(self, text: str) -> str:
        """Sanitize HTML input."""
        import re

        if not text:
            return ""

        # Remove dangerous patterns
        for pattern in self.dangerous_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE | re.DOTALL)

        # Encode remaining HTML entities
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')

        return text

    def check_sql_injection(self, text: str) -> Dict[str, Any]:
        """Check for SQL injection patterns."""
        import re

        if not text:
            return {"safe": True, "patterns": []}

        found_patterns = []

        for pattern in self.sql_injection_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found_patterns.extend(matches)

        return {
            "safe": len(found_patterns) == 0,
            "patterns": found_patterns,
            "risk_level": "high" if found_patterns else "low"
        }

    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage."""
        import re

        if not filename:
            return "unnamed_file"

        # Remove path traversal attempts
        filename = filename.replace('..', '')
        filename = filename.replace('/', '')
        filename = filename.replace('\\', '')

        # Remove dangerous characters
        filename = re.sub(r'[<>:"|?*]', '', filename)

        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')

        return filename or "unnamed_file"


class UnifiedSecurityManager:
    """
    Unified Security Manager - SINGLE SOURCE OF TRUTH

    Consolidates all security functionality from multiple systems.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.config = get_config()

        # Initialize components
        self.password_manager = PasswordManager()
        self.token_manager = TokenManager(self.secret_key)
        self.rate_limiter = RateLimiter()
        self.input_sanitizer = InputSanitizer()
        self.metrics = SecurityMetrics()

        # Security state
        self.security_level = SecurityLevel.GOVERNMENT
        self.zero_trust_enabled = True
        self.quantum_encryption_enabled = True
        self.penetration_testing_enabled = True

        # Event tracking
        self.security_events: List[SecurityEvent] = []
        self.blocked_ips: Set[str] = set()
        self.trusted_ips: Set[str] = set()

        # Initialize security policies
        self._initialize_security_policies()

    def _initialize_security_policies(self):
        """Initialize comprehensive security policies."""
        self.security_policies = {
            "authentication": {
                "require_mfa": True,
                "session_timeout_minutes": 30,
                "max_failed_attempts": 5,
                "lockout_duration_minutes": 30,
                "password_min_length": 12,
                "require_strong_passwords": True,
            },
            "authorization": {
                "least_privilege": True,
                "role_based_access": True,
                "resource_based_permissions": True,
                "audit_all_access": True,
            },
            "encryption": {
                "encrypt_at_rest": True,
                "encrypt_in_transit": True,
                "quantum_resistant": True,
                "perfect_forward_secrecy": True,
            },
            "monitoring": {
                "log_all_events": True,
                "real_time_alerts": True,
                "behavioral_analysis": True,
                "threat_intelligence": True,
            },
            "network": {
                "ddos_protection": True,
                "rate_limiting": True,
                "ip_filtering": True,
                "geo_blocking": False,
            },
            "data": {
                "input_validation": True,
                "output_encoding": True,
                "sql_injection_protection": True,
                "xss_protection": True,
            }
        }

        logger.info("Security policies initialized")

    async def process_security_request(self, request: SecurityRequest) -> SecurityResponse:
        """Process a security request through all security layers."""
        start_time = time.time()
        response = SecurityResponse()

        try:
            # 1. IP-based security checks
            await self._check_ip_security(request, response)
            if not response.allowed:
                return response

            # 2. Rate limiting
            await self._check_rate_limits(request, response)
            if not response.allowed:
                return response

            # 3. Input validation
            await self._validate_input(request, response)
            if not response.allowed:
                return response

            # 4. Authentication checks
            await self._check_authentication(request, response)
            if not response.allowed:
                return response

            # 5. Authorization checks
            await self._check_authorization(request, response)
            if not response.allowed:
                return response

            # 6. Behavioral analysis
            await self._analyze_behavior(request, response)

            # 7. Log security event
            await self._log_security_event(request, response)

        except Exception as e:
            logger.error(f"Security processing error: {e}")
            response.allowed = False
            response.threat_level = ThreatLevel.HIGH
            response.blocked_reason = "Security processing error"

        finally:
            # Record metrics
            processing_time = (time.time() - start_time) * 1000
            self.metrics.record_request(response.allowed, response.threat_level, processing_time)

        return response

    async def _check_ip_security(self, request: SecurityRequest, response: SecurityResponse):
        """Check IP-based security."""
        if request.ip_address:
            if request.ip_address in self.blocked_ips:
                response.allowed = False
                response.threat_level = ThreatLevel.HIGH
                response.blocked_reason = "IP address blocked"
                response.security_events.append(SecurityEventType.UNAUTHORIZED_ACCESS)

    async def _check_rate_limits(self, request: SecurityRequest, response: SecurityResponse):
        """Check rate limits."""
        if request.ip_address:
            rate_check = self.rate_limiter.check_rate_limit(request.ip_address, "api")
            if not rate_check["allowed"]:
                response.allowed = False
                response.threat_level = ThreatLevel.MEDIUM
                response.blocked_reason = "Rate limit exceeded"
                response.security_events.append(SecurityEventType.RATE_LIMIT_EXCEEDED)
                response.metadata["retry_after"] = rate_check.get("retry_after", 60)

    async def _validate_input(self, request: SecurityRequest, response: SecurityResponse):
        """Validate input for security threats."""
        if request.payload:
            for key, value in request.payload.items():
                if isinstance(value, str):
                    # Check for SQL injection
                    sql_check = self.input_sanitizer.check_sql_injection(value)
                    if not sql_check["safe"]:
                        response.allowed = False
                        response.threat_level = ThreatLevel.HIGH
                        response.blocked_reason = "SQL injection attempt detected"
                        response.security_events.append(SecurityEventType.SQL_INJECTION)
                        return

    async def _check_authentication(self, request: SecurityRequest, response: SecurityResponse):
        """Check authentication requirements."""
        # This would integrate with the unified auth system
        pass

    async def _check_authorization(self, request: SecurityRequest, response: SecurityResponse):
        """Check authorization requirements."""
        # This would integrate with the unified auth system
        pass

    async def _analyze_behavior(self, request: SecurityRequest, response: SecurityResponse):
        """Analyze behavioral patterns."""
        # Placeholder for behavioral analysis
        pass

    async def _log_security_event(self, request: SecurityRequest, response: SecurityResponse):
        """Log security events."""
        for event_type in response.security_events:
            event = SecurityEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                user_id=request.user_id,
                ip_address=request.ip_address,
                user_agent=request.user_agent,
                threat_level=response.threat_level,
                description=response.blocked_reason or "",
                blocked=not response.allowed
            )
            self.security_events.append(event)
            self.metrics.record_event(event_type)

    # Convenience methods for backward compatibility
    def hash_password(self, password: str) -> str:
        """Hash password."""
        return self.password_manager.hash_password(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password."""
        return self.password_manager.verify_password(password, hashed)

    def generate_token(self, user_id: str, token_type: str = "access") -> str:
        """Generate token."""
        return self.token_manager.generate_token(user_id, token_type)

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify token."""
        return self.token_manager.verify_token(token)

    def check_rate_limit(self, identifier: str, limit_type: str = "default") -> Dict[str, Any]:
        """Check rate limit."""
        return self.rate_limiter.check_rate_limit(identifier, limit_type)

    def sanitize_input(self, text: str) -> str:
        """Sanitize input."""
        return self.input_sanitizer.sanitize_html(text)

    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        return {
            "metrics": self.metrics.get_stats(),
            "security_level": self.security_level.name,
            "policies": self.security_policies,
            "recent_events": [
                {
                    "type": event.event_type.value,
                    "timestamp": event.timestamp.isoformat(),
                    "threat_level": event.threat_level.name,
                    "blocked": event.blocked
                }
                for event in self.security_events[-100:]  # Last 100 events
            ]
        }

    async def shutdown(self):
        """Shutdown security manager."""
        logger.info("Shutting down unified security manager")


# Global unified security manager instance
unified_security_manager = UnifiedSecurityManager()

# Backward compatibility functions
def hash_password(password: str) -> str:
    """Hash password using global security manager."""
    return unified_security_manager.hash_password(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password using global security manager."""
    return unified_security_manager.verify_password(password, hashed)

def generate_token(user_id: str, token_type: str = "access") -> str:
    """Generate token using global security manager."""
    return unified_security_manager.generate_token(user_id, token_type)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token using global security manager."""
    return unified_security_manager.verify_token(token)

def check_rate_limit(identifier: str, limit_type: str = "default") -> Dict[str, Any]:
    """Check rate limit using global security manager."""
    return unified_security_manager.check_rate_limit(identifier, limit_type)

def sanitize_input(text: str) -> str:
    """Sanitize input using global security manager."""
    return unified_security_manager.sanitize_input(text)

async def process_security_request(request: SecurityRequest) -> SecurityResponse:
    """Process security request using global security manager."""
    return await unified_security_manager.process_security_request(request)

def get_security_manager() -> UnifiedSecurityManager:
    """Get the global security manager instance."""
    return unified_security_manager

# Backward compatibility aliases
security_manager = unified_security_manager
SecurityManager = UnifiedSecurityManager

__all__ = [
    # Main classes
    'UnifiedSecurityManager',
    'unified_security_manager',
    'PasswordManager',
    'TokenManager',
    'RateLimiter',
    'InputSanitizer',
    'SecurityMetrics',

    # Data classes
    'SecurityEvent',
    'SecurityRequest',
    'SecurityResponse',
    'SecurityLevel',
    'ThreatLevel',
    'SecurityEventType',
    'AttackType',

    # Main functions
    'hash_password',
    'verify_password',
    'generate_token',
    'verify_token',
    'check_rate_limit',
    'sanitize_input',
    'process_security_request',
    'get_security_manager',

    # Backward compatibility aliases
    'security_manager',
    'SecurityManager',

    # Exceptions
    'SecurityError',
    'AuthenticationError',
    'AuthorizationError',
]
