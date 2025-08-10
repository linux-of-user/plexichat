"""
Unified Security System for PlexiChat
Comprehensive security framework providing watertight protection like a deep-sea submarine.
Integrates all security components into a unified, cohesive system.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import jwt
import re
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Union, Tuple
from pathlib import Path
import ipaddress

# Core security imports
SECURITY_MANAGER_AVAILABLE = False
try:
    from . import comprehensive_security_manager
    SECURITY_MANAGER_AVAILABLE = True
except ImportError:
    pass

# Define our own security enums and classes
class SecurityLevel(Enum):
    """Security access levels for endpoints."""
    PUBLIC = 0
    BASIC = 1
    AUTHENTICATED = 2
    ELEVATED = 3
    ADMIN = 4
    SYSTEM = 5


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class SecurityEventType(Enum):
    """Types of security events."""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ACCESS_DENIED = "access_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


@dataclass
class SecurityContext:
    """Security context for requests."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    authenticated: bool = False
    permissions: Set[str] = field(default_factory=set)
    security_level: SecurityLevel = SecurityLevel.PUBLIC

# Logging setup
logger = logging.getLogger(__name__)


class AuthenticationMethod(Enum):
    """Authentication methods supported."""
    PASSWORD = "password"
    TOKEN = "token"
    API_KEY = "api_key"
    TWO_FACTOR = "two_factor"
    CERTIFICATE = "certificate"


class EncryptionAlgorithm(Enum):
    """Encryption algorithms supported."""
    AES_256_GCM = "aes_256_gcm"
    CHACHA20_POLY1305 = "chacha20_poly1305"
    RSA_4096 = "rsa_4096"


@dataclass
class SecurityPolicy:
    """Security policy configuration."""
    name: str
    description: str
    min_security_level: SecurityLevel = SecurityLevel.PUBLIC
    required_auth_methods: List[AuthenticationMethod] = field(default_factory=list)
    max_session_duration_minutes: int = 60
    require_encryption: bool = True
    encryption_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
    rate_limit_requests_per_minute: int = 60
    enable_audit_logging: bool = True
    auto_lockout_enabled: bool = True
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30


@dataclass
class UserCredentials:
    """User credentials for authentication."""
    username: str
    password_hash: str
    salt: str
    two_factor_secret: Optional[str] = None
    api_keys: List[str] = field(default_factory=list)
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    permissions: Set[str] = field(default_factory=set)


@dataclass
class SecurityToken:
    """Security token for authentication."""
    token_id: str
    user_id: str
    token_type: str
    expires_at: datetime
    permissions: Set[str] = field(default_factory=set)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: Optional[datetime] = None


class PasswordManager:
    """Secure password management with advanced hashing."""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.min_password_length = 8
        self.require_special_chars = True
        self.require_numbers = True
        self.require_uppercase = True
        
        # Password strength patterns
        self.strength_patterns = {
            'uppercase': re.compile(r'[A-Z]'),
            'lowercase': re.compile(r'[a-z]'),
            'numbers': re.compile(r'\d'),
            'special': re.compile(r'[!@#$%^&*(),.?":{}|<>]')
        }
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt using secure algorithm."""
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100,000 iterations
        )
        
        return password_hash.hex(), salt
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash."""
        try:
            computed_hash, _ = self.hash_password(password, salt)
            return hmac.compare_digest(computed_hash, password_hash)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength."""
        issues = []
        
        if len(password) < self.min_password_length:
            issues.append(f"Password must be at least {self.min_password_length} characters")
        
        if self.require_uppercase and not self.strength_patterns['uppercase'].search(password):
            issues.append("Password must contain uppercase letters")
        
        if not self.strength_patterns['lowercase'].search(password):
            issues.append("Password must contain lowercase letters")
        
        if self.require_numbers and not self.strength_patterns['numbers'].search(password):
            issues.append("Password must contain numbers")
        
        if self.require_special_chars and not self.strength_patterns['special'].search(password):
            issues.append("Password must contain special characters")
        
        return len(issues) == 0, issues


class TokenManager:
    """JWT token management with advanced security."""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.algorithm = 'HS256'
        self.access_token_expiry = timedelta(hours=1)
        self.refresh_token_expiry = timedelta(days=7)
        self.active_tokens: Set[str] = set()
        self.revoked_tokens: Set[str] = set()
    
    def create_access_token(self, user_id: str, permissions: Set[str]) -> str:
        """Create JWT access token."""
        now = datetime.now(timezone.utc)
        payload = {
            'user_id': user_id,
            'permissions': list(permissions),
            'token_type': 'access',
            'iat': now,
            'exp': now + self.access_token_expiry,
            'jti': secrets.token_hex(16)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        self.active_tokens.add(payload['jti'])
        return token
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create JWT refresh token."""
        now = datetime.now(timezone.utc)
        payload = {
            'user_id': user_id,
            'token_type': 'refresh',
            'iat': now,
            'exp': now + self.refresh_token_expiry,
            'jti': secrets.token_hex(16)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        self.active_tokens.add(payload['jti'])
        return token
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is revoked
            if payload.get('jti') in self.revoked_tokens:
                return False, None
            
            return True, payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return False, None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return False, None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            jti = payload.get('jti')
            if jti:
                self.revoked_tokens.add(jti)
                self.active_tokens.discard(jti)
                return True
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
        return False


class InputSanitizer:
    """Advanced input sanitization and validation."""
    
    def __init__(self):
        # Dangerous patterns for various attack types
        self.sql_injection_patterns = [
            re.compile(r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|--|;|\/\*|\*\/)", re.IGNORECASE),
            re.compile(r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", re.IGNORECASE),
            re.compile(r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
            re.compile(r"((\%27)|(\'))union", re.IGNORECASE)
        ]
        
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE)
        ]
        
        self.path_traversal_patterns = [
            re.compile(r"\.\.[\\/]"),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"%2e%2e%5c", re.IGNORECASE)
        ]
    
    def sanitize_input(self, input_data: str) -> str:
        """Sanitize input data."""
        if not isinstance(input_data, str):
            return str(input_data)
        
        # Remove null bytes
        sanitized = input_data.replace('\x00', '')
        
        # Escape HTML entities
        sanitized = sanitized.replace('&', '&amp;')
        sanitized = sanitized.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        
        return sanitized
    
    def detect_threats(self, input_data: str) -> List[str]:
        """Detect potential security threats in input."""
        threats = []
        
        # Check for SQL injection, but allow it if it's wrapped in [sql]...[/sql]
        sql_pattern = re.compile(r'\[sql\](.*?)\[/sql\]', re.DOTALL | re.IGNORECASE)
        clean_input = sql_pattern.sub('', input_data)

        for pattern in self.sql_injection_patterns:
            if pattern.search(clean_input):
                threats.append("SQL injection attempt detected")
                break
        
        # Check for XSS
        for pattern in self.xss_patterns:
            if pattern.search(input_data):
                threats.append("XSS attempt detected")
                break
        
        # Check for path traversal
        for pattern in self.path_traversal_patterns:
            if pattern.search(input_data):
                threats.append("Path traversal attempt detected")
                break
        
        return threats


class UnifiedSecuritySystem:
    """
    Unified Security System providing watertight protection like a deep-sea submarine.
    
    Integrates all security components:
    - Authentication and authorization
    - Password management
    - Token management
    - Input sanitization
    - Threat detection
    - Security policies
    - Audit logging
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        
        # Initialize security components
        self.password_manager = PasswordManager(self.secret_key)
        self.token_manager = TokenManager(self.secret_key)
        self.input_sanitizer = InputSanitizer()
        
        # Security policies
        self.security_policies: Dict[str, SecurityPolicy] = {}
        self.user_credentials: Dict[str, UserCredentials] = {}
        
        # Get comprehensive security manager if available
        if SECURITY_MANAGER_AVAILABLE:
            try:
                from .comprehensive_security_manager import get_security_manager
                self.security_manager = get_security_manager()
            except ImportError:
                self.security_manager = None
        else:
            self.security_manager = None
        
        # Security metrics
        self.metrics = {
            'authentication_attempts': 0,
            'successful_authentications': 0,
            'failed_authentications': 0,
            'threats_detected': 0,
            'tokens_issued': 0,
            'tokens_revoked': 0
        }
        
        # Initialize default security policies
        self._initialize_default_policies()
        
        logger.info("Unified Security System initialized with watertight protection")

    witty_responses = {
        "SQL injection attempt detected": "Nice try, but my database is locked down tighter than a submarine. Try a longer needle.",
        "XSS attempt detected": "My, my, what a creative script you have there. Unfortunately, this is not a playground.",
        "Path traversal attempt detected": "Lost, are we? Let me show you the way back to the main road.",
    }

    async def process_security_request(self, request_data: Any) -> Tuple[bool, Optional[str]]:
        """Process a security request and return a witty response if a threat is detected."""
        if isinstance(request_data, str):
            threats = self.input_sanitizer.detect_threats(request_data)
            if threats:
                threat = threats[0]
                self.metrics['threats_detected'] += 1
                return False, self.witty_responses.get(threat, "I've got a bad feeling about this.")
        return True, None
    
    def _initialize_default_policies(self) -> None:
        """Initialize default security policies."""
        self.security_policies['default'] = SecurityPolicy(
            name="Default Security Policy",
            description="Standard security policy for general endpoints",
            min_security_level=SecurityLevel.PUBLIC,
            required_auth_methods=[AuthenticationMethod.TOKEN],
            max_session_duration_minutes=60,
            require_encryption=True,
            rate_limit_requests_per_minute=60,
            enable_audit_logging=True
        )
        
        self.security_policies['admin'] = SecurityPolicy(
            name="Admin Security Policy",
            description="High-security policy for administrative endpoints",
            min_security_level=SecurityLevel.ADMIN,
            required_auth_methods=[AuthenticationMethod.TOKEN, AuthenticationMethod.TWO_FACTOR],
            max_session_duration_minutes=30,
            require_encryption=True,
            rate_limit_requests_per_minute=30,
            enable_audit_logging=True,
            max_failed_attempts=3,
            lockout_duration_minutes=60
        )
    
    async def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[SecurityContext]]:
        """Authenticate user with comprehensive security checks."""
        try:
            self.metrics['authentication_attempts'] += 1
            
            # Check if user exists
            if username not in self.user_credentials:
                self.metrics['failed_authentications'] += 1
                return False, None
            
            credentials = self.user_credentials[username]
            
            # Check if account is locked
            if credentials.locked_until and credentials.locked_until > datetime.now(timezone.utc):
                self.metrics['failed_authentications'] += 1
                return False, None
            
            # Verify password
            if not self.password_manager.verify_password(password, credentials.password_hash, credentials.salt):
                credentials.failed_attempts += 1
                
                # Lock account if too many failed attempts
                if credentials.failed_attempts >= 5:
                    credentials.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                
                self.metrics['failed_authentications'] += 1
                return False, None
            
            # Reset failed attempts on successful authentication
            credentials.failed_attempts = 0
            credentials.locked_until = None
            credentials.last_login = datetime.now(timezone.utc)
            
            # Create security context
            context = SecurityContext(
                user_id=username,
                authenticated=True
            )
            context.permissions = credentials.permissions
            
            self.metrics['successful_authentications'] += 1
            return True, context
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            self.metrics['failed_authentications'] += 1
            return False, None
    
    async def validate_request_security(self, request_data: Any, policy_name: str = 'default') -> Tuple[bool, List[str]]:
        """Validate request against security policies."""
        try:
            issues = []
            
            # Get security policy
            policy = self.security_policies.get(policy_name)
            if not policy:
                issues.append(f"Security policy '{policy_name}' not found")
                return False, issues
            
            # Sanitize and check input
            allowed, witty_response = await self.process_security_request(request_data)
            if not allowed:
                issues.append(witty_response)

            # Additional security validations would go here
            
            return len(issues) == 0, issues
            
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            return False, [f"Security validation failed: {str(e)}"]
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security system status."""
        return {
            'metrics': self.metrics.copy(),
            'active_tokens': len(self.token_manager.active_tokens),
            'revoked_tokens': len(self.token_manager.revoked_tokens),
            'registered_users': len(self.user_credentials),
            'security_policies': len(self.security_policies),
            'security_manager_available': SECURITY_MANAGER_AVAILABLE
        }
    
    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> Tuple[bool, str]:
        """Validate file upload against security policies."""
        # This is a placeholder. A real implementation would have more robust checks.
        if ".." in filename or "/" in filename or "\\" in filename:
            return False, "Invalid filename."

        if file_size > 100 * 1024 * 1024: # 100MB
            return False, "File is too large."

        return True, "File is valid."

    async def shutdown(self) -> None:
        """Shutdown the unified security system."""
        logger.info("Unified Security System shutting down")


# Global unified security system instance
_global_security_system: Optional[UnifiedSecuritySystem] = None


def get_unified_security_system() -> UnifiedSecuritySystem:
    """Get the global unified security system instance."""
    global _global_security_system
    if _global_security_system is None:
        _global_security_system = UnifiedSecuritySystem()
    return _global_security_system


async def initialize_unified_security_system(secret_key: Optional[str] = None) -> UnifiedSecuritySystem:
    """Initialize the global unified security system."""
    global _global_security_system
    _global_security_system = UnifiedSecuritySystem(secret_key)
    return _global_security_system


async def shutdown_unified_security_system() -> None:
    """Shutdown the global unified security system."""
    global _global_security_system
    if _global_security_system:
        await _global_security_system.shutdown()
        _global_security_system = None


__all__ = [
    "UnifiedSecuritySystem",
    "SecurityPolicy",
    "UserCredentials",
    "SecurityToken",
    "PasswordManager",
    "TokenManager",
    "InputSanitizer",
    "AuthenticationMethod",
    "EncryptionAlgorithm",
    "get_unified_security_system",
    "initialize_unified_security_system",
    "shutdown_unified_security_system"
]
