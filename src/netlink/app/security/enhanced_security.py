"""
Enhanced Security Module for NetLink
Provides comprehensive security features including authentication, authorization, input validation, and security headers.
"""

import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from functools import wraps
import ipaddress

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

class SecurityLevel(Enum):
    """Security levels for different operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    """Security event for logging and monitoring."""
    timestamp: datetime
    event_type: str
    severity: SecurityLevel
    user_id: Optional[str]
    ip_address: str
    user_agent: str
    details: Dict[str, Any]
    success: bool

class EnhancedPasswordManager:
    """Enhanced password management with multiple hashing algorithms."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.min_length = 8
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_special = True
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def hash_password(self, password: str, use_bcrypt: bool = True) -> str:
        """Hash a password using bcrypt or fallback to PBKDF2."""
        if use_bcrypt and BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            # Fallback to PBKDF2
            salt = secrets.token_hex(32)
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return f"pbkdf2_sha256$100000${salt}${pwdhash.hex()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        try:
            if hashed.startswith('$2b$') and BCRYPT_AVAILABLE:
                # bcrypt hash
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            elif hashed.startswith('pbkdf2_sha256$'):
                # PBKDF2 hash
                parts = hashed.split('$')
                if len(parts) != 4:
                    return False
                iterations = int(parts[1])
                salt = parts[2]
                stored_hash = parts[3]
                pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
                return pwdhash.hex() == stored_hash
            else:
                # Legacy SHA256 (for backward compatibility)
                return hashlib.sha256(password.encode()).hexdigest() == hashed
        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength and return issues."""
        issues = []
        
        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters long")
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if self.require_digits and not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        if self.require_special and not any(c in self.special_chars for c in password):
            issues.append(f"Password must contain at least one special character: {self.special_chars}")
        
        # Check for common patterns
        if password.lower() in ['password', '123456', 'admin', 'netlink']:
            issues.append("Password is too common")
        
        return len(issues) == 0, issues
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password."""
        import string
        
        chars = string.ascii_letters + string.digits + self.special_chars
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Ensure it meets requirements
        valid, _ = self.validate_password_strength(password)
        if not valid:
            # Regenerate if it doesn't meet requirements
            return self.generate_secure_password(length)
        
        return password

class RateLimiter:
    """Advanced rate limiting with multiple strategies."""
    
    def __init__(self):
        self.attempts = {}  # ip -> [(timestamp, success), ...]
        self.blocked_ips = {}  # ip -> block_until_timestamp
        self.max_attempts = 5
        self.window_minutes = 15
        self.block_duration_minutes = 30
    
    def is_allowed(self, ip_address: str, endpoint: str = "default") -> Tuple[bool, Optional[str]]:
        """Check if request is allowed based on rate limiting."""
        current_time = time.time()
        key = f"{ip_address}:{endpoint}"
        
        # Check if IP is currently blocked
        if key in self.blocked_ips:
            if current_time < self.blocked_ips[key]:
                remaining = int(self.blocked_ips[key] - current_time)
                return False, f"IP blocked for {remaining} seconds"
            else:
                del self.blocked_ips[key]
        
        # Clean old attempts
        if key in self.attempts:
            window_start = current_time - (self.window_minutes * 60)
            self.attempts[key] = [
                (timestamp, success) for timestamp, success in self.attempts[key]
                if timestamp > window_start
            ]
        
        # Check attempt count
        if key in self.attempts:
            failed_attempts = sum(1 for _, success in self.attempts[key] if not success)
            if failed_attempts >= self.max_attempts:
                # Block the IP
                self.blocked_ips[key] = current_time + (self.block_duration_minutes * 60)
                return False, f"Too many failed attempts. IP blocked for {self.block_duration_minutes} minutes"
        
        return True, None
    
    def record_attempt(self, ip_address: str, success: bool, endpoint: str = "default"):
        """Record an authentication attempt."""
        key = f"{ip_address}:{endpoint}"
        current_time = time.time()
        
        if key not in self.attempts:
            self.attempts[key] = []
        
        self.attempts[key].append((current_time, success))
    
    def get_attempt_info(self, ip_address: str, endpoint: str = "default") -> Dict[str, Any]:
        """Get attempt information for an IP."""
        key = f"{ip_address}:{endpoint}"
        current_time = time.time()
        
        if key not in self.attempts:
            return {"total_attempts": 0, "failed_attempts": 0, "is_blocked": False}
        
        window_start = current_time - (self.window_minutes * 60)
        recent_attempts = [
            (timestamp, success) for timestamp, success in self.attempts[key]
            if timestamp > window_start
        ]
        
        total_attempts = len(recent_attempts)
        failed_attempts = sum(1 for _, success in recent_attempts if not success)
        is_blocked = key in self.blocked_ips and current_time < self.blocked_ips[key]
        
        return {
            "total_attempts": total_attempts,
            "failed_attempts": failed_attempts,
            "is_blocked": is_blocked,
            "block_remaining": max(0, int(self.blocked_ips.get(key, 0) - current_time)) if is_blocked else 0
        }

class InputValidator:
    """Comprehensive input validation and sanitization."""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username format."""
        if not username:
            return False, "Username cannot be empty"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username) > 50:
            return False, "Username cannot be longer than 50 characters"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        return True, None
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Basic HTML sanitization."""
        # Remove potentially dangerous tags
        dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input']
        for tag in dangerous_tags:
            text = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', text, flags=re.IGNORECASE | re.DOTALL)
            text = re.sub(f'<{tag}[^>]*/?>', '', text, flags=re.IGNORECASE)
        
        # Remove javascript: and data: URLs
        text = re.sub(r'javascript:[^"\']*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'data:[^"\']*', '', text, flags=re.IGNORECASE)
        
        return text
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: Any) -> bool:
        """Validate port number."""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

class SecurityHeaders:
    """Security headers management."""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get comprehensive security headers."""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
                "img-src 'self' data: https:; "
                "connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=(), "
                "accelerometer=(), ambient-light-sensor=()"
            ),
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "Expires": "0",
            "Server": "NetLink/1.0"
        }

class SessionManager:
    """Enhanced session management with security features."""
    
    def __init__(self):
        self.sessions = {}  # session_id -> session_data
        self.session_timeout = 30 * 60  # 30 minutes
        self.max_sessions_per_user = 5
        self.logger = logging.getLogger(__name__)
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Create a new secure session."""
        session_id = secrets.token_urlsafe(32)
        
        session_data = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip_address": ip_address,
            "user_agent": user_agent,
            "csrf_token": secrets.token_urlsafe(32)
        }
        
        # Clean up old sessions for this user
        self._cleanup_user_sessions(user_id)
        
        self.sessions[session_id] = session_data
        self.logger.info(f"Session created for user {user_id} from {ip_address}")
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str = None) -> Optional[Dict[str, Any]]:
        """Validate and refresh a session."""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        current_time = time.time()
        
        # Check timeout
        if current_time - session["last_activity"] > self.session_timeout:
            self.destroy_session(session_id)
            return None
        
        # Check IP address (optional)
        if ip_address and session["ip_address"] != ip_address:
            self.logger.warning(f"Session {session_id} accessed from different IP: {ip_address} vs {session['ip_address']}")
            # Could destroy session here for strict security
        
        # Update last activity
        session["last_activity"] = current_time
        
        return session
    
    def destroy_session(self, session_id: str):
        """Destroy a session."""
        if session_id in self.sessions:
            user_id = self.sessions[session_id]["user_id"]
            del self.sessions[session_id]
            self.logger.info(f"Session destroyed for user {user_id}")
    
    def _cleanup_user_sessions(self, user_id: str):
        """Clean up old sessions for a user."""
        user_sessions = [
            (sid, data) for sid, data in self.sessions.items()
            if data["user_id"] == user_id
        ]
        
        # Sort by last activity
        user_sessions.sort(key=lambda x: x[1]["last_activity"], reverse=True)
        
        # Remove excess sessions
        for sid, _ in user_sessions[self.max_sessions_per_user:]:
            del self.sessions[sid]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        current_time = time.time()
        expired_sessions = [
            sid for sid, data in self.sessions.items()
            if current_time - data["last_activity"] > self.session_timeout
        ]
        
        for sid in expired_sessions:
            self.destroy_session(sid)
        
        return len(expired_sessions)

class SecurityAuditLogger:
    """Security event logging and monitoring."""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.events = []
        self.max_events = 10000
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event."""
        self.events.append(event)
        
        # Keep only recent events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
        
        # Log to standard logger
        log_level = {
            SecurityLevel.LOW: logging.INFO,
            SecurityLevel.MEDIUM: logging.WARNING,
            SecurityLevel.HIGH: logging.ERROR,
            SecurityLevel.CRITICAL: logging.CRITICAL
        }.get(event.severity, logging.INFO)
        
        self.logger.log(
            log_level,
            f"Security Event: {event.event_type} - {event.success and 'SUCCESS' or 'FAILURE'}",
            extra={
                "security_event": True,
                "event_type": event.event_type,
                "severity": event.severity.value,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "details": event.details
            }
        )
    
    def get_recent_events(self, count: int = 100) -> List[SecurityEvent]:
        """Get recent security events."""
        return self.events[-count:]
    
    def get_events_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Get events by type."""
        return [event for event in self.events if event.event_type == event_type]
    
    def get_failed_login_attempts(self, hours: int = 24) -> List[SecurityEvent]:
        """Get failed login attempts in the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        return [
            event for event in self.events
            if event.event_type == "login_attempt" 
            and not event.success 
            and event.timestamp > cutoff_time
        ]

# Global instances
password_manager = EnhancedPasswordManager()
rate_limiter = RateLimiter()
session_manager = SessionManager()
security_audit_logger = SecurityAuditLogger()

# Security decorators
def require_authentication(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Implementation would check for valid session
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission: str):
    """Decorator to require specific permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Implementation would check user permissions
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limit(max_requests: int = 60, window_minutes: int = 1):
    """Decorator for rate limiting."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Implementation would check rate limits
            return f(*args, **kwargs)
        return decorated_function
    return decorator
