"""
PlexiChat Security Manager

Security management with threading and performance optimization.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    import jwt
except ImportError:
    jwt = None

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    Fernet = None
    hashes = None
    PBKDF2HMAC = None

try:
    from plexichat.core_system.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.cache_manager import cache_get, cache_set, cache_delete
except ImportError:
    cache_get = None
    cache_set = None
    cache_delete = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core_system.logging.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None

@dataclass
class SecurityEvent:
    """Security event data."""
    event_type: str
    user_id: Optional[int]
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Dict[str, Any]
    severity: str

class SecurityManager:
    """Security manager with threading support."""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        
        # Security settings
        self.password_min_length = 8
        self.password_max_attempts = 5
        self.token_expiry_hours = 24
        self.refresh_token_expiry_days = 30
        
        # Rate limiting
        self.login_attempts = {}
        self.rate_limits = {}
        
        # Encryption
        self.fernet = None
        if Fernet:
            self._setup_encryption()
    
    def _setup_encryption(self):
        """Setup encryption with Fernet."""
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
        except Exception as e:
            logger.error(f"Error setting up encryption: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt."""
        try:
            if bcrypt:
                salt = bcrypt.gensalt()
                hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
                return hashed.decode('utf-8')
            else:
                # Fallback to hashlib
                salt = secrets.token_hex(16)
                hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
                return f"{salt}:{hashed.hex()}"
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
            raise
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        try:
            if bcrypt and hashed.startswith('$2'):
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            else:
                # Fallback verification
                if ':' in hashed:
                    salt, hash_hex = hashed.split(':', 1)
                    expected_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
                    return hash_hex == expected_hash.hex()
                return False
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength."""
        errors = []
        
        if len(password) < self.password_min_length:
            errors.append(f"Password must be at least {self.password_min_length} characters")
        
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def generate_token(self, user_id: int, token_type: str = "access") -> str:
        """Generate JWT token."""
        try:
            if not jwt:
                raise ValueError("JWT library not available")
            
            now = datetime.utcnow()
            
            if token_type == "access":
                exp = now + timedelta(hours=self.token_expiry_hours)
            else:  # refresh
                exp = now + timedelta(days=self.refresh_token_expiry_days)
            
            payload = {
                "user_id": user_id,
                "token_type": token_type,
                "iat": now,
                "exp": exp,
                "jti": secrets.token_urlsafe(16)
            }
            
            token = jwt.encode(payload, self.secret_key, algorithm="HS256")
            
            # Cache token info
            if cache_set:
                cache_key = f"token_{payload['jti']}"
                cache_set(cache_key, {"user_id": user_id, "token_type": token_type}, ttl=int((exp - now).total_seconds()))
            
            return token
            
        except Exception as e:
            logger.error(f"Error generating token: {e}")
            raise
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token."""
        try:
            if not jwt:
                return None
            
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            
            # Check if token is blacklisted
            if cache_get:
                blacklist_key = f"blacklist_{payload.get('jti')}"
                if cache_get(blacklist_key):
                    return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            return None
    
    def blacklist_token(self, token: str) -> bool:
        """Blacklist token."""
        try:
            payload = self.verify_token(token)
            if not payload:
                return False
            
            if cache_set:
                blacklist_key = f"blacklist_{payload['jti']}"
                exp = payload.get('exp', 0)
                ttl = max(0, exp - int(time.time()))
                cache_set(blacklist_key, True, ttl=ttl)
            
            return True
            
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            return False
    
    def check_rate_limit(self, identifier: str, limit: int, window: int) -> bool:
        """Check rate limit for identifier."""
        try:
            now = time.time()
            window_start = now - window
            
            if identifier not in self.rate_limits:
                self.rate_limits[identifier] = []
            
            # Remove old entries
            self.rate_limits[identifier] = [
                timestamp for timestamp in self.rate_limits[identifier]
                if timestamp > window_start
            ]
            
            # Check limit
            if len(self.rate_limits[identifier]) >= limit:
                return False
            
            # Add current request
            self.rate_limits[identifier].append(now)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True  # Allow on error
    
    def check_login_attempts(self, identifier: str) -> bool:
        """Check login attempts for identifier."""
        now = time.time()
        
        if identifier not in self.login_attempts:
            self.login_attempts[identifier] = []
        
        # Remove old attempts (older than 1 hour)
        self.login_attempts[identifier] = [
            timestamp for timestamp in self.login_attempts[identifier]
            if timestamp > (now - 3600)
        ]
        
        return len(self.login_attempts[identifier]) < self.password_max_attempts
    
    def record_login_attempt(self, identifier: str, success: bool):
        """Record login attempt."""
        now = time.time()
        
        if not success:
            if identifier not in self.login_attempts:
                self.login_attempts[identifier] = []
            self.login_attempts[identifier].append(now)
        else:
            # Clear attempts on successful login
            if identifier in self.login_attempts:
                del self.login_attempts[identifier]
    
    def encrypt_data(self, data: str) -> Optional[str]:
        """Encrypt data."""
        try:
            if self.fernet:
                encrypted = self.fernet.encrypt(data.encode())
                return encrypted.decode()
            return None
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return None
    
    def decrypt_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt data."""
        try:
            if self.fernet:
                decrypted = self.fernet.decrypt(encrypted_data.encode())
                return decrypted.decode()
            return None
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return None
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate secure random token."""
        return secrets.token_urlsafe(length)
    
    def generate_api_key(self, user_id: int) -> str:
        """Generate API key for user."""
        timestamp = str(int(time.time()))
        data = f"{user_id}:{timestamp}:{secrets.token_urlsafe(16)}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def validate_api_key(self, api_key: str) -> Optional[int]:
        """Validate API key and return user ID."""
        try:
            # This would typically check against database
            # Placeholder implementation
            if cache_get:
                cache_key = f"api_key_{api_key}"
                user_data = cache_get(cache_key)
                if user_data:
                    return user_data.get("user_id")
            
            return None
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None
    
    async def log_security_event(self, event: SecurityEvent):
        """Log security event."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO security_events (
                        event_type, user_id, ip_address, user_agent,
                        timestamp, details, severity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """
                params = {
                    "event_type": event.event_type,
                    "user_id": event.user_id,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "timestamp": event.timestamp,
                    "details": str(event.details),
                    "severity": event.severity
                }
                await self.db_manager.execute_query(query, params)
            
            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("security_events_logged", 1, "count")
                self.performance_logger.record_metric(f"security_events_{event.severity}", 1, "count")
                
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    def sanitize_input(self, input_str: str) -> str:
        """Sanitize user input."""
        try:
            # Remove potentially dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
            sanitized = input_str
            
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '')
            
            # Limit length
            return sanitized[:1000]
            
        except Exception as e:
            logger.error(f"Error sanitizing input: {e}")
            return ""
    
    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> Tuple[bool, str]:
        """Validate file upload."""
        try:
            # Check file extension
            allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx'}
            file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
            
            if f'.{file_ext}' not in allowed_extensions:
                return False, "File type not allowed"
            
            # Check content type
            allowed_content_types = {
                'image/jpeg', 'image/png', 'image/gif',
                'application/pdf', 'text/plain',
                'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            }
            
            if content_type not in allowed_content_types:
                return False, "Content type not allowed"
            
            # Check file size (10MB limit)
            if file_size > 10 * 1024 * 1024:
                return False, "File too large"
            
            return True, "Valid file"
            
        except Exception as e:
            logger.error(f"Error validating file upload: {e}")
            return False, "Validation error"
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        return {
            "active_rate_limits": len(self.rate_limits),
            "failed_login_attempts": len(self.login_attempts),
            "password_min_length": self.password_min_length,
            "token_expiry_hours": self.token_expiry_hours,
            "encryption_enabled": self.fernet is not None
        }

# Global security manager
security_manager = SecurityManager()

# Convenience functions
def hash_password(password: str) -> str:
    """Hash password using global security manager."""
    return security_manager.hash_password(password)

def verify_password(password: str, hashed: str) -> bool:
    """Verify password using global security manager."""
    return security_manager.verify_password(password, hashed)

def generate_token(user_id: int, token_type: str = "access") -> str:
    """Generate token using global security manager."""
    return security_manager.generate_token(user_id, token_type)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token using global security manager."""
    return security_manager.verify_token(token)

def check_rate_limit(identifier: str, limit: int = 100, window: int = 3600) -> bool:
    """Check rate limit using global security manager."""
    return security_manager.check_rate_limit(identifier, limit, window)

def sanitize_input(input_str: str) -> str:
    """Sanitize input using global security manager."""
    return security_manager.sanitize_input(input_str)
