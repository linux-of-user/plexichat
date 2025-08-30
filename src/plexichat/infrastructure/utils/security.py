# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import base64
import html
import re
import os

# Cryptography imports
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    Fernet = None
    hashes = None
    PBKDF2HMAC = None
    CRYPTOGRAPHY_AVAILABLE = False

# Password hashing
try:
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    pwd_context = None
    PASSLIB_AVAILABLE = False

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Configuration imports
try:
    from plexichat.core.config import settings
except ImportError:
    class MockSettings:
        JWT_SECRET = "mock-secret-key"
        SECURITY_LEVEL = "STANDARD"
    settings = MockSettings()

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class SecurityUtilities:
    """Enhanced security utilities using EXISTING systems."""
    def __init__(self):
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.security_level = getattr(settings, 'SECURITY_LEVEL', 'STANDARD')
        self._encryption_key = None

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        try:
            if pwd_context:
                if self.performance_logger and timer:
                    with timer("password_hashing"):
                        return pwd_context.hash(password)
                else:
                    return pwd_context.hash(password)
            else:
                # Fallback to simple hashing (not recommended for production)
                return hashlib.sha256(password.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
            return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        try:
            if pwd_context:
                if self.performance_logger and timer:
                    with timer("password_verification"):
                        return pwd_context.verify(plain_password, hashed_password)
                else:
                    return pwd_context.verify(plain_password, hashed_password)
            else:
                # Fallback verification
                return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token."""
        try:
            return secrets.token_urlsafe(length)
        except Exception as e:
            logger.error(f"Error generating secure token: {e}")
            return secrets.token_hex(length)

    def generate_api_key(self, user_id: int) -> str:
        """Generate API key for user."""
        try:
            timestamp = str(int(time.time()))
            random_part = secrets.token_hex(16)
            data = f"{user_id}:{timestamp}:{random_part}"

            # Create HMAC signature
            secret_key = getattr(settings, 'JWT_SECRET', 'mock-secret-key')
            signature = hmac.new(
                secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()

            return f"{data}:{signature}"
        except Exception as e:
            logger.error(f"Error generating API key: {e}")
            return f"api_{user_id}_{secrets.token_hex(16)}"

    def validate_api_key(self, api_key: str) -> Optional[int]:
        """Validate API key and return user ID."""
        try:
            parts = api_key.split(':')
            if len(parts) != 4:
                return None

            user_id, timestamp, random_part, signature = parts
            data = f"{user_id}:{timestamp}:{random_part}"

            # Verify HMAC signature
            secret_key = getattr(settings, 'JWT_SECRET', 'mock-secret-key')
            expected_signature = hmac.new(
                secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(signature, expected_signature):
                return int(user_id)

            return None
        except Exception as e:
            logger.error(f"Error validating API key: {e}")
            return None

    def get_encryption_key(self) -> bytes:
        """Get or generate encryption key."""
        if self._encryption_key is None:
            try:
                if CRYPTOGRAPHY_AVAILABLE:
                    password = getattr(settings, 'JWT_SECRET', 'mock-secret-key').encode()
                    salt = b'plexichat_salt_2024'  # In production, use random salt

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    self._encryption_key = key
                else:
                    # Fallback key generation
                    self._encryption_key = hashlib.sha256(
                        getattr(settings, 'JWT_SECRET', 'mock-secret-key').encode()
                    ).digest()
            except Exception as e:
                logger.error(f"Error generating encryption key: {e}")
                self._encryption_key = b'fallback_key_32_bytes_long_123'

        return self._encryption_key

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        try:
            if CRYPTOGRAPHY_AVAILABLE:
                key = self.get_encryption_key()
                f = Fernet(key)
                encrypted_data = f.encrypt(data.encode())
                return base64.urlsafe_b64encode(encrypted_data).decode()
            else:
                # Simple XOR encryption (not secure, for fallback only)
                key = self.get_encryption_key()[:16]  # Use first 16 bytes
                encrypted = bytearray()
                for i, byte in enumerate(data.encode()):
                    encrypted.append(byte ^ key[i % len(key)])
                return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            return data  # Return unencrypted on error

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        try:
            if CRYPTOGRAPHY_AVAILABLE:
                key = self.get_encryption_key()
                f = Fernet(key)
                decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
                decrypted_data = f.decrypt(decoded_data)
                return decrypted_data.decode()
            else:
                # Simple XOR decryption (matches encryption fallback)
                key = self.get_encryption_key()[:16]
                encrypted_bytes = base64.b64decode(encrypted_data.encode())
                decrypted = bytearray()
                for i, byte in enumerate(encrypted_bytes):
                    decrypted.append(byte ^ key[i % len(key)])
                return decrypted.decode()
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            return encrypted_data  # Return as-is on error

    def sanitize_input(self, input_data: str) -> str:
        """Sanitize user input to prevent XSS and injection attacks."""
        try:
            # HTML escape
            sanitized = html.escape(input_data)

            # Remove potentially dangerous patterns
            dangerous_patterns = [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'vbscript:',
                r'onload=',
                r'onerror=',
                r'onclick=',
                r'onmouseover=',
            ]

            for pattern in dangerous_patterns:
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)

            return sanitized.strip()
        except Exception as e:
            logger.error(f"Error sanitizing input: {e}")
            return input_data

    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> Dict[str, Any]:
        """Validate file upload for security."""
        try:
            result = {
                "valid": True,
                "errors": [],
                "warnings": []
            }

            # Check file extension
            allowed_extensions = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp',  # Images
                '.pdf', '.txt', '.doc', '.docx', '.rtf',  # Documents
                '.mp3', '.wav', '.ogg',  # Audio
                '.mp4', '.avi', '.mov', '.webm',  # Video
                '.zip', '.tar', '.gz'  # Archives
            }

            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in allowed_extensions:
                result["valid"] = False
                result["errors"].append(f"File extension {file_ext} not allowed")

            # Check file size (100MB limit)
            max_size = 100 * 1024 * 1024
            if file_size > max_size:
                result["valid"] = False
                result["errors"].append(f"File size {file_size} exceeds limit of {max_size} bytes")

            # Check content type
            allowed_content_types = {
                'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
                'application/pdf', 'text/plain', 'application/msword',
                'audio/mpeg', 'audio/wav', 'audio/ogg',
                'video/mp4', 'video/avi', 'video/quicktime',
                'application/zip', 'application/x-tar'
            }

            if content_type not in allowed_content_types:
                result["warnings"].append(f"Content type {content_type} may not be safe")

            # Check filename for dangerous patterns
            dangerous_filename_patterns = [
                r'\.\./',  # Directory traversal
                r'[<>:"/\\|?*]',  # Invalid characters
                r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$',  # Windows reserved names
            ]

            for pattern in dangerous_filename_patterns:
                if re.search(pattern, filename, re.IGNORECASE):
                    result["valid"] = False
                    result["errors"].append("Filename contains dangerous patterns")
                    break

            return result
        except Exception as e:
            logger.error(f"Error validating file upload: {e}")
            return {"valid": False, "errors": ["Validation error"], "warnings": []}

    @async_track_performance("security_audit") if async_track_performance else lambda f: f
    async def log_security_event(self, event_type: str, user_id: Optional[int], details: Dict[str, Any]):
        """Log security event using EXISTING database abstraction."""
        try:
            if self.db_manager:
                import json

                query = """
                    INSERT INTO security_logs (event_type, user_id, details, timestamp, severity)
                    VALUES (?, ?, ?, ?, ?)
                """

                # Determine severity
                high_severity_events = ['login_failure', 'unauthorized_access', 'suspicious_activity']
                severity = 'high' if event_type in high_severity_events else 'medium'

                params = {
                    "event_type": event_type,
                    "user_id": user_id,
                    "details": json.dumps(details),
                    "timestamp": datetime.now(),
                    "severity": severity
                }

                if self.performance_logger and timer:
                    with timer("security_log_insert"):
                        await self.db_manager.execute_query(query, params)
                else:
                    await self.db_manager.execute_query(query, params)

                # Performance tracking
                if self.performance_logger:
                    self.performance_logger.increment_counter("security_events_logged", 1)
                    self.performance_logger.increment_counter(f"security_event_{event_type}", 1)

            # Also log to application logger
            logger.warning(f"Security Event: {event_type} - User: {user_id} - Details: {details}")

        except Exception as e:
            logger.error(f"Error logging security event: {e}")

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Check password strength and return recommendations."""
        try:
            result = {
                "score": 0,
                "strength": "weak",
                "recommendations": []
            }

            # Length check
            if len(password) >= 8:
                result["score"] += 2
            else:
                result["recommendations"].append("Use at least 8 characters")

            if len(password) >= 12:
                result["score"] += 1

            # Character variety checks
            if re.search(r'[a-z]', password):
                result["score"] += 1
            else:
                result["recommendations"].append("Include lowercase letters")

            if re.search(r'[A-Z]', password):
                result["score"] += 1
            else:
                result["recommendations"].append("Include uppercase letters")

            if re.search(r'\d', password):
                result["score"] += 1
            else:
                result["recommendations"].append("Include numbers")

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                result["score"] += 2
            else:
                result["recommendations"].append("Include special characters")

            # Common password check
            common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
            if password.lower() in common_passwords:
                result["score"] = 0
                result["recommendations"].append("Avoid common passwords")

            # Determine strength
            if result["score"] >= 7:
                result["strength"] = "strong"
            elif result["score"] >= 5:
                result["strength"] = "medium"
            else:
                result["strength"] = "weak"

            return result
        except Exception as e:
            logger.error(f"Error checking password strength: {e}")
            return {"score": 0, "strength": "unknown", "recommendations": ["Error checking password"]}

# Global security utilities instance
security_utils = SecurityUtilities()

# Convenience functions
def hash_password(password: str) -> str:
    """Hash password."""
    return security_utils.hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password."""
    return security_utils.verify_password(plain_password, hashed_password)

def generate_secure_token(length: int = 32) -> str:
    """Generate secure token."""
    return security_utils.generate_secure_token(length)

def sanitize_input(input_data: str) -> str:
    """Sanitize user input."""
    return security_utils.sanitize_input(input_data)

def encrypt_data(data: str) -> str:
    """Encrypt data."""
    return security_utils.encrypt_data(data)

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data."""
    return security_utils.decrypt_data(encrypted_data)
