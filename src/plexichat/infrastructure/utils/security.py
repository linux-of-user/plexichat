import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import base32
import bcrypt
import bleach
import magic
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import Request
from jose import JWTError, jwt
from passlib.context import CryptContext
from PIL import Image

from plexichat.app.logger_config import logger, settings

# app/utils/security.py
"""
Comprehensive security utilities including input sanitization,
password management, session handling, and advanced security features.
"""

# Additional imports for file security
try:
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logger.warning("python-magic not available, file type detection limited")

try:
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("Pillow not available, image validation disabled")

# Legacy support
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """Legacy function for backward compatibility."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Legacy function for backward compatibility."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: Dict, scopes: List[str] = []) -> str:
    """Legacy function for backward compatibility."""
    to_encode = data.copy()
    to_encode.update({
        "exp": from datetime import datetime
datetime.utcnow() + timedelta(minutes=from plexichat.core.config import settings
settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "scopes": scopes
    })
    return jwt.encode(to_encode, from plexichat.core.config import settings
settings.SECRET_KEY, algorithm="HS256")


class InputSanitizer:
    """Advanced input sanitization and validation."""

    # Regex patterns for validation
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{3,50}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    PHONE_PATTERN = re.compile(r'^\+?[1-9]\d{1,14}$')

    # Dangerous patterns to detect
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\bUNION\s+SELECT\b)",
        r"(\b(SCRIPT|JAVASCRIPT|VBSCRIPT)\b)"
    ]

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>"
    ]

    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000, allow_html: bool = False) -> str:
        """Sanitize a general string input."""
        if not isinstance(value, str):
            raise ValueError("Input must be a string")

        # Trim whitespace
        value = value.strip()

        # Check length
        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} characters)")

        # Remove null bytes
        value = value.replace('\x00', '')

        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning("Potential SQL injection attempt detected: %s", value[:100])
                raise ValueError("Invalid input detected")

        # Handle HTML content
        if allow_html:
            # Allow only safe HTML tags
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
            allowed_attributes = {'a': ['href', 'title']}
            value = bleach.clean(value, tags=allowed_tags, attributes=allowed_attributes)
        else:
            # Check for XSS patterns
            for pattern in cls.XSS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning("Potential XSS attempt detected: %s", value[:100])
                    raise ValueError("Invalid input detected")

            # Escape HTML entities
            value = bleach.clean(value, tags=[], strip=True)

        return value

    @classmethod
    def sanitize_username(cls, username: str) -> str:
        """Sanitize username input."""
        username = cls.sanitize_string(username, max_length=50)

        if not cls.USERNAME_PATTERN.match(username):
            raise ValueError("Username contains invalid characters")

        return username.lower()

    @classmethod
    def sanitize_email(cls, email: str) -> str:
        """Sanitize email input."""
        email = cls.sanitize_string(email, max_length=254)

        if not cls.EMAIL_PATTERN.match(email):
            raise ValueError("Invalid email format")

        return email.lower()

    @classmethod
    def sanitize_password(cls, password: str) -> str:
        """Sanitize password input (minimal processing to preserve complexity)."""
        if not isinstance(password, str):
            raise ValueError("Password must be a string")

        # Check length
        if len(password) < 8 or len(password) > 128:
            raise ValueError("Password must be between 8 and 128 characters")

        # Remove null bytes
        password = password.replace('\x00', '')

        return password


class AdvancedEncryption:
    """Advanced encryption utilities for end-to-end encryption."""

    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair for end-to-end encryption."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode('utf-8'), public_pem.decode('utf-8')

    @staticmethod
    def encrypt_message(message: str, public_key_pem: str) -> str:
        """Encrypt message using RSA public key."""
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

        # Encrypt message
        encrypted = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_message(encrypted_message: str, private_key_pem: str) -> str:
        """Decrypt message using RSA private key."""
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
        )

        # Decrypt message
        encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted.decode('utf-8')

    @staticmethod
    def generate_symmetric_key() -> str:
        """Generate symmetric key for AES encryption."""
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def encrypt_symmetric(data: str, key: str) -> str:
        """Encrypt data using symmetric encryption."""
        f = Fernet(key.encode('utf-8'))
        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt_symmetric(encrypted_data: str, key: str) -> str:
        """Decrypt data using symmetric encryption."""
        f = Fernet(key.encode('utf-8'))
        return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')


class TimeBasedSecurity:
    """Time-based security features including OTP and time-locked encryption."""

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate TOTP secret for 2FA."""
        return base32.b32encode(secrets.token_bytes(20)).decode('utf-8')

    @staticmethod
    def generate_totp_code(secret: str, time_step: int = 30) -> str:
        """Generate TOTP code."""
        # Convert secret from base32
        key = base64.b32decode(secret.upper() + '=' * (8 - len(secret) % 8))

        # Calculate time counter
        counter = int(time.time()) // time_step

        # Generate HMAC
        hmac_digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()

        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0f
        code = struct.unpack('>I', hmac_digest[offset:offset + 4])[0] & 0x7fffffff

        # Return 6-digit code
        return f"{code % 1000000:06d}"

    @staticmethod
    def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
        """Verify TOTP code with time window tolerance."""
        current_time = int(time.time()) // 30

        # Check current time and adjacent windows
        for i in range(-window, window + 1):
            current_time + i
            test_code = TimeBasedSecurity.generate_totp_code(secret)
            if test_code == code:
                return True

        return False

    @staticmethod
    def create_time_locked_message(message: str, unlock_time: datetime) -> Dict[str, Any]:
        """Create a message that can only be decrypted after a specific time."""
        # Generate encryption key
        key = Fernet.generate_key()
        f = Fernet(key)

        # Encrypt message
        encrypted_message = f.encrypt(message.encode('utf-8'))

        # Create time-locked container
        container = {
            'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
            'unlock_time': unlock_time.isoformat(),
            'key_hash': hashlib.sha256(key).hexdigest()
        }

        # Encrypt the key with time-based derivation
        time_key = TimeBasedSecurity._derive_time_key(unlock_time)
        encrypted_key = AdvancedEncryption.encrypt_symmetric(key.decode('utf-8'), time_key)
        container['encrypted_key'] = encrypted_key

        return container

    @staticmethod
    def unlock_time_locked_message(container: Dict[str, Any]) -> Optional[str]:
        """Unlock a time-locked message if the time has passed."""
        unlock_time = datetime.fromisoformat(container['unlock_time'])
        current_time = datetime.now(timezone.utc)

        # Check if unlock time has passed
        if current_time < unlock_time:
            return None

        try:
            # Derive time key
            time_key = TimeBasedSecurity._derive_time_key(unlock_time)

            # Decrypt the encryption key
            key = AdvancedEncryption.decrypt_symmetric(container['encrypted_key'], time_key)

            # Verify key hash
            if hashlib.sha256(key.encode('utf-8')).hexdigest() != container['key_hash']:
                raise ValueError("Key verification failed")

            # Decrypt message
            f = Fernet(key.encode('utf-8'))
            encrypted_message = base64.b64decode(container['encrypted_message'])
            message = f.decrypt(encrypted_message)

            return message.decode('utf-8')

        except Exception as e:
            logger.error("Failed to unlock time-locked message: %s", e)
            return None

    @staticmethod
    def _derive_time_key(unlock_time: datetime) -> str:
        """Derive encryption key based on unlock time."""
        # Use unlock time as salt
        salt = unlock_time.isoformat().encode('utf-8')

        # Derive key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(b"time_lock_key"))
        return key.decode('utf-8')


class SecurityManager:
    """Comprehensive security management."""

    def __init__(self):
        self.secret_key = from plexichat.core.config import settings
settings.SECRET_KEY
        self.algorithm = "HS256"
        self.access_token_expire_minutes = from plexichat.core.config import settings
settings.ACCESS_TOKEN_EXPIRE_MINUTES

        # Initialize encryption
        self._init_encryption()

        # Session storage (in production, use Redis or database)
        self.active_sessions: Dict[str, Dict] = {}
        self.blacklisted_tokens: Set[str] = set()
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.password_history: Dict[int, List[str]] = {}

    def _init_encryption(self):
        """Initialize encryption for sensitive data."""
        # Generate key from secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chat_api_salt',  # In production, use random salt per installation
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode()))
        self.cipher_suite = Fernet(key)

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False

    @staticmethod
    def validate_password_strength(password: str) -> str:
        """Validate password strength and return the password if valid."""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        if len(password) > 128:
            raise ValueError("Password must be less than 128 characters")

        # Check for required character types
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            raise ValueError(
                "Password must contain uppercase, lowercase, digit, and special character"
            )

        # Check for common patterns
        common_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        ]

        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                raise ValueError("Password contains common patterns")

        return password

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)

        to_encode.update({"exp": expire, "type": "access"})

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: int, session_id: str) -> str:
        """Create JWT refresh token."""
        expire = datetime.now(timezone.utc) + timedelta(days=30)

        to_encode = {
            "user_id": user_id,
            "session_id": session_id,
            "exp": expire,
            "type": "refresh"
        }

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def validate_access_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode access token."""
        if token in self.blacklisted_tokens:
            raise JWTError("Token has been revoked")

        try:
            payload = import jwt
jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get("type") != "access":
                raise JWTError("Invalid token type")

            return payload

        except JWTError as e:
            logger.warning("Token validation failed: %s", e)
            raise

    def validate_refresh_token(self, token: str) -> Dict[str, Any]:
        """Validate and decode refresh token."""
        try:
            payload = import jwt
jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get("type") != "refresh":
                raise JWTError("Invalid token type")

            return payload

        except JWTError as e:
            logger.warning("Refresh token validation failed: %s", e)
            raise

    def blacklist_token(self, token: str):
        """Add token to blacklist."""
        self.blacklisted_tokens.add(token)

        # In production, store in Redis with expiration
        logger.debug("Token blacklisted")

    def get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def generate_device_fingerprint(self, request: Request, device_info: Optional[Dict] = None) -> str:
        """Generate device fingerprint for session tracking."""
        fingerprint_data = {
            "user_agent": request.headers.get("User-Agent", ""),
            "accept_language": request.headers.get("Accept-Language", ""),
            "accept_encoding": request.headers.get("Accept-Encoding", ""),
        }

        if device_info:
            fingerprint_data.update(device_info)

        fingerprint_string = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()


# File Security Constants and Functions
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
    '.app', '.deb', '.pkg', '.dmg', '.run', '.bin', '.sh', '.ps1', '.msi',
    '.dll', '.so', '.dylib', '.sys', '.drv'
}

SUSPICIOUS_PATTERNS = [
    rb'<script[^>]*>',
    rb'javascript:',
    rb'vbscript:',
    rb'onload\s*=',
    rb'onerror\s*=',
    rb'eval\s*\(',
    rb'document\.write',
    rb'<iframe[^>]*>',
    rb'<object[^>]*>',
    rb'<embed[^>]*>',
]

SAFE_MIME_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
    'text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript',
    'application/json', 'application/xml', 'application/pdf',
    'application/zip', 'application/x-tar', 'application/gzip',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'video/mp4', 'video/avi', 'video/mov', 'video/wmv',
    'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/flac'
}

def sanitize_filename(filename: str) -> Optional[str]:
    """
    Sanitize filename to prevent directory traversal and other attacks.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename or None if invalid
    """
    if not filename:
        return None

    # Remove path components
    filename = os.path.basename(filename)

    # Remove dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32)

    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')

    # Ensure filename is not empty and not too long
    if not filename or len(filename) > 255:
        return None

    # Check for reserved names (Windows)
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
        'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }

    name_without_ext = from pathlib import Path
Path(filename).stem.upper()
    if name_without_ext in reserved_names:
        filename = f"file_{filename}"

    return filename

def validate_file_type(extension: str, allowed_extensions: Dict[str, Set[str]]) -> bool:
    """
    Validate file type against allowed extensions.

    Args:
        extension: File extension (with dot)
        allowed_extensions: Dictionary of allowed extensions by category

    Returns:
        True if file type is allowed
    """
    extension = extension.lower()

    # Check if extension is dangerous
    if extension in DANGEROUS_EXTENSIONS:
        logger.warning(f"Dangerous file extension blocked: {extension}")
        return False

    # Check if extension is in allowed list
    for category, extensions in allowed_extensions.items():
        if extension in extensions:
            return True

    logger.warning(f"File extension not allowed: {extension}")
    return False

def scan_file_content(content: bytes, extension: str) -> bool:
    """
    Scan file content for malicious patterns and validate structure.

    Args:
        content: File content as bytes
        extension: File extension

    Returns:
        True if file passes security scan
    """
    try:
        # Check file size (basic DoS protection)
        if len(content) == 0:
            logger.warning("Empty file rejected")
            return False

        # Check for suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                logger.warning("Suspicious pattern found in file")
                return False

        # MIME type validation if magic is available
        if MAGIC_AVAILABLE:
            detected_mime = magic.from_buffer(content, mime=True)
            if detected_mime not in SAFE_MIME_TYPES:
                logger.warning(f"Unsafe MIME type detected: {detected_mime}")
                return False

        # File-specific validation
        if extension.lower() in {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}:
            return validate_image_file(content)
        elif extension.lower() in {'.txt', '.csv', '.json', '.xml'}:
            return validate_text_file(content)

        return True

    except Exception as e:
        logger.error(f"File content scan error: {e}")
        return False

def validate_image_file(content: bytes) -> bool:
    """
    Validate image file structure and content.

    Args:
        content: Image file content

    Returns:
        True if image is valid and safe
    """
    if not PIL_AVAILABLE:
        return True  # Skip validation if PIL not available

    try:
        with Image.open(BytesIO(content)) as img:
            # Check image dimensions (prevent zip bombs)
            if img.width * img.height > 50000000:  # 50MP limit
                logger.warning("Image too large (potential zip bomb)")
                return False

            # Verify image format
            if img.format not in {'JPEG', 'PNG', 'GIF', 'BMP', 'WEBP'}:
                logger.warning(f"Unsupported image format: {img.format}")
                return False

        return True

    except Exception as e:
        logger.warning(f"Image validation failed: {e}")
        return False

def validate_text_file(content: bytes) -> bool:
    """
    Validate text file content.

    Args:
        content: Text file content

    Returns:
        True if text file is safe
    """
    try:
        # Try to decode as UTF-8
        text_content = content.decode('utf-8')

        # Check for suspicious patterns in text
        suspicious_text_patterns = [
            'javascript:', 'vbscript:', '<script', 'eval(', 'document.write',
            'window.location', 'document.cookie', 'localStorage', 'sessionStorage'
        ]

        text_lower = text_content.lower()
        for pattern in suspicious_text_patterns:
            if pattern in text_lower:
                logger.warning(f"Suspicious pattern in text file: {pattern}")
                return False

        return True

    except UnicodeDecodeError:
        logger.warning("Text file contains invalid UTF-8")
        return False
    except Exception as e:
        logger.warning(f"Text file validation failed: {e}")
        return False
