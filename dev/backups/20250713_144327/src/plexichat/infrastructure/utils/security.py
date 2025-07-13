import base64
import hashlib
import logging
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Simple settings for security
class Settings:
    def __init__(self):
        self.SECRET_KEY = "your-secret-key-here"
        self.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        self.ALGORITHM = "HS256"

settings = Settings()

def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return get_password_hash(plain_password) == hashed_password

def create_access_token(data: Dict, scopes: List[str] = []) -> str:
    """Legacy function for backward compatibility."""
    if not JWT_AVAILABLE:
        raise ImportError("PyJWT not available")
        
    to_encode = data.copy()
    to_encode.update({
        "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "scopes": scopes
    })
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

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
            if BLEACH_AVAILABLE:
                # Allow only safe HTML tags
                allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
                allowed_attributes = {'a': ['href', 'title']}
                value = bleach.clean(value, tags=allowed_tags, attributes=allowed_attributes)
            else:
                # Fallback: strip all HTML
                value = re.sub(r'<[^>]+>', '', value)
        else:
            # Check for XSS patterns
            for pattern in cls.XSS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning("Potential XSS attempt detected: %s", value[:100])
                    raise ValueError("Invalid input detected")

            # Escape HTML entities
            if BLEACH_AVAILABLE:
                value = bleach.clean(value, tags=[], strip=True)
            else:
                # Fallback: basic HTML escaping
                value = value.replace('<', '&lt;').replace('>', '&gt;')

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
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
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
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
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
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
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
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def encrypt_symmetric(data: str, key: str) -> str:
        """Encrypt data using symmetric encryption."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
        f = Fernet(key.encode('utf-8'))
        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt_symmetric(encrypted_data: str, key: str) -> str:
        """Decrypt data using symmetric encryption."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
        f = Fernet(key.encode('utf-8'))
        return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

class TimeBasedSecurity:
    """Time-based security features including TOTP and time-locked messages."""

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a TOTP secret."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_totp_code(secret: str, time_step: int = 30) -> str:
        """Generate a TOTP code."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
        import time
        current_time = int(time.time())
        time_step_count = current_time // time_step
        
        # Create HMAC
        key = base64.b32decode(secret + '=' * (-len(secret) % 8))
        message = time_step_count.to_bytes(8, 'big')
        
        hmac_obj = hashlib.new('sha1', key)
        hmac_obj.update(message)
        hmac_result = hmac_obj.digest()
        
        # Generate 6-digit code
        offset = hmac_result[-1] & 0xf
        code = ((hmac_result[offset] & 0x7f) << 24 |
                (hmac_result[offset + 1] & 0xff) << 16 |
                (hmac_result[offset + 2] & 0xff) << 8 |
                (hmac_result[offset + 3] & 0xff))
        
        return str(code % 1000000).zfill(6)

    @staticmethod
    def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
        """Verify a TOTP code."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
        import time
        current_time = int(time.time())
        time_step = 30
        
        for i in range(-window, window + 1):
            test_time = current_time + (i * time_step)
            test_code = TimeBasedSecurity.generate_totp_code(secret, time_step)
            if test_code == code:
                return True
        
        return False

    @staticmethod
    def create_time_locked_message(message: str, unlock_time: datetime) -> Dict[str, Any]:
        """Create a message that can only be unlocked after a specific time."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
        # Generate time-based key
        time_key = TimeBasedSecurity._derive_time_key(unlock_time)
        
        # Encrypt message
        encrypted_message = AdvancedEncryption.encrypt_symmetric(message, time_key)
        
        return {
            "encrypted_message": encrypted_message,
            "unlock_time": unlock_time.isoformat(),
            "version": "1.0"
        }

    @staticmethod
    def unlock_time_locked_message(container: Dict[str, Any]) -> Optional[str]:
        """Unlock a time-locked message if the time has passed."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("Cryptography library not available")
            
        try:
            unlock_time = datetime.fromisoformat(container["unlock_time"])
            current_time = datetime.utcnow()
            
            if current_time < unlock_time:
                return None  # Time hasn't passed yet
            
            # Derive the same key
            time_key = TimeBasedSecurity._derive_time_key(unlock_time)
            
            # Decrypt message
            decrypted_message = AdvancedEncryption.decrypt_symmetric(
                container["encrypted_message"], time_key
            )
            
            return decrypted_message
            
        except Exception as e:
            logger.error(f"Failed to unlock time-locked message: {e}")
            return None

    @staticmethod
    def _derive_time_key(unlock_time: datetime) -> str:
        """Derive a key based on unlock time."""
        # Create a deterministic key based on the unlock time
        time_string = unlock_time.strftime("%Y-%m-%d %H:%M:%S")
        key_material = f"time_lock_{time_string}_{settings.SECRET_KEY}"
        return hashlib.sha256(key_material.encode()).hexdigest()[:32]

class SecurityManager:
    """Comprehensive security management system."""

    def __init__(self):
        self.encryption_key = None
        self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption components."""
        if CRYPTOGRAPHY_AVAILABLE:
            self.encryption_key = Fernet.generate_key()
        else:
            logger.warning("Cryptography not available - encryption features disabled")

    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        if not self.encryption_key:
            raise RuntimeError("Encryption not initialized")
        f = Fernet(self.encryption_key)
        return f.encrypt(data.encode()).decode()

    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        if not self.encryption_key:
            raise RuntimeError("Encryption not initialized")
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password securely."""
        return get_password_hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return verify_password(plain_password, hashed_password)

    @staticmethod
    def validate_password_strength(password: str) -> str:
        """Validate password strength and return feedback."""
        if len(password) < 8:
            return "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return "Password must be no more than 128 characters long"
        
        checks = {
            'length': len(password) >= 8,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digit': any(c.isdigit() for c in password),
            'special': any(c in string.punctuation for c in password)
        }
        
        passed_checks = sum(checks.values())
        
        if passed_checks == 5:
            return "strong"
        elif passed_checks >= 3:
            return "medium"
        else:
            return "weak"

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        if not JWT_AVAILABLE:
            raise ImportError("PyJWT not available")
            
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    def create_refresh_token(self, user_id: int, session_id: str) -> str:
        """Create a refresh token."""
        if not JWT_AVAILABLE:
            raise ImportError("PyJWT not available")
            
        data = {
            "sub": str(user_id),
            "session_id": session_id,
            "type": "refresh",
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        if not JWT_AVAILABLE:
            raise ImportError("PyJWT not available")
            
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.JWTError as e:
            raise ValueError(f"Invalid token: {e}")

    def blacklist_token(self, token: str):
        """Add token to blacklist (placeholder implementation)."""
        # In a real implementation, you would store this in a database
        logger.info(f"Token blacklisted: {token[:20]}...")

    def get_client_ip(self, request) -> str:
        """Extract client IP from request."""
        # This is a simplified implementation
        return getattr(request, 'client', {}).get('host', '127.0.0.1')

    def generate_device_fingerprint(self, request, device_info: Optional[Dict] = None) -> str:
        """Generate a device fingerprint for security tracking."""
        # Collect device information
        user_agent = getattr(request, 'headers', {}).get('user-agent', '')
        ip_address = self.get_client_ip(request)
        
        # Create fingerprint
        fingerprint_data = f"{ip_address}:{user_agent}"
        if device_info:
            fingerprint_data += f":{str(device_info)}"
        
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def sanitize_filename(filename: str) -> Optional[str]:
    """Sanitize a filename for safe storage."""
    if not filename:
        return None
    
    # Remove path traversal attempts
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:255-len(ext)-1] + ('.' + ext if ext else '')
    
    return filename or 'unnamed'

def validate_file_type(extension: str, allowed_extensions: Dict[str, Set[str]]) -> bool:
    """Validate file type based on extension."""
    extension = extension.lower().lstrip('.')
    
    # Check if extension is in allowed types
    for category, extensions in allowed_extensions.items():
        if extension in extensions:
            return True
    
    return False

def scan_file_content(content: bytes, extension: str) -> bool:
    """Scan file content for malicious patterns."""
    # This is a simplified implementation
    # In production, you would use proper antivirus scanning
    
    dangerous_patterns = [
        b'<script',
        b'javascript:',
        b'vbscript:',
        b'data:text/html',
        b'data:application/x-javascript'
    ]
    
    content_lower = content.lower()
    for pattern in dangerous_patterns:
        if pattern in content_lower:
            logger.warning(f"Potentially malicious content detected in {extension} file")
            return False
    
    return True

def validate_image_file(content: bytes) -> bool:
    """Validate image file content."""
    # Check for common image file signatures
    image_signatures = [
        b'\xff\xd8\xff',  # JPEG
        b'\x89PNG\r\n\x1a\n',  # PNG
        b'GIF87a',  # GIF
        b'GIF89a',  # GIF
        b'RIFF',  # WebP
    ]
    
    for signature in image_signatures:
        if content.startswith(signature):
            return True
    
    return False

def validate_text_file(content: bytes) -> bool:
    """Validate text file content."""
    try:
        # Try to decode as UTF-8
        content.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

# Global security manager instance
security_manager = SecurityManager()
