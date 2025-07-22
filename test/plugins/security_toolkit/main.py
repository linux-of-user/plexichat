"""
Security Toolkit Plugin

Security toolkit with file encryption, password management, secure communication, and cryptographic utilities.
"""

import asyncio
import json
import logging
import secrets
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import bcrypt

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Fallback definitions for plugin interface
class PluginInterface:
    def get_metadata(self) -> Dict[str, Any]:
        return {}

class PluginMetadata:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class PluginType:
    SECURITY = "security"

class ModulePermissions:
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

class ModuleCapability:
    ENCRYPTION = "encryption"
    SECURITY = "security"

logger = logging.getLogger(__name__)


class EncryptionRequest(BaseModel):
    """Encryption request model."""
    data: str
    password: Optional[str] = None
    algorithm: str = "AES-256-GCM"


class SecurityToolkitCore:
    """Core security toolkit functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.encryption_algorithm = config.get('encryption_algorithm', 'AES-256-GCM')
        self.password_policy = config.get('password_policy', {})
        
    async def encrypt_data(self, data: str, password: str) -> Dict[str, Any]:
        """Encrypt data using password-based encryption."""
        try:
            # Generate salt
            salt = secrets.token_bytes(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Encrypt data
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "salt": base64.b64encode(salt).decode(),
                "algorithm": self.encryption_algorithm,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            raise
    
    async def decrypt_data(self, encrypted_data: str, password: str, salt: str) -> str:
        """Decrypt data using password-based decryption."""
        try:
            # Decode salt and encrypted data
            salt_bytes = base64.b64decode(salt.encode())
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt_bytes,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Decrypt data
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            return decrypted_data.decode()
            
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            raise
    
    async def encrypt_file(self, file_path: str, password: str) -> bool:
        """Encrypt a file."""
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Read file content
            with open(path, 'rb') as f:
                file_data = f.read()
            
            # Encrypt data
            encrypted_result = await self.encrypt_data(
                base64.b64encode(file_data).decode(), password
            )
            
            # Write encrypted file
            encrypted_path = path.with_suffix(path.suffix + '.encrypted')
            with open(encrypted_path, 'w') as f:
                json.dump(encrypted_result, f)
            
            return True
            
        except Exception as e:
            logger.error(f"Error encrypting file {file_path}: {e}")
            return False
    
    async def decrypt_file(self, encrypted_file_path: str, password: str, output_path: str) -> bool:
        """Decrypt a file."""
        try:
            # Read encrypted file
            with open(encrypted_file_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Decrypt data
            decrypted_data = await self.decrypt_data(
                encrypted_data['encrypted_data'],
                password,
                encrypted_data['salt']
            )
            
            # Decode and write file
            file_data = base64.b64decode(decrypted_data.encode())
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return True
            
        except Exception as e:
            logger.error(f"Error decrypting file {encrypted_file_path}: {e}")
            return False
    
    async def generate_password(self, length: int = 16, include_symbols: bool = True) -> str:
        """Generate a secure password."""
        try:
            import string
            
            characters = string.ascii_letters + string.digits
            if include_symbols:
                characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            password = ''.join(secrets.choice(characters) for _ in range(length))
            
            # Ensure password meets policy
            if self._validate_password(password):
                return password
            else:
                # Regenerate if doesn't meet policy
                return await self.generate_password(length, include_symbols)
            
        except Exception as e:
            logger.error(f"Error generating password: {e}")
            raise
    
    def _validate_password(self, password: str) -> bool:
        """Validate password against policy."""
        policy = self.password_policy
        
        if len(password) < policy.get('min_length', 8):
            return False
        
        if policy.get('require_uppercase', False) and not any(c.isupper() for c in password):
            return False
        
        if policy.get('require_lowercase', False) and not any(c.islower() for c in password):
            return False
        
        if policy.get('require_numbers', False) and not any(c.isdigit() for c in password):
            return False
        
        if policy.get('require_symbols', False) and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False
        
        return True
    
    async def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
            raise
    
    async def verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error verifying password: {e}")
            return False
    
    async def generate_key_pair(self) -> Dict[str, str]:
        """Generate RSA key pair."""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                "private_key": private_pem.decode(),
                "public_key": public_pem.decode(),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating key pair: {e}")
            raise
    
    async def calculate_hash(self, data: str, algorithm: str = "sha256") -> str:
        """Calculate hash of data."""
        try:
            data_bytes = data.encode('utf-8')
            
            if algorithm.lower() == "md5":
                hash_obj = hashlib.md5(data_bytes)
            elif algorithm.lower() == "sha1":
                hash_obj = hashlib.sha1(data_bytes)
            elif algorithm.lower() == "sha256":
                hash_obj = hashlib.sha256(data_bytes)
            elif algorithm.lower() == "sha512":
                hash_obj = hashlib.sha512(data_bytes)
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            raise
    
    async def secure_delete(self, file_path: str) -> bool:
        """Securely delete a file by overwriting it."""
        try:
            path = Path(file_path)
            if not path.exists():
                return True
            
            # Get file size
            file_size = path.stat().st_size
            
            # Overwrite with random data multiple times
            with open(path, 'r+b') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
            
            # Delete the file
            path.unlink()
            return True
            
        except Exception as e:
            logger.error(f"Error securely deleting file {file_path}: {e}")
            return False


class SecurityToolkitPlugin(PluginInterface):
    """Security Toolkit Plugin."""
    
    def __init__(self):
        super().__init__("security_toolkit", "1.0.0")
        self.router = APIRouter()
        self.security = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        
    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": "security_toolkit",
            "version": "1.0.0",
            "description": "Security toolkit with file encryption, password management, secure communication, and cryptographic utilities",
            "plugin_type": "security"
        }
    
    def get_required_permissions(self) -> Dict[str, Any]:
        """Get required permissions."""
        return {
            "capabilities": [
                "file_system",
                "network",
                "web_ui",
                "crypto"
            ],
            "network_access": True,
            "file_system_access": True,
            "database_access": False
        }
