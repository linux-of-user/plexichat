"""
Government-Level Authentication System for PlexiChat
Ultra-secure authentication with auto-generated credentials and mandatory password changes.
"""

import os
import secrets
import string
import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import bcrypt

from plexichat.app.logger_config import logger


@dataclass
class AdminCredentials:
    """Admin credentials structure."""
    username: str
    password_hash: str
    salt: str
    created_at: datetime
    last_changed: datetime
    must_change_password: bool = True
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    backup_codes: List[str] = None
    session_tokens: List[str] = None


@dataclass
class SecurityPolicy:
    """Government-level security policy."""
    min_password_length: int = 16
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    password_history_count: int = 12
    max_failed_attempts: int = 3
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 60
    require_2fa: bool = True
    force_password_change_days: int = 90


class GovernmentAuthSystem:
    """Government-level authentication system."""
    
    def __init__(self, credentials_file: str = "admin_credentials.json"):
        self.credentials_file = Path(credentials_file)
        self.security_policy = SecurityPolicy()
        
        # Encryption key for sensitive data
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Admin credentials storage
        self.admin_credentials: Dict[str, AdminCredentials] = {}
        self.password_history: Dict[str, List[str]] = {}
        
        # Session management
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Initialize system
        self._initialize_system()
        
        logger.info("Government-level authentication system initialized")
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data."""
        key_file = Path("config/encryption.key")
        key_file.parent.mkdir(exist_ok=True)
        
        if key_file.exists():
            return key_file.read_bytes()
        else:
            key = Fernet.generate_key()
            key_file.write_bytes(key)
            key_file.chmod(0o600)  # Restrict permissions
            logger.info("New encryption key generated")
            return key
    
    def _initialize_system(self):
        """Initialize the authentication system."""
        # Load existing credentials
        self._load_credentials()
        
        # Create default admin if none exists
        if not self.admin_credentials:
            self._create_default_admin()
        
        # Create credentials file in project root
        self._create_root_credentials_file()
    
    def _create_default_admin(self):
        """Create default admin with auto-generated credentials."""
        # Generate secure random credentials
        username = "admin"
        password = self._generate_secure_password()
        
        # Create admin credentials
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
        admin_creds = AdminCredentials(
            username=username,
            password_hash=password_hash,
            salt=salt.decode('utf-8'),
            created_at=datetime.utcnow(),
            last_changed=datetime.utcnow(),
            must_change_password=True,
            backup_codes=[],
            session_tokens=[]
        )
        
        self.admin_credentials[username] = admin_creds
        self.password_history[username] = [password_hash]
        
        # Save credentials
        self._save_credentials()
        
        # Store plain password temporarily for root file
        self._temp_password = password
        
        logger.info(f"Default admin created with username: {username}")
    
    def _generate_secure_password(self, length: int = 20) -> str:
        """Generate cryptographically secure password."""
        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each required set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def _create_root_credentials_file(self):
        """Create credentials file in project root."""
        root_creds_file = Path("DEFAULT_ADMIN_CREDENTIALS.txt")
        
        if hasattr(self, '_temp_password') and not root_creds_file.exists():
            content = f"""
PLEXICHAT ADMIN CREDENTIALS
========================

⚠️  CRITICAL SECURITY NOTICE ⚠️
These are your DEFAULT admin credentials. You MUST change them immediately after first login.

Username: admin
Password: {self._temp_password}

IMPORTANT SECURITY INSTRUCTIONS:
1. Log in immediately and change the default password
2. Enable 2FA (Two-Factor Authentication) 
3. Delete this file after changing credentials
4. Never share these credentials
5. Use a strong, unique password

Access URLs:
- Web Admin: https://localhost:8000/admin
- Documentation: https://localhost:8000/docs

Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

This file will be automatically deleted after first successful password change.
"""
            
            root_creds_file.write_text(content.strip())
            root_creds_file.chmod(0o600)  # Restrict permissions
            
            # Clear temporary password
            delattr(self, '_temp_password')
            
            logger.warning("Default credentials file created in project root - CHANGE IMMEDIATELY")
    
    def authenticate(self, username: str, password: str, totp_code: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate user with government-level security."""
        if username not in self.admin_credentials:
            logger.warning(f"Authentication attempt with invalid username: {username}")
            return {'success': False, 'error': 'Invalid credentials'}
        
        admin = self.admin_credentials[username]
        
        # Check if account is locked
        if admin.locked_until and datetime.utcnow() < admin.locked_until:
            remaining = (admin.locked_until - datetime.utcnow()).total_seconds()
            logger.warning(f"Authentication attempt on locked account: {username}")
            return {
                'success': False, 
                'error': f'Account locked. Try again in {int(remaining/60)} minutes'
            }
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), admin.password_hash.encode('utf-8')):
            admin.failed_attempts += 1
            
            # Lock account after max failed attempts
            if admin.failed_attempts >= self.security_policy.max_failed_attempts:
                admin.locked_until = datetime.utcnow() + timedelta(
                    minutes=self.security_policy.lockout_duration_minutes
                )
                logger.warning(f"Account locked due to failed attempts: {username}")
            
            self._save_credentials()
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Check 2FA if enabled
        if admin.two_factor_enabled:
            if not totp_code:
                return {
                    'success': False, 
                    'error': '2FA code required',
                    'requires_2fa': True
                }
            
            # Verify 2FA code (simplified - would use proper TOTP verification)
            if not self._verify_2fa_code(username, totp_code):
                admin.failed_attempts += 1
                self._save_credentials()
                return {'success': False, 'error': 'Invalid 2FA code'}
        
        # Reset failed attempts on successful authentication
        admin.failed_attempts = 0
        admin.locked_until = None
        
        # Create session
        session_token = self._create_session(username)
        
        # Check if password change is required
        password_change_required = (
            admin.must_change_password or
            (datetime.utcnow() - admin.last_changed).days >= self.security_policy.force_password_change_days
        )
        
        self._save_credentials()
        
        logger.info(f"Successful authentication for user: {username}")
        
        return {
            'success': True,
            'session_token': session_token,
            'username': username,
            'must_change_password': password_change_required,
            'two_factor_enabled': admin.two_factor_enabled
        }
    
    def _verify_2fa_code(self, username: str, code: str) -> bool:
        """Verify 2FA TOTP code."""
        # This would implement proper TOTP verification
        # For now, simplified implementation
        admin = self.admin_credentials[username]
        if not admin.two_factor_secret:
            return False
        
        # Would use pyotp or similar library for actual TOTP verification
        # return pyotp.TOTP(admin.two_factor_secret).verify(code)
        return len(code) == 6 and code.isdigit()  # Simplified for now
    
    def _create_session(self, username: str) -> str:
        """Create secure session token."""
        session_token = secrets.token_urlsafe(32)
        
        session_data = {
            'username': username,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(
                minutes=self.security_policy.session_timeout_minutes
            )
        }
        
        self.active_sessions[session_token] = session_data
        
        # Add to user's session tokens
        admin = self.admin_credentials[username]
        if not admin.session_tokens:
            admin.session_tokens = []
        admin.session_tokens.append(session_token)
        
        return session_token
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate session token."""
        if session_token not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_token]
        
        # Check if session expired
        if datetime.utcnow() > session['expires_at']:
            self._destroy_session(session_token)
            return None
        
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        
        return session
    
    def _destroy_session(self, session_token: str):
        """Destroy session."""
        if session_token in self.active_sessions:
            username = self.active_sessions[session_token]['username']
            del self.active_sessions[session_token]
            
            # Remove from user's session tokens
            admin = self.admin_credentials[username]
            if admin.session_tokens and session_token in admin.session_tokens:
                admin.session_tokens.remove(session_token)
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """Change user password with security validation."""
        if username not in self.admin_credentials:
            return {'success': False, 'error': 'User not found'}
        
        admin = self.admin_credentials[username]
        
        # Verify old password
        if not bcrypt.checkpw(old_password.encode('utf-8'), admin.password_hash.encode('utf-8')):
            return {'success': False, 'error': 'Current password is incorrect'}
        
        # Validate new password
        validation_result = self._validate_password(new_password, username)
        if not validation_result['valid']:
            return {'success': False, 'error': validation_result['error']}
        
        # Update password
        salt = bcrypt.gensalt()
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
        
        admin.password_hash = new_password_hash
        admin.salt = salt.decode('utf-8')
        admin.last_changed = datetime.utcnow()
        admin.must_change_password = False
        
        # Update password history
        if username not in self.password_history:
            self.password_history[username] = []
        self.password_history[username].append(new_password_hash)
        
        # Keep only recent passwords
        if len(self.password_history[username]) > self.security_policy.password_history_count:
            self.password_history[username] = self.password_history[username][-self.security_policy.password_history_count:]
        
        self._save_credentials()
        
        # Delete default credentials file if it exists
        default_creds_file = Path("DEFAULT_ADMIN_CREDENTIALS.txt")
        if default_creds_file.exists():
            default_creds_file.unlink()
            logger.info("Default credentials file deleted after password change")
        
        logger.info(f"Password changed successfully for user: {username}")
        
        return {'success': True, 'message': 'Password changed successfully'}
    
    def _validate_password(self, password: str, username: str) -> Dict[str, Any]:
        """Validate password against security policy."""
        policy = self.security_policy
        
        # Length check
        if len(password) < policy.min_password_length:
            return {
                'valid': False, 
                'error': f'Password must be at least {policy.min_password_length} characters long'
            }
        
        # Character requirements
        if policy.require_uppercase and not any(c.isupper() for c in password):
            return {'valid': False, 'error': 'Password must contain uppercase letters'}
        
        if policy.require_lowercase and not any(c.islower() for c in password):
            return {'valid': False, 'error': 'Password must contain lowercase letters'}
        
        if policy.require_numbers and not any(c.isdigit() for c in password):
            return {'valid': False, 'error': 'Password must contain numbers'}
        
        if policy.require_special_chars and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return {'valid': False, 'error': 'Password must contain special characters'}
        
        # Check password history
        if username in self.password_history:
            new_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            for old_hash in self.password_history[username]:
                if bcrypt.checkpw(password.encode('utf-8'), old_hash.encode('utf-8')):
                    return {'valid': False, 'error': 'Password has been used recently'}
        
        return {'valid': True}
    
    def _load_credentials(self):
        """Load credentials from encrypted file."""
        if not self.credentials_file.exists():
            return
        
        try:
            encrypted_data = self.credentials_file.read_bytes()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode('utf-8'))
            
            # Load admin credentials
            for username, cred_data in data.get('admin_credentials', {}).items():
                cred_data['created_at'] = datetime.fromisoformat(cred_data['created_at'])
                cred_data['last_changed'] = datetime.fromisoformat(cred_data['last_changed'])
                if cred_data.get('locked_until'):
                    cred_data['locked_until'] = datetime.fromisoformat(cred_data['locked_until'])
                
                self.admin_credentials[username] = AdminCredentials(**cred_data)
            
            # Load password history
            self.password_history = data.get('password_history', {})
            
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
    
    def _save_credentials(self):
        """Save credentials to encrypted file."""
        try:
            # Prepare data for serialization
            data = {
                'admin_credentials': {},
                'password_history': self.password_history
            }
            
            for username, admin in self.admin_credentials.items():
                admin_dict = asdict(admin)
                admin_dict['created_at'] = admin.created_at.isoformat()
                admin_dict['last_changed'] = admin.last_changed.isoformat()
                if admin.locked_until:
                    admin_dict['locked_until'] = admin.locked_until.isoformat()
                else:
                    admin_dict['locked_until'] = None
                
                data['admin_credentials'][username] = admin_dict
            
            # Encrypt and save
            json_data = json.dumps(data, indent=2)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            # Ensure config directory exists
            self.credentials_file.parent.mkdir(exist_ok=True)
            self.credentials_file.write_bytes(encrypted_data)
            self.credentials_file.chmod(0o600)  # Restrict permissions
            
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")


# Global authentication system - lazy initialization to avoid import-time hanging
government_auth = None

def get_government_auth() -> GovernmentAuthSystem:
    """Get the global government auth system instance (lazy initialization)."""
    global government_auth
    if government_auth is None:
        government_auth = GovernmentAuthSystem()
    return government_auth
