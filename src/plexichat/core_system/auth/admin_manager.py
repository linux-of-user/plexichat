"""
Default Admin Credentials System
Creates secure default admin account on first startup.
"""

import os
import json
import secrets
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
import bcrypt
import logging

logger = logging.getLogger("plexichat.auth.default_admin")

class DefaultAdminManager:
    """Manages default admin account creation and credentials."""
    
    def __init__(self):
        self.config_dir = Path("config")
        self.config_dir.mkdir(exist_ok=True)
        
        self.admin_file = self.config_dir / "default_admin.json"
        self.credentials_file = self.config_dir / "admin_credentials.txt"
        
    def ensure_default_admin_exists(self) -> Dict[str, str]:
        """Ensure default admin account exists and return credentials."""
        
        # Check if default admin already exists
        if self.admin_file.exists():
            try:
                with open(self.admin_file, 'r', encoding='utf-8') as f:
                    admin_data = json.load(f)
                    
                # Verify admin account is still valid
                if self._verify_admin_account(admin_data):
                    logger.info("Default admin account verified")
                    return {
                        "username": admin_data["username"],
                        "password": "[STORED_SECURELY]",
                        "status": "existing"
                    }
            except Exception as e:
                logger.error(f"Error reading default admin file: {e}")
        
        # Create new default admin
        return self._create_default_admin()
    
    def _create_default_admin(self) -> Dict[str, str]:
        """Create a new default admin account."""
        try:
            # Generate secure credentials
            username = "admin"
            password = self._generate_secure_password()
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create admin data
            admin_data = {
                "username": username,
                "password_hash": password_hash,
                "role": "super_admin",
                "created_at": datetime.now().isoformat(),
                "is_default": True,
                "must_change_password": True,
                "api_key": secrets.token_urlsafe(32),
                "permissions": [
                    "user_management", "system_config", "security_audit",
                    "backup_management", "cluster_management", "api_access",
                    "log_access", "performance_monitoring", "emergency_access"
                ]
            }
            
            # Save admin data
            with open(self.admin_file, 'w', encoding='utf-8') as f:
                json.dump(admin_data, f, indent=2)
            
            # Set restrictive permissions
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.admin_file, 0o600)
            
            # Save credentials to readable file (for first-time setup)
            self._save_credentials_file(username, password)
            
            logger.info("Default admin account created successfully")
            
            return {
                "username": username,
                "password": password,
                "status": "created"
            }
            
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
            raise
    
    def _generate_secure_password(self) -> str:
        """Generate a secure random password."""
        # Use a mix of characters for security
        import string
        
        # Ensure password has at least one of each type
        lowercase = secrets.choice(string.ascii_lowercase)
        uppercase = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice("!@#$%^&*")
        
        # Generate remaining characters
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        remaining = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Combine and shuffle
        password_chars = list(lowercase + uppercase + digit + special + remaining)
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_admin_account(self, admin_data: Dict) -> bool:
        """Verify admin account data is valid."""
        required_fields = ["username", "password_hash", "role", "created_at"]
        return all(field in admin_data for field in required_fields)
    
    def _save_credentials_file(self, username: str, password: str):
        """Save credentials to a readable file for first-time setup."""
        credentials_content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          PLEXICHAT DEFAULT ADMIN CREDENTIALS                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Username: {username:<63} ║
║  Password: {password:<63} ║
║                                                                              ║
║  IMPORTANT SECURITY NOTES:                                                   ║
║  • Change this password immediately after first login                       ║
║  • Delete this file after noting the credentials                            ║
║  • These credentials provide full system access                             ║
║  • Access is logged and monitored                                           ║
║                                                                              ║
║  Admin Panel: http://localhost:8000/ui                                      ║
║  Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<58} ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

SECURITY WARNING: This file contains sensitive credentials. 
Delete it immediately after copying the credentials to a secure location.

CLI Commands to manage admin users:
  python -m plexichat.cli.admin_manager list
  python -m plexichat.cli.admin_manager create --username newadmin --role admin
  python -m plexichat.cli.admin_manager reset-password --username admin

For security, this default account requires a password change on first login.
        """.strip()
        
        try:
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                f.write(credentials_content)
            
            # Set restrictive permissions
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.credentials_file, 0o600)
                
            logger.info(f"Default credentials saved to: {self.credentials_file}")
            
        except Exception as e:
            logger.error(f"Error saving credentials file: {e}")
    
    def get_default_admin_data(self) -> Optional[Dict]:
        """Get default admin data if it exists."""
        if not self.admin_file.exists():
            return None
        
        try:
            with open(self.admin_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading default admin data: {e}")
            return None
    
    def verify_admin_credentials(self, username: str, password: str) -> bool:
        """Verify admin credentials."""
        admin_data = self.get_default_admin_data()
        if not admin_data:
            return False
        
        if admin_data["username"] != username:
            return False
        
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                admin_data["password_hash"].encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Error verifying credentials: {e}")
            return False
    
    def update_admin_password(self, username: str, new_password: str) -> bool:
        """Update admin password."""
        admin_data = self.get_default_admin_data()
        if not admin_data or admin_data["username"] != username:
            return False
        
        try:
            # Hash new password
            admin_data["password_hash"] = self._hash_password(new_password)
            admin_data["must_change_password"] = False
            admin_data["password_changed_at"] = datetime.now().isoformat()
            
            # Save updated data
            with open(self.admin_file, 'w', encoding='utf-8') as f:
                json.dump(admin_data, f, indent=2)
            
            logger.info(f"Password updated for admin user: {username}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            return False
    
    def delete_credentials_file(self):
        """Delete the credentials file for security."""
        try:
            if self.credentials_file.exists():
                self.credentials_file.unlink()
                logger.info("Credentials file deleted for security")
        except Exception as e:
            logger.error(f"Error deleting credentials file: {e}")
    
    def get_admin_info(self) -> Dict[str, str]:
        """Get admin information for display."""
        admin_data = self.get_default_admin_data()
        if not admin_data:
            return {"status": "not_created"}
        
        return {
            "status": "exists",
            "username": admin_data["username"],
            "role": admin_data["role"],
            "created_at": admin_data["created_at"],
            "must_change_password": admin_data.get("must_change_password", False),
            "is_default": admin_data.get("is_default", False)
        }

# Global instance
default_admin_manager = DefaultAdminManager()

def ensure_default_admin() -> Dict[str, str]:
    """Ensure default admin exists and return credentials info."""
    return default_admin_manager.ensure_default_admin_exists()

def verify_admin_login(username: str, password: str) -> bool:
    """Verify admin login credentials."""
    return default_admin_manager.verify_admin_credentials(username, password)

def get_admin_info() -> Dict[str, str]:
    """Get admin account information."""
    return default_admin_manager.get_admin_info()
