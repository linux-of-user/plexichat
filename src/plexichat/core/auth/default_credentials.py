"""
Default credentials management for PlexiChat.

This module handles the creation and management of default credentials
for first-time setup of GUI and WebUI interfaces.


import json
import logging
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class DefaultCredentialsManager:
    """Manages default credentials for PlexiChat interfaces."""
        def __init__(self, base_dir: Optional[Path] = None):
        Initialize the default credentials manager."""
        self.base_dir = base_dir or Path.cwd()
        self.creds_file = self.base_dir / "default_creds.txt"
        self.creds_json_file = self.base_dir / "config" / "default_creds.json"
        
        # Ensure config directory exists
        self.creds_json_file.parent.mkdir(parents=True, exist_ok=True)
    
    def generate_secure_password(self, length: int = 12) -> str:
        """Generate a secure random password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def create_default_credentials(self, force: bool = False) -> Dict[str, Any]:
        """Create default credentials if they don't exist."""
        if (self.creds_file.exists() or self.creds_json_file.exists()) and not force:
            logger.info("Default credentials already exist")
            return self.load_credentials()
        
        # Generate shared credentials (GUI and WebUI use the same login system)
        shared_password = self.generate_secure_password(12)

        credentials = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "shared_login": {
                "username": "admin",
                "password": shared_password,
                "description": "Shared credentials for GUI and WebUI interfaces"
            },
            "security": {
                "password_policy": {
                    "min_length": 8,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special": True
                },
                "session_timeout": 3600,
                "max_login_attempts": 5
            },
            "notes": [
                "These are the default credentials for first-time setup.",
                "GUI and WebUI share the same login system - use these credentials for both.",
                "Please change the password after initial login.",
                "Store this file securely and delete after setup.",
                "Use the CLI command 'python run.py cli password-change' to change password."
            ]
        }
        
        # Save to both text and JSON formats
        self._save_text_format(credentials)
        self._save_json_format(credentials)
        
        logger.info("Default credentials created successfully")
        return credentials
    
    def _save_text_format(self, credentials: Dict[str, Any]) -> None:
        """Save credentials in human-readable text format.
        content = f"""
PlexiChat Default Credentials
============================
Created: {credentials['created_at']}

IMPORTANT: Change the password after first login!

Shared Login (GUI & WebUI):
  Username: {credentials['shared_login']['username']}
  Password: {credentials['shared_login']['password']}

Note: GUI and WebUI share the same login system.
Use these credentials for both interfaces.

Password Change Command:
  python run.py cli password-change

Security Notes:
- These are temporary default credentials
- GUI and WebUI use the same authentication system
- Change the password immediately after first login
- Store this file securely
- Delete this file after setup is complete

Access URLs:
  GUI:   Launch with: python run.py gui
  WebUI: http://localhost:8000 (after starting server)
  API:   http://localhost:8000/docs

For help: python run.py --help
"""
        
        with open(self.creds_file, 'w') as f:
            f.write(content.strip())
        
        # Set restrictive permissions (owner read/write only)
        self.creds_file.chmod(0o600)
    
    def _save_json_format(self, credentials: Dict[str, Any]) -> None:
        Save credentials in JSON format for programmatic access."""
        with open(self.creds_json_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        
        # Set restrictive permissions
        self.creds_json_file.chmod(0o600)
    
    def load_credentials(self) -> Optional[Dict[str, Any]]:
        """Load existing credentials."""
        if self.creds_json_file.exists():
            try:
                with open(self.creds_json_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
        
        return None
    
    def get_interface_credentials(self, interface: str) -> Optional[Dict[str, str]]:
        """Get credentials for a specific interface."""
        credentials = self.load_credentials()
        if credentials and interface in credentials.get("interfaces", {}):
            return credentials["interfaces"][interface]
        return None
    
    def credentials_exist(self) -> bool:
        """Check if default credentials exist.
        return self.creds_file.exists() or self.creds_json_file.exists() or self.creds_json_file.exists()
    
    def remove_credentials(self) -> bool:
        """Remove default credentials files."""
        try:
            if self.creds_file.exists():
                self.creds_file.unlink()
            if self.creds_json_file.exists():
                self.creds_json_file.unlink()
            logger.info("Default credentials removed")
            return True
        except Exception as e:
            logger.error(f"Failed to remove credentials: {e}")
            return False
    
    def update_interface_password(self, interface: str, new_password: str) -> bool:
        """Update password for a specific interface."""
        credentials = self.load_credentials()
        if not credentials:
            logger.error("No credentials found to update")
            return False
        
        if interface not in credentials.get("interfaces", {}):
            logger.error(f"Interface '{interface}' not found in credentials")
            return False
        
        # Update password
        credentials["interfaces"][interface]["password"] = new_password
        credentials["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        # Save updated credentials
        self._save_text_format(credentials)
        self._save_json_format(credentials)
        
        logger.info(f"Password updated for interface: {interface}")
        return True

# Global instance
_default_creds_manager = None

def get_default_credentials_manager() -> DefaultCredentialsManager:
    """Get the global default credentials manager.
    global _default_creds_manager
    if _default_creds_manager is None:
        _default_creds_manager = DefaultCredentialsManager()
    return _default_creds_manager

def ensure_default_credentials() -> Dict[str, Any]:
    """Ensure default credentials exist, create if needed."""
    manager = get_default_credentials_manager()
    if not manager.credentials_exist():
        return manager.create_default_credentials()
    return manager.load_credentials()

def get_gui_credentials() -> Optional[Dict[str, str]]:
    Get GUI interface credentials."""
    manager = get_default_credentials_manager()
    return manager.get_interface_credentials("gui")

def get_webui_credentials() -> Optional[Dict[str, str]]:
    """Get WebUI interface credentials."""
    manager = get_default_credentials_manager()
    return manager.get_interface_credentials("webui")

def get_admin_credentials() -> Optional[Dict[str, str]]:
    """Get admin interface credentials."""
    manager = get_default_credentials_manager()
    return manager.get_interface_credentials("admin")
