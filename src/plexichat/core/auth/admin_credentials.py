import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import bcrypt

"""
PlexiChat Admin Credentials Manager
Handles secure storage and management of admin passwords separately from user passwords.
"""

logger = logging.getLogger(__name__)


class AdminCredentialsManager:
    """Manages admin credentials securely."""

    def __init__(self):
        """Initialize the admin credentials manager."""
        self.config_dir = Path.home() / ".plexichat"
        self.admin_creds_file = self.config_dir / "admin_credentials.json"
        self.default_creds_file = self.config_dir / "default_creds.txt"

        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)

        # Initialize admin credentials if they don't exist
        self._initialize_admin_credentials()

        logger.info("Admin credentials manager initialized")

    def _initialize_admin_credentials(self):
        """Initialize admin credentials from default_creds.txt or create new ones."""
        if self.admin_creds_file and not self.admin_creds_file.exists():
            # Check if default_creds.txt exists
            if self.default_creds_file and self.default_creds_file.exists():
                self._migrate_from_default_creds()
            else:
                self._create_default_admin()

    def _migrate_from_default_creds(self):
        """Migrate credentials from default_creds.txt."""
        try:
            with open(self.default_creds_file, 'r') as f:
                content = f.read().strip()

            # Parse default_creds.txt format
            lines = content.split('\n')
            username = "admin"
            password = "admin123"

            for line in lines:
                if line.startswith("Username:"):
                    username = line.split(":", 1)[1].strip()
                elif line.startswith("Password:"):
                    password = line.split(":", 1)[1].strip()

            # Create hashed admin credentials
            self.create_admin_user(username, password)

            # Update default_creds.txt to minimal content
            with open(self.default_creds_file, 'w') as f:
                f.write("# PlexiChat Admin Credentials\n")
                f.write("# Use 'plexichat admin password' command to change admin password\n")
                f.write(f"# Default admin username: {username}\n")

            logger.info("Migrated admin credentials from default_creds.txt")

        except Exception as e:
            logger.error(f"Failed to migrate from default_creds.txt: {e}")
            self._create_default_admin()

    def _create_default_admin(self):
        """Create default admin credentials."""
        self.create_admin_user("admin", "admin123")

        # Create minimal default_creds.txt
        with open(self.default_creds_file, 'w') as f:
            f.write("# PlexiChat Admin Credentials\n")
            f.write("# Use 'plexichat admin password' command to change admin password\n")
            f.write("# Default admin username: admin\n")
            f.write("# Default admin password: admin123\n")

        logger.info("Created default admin credentials")

    def _hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def create_admin_user(self, username: str, password: str) -> bool:
        """Create or update admin user credentials."""
        try:
            # Hash the password
            hashed_password = self._hash_password(password)

            # Create admin credentials structure
            admin_data = {
                "version": "1.0",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "admins": {
                    username: {
                        "password_hash": hashed_password,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "last_login": None,
                        "login_attempts": 0,
                        "locked_until": None,
                        "permissions": ["full_admin"],
                        "session_token": None
                    }
                }
            }

            # Save to file with restricted permissions
            with open(self.admin_creds_file, 'w') as f:
                json.dump(admin_data, f, indent=2)

            # Set restrictive file permissions (owner read/write only)
            os.chmod(self.admin_creds_file, 0o600)

            logger.info(f"Admin user '{username}' created/updated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to create admin user: {e}")
            return False

    def verify_admin_credentials(self, username: str, password: str) -> bool:
        """Verify admin credentials."""
        try:
            if not self.admin_creds_file.exists() if self.admin_creds_file else False:
                logger.warning("Admin credentials file not found")
                return False

            with open(self.admin_creds_file, 'r') as f:
                admin_data = json.load(f)

            if username not in admin_data.get("admins", {}):
                logger.warning(f"Admin user '{username}' not found")
                return False

            admin_info = admin_data["admins"][username]

            # Check if account is locked
            if admin_info.get("locked_until"):
                lock_time = datetime.fromisoformat(admin_info["locked_until"])
                if datetime.now(timezone.utc) < lock_time:
                    logger.warning(f"Admin account '{username}' is locked")
                    return False
                else:
                    # Unlock account
                    admin_info["locked_until"] = None
                    admin_info["login_attempts"] = 0

            # Verify password
            if self._verify_password(password, admin_info["password_hash"]):
                # Reset login attempts and update last login
                admin_info["login_attempts"] = 0
                admin_info["last_login"] = datetime.now(timezone.utc).isoformat()
                admin_info["locked_until"] = None

                # Save updated data
                with open(self.admin_creds_file, 'w') as f:
                    json.dump(admin_data, f, indent=2)

                logger.info(f"Admin '{username}' authenticated successfully")
                return True
            else:
                # Increment login attempts
                admin_info["login_attempts"] = admin_info.get("login_attempts", 0) + 1

                # Lock account after 5 failed attempts for 30 minutes
                if admin_info["login_attempts"] >= 5:
                    lock_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                    admin_info["locked_until"] = lock_until.isoformat()
                    logger.warning(f"Admin account '{username}' locked due to failed attempts")

                # Save updated data
                with open(self.admin_creds_file, 'w') as f:
                    json.dump(admin_data, f, indent=2)

                logger.warning(f"Invalid password for admin '{username}'")
                return False

        except Exception as e:
            logger.error(f"Admin credential verification error: {e}")
            return False

    def change_admin_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change admin password."""
        try:
            # Verify current password
            if not self.verify_admin_credentials(username, old_password):
                logger.warning(f"Failed to verify current password for admin '{username}'")
                return False

            # Load admin data
            with open(self.admin_creds_file, 'r') as f:
                admin_data = json.load(f)

            if username not in admin_data.get("admins", {}):
                return False

            # Update password
            admin_data["admins"][username]["password_hash"] = self._hash_password(new_password)
            admin_data["admins"][username]["last_updated"] = datetime.now(timezone.utc).isoformat()
            admin_data["last_updated"] = datetime.now(timezone.utc).isoformat()

            # Save updated data
            with open(self.admin_creds_file, 'w') as f:
                json.dump(admin_data, f, indent=2)

            logger.info(f"Password changed successfully for admin '{username}'")
            return True

        except Exception as e:
            logger.error(f"Failed to change admin password: {e}")
            return False

    def list_admin_users(self) -> Dict[str, Any]:
        """List all admin users (without sensitive data)."""
        try:
            if not self.admin_creds_file.exists() if self.admin_creds_file else False:
                return {}}}

            with open(self.admin_creds_file, 'r') as f:
                admin_data = json.load(f)

            # Return admin info without password hashes
            admin_list = {}
            for username, info in admin_data.get("admins", {}).items():
                admin_list[username] = {
                    "created_at": info.get("created_at"),
                    "last_login": info.get("last_login"),
                    "login_attempts": info.get("login_attempts", 0),
                    "locked": bool(info.get("locked_until")),
                    "permissions": info.get("permissions", [])
                }

            return admin_list

        except Exception as e:
            logger.error(f"Failed to list admin users: {e}")
            return {}}}

    def reset_admin_password(self, username: str) -> Optional[str]:
        """Reset admin password to a random password (emergency use)."""
        try:
            # Generate random password
            new_password = secrets.token_urlsafe(16)

            # Load admin data
            if not self.admin_creds_file.exists() if self.admin_creds_file else False:
                return None

            with open(self.admin_creds_file, 'r') as f:
                admin_data = json.load(f)

            if username not in admin_data.get("admins", {}):
                return None

            # Update password and reset locks
            admin_data["admins"][username]["password_hash"] = self._hash_password(new_password)
            admin_data["admins"][username]["login_attempts"] = 0
            admin_data["admins"][username]["locked_until"] = None
            admin_data["admins"][username]["last_updated"] = datetime.now(timezone.utc).isoformat()
            admin_data["last_updated"] = datetime.now(timezone.utc).isoformat()

            # Save updated data
            with open(self.admin_creds_file, 'w') as f:
                json.dump(admin_data, f, indent=2)

            logger.info(f"Password reset for admin '{username}'")
            return new_password

        except Exception as e:
            logger.error(f"Failed to reset admin password: {e}")
            return None


# Global admin credentials manager instance
admin_credentials_manager = AdminCredentialsManager()
