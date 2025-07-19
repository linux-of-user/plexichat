"""
import time
PlexiChat Admin Management System

Unified admin management with authentication, permissions, and system control.
"""

import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from plexichat.app.logger_config import get_logger
    from plexichat.core.auth.credentials_admin import AdminCredentialsManager
    from plexichat.core.security.security_manager import SecurityManager
except ImportError:
    get_logger = logging.getLogger
    AdminCredentialsManager = None
    SecurityManager = None

logger = get_logger(__name__)

@dataclass
class AdminUser:
    """Admin user data model."""
    username: str
    email: str
    role: str
    permissions: List[str]
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    session_token: Optional[str] = None
    api_key: Optional[str] = None

@dataclass
class AdminSession:
    """Admin session data model."""
    token: str
    username: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class AdminManager:
    """Unified admin management system."""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("data/admin")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.admin_file = self.data_dir / "admins.json"
        self.sessions_file = self.data_dir / "sessions.json"

        self.admins: Dict[str, AdminUser] = {}
        self.sessions: Dict[str, AdminSession] = {}

        # Initialize credentials manager if available
        self.credentials_manager = AdminCredentialsManager() if AdminCredentialsManager else None
        self.security_manager = SecurityManager() if SecurityManager else None

        # Load existing data
        self._load_data()

        # Create default admin if none exist
        if not self.admins:
            self._create_default_admin()

    def _load_data(self):
        """Load admin and session data from files."""
        try:
            # Load admins
            if self.admin_file.exists():
                with open(self.admin_file, 'r') as f:
                    data = json.load(f)
                    for username, admin_data in data.items():
                        admin_data['created_at'] = datetime.fromisoformat(admin_data['created_at'])
                        if admin_data.get('last_login'):
                            admin_data['last_login'] = datetime.fromisoformat(admin_data['last_login'])
                        self.admins[username] = AdminUser(**admin_data)

            # Load sessions
            if self.sessions_file.exists():
                with open(self.sessions_file, 'r') as f:
                    data = json.load(f)
                    for token, session_data in data.items():
                        session_data['created_at'] = datetime.fromisoformat(session_data['created_at'])
                        session_data['expires_at'] = datetime.fromisoformat(session_data['expires_at'])
                        self.sessions[token] = AdminSession(**session_data)

            # Clean expired sessions
            self._clean_expired_sessions()

        except Exception as e:
            logger.error(f"Error loading admin data: {e}")

    def _save_data(self):
        """Save admin and session data to files."""
        try:
            # Save admins
            admin_data = {}
            for username, admin in self.admins.items():
                data = asdict(admin)
                data['created_at'] = admin.created_at.isoformat()
                if admin.last_login:
                    data['last_login'] = admin.last_login.isoformat()
                admin_data[username] = data

            with open(self.admin_file, 'w') as f:
                json.dump(admin_data, f, indent=2)

            # Save sessions
            session_data = {}
            for token, session in self.sessions.items():
                data = asdict(session)
                data['created_at'] = session.created_at.isoformat()
                data['expires_at'] = session.expires_at.isoformat()
                session_data[token] = data

            with open(self.sessions_file, 'w') as f:
                json.dump(session_data, f, indent=2)

        except Exception as e:
            logger.error(f"Error saving admin data: {e}")

    def _create_default_admin(self):
        """Create default admin user."""
        try:
            password = secrets.token_urlsafe(16)

            admin = AdminUser()
                username="admin",
                email="admin@plexichat.local",
                role="super_admin",
                permissions=[
                    "user_management", "system_config", "security_audit",
                    "backup_management", "cluster_management", "api_access",
                    "log_access", "performance_monitoring", "emergency_access"
                ],
                created_at=datetime.now(timezone.utc),
                api_key=secrets.token_urlsafe(32)
            )

            self.admins["admin"] = admin
            self._save_data()

            # Also create in credentials manager if available
            if self.credentials_manager:
                self.credentials_manager.create_admin_user("admin", password)

            logger.info(f"Default admin created - Username: admin, Password: {password}")

        except Exception as e:
            logger.error(f"Error creating default admin: {e}")

    def _clean_expired_sessions(self):
        """Remove expired sessions."""
        now = datetime.now(timezone.utc)
        expired_tokens = [
            token for token, session in self.sessions.items()
            if session.expires_at < now
        ]

        for token in expired_tokens:
            del self.sessions[token]

        if expired_tokens:
            self._save_data()

    async def authenticate(self, username: str, password: str, )
                          ip_address: Optional[str] = None,
                          user_agent: Optional[str] = None) -> Optional[str]:
        """Authenticate admin user and create session."""
        try:
            # Use credentials manager if available
            if self.credentials_manager:
                if not self.credentials_manager.verify_admin_credentials(username, password):
                    return None

            # Check if admin exists
            if username not in self.admins:
                return None

            admin = self.admins[username]
            if not admin.is_active:
                return None

            # Create session
            token = secrets.token_urlsafe(32)
            session = AdminSession(
                token=token,
                username=username,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
                ip_address=ip_address,
                user_agent=user_agent
            )

            self.sessions[token] = session

            # Update last login
            admin.last_login = datetime.now(timezone.utc)
            admin.session_token = token

            self._save_data()

            logger.info(f"Admin {username} authenticated successfully")
            return token

        except Exception as e:
            logger.error(f"Error authenticating admin: {e}")
            return None

    def validate_session(self, token: str) -> Optional[AdminUser]:
        """Validate admin session token."""
        try:
            self._clean_expired_sessions()

            if token not in self.sessions:
                return None

            session = self.sessions[token]
            admin = self.admins.get(session.username)

            if not admin or not admin.is_active:
                return None

            return admin

        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None

    def logout(self, token: str) -> bool:
        """Logout admin user."""
        try:
            if token in self.sessions:
                session = self.sessions[token]
                admin = self.admins.get(session.username)

                if admin:
                    admin.session_token = None

                del self.sessions[token]
                self._save_data()

                logger.info(f"Admin {session.username} logged out")
                return True

            return False

        except Exception as e:
            logger.error(f"Error logging out admin: {e}")
            return False

    def create_admin(self, username: str, email: str, password: str,):
                    role: str = "admin", permissions: Optional[List[str]] = None) -> bool:
        """Create new admin user."""
        try:
            if username in self.admins:
                return False

            admin = AdminUser()
                username=username,
                email=email,
                role=role,
                permissions=permissions or ["user_management", "system_config"],
                created_at=datetime.now(timezone.utc),
                api_key=secrets.token_urlsafe(32)
            )

            self.admins[username] = admin

            # Create in credentials manager if available
            if self.credentials_manager:
                self.credentials_manager.create_admin_user(username, password)

            self._save_data()

            logger.info(f"Admin {username} created successfully")
            return True

        except Exception as e:
            logger.error(f"Error creating admin: {e}")
            return False

    def get_admin(self, username: str) -> Optional[AdminUser]:
        """Get admin user by username."""
        return self.admins.get(username)

    def list_admins(self) -> List[AdminUser]:
        """List all admin users."""
        return list(self.admins.values())

    def has_permission(self, username: str, permission: str) -> bool:
        """Check if admin has specific permission."""
        admin = self.admins.get(username)
        if not admin:
            return False

        return permission in admin.permissions or admin.role == "super_admin"

# Global admin manager instance
admin_manager = AdminManager()

__all__ = ["AdminManager", "AdminUser", "AdminSession", "admin_manager"]
