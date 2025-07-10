"""
PlexiChat Authentication and Login Manager
Handles authentication for both web UI and desktop application.
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import jwt
from passlib.context import CryptContext

class LoginManager:
    """Manages authentication and login sessions."""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = self._get_secret_key()
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
        self.users_file = Path("data/users.json")
        self.sessions_file = Path("data/sessions.json")
        self.ensure_data_directory()
        self.ensure_default_admin()
    
    def _get_secret_key(self) -> str:
        """Get or generate secret key."""
        try:
            from app.logger_config import settings
            return getattr(settings, 'SECRET_KEY', self._generate_secret_key())
        except ImportError:
            return self._generate_secret_key()
    
    def _generate_secret_key(self) -> str:
        """Generate a new secret key."""
        return secrets.token_urlsafe(32)
    
    def ensure_data_directory(self):
        """Ensure data directory exists."""
        self.users_file.parent.mkdir(exist_ok=True)
        self.sessions_file.parent.mkdir(exist_ok=True)
    
    def ensure_default_admin(self):
        """Ensure default admin user exists."""
        if not self.users_file.exists():
            # Create default admin user
            admin_user = {
                "username": "admin",
                "email": "admin@plexichat.local",
                "hashed_password": self.get_password_hash("admin123"),
                "is_active": True,
                "is_admin": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None
            }
            
            users_data = {"admin": admin_user}
            self._save_users(users_data)
    
    def _load_users(self) -> Dict[str, Any]:
        """Load users from file."""
        if not self.users_file.exists():
            return {}
        
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_users(self, users_data: Dict[str, Any]):
        """Save users to file."""
        with open(self.users_file, 'w') as f:
            json.dump(users_data, f, indent=2)
    
    def _load_sessions(self) -> Dict[str, Any]:
        """Load sessions from file."""
        if not self.sessions_file.exists():
            return {}
        
        try:
            with open(self.sessions_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_sessions(self, sessions_data: Dict[str, Any]):
        """Save sessions to file."""
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions_data, f, indent=2)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password."""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user."""
        users = self._load_users()
        user = users.get(username)
        
        if not user:
            return None
        
        if not self.verify_password(password, user["hashed_password"]):
            return None
        
        if not user.get("is_active", True):
            return None
        
        # Update last login
        user["last_login"] = datetime.utcnow().isoformat()
        users[username] = user
        self._save_users(users)
        
        return user
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            
            if username is None:
                return None
            
            return {"username": username, "payload": payload}
        except jwt.PyJWTError:
            return None
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Login user and create session."""
        user = self.authenticate_user(username, password)
        
        if not user:
            return {
                "success": False,
                "message": "Invalid username or password"
            }
        
        # Create access token
        access_token = self.create_access_token(
            data={"sub": username, "admin": user.get("is_admin", False)}
        )
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        sessions = self._load_sessions()
        sessions[session_id] = {
            "username": username,
            "token": access_token,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)).isoformat(),
            "is_admin": user.get("is_admin", False)
        }
        self._save_sessions(sessions)
        
        return {
            "success": True,
            "message": "Login successful",
            "access_token": access_token,
            "session_id": session_id,
            "token_type": "bearer",
            "user": {
                "username": username,
                "email": user.get("email"),
                "is_admin": user.get("is_admin", False)
            }
        }
    
    def logout(self, session_id: str) -> Dict[str, Any]:
        """Logout user and remove session."""
        sessions = self._load_sessions()
        
        if session_id in sessions:
            del sessions[session_id]
            self._save_sessions(sessions)
            return {"success": True, "message": "Logout successful"}
        
        return {"success": False, "message": "Session not found"}
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Validate session."""
        sessions = self._load_sessions()
        session = sessions.get(session_id)
        
        if not session:
            return None
        
        # Check if session expired
        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.utcnow() > expires_at:
            # Remove expired session
            del sessions[session_id]
            self._save_sessions(sessions)
            return None
        
        return session
    
    def create_user(self, username: str, email: str, password: str, is_admin: bool = False) -> Dict[str, Any]:
        """Create a new user."""
        users = self._load_users()
        
        if username in users:
            return {"success": False, "message": "Username already exists"}
        
        # Check if email already exists
        for user_data in users.values():
            if user_data.get("email") == email:
                return {"success": False, "message": "Email already exists"}
        
        # Create user
        user = {
            "username": username,
            "email": email,
            "hashed_password": self.get_password_hash(password),
            "is_active": True,
            "is_admin": is_admin,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }
        
        users[username] = user
        self._save_users(users)
        
        return {"success": True, "message": "User created successfully"}
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """Change user password."""
        users = self._load_users()
        user = users.get(username)
        
        if not user:
            return {"success": False, "message": "User not found"}
        
        if not self.verify_password(old_password, user["hashed_password"]):
            return {"success": False, "message": "Invalid current password"}
        
        # Update password
        user["hashed_password"] = self.get_password_hash(new_password)
        users[username] = user
        self._save_users(users)
        
        return {"success": True, "message": "Password changed successfully"}
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        users = self._load_users()
        user = users.get(username)
        
        if not user:
            return None
        
        # Return user info without password hash
        return {
            "username": user["username"],
            "email": user.get("email"),
            "is_active": user.get("is_active", True),
            "is_admin": user.get("is_admin", False),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login")
        }
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users (admin only)."""
        users = self._load_users()
        user_list = []
        
        for username, user_data in users.items():
            user_list.append({
                "username": username,
                "email": user_data.get("email"),
                "is_active": user_data.get("is_active", True),
                "is_admin": user_data.get("is_admin", False),
                "created_at": user_data.get("created_at"),
                "last_login": user_data.get("last_login")
            })
        
        return user_list
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        sessions = self._load_sessions()
        current_time = datetime.utcnow()
        
        expired_sessions = []
        for session_id, session in sessions.items():
            expires_at = datetime.fromisoformat(session["expires_at"])
            if current_time > expires_at:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del sessions[session_id]
        
        if expired_sessions:
            self._save_sessions(sessions)
        
        return len(expired_sessions)

# Global login manager instance
login_manager = LoginManager()
