"""
Advanced Authentication System for PlexiChat
Custom login interface with password reset, attempt tracking, and modern security features.
"""

import secrets
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr

from ..security.enhanced_security import password_manager, rate_limiter, session_manager
from ..utils.utilities import config_manager, DateTimeUtils, StringUtils

class AuthAction(Enum):
    """Authentication actions."""
    LOGIN = "login"
    LOGOUT = "logout"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_CONFIRM = "password_reset_confirm"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"

@dataclass
class AuthAttempt:
    """Authentication attempt record."""
    timestamp: datetime
    username: str
    ip_address: str
    user_agent: str
    action: AuthAction
    success: bool
    failure_reason: Optional[str] = None
    reset_code: Optional[str] = None

@dataclass
class AdminAccount:
    """Enhanced admin account with full features."""
    username: str
    email: str
    password_hash: str
    role: str
    permissions: List[str]
    created_at: datetime
    last_login: Optional[datetime] = None
    login_count: int = 0
    failed_attempts: int = 0
    is_locked: bool = False
    locked_until: Optional[datetime] = None
    password_reset_code: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    preferences: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.preferences is None:
            self.preferences = {}

class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str
    remember_me: bool = False
    two_factor_code: Optional[str] = None

class PasswordResetRequest(BaseModel):
    """Password reset request model."""
    username: str
    email: str

class PasswordResetConfirm(BaseModel):
    """Password reset confirmation model."""
    username: str
    reset_code: str
    new_password: str

class AdvancedAuthManager:
    """Advanced authentication manager with comprehensive features."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.accounts_file = Path("data/admin_accounts.json")
        self.attempts_file = Path("data/auth_attempts.json")
        self.accounts: Dict[str, AdminAccount] = {}
        self.auth_attempts: List[AuthAttempt] = []
        self.reset_codes: Dict[str, str] = {}  # username -> reset_code
        
        # Configuration
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30
        self.reset_code_expiry_minutes = 15
        self.session_duration_minutes = 480  # 8 hours
        
        # Load existing data
        self._load_accounts()
        self._load_attempts()
        
        # Create default admin if none exist
        if not self.accounts:
            self._create_default_admin()
    
    def _load_accounts(self):
        """Load admin accounts from file."""
        try:
            if self.accounts_file.exists():
                with open(self.accounts_file, 'r') as f:
                    data = json.load(f)
                
                for username, account_data in data.items():
                    # Convert datetime strings back to datetime objects
                    if account_data.get('created_at'):
                        account_data['created_at'] = datetime.fromisoformat(account_data['created_at'])
                    if account_data.get('last_login'):
                        account_data['last_login'] = datetime.fromisoformat(account_data['last_login'])
                    if account_data.get('locked_until'):
                        account_data['locked_until'] = datetime.fromisoformat(account_data['locked_until'])
                    if account_data.get('password_reset_expires'):
                        account_data['password_reset_expires'] = datetime.fromisoformat(account_data['password_reset_expires'])
                    
                    self.accounts[username] = AdminAccount(**account_data)
                
                self.logger.info(f"Loaded {len(self.accounts)} admin accounts")
        except Exception as e:
            self.logger.error(f"Failed to load accounts: {e}")
    
    def _save_accounts(self):
        """Save admin accounts to file."""
        try:
            self.accounts_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert accounts to serializable format
            data = {}
            for username, account in self.accounts.items():
                account_dict = asdict(account)
                # Convert datetime objects to strings
                for field in ['created_at', 'last_login', 'locked_until', 'password_reset_expires']:
                    if account_dict.get(field):
                        account_dict[field] = account_dict[field].isoformat()
                data[username] = account_dict
            
            with open(self.accounts_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.debug("Admin accounts saved")
        except Exception as e:
            self.logger.error(f"Failed to save accounts: {e}")
    
    def _load_attempts(self):
        """Load authentication attempts from file."""
        try:
            if self.attempts_file.exists():
                with open(self.attempts_file, 'r') as f:
                    data = json.load(f)
                
                for attempt_data in data:
                    attempt_data['timestamp'] = datetime.fromisoformat(attempt_data['timestamp'])
                    attempt_data['action'] = AuthAction(attempt_data['action'])
                    self.auth_attempts.append(AuthAttempt(**attempt_data))
                
                # Keep only recent attempts (last 30 days)
                cutoff = datetime.now() - timedelta(days=30)
                self.auth_attempts = [a for a in self.auth_attempts if a.timestamp > cutoff]
                
                self.logger.info(f"Loaded {len(self.auth_attempts)} authentication attempts")
        except Exception as e:
            self.logger.error(f"Failed to load auth attempts: {e}")
    
    def _save_attempts(self):
        """Save authentication attempts to file."""
        try:
            self.attempts_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert attempts to serializable format
            data = []
            for attempt in self.auth_attempts[-1000:]:  # Keep last 1000 attempts
                attempt_dict = asdict(attempt)
                attempt_dict['timestamp'] = attempt_dict['timestamp'].isoformat()
                attempt_dict['action'] = attempt_dict['action'].value
                data.append(attempt_dict)
            
            with open(self.attempts_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.debug("Authentication attempts saved")
        except Exception as e:
            self.logger.error(f"Failed to save auth attempts: {e}")
    
    def _create_default_admin(self):
        """Create default admin account."""
        # Generate a secure random password
        import secrets
        import string

        # Create a strong random password
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        default_password = ''.join(secrets.choice(chars) for _ in range(20))

        # Ensure it meets complexity requirements
        while not (any(c.isupper() for c in default_password) and
                  any(c.islower() for c in default_password) and
                  any(c.isdigit() for c in default_password) and
                  any(c in "!@#$%^&*" for c in default_password)):
            default_password = ''.join(secrets.choice(chars) for _ in range(20))
        
        admin_account = AdminAccount(
            username="admin",
            email="admin@plexichat.local",
            password_hash=password_manager.hash_password(default_password),
            role="super_admin",
            permissions=["all"],
            created_at=datetime.now(),
            preferences={
                "theme": "dark",
                "language": "en",
                "timezone": "UTC",
                "notifications": True
            }
        )
        
        self.accounts["admin"] = admin_account
        self._save_accounts()
        
        self.logger.warning(f"Created default admin account with password: {default_password}")
        print(f"\n🔐 Default admin account created:")
        print(f"   Username: admin")
        print(f"   Password: {default_password}")
        print(f"   Please change this password after first login!\n")
    
    def authenticate(self, username: str, password: str, ip_address: str, user_agent: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Authenticate user with comprehensive security checks."""
        
        # Check rate limiting
        allowed, rate_limit_msg = rate_limiter.is_allowed(ip_address, "login")
        if not allowed:
            self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, rate_limit_msg)
            return False, rate_limit_msg, None
        
        # Check if account exists
        if username not in self.accounts:
            self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, "Account not found")
            rate_limiter.record_attempt(ip_address, False, "login")
            return False, "Invalid username or password", None
        
        account = self.accounts[username]
        
        # Check if account is locked
        if account.is_locked:
            if account.locked_until and datetime.now() < account.locked_until:
                remaining = account.locked_until - datetime.now()
                msg = f"Account locked for {remaining.seconds // 60} more minutes"
                self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, msg)
                return False, msg, None
            else:
                # Unlock account if lock period has expired
                account.is_locked = False
                account.locked_until = None
                account.failed_attempts = 0
                self._save_accounts()
        
        # Verify password
        if not password_manager.verify_password(password, account.password_hash):
            account.failed_attempts += 1
            
            # Lock account if too many failed attempts
            if account.failed_attempts >= self.max_failed_attempts:
                account.is_locked = True
                account.locked_until = datetime.now() + timedelta(minutes=self.lockout_duration_minutes)
                self._log_attempt(username, ip_address, user_agent, AuthAction.ACCOUNT_LOCKED, False, "Too many failed attempts")
            
            self._save_accounts()
            self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, False, "Invalid password")
            rate_limiter.record_attempt(ip_address, False, "login")
            return False, "Invalid username or password", None
        
        # Successful authentication
        account.failed_attempts = 0
        account.last_login = datetime.now()
        account.login_count += 1
        self._save_accounts()
        
        # Create session
        session_id = session_manager.create_session(username, ip_address, user_agent)
        
        self._log_attempt(username, ip_address, user_agent, AuthAction.LOGIN, True)
        rate_limiter.record_attempt(ip_address, True, "login")
        
        user_data = {
            "username": username,
            "email": account.email,
            "role": account.role,
            "permissions": account.permissions,
            "session_id": session_id,
            "preferences": account.preferences
        }
        
        return True, "Login successful", user_data
    
    def request_password_reset(self, username: str, email: str, ip_address: str, user_agent: str) -> Tuple[bool, str, Optional[str]]:
        """Request password reset with CLI terminal code."""
        
        if username not in self.accounts:
            self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_REQUEST, False, "Account not found")
            return False, "If the account exists, a reset code has been sent", None
        
        account = self.accounts[username]
        
        if account.email.lower() != email.lower():
            self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_REQUEST, False, "Email mismatch")
            return False, "If the account exists, a reset code has been sent", None
        
        # Generate reset code
        reset_code = StringUtils.generate_id(8).upper()
        account.password_reset_code = reset_code
        account.password_reset_expires = datetime.now() + timedelta(minutes=self.reset_code_expiry_minutes)
        
        self._save_accounts()
        self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_REQUEST, True, reset_code=reset_code)
        
        # Send code to CLI terminal (this will be displayed in the running CLI)
        self._send_reset_code_to_cli(username, reset_code)
        
        return True, "Reset code sent to CLI terminal", reset_code
    
    def _send_reset_code_to_cli(self, username: str, reset_code: str):
        """Send reset code to CLI terminal."""
        try:
            # Write to a special file that the CLI monitors
            cli_messages_file = Path("data/cli_messages.json")
            cli_messages_file.parent.mkdir(parents=True, exist_ok=True)
            
            message = {
                "timestamp": datetime.now().isoformat(),
                "type": "password_reset",
                "username": username,
                "reset_code": reset_code,
                "expires_at": (datetime.now() + timedelta(minutes=self.reset_code_expiry_minutes)).isoformat(),
                "message": f"🔐 Password reset code for {username}: {reset_code} (expires in {self.reset_code_expiry_minutes} minutes)"
            }
            
            # Load existing messages
            messages = []
            if cli_messages_file.exists():
                try:
                    with open(cli_messages_file, 'r') as f:
                        messages = json.load(f)
                except:
                    messages = []
            
            # Add new message
            messages.append(message)
            
            # Keep only recent messages (last 24 hours)
            cutoff = datetime.now() - timedelta(hours=24)
            messages = [m for m in messages if datetime.fromisoformat(m['timestamp']) > cutoff]
            
            # Save messages
            with open(cli_messages_file, 'w') as f:
                json.dump(messages, f, indent=2)
            
            self.logger.info(f"Reset code {reset_code} sent to CLI for user {username}")
            
        except Exception as e:
            self.logger.error(f"Failed to send reset code to CLI: {e}")
    
    def confirm_password_reset(self, username: str, reset_code: str, new_password: str, ip_address: str, user_agent: str) -> Tuple[bool, str]:
        """Confirm password reset with code."""
        
        if username not in self.accounts:
            self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_CONFIRM, False, "Account not found")
            return False, "Invalid reset code"
        
        account = self.accounts[username]
        
        # Check reset code
        if (not account.password_reset_code or 
            account.password_reset_code != reset_code or
            not account.password_reset_expires or
            datetime.now() > account.password_reset_expires):
            
            self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_CONFIRM, False, "Invalid or expired reset code")
            return False, "Invalid or expired reset code"
        
        # Validate new password
        valid, issues = password_manager.validate_password_strength(new_password)
        if not valid:
            return False, f"Password requirements not met: {'; '.join(issues)}"
        
        # Update password
        account.password_hash = password_manager.hash_password(new_password)
        account.password_reset_code = None
        account.password_reset_expires = None
        account.failed_attempts = 0
        account.is_locked = False
        account.locked_until = None
        
        self._save_accounts()
        self._log_attempt(username, ip_address, user_agent, AuthAction.PASSWORD_RESET_CONFIRM, True)
        
        return True, "Password reset successful"
    
    def _log_attempt(self, username: str, ip_address: str, user_agent: str, action: AuthAction, success: bool, failure_reason: str = None, reset_code: str = None):
        """Log authentication attempt."""
        attempt = AuthAttempt(
            timestamp=datetime.now(),
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            success=success,
            failure_reason=failure_reason,
            reset_code=reset_code
        )
        
        self.auth_attempts.append(attempt)
        self._save_attempts()
        
        # Log to standard logger
        log_level = logging.INFO if success else logging.WARNING
        self.logger.log(log_level, f"Auth {action.value}: {username} from {ip_address} - {'SUCCESS' if success else 'FAILED'}")
    
    def get_account(self, username: str) -> Optional[AdminAccount]:
        """Get account by username."""
        return self.accounts.get(username)
    
    def create_account(self, username: str, email: str, password: str, role: str, permissions: List[str]) -> Tuple[bool, str]:
        """Create new admin account."""
        if username in self.accounts:
            return False, "Username already exists"
        
        # Validate password
        valid, issues = password_manager.validate_password_strength(password)
        if not valid:
            return False, f"Password requirements not met: {'; '.join(issues)}"
        
        account = AdminAccount(
            username=username,
            email=email,
            password_hash=password_manager.hash_password(password),
            role=role,
            permissions=permissions,
            created_at=datetime.now(),
            preferences={
                "theme": "light",
                "language": "en",
                "timezone": "UTC",
                "notifications": True
            }
        )
        
        self.accounts[username] = account
        self._save_accounts()
        
        return True, "Account created successfully"
    
    def get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        recent_attempts = [a for a in self.auth_attempts if a.timestamp > last_24h]
        weekly_attempts = [a for a in self.auth_attempts if a.timestamp > last_7d]
        
        return {
            "total_accounts": len(self.accounts),
            "locked_accounts": sum(1 for a in self.accounts.values() if a.is_locked),
            "attempts_24h": len(recent_attempts),
            "failed_attempts_24h": sum(1 for a in recent_attempts if not a.success),
            "attempts_7d": len(weekly_attempts),
            "unique_ips_24h": len(set(a.ip_address for a in recent_attempts)),
            "password_resets_24h": sum(1 for a in recent_attempts if a.action == AuthAction.PASSWORD_RESET_REQUEST)
        }

# Authentication router
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

# Templates
import os
template_dir = os.path.join(os.path.dirname(__file__), "..", "web", "templates")
templates = Jinja2Templates(directory=template_dir)

@auth_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Custom login page."""
    return templates.TemplateResponse("auth/login.html", {"request": request})

@auth_router.post("/login")
async def login(request: Request, login_data: LoginRequest):
    """Authenticate user."""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    success, message, user_data = auth_manager.authenticate(
        login_data.username,
        login_data.password,
        client_ip,
        user_agent
    )

    if success:
        response = JSONResponse({
            "success": True,
            "message": message,
            "data": user_data
        })

        # Set session cookie
        if user_data and user_data.get("session_id"):
            response.set_cookie(
                "plexichat_session",
                user_data["session_id"],
                max_age=auth_manager.session_duration_minutes * 60,
                httponly=True,
                secure=True,
                samesite="strict"
            )

        return response
    else:
        return JSONResponse({
            "success": False,
            "message": message
        }, status_code=401)

@auth_router.post("/password-reset-request")
async def password_reset_request(request: Request, reset_data: PasswordResetRequest):
    """Request password reset."""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    success, message, reset_code = auth_manager.request_password_reset(
        reset_data.username,
        reset_data.email,
        client_ip,
        user_agent
    )

    return JSONResponse({
        "success": success,
        "message": message
    })

@auth_router.post("/password-reset-confirm")
async def password_reset_confirm(request: Request, confirm_data: PasswordResetConfirm):
    """Confirm password reset."""
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    success, message = auth_manager.confirm_password_reset(
        confirm_data.username,
        confirm_data.reset_code,
        confirm_data.new_password,
        client_ip,
        user_agent
    )

    return JSONResponse({
        "success": success,
        "message": message
    })

@auth_router.post("/verify-session")
async def verify_session(request: Request, session_data: dict):
    """Verify session validity."""
    session_id = session_data.get("session_id")
    if not session_id:
        return JSONResponse({"success": False, "message": "No session ID provided"})

    client_ip = request.client.host
    session = session_manager.validate_session(session_id, client_ip)

    if session:
        return JSONResponse({
            "success": True,
            "data": {
                "username": session["user_id"],
                "valid": True
            }
        })
    else:
        return JSONResponse({"success": False, "message": "Invalid session"})

@auth_router.post("/logout")
async def logout(request: Request):
    """Logout user."""
    session_id = request.cookies.get("plexichat_session")
    if session_id:
        session_manager.destroy_session(session_id)

    response = JSONResponse({"success": True, "message": "Logged out successfully"})
    response.delete_cookie("plexichat_session")
    return response

@auth_router.get("/stats")
async def auth_stats():
    """Get authentication statistics."""
    return JSONResponse(auth_manager.get_auth_stats())

# Global auth manager instance
auth_manager = AdvancedAuthManager()
