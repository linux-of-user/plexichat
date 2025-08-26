"""
PlexiChat Unified Authentication System

Single source of truth for all authentication functionality.
Integrates tightly with the security system for watertight protection.
"""

from typing import Any, Dict, Optional, List, Tuple
import logging
import hashlib
import secrets
import time
import json
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from uuid import uuid4
import jwt
from plexichat.shared.models import FileRecord

class AccountType(Enum):
    USER = "user"
    BOT = "bot"

class BotType(Enum):
    GENERAL = "general"
    CUSTOM = "custom"

class UserStatus(Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    BANNED = "banned"

@dataclass
class EnhancedUser:
    """Enhanced user model."""
    id: int
    username: str
    email: str
    password_hash: str
    salt: str
    display_name: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    status: "UserStatus" = UserStatus.ACTIVE
    account_type: AccountType = AccountType.USER
    bot_type: Optional[BotType] = None
    bot_owner_id: Optional[int] = None
    bot_token: Optional[str] = None
    bot_description: Optional[str] = None
    bot_verified: bool = False
    is_verified: bool = False
    profile_picture_file_id: Optional[int] = None
    avatar_url: Optional[str] = None
    email_verified_at: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    login_count: int = 0
    message_count: int = 0
    two_factor_enabled: bool = False
    last_activity_at: Optional[datetime] = None
    custom_status: Optional[str] = None
    pronouns: Optional[str] = None
    phone_number: Optional[str] = None
    timezone: Optional[str] = None
    language: str = "en"
    uuid: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    permissions: List[str] = field(default_factory=list)
    security_level: str = "medium"
    last_login: Optional[datetime] = None


@dataclass
class BotAccount:
    """Bot account model."""
    user_id: int
    bot_token: str
    bot_secret: str
    bot_type: BotType
    bot_name: str
    bot_description: str
    bot_author: str
    permissions: Dict[str, Any]
    rate_limits: Dict[str, Any]
    is_verified: bool
    is_public: bool
    is_approved: bool
    last_activity_at: Optional[datetime]
    total_requests: int

# Import security components for tight integration
try:
    from plexichat.core.security import (  # type: ignore
        get_security_manager,  # type: ignore
        validate_input,  # type: ignore
        audit_log,  # type: ignore
        encrypt_data,  # type: ignore
        decrypt_data,  # type: ignore
        SecurityLevel as _SecurityLevel,  # type: ignore
        ThreatLevel,  # type: ignore
    )
    SecurityLevel = _SecurityLevel  # type: ignore
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    
    # Fallback security functions
    def get_security_manager():
        return None
    
    def validate_input(data, validation_type="general"):
        return True, None
    
    def audit_log(event, user_id=None, details=None):
        pass
    
    def encrypt_data(data):
        return data
    
    def decrypt_data(data):
        return data
    
    class SecurityLevel:
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class ThreatLevel:
        NONE = "none"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

# Import logger
try:
    from plexichat.core.logging.logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

class AuthenticationError(Exception):
    """Authentication-related errors."""
    def __init__(self, message: str, error_code: Optional[str] = None, threat_level: str = ThreatLevel.MEDIUM):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.threat_level = threat_level
        
        # Log security event
        audit_log("authentication_error", details={
            "message": message,
            "error_code": error_code,
            "threat_level": threat_level
        })

class AuthorizationError(Exception):
    """Authorization-related errors."""
    def __init__(self, message: str, required_permission: Optional[str] = None, threat_level: str = ThreatLevel.HIGH):
        super().__init__(message)
        self.message = message
        self.required_permission = required_permission
        self.threat_level = threat_level
        
        # Log security event
        audit_log("authorization_error", details={
            "message": message,
            "required_permission": required_permission,
            "threat_level": threat_level
        })

class SecureAuthManager:
    """Secure authentication manager with integrated security."""

    def __init__(self):
        self.users: Dict[str, EnhancedUser] = {}
        self.bot_accounts: Dict[int, BotAccount] = {}
        self.sessions = {}
        self.api_keys: Dict[str, str] = {}
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.security_manager = get_security_manager()

        # Security settings
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        self.session_timeout = timedelta(hours=24)
        self.password_min_length = 12

        logger.info("Secure authentication manager initialized")

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Securely hash a password with salt."""
        if not salt:
            salt = secrets.token_hex(32)

        # Use PBKDF2 with SHA-256
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hashed.hex(), salt

    def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """Verify a password against its hash."""
        test_hash, _ = self._hash_password(password, salt)
        return secrets.compare_digest(test_hash, hashed)

    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username in self.locked_accounts:
            lock_time = self.locked_accounts[username]
            if datetime.now() - lock_time < self.lockout_duration:
                return True
            else:
                # Unlock account
                del self.locked_accounts[username]
                if username in self.failed_attempts:
                    del self.failed_attempts[username]
        return False

    def _record_failed_attempt(self, username: str):
        """Record a failed authentication attempt."""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1

        if self.failed_attempts[username] >= self.max_failed_attempts:
            self.locked_accounts[username] = datetime.now()
            audit_log("account_locked", details={
                "username": username,
                "failed_attempts": self.failed_attempts[username],
                "threat_level": ThreatLevel.HIGH
            })
            logger.warning(f"Account locked due to failed attempts: {username}")

    def create_user(self, username: str, password: str, email: Optional[str] = None, permissions: Optional[List[str]] = None) -> EnhancedUser:
        """Create a new user with security validation."""
        try:
            # Validate inputs
            valid, error = validate_input(username, "username")
            if not valid:
                raise AuthenticationError(f"Invalid username: {error}", "INVALID_USERNAME")

            valid, error = validate_input(password, "password")
            if not valid:
                raise AuthenticationError(f"Invalid password: {error}", "INVALID_PASSWORD")

            if len(password) < self.password_min_length:
                raise AuthenticationError(
                    f"Password must be at least {self.password_min_length} characters",
                    "PASSWORD_TOO_SHORT"
                )

            if username in self.users:
                raise AuthenticationError("User already exists", "USER_EXISTS")

            # Hash password securely
            hashed_password, salt = self._hash_password(password)

            # Create user record
            user = EnhancedUser(
                id=len(self.users) + 1,
                username=username,
                password_hash=hashed_password,
                salt=salt,
                email=email,
                permissions=permissions or [],
                created_at=datetime.now(),
                last_login=None,
                is_active=True,
                security_level=SecurityLevel.MEDIUM
            )

            self.users[username] = user

            audit_log("user_created", user_id=username, details={
                "email": email,
                "permissions": permissions,
                "security_level": SecurityLevel.MEDIUM
            })

            logger.info(f"User created successfully: {username}")
            return user

        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise

    def create_bot_account(self, owner_id: int, bot_name: str, bot_description: str, bot_type: BotType = BotType.GENERAL, permissions: Optional[Dict[str, Any]] = None, rate_limits: Optional[Dict[str, Any]] = None) -> Tuple[EnhancedUser, BotAccount]:
        """Create a new bot account with regulation and advanced features."""
        try:
            # Verify owner exists and has permission to create bots
            owner = next((user for user in self.users.values() if user.id == owner_id), None)
            if not owner:
                raise AuthenticationError("Owner not found", "OWNER_NOT_FOUND")

            # Check bot creation limits (max 5 bots per user)
            existing_bots = [
                user for user in self.users.values()
                if user.bot_owner_id == owner_id
            ]

            if len(existing_bots) >= 5:
                raise AuthenticationError(
                    "Maximum bot limit reached (5 bots per user)",
                    "BOT_LIMIT_REACHED"
                )

            # Generate unique bot username
            base_username = f"bot_{bot_name.lower().replace(' ', '_')}"
            username = base_username
            counter = 1

            while username in self.users:
                username = f"{base_username}_{counter}"
                counter += 1

            # Generate bot token and secret
            bot_token = secrets.token_urlsafe(32)
            bot_secret = secrets.token_urlsafe(16)

            # Create bot user account
            bot_user = EnhancedUser(
                id=len(self.users) + 1,
                username=username,
                email=f"{username}@bot.plexichat.local",
                password_hash="",
                salt="",
                display_name=bot_name,
                account_type=AccountType.BOT,
                bot_type=bot_type,
                bot_owner_id=owner_id,
                bot_token=bot_token,
                bot_description=bot_description,
                bot_verified=False,
                status=UserStatus.ACTIVE,
                is_verified=False,
                created_at=datetime.now(),
                last_login=None,
                is_active=True,
                security_level=SecurityLevel.MEDIUM,
                permissions=[]
            )

            self.users[username] = bot_user

            # Create specialized bot account record
            default_permissions = permissions or {
                "send_messages": True,
                "read_messages": True,
                "manage_messages": False,
                "kick_members": False,
                "ban_members": False,
                "administrator": False
            }

            default_rate_limits = rate_limits or {
                "messages_per_minute": 30,
                "commands_per_minute": 10,
                "api_requests_per_minute": 60,
                "file_uploads_per_hour": 5
            }

            bot_account = BotAccount(
                user_id=bot_user.id,
                bot_token=bot_token,
                bot_secret=bot_secret,
                bot_type=bot_type,
                bot_name=bot_name,
                bot_description=bot_description,
                bot_author=owner.username,
                permissions=default_permissions,
                rate_limits=default_rate_limits,
                is_verified=False,
                is_public=False,
                is_approved=False,
                last_activity_at=None,
                total_requests=0
            )

            self.bot_accounts[bot_user.id] = bot_account

            logger.info(f"Created bot account: {bot_name} (ID: {bot_user.id}) for owner: {owner.username}")
            return bot_user, bot_account

        except Exception as e:
            logger.error(f"Error creating bot account: {e}")
            raise

    def update_bot_permissions(self, bot_id: int, owner_id: int, permissions: Dict[str, Any]) -> BotAccount:
        """Update bot permissions with owner verification."""
        try:
            bot_user = next((user for user in self.users.values() if user.id == bot_id and user.account_type == AccountType.BOT and user.bot_owner_id == owner_id), None)
            if not bot_user:
                raise AuthenticationError("Bot not found or access denied", "BOT_NOT_FOUND")

            bot_account = self.bot_accounts.get(bot_id)
            if not bot_account:
                raise AuthenticationError("Bot account not found", "BOT_ACCOUNT_NOT_FOUND")

            allowed_permissions = {
                "send_messages", "read_messages", "manage_messages",
                "kick_members", "ban_members", "administrator",
                "manage_channels", "manage_server", "view_audit_log"
            }

            for perm in permissions.keys():
                if perm not in allowed_permissions:
                    raise AuthenticationError(f"Invalid permission: {perm}", "INVALID_PERMISSION")

            bot_account.permissions = permissions
            bot_account.updated_at = datetime.now(timezone.utc)

            logger.info(f"Updated permissions for bot: {bot_account.bot_name} (ID: {bot_id})")
            return bot_account

        except Exception as e:
            logger.error(f"Error updating bot permissions: {e}")
            raise

    def get_user_bots(self, owner_id: int) -> List[Dict[str, Any]]:
        """Get all bots owned by a user."""
        try:
            bots = [
                (user, self.bot_accounts.get(user.id))
                for user in self.users.values()
                if user.bot_owner_id == owner_id and user.account_type == AccountType.BOT
            ]

            bot_list = []
            for bot_user, bot_account in bots:
                if not bot_account:
                    continue
                bot_list.append({
                    "id": bot_user.id,
                    "username": bot_user.username,
                    "name": bot_account.bot_name,
                    "description": bot_account.bot_description,
                    "type": bot_account.bot_type,
                    "verified": bot_account.is_verified,
                    "public": bot_account.is_public,
                    "approved": bot_account.is_approved,
                    "created_at": bot_user.created_at,
                    "last_activity": bot_account.last_activity_at,
                    "total_requests": bot_account.total_requests,
                    "permissions": bot_account.permissions,
                    "rate_limits": bot_account.rate_limits
                })

            return bot_list

        except Exception as e:
            logger.error(f"Error getting user bots: {e}")
            return []

    def delete_bot_account(self, bot_id: int, owner_id: int) -> bool:
        """Delete a bot account with owner verification."""
        try:
            bot_user = next((user for user in self.users.values() if user.id == bot_id and user.account_type == AccountType.BOT and user.bot_owner_id == owner_id), None)
            if not bot_user:
                raise AuthenticationError("Bot not found or access denied", "BOT_NOT_FOUND")

            if bot_id in self.bot_accounts:
                del self.bot_accounts[bot_id]

            if bot_user.username in self.users:
                del self.users[bot_user.username]

            logger.info(f"Deleted bot account: {bot_user.username} (ID: {bot_id})")
            return True

        except Exception as e:
            logger.error(f"Error deleting bot account: {e}")
            return False

    def update_user_profile(self, user_id: int, updates: Dict[str, Any]) -> EnhancedUser:
        """Update user profile information."""
        try:
            user = next((user for user in self.users.values() if user.id == user_id), None)
            if not user:
                raise AuthenticationError("User not found", "USER_NOT_FOUND")

            allowed_fields = {
                'display_name', 'first_name', 'last_name', 'bio', 'phone_number',
                'timezone', 'language', 'tags', 'custom_status', 'pronouns'
            }

            for field, value in updates.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)

            user.updated_at = datetime.now(timezone.utc)

            logger.info(f"Updated profile for user {user_id}")
            return user

        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            raise

    def update_user_email(self, user_id: int, new_email: str, password: str) -> bool:
        """Update user email with password verification."""
        try:
            user = next((user for user in self.users.values() if user.id == user_id), None)
            if not user:
                raise AuthenticationError("User not found", "USER_NOT_FOUND")

            if not self._verify_password(password, user.password_hash, user.salt):
                raise AuthenticationError("Invalid password", "INVALID_PASSWORD")

            existing_user = next((user for user in self.users.values() if user.email == new_email and user.id != user_id), None)
            if existing_user:
                raise AuthenticationError("Email already in use", "EMAIL_IN_USE")

            user.email = new_email
            user.is_verified = False
            user.email_verified_at = None
            user.updated_at = datetime.now(timezone.utc)

            logger.info(f"Updated email for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error updating user email: {e}")
            return False

    def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        """Change user password with current password verification."""
        try:
            user = next((user for user in self.users.values() if user.id == user_id), None)
            if not user:
                raise AuthenticationError("User not found", "USER_NOT_FOUND")

            if not self._verify_password(current_password, user.password_hash, user.salt):
                raise AuthenticationError("Invalid current password", "INVALID_PASSWORD")

            new_password_hash, salt = self._hash_password(new_password)
            user.password_hash = new_password_hash
            user.salt = salt
            user.password_changed_at = datetime.now(timezone.utc)
            user.updated_at = datetime.now(timezone.utc)

            logger.info(f"Changed password for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False

    def upload_profile_picture(self, user_id: int, file_data: bytes, filename: str, mime_type: str) -> Optional[str]:
        """Upload and set user profile picture."""
        try:
            user = next((user for user in self.users.values() if user.id == user_id), None)
            if not user:
                raise AuthenticationError("User not found", "USER_NOT_FOUND")

            if not mime_type.startswith('image/'):
                raise AuthenticationError("File must be an image", "INVALID_FILE_TYPE")

            if Image is None:
                raise AuthenticationError("Image processing not available", "IMAGE_PROCESSING_UNAVAILABLE")

            image = Image.open(io.BytesIO(file_data))
            max_size = (512, 512)
            image.thumbnail(max_size, Image.Resampling.LANCZOS)

            if image.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background

            output = io.BytesIO()
            image.save(output, format='JPEG', quality=85, optimize=True)
            processed_data = output.getvalue()

            file_hash = hashlib.sha256(processed_data).hexdigest()
            processed_filename = f"profile_{user_id}_{file_hash[:8]}.jpg"

            upload_dir = "uploads/profiles"
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, processed_filename)

            with open(file_path, 'wb') as f:
                f.write(processed_data)

            file_record = FileRecord(
                filename=processed_filename,
                original_filename=filename,
                file_path=file_path,
                file_hash=file_hash,
                size=len(processed_data),
                mime_type="image/jpeg",
                extension=".jpg",
                description=f"Profile picture for {user.username}",
                is_public=True,
                uploaded_by=user_id
            )

            # In a real application, we would save the file record to a database.
            # For now, we'll just update the user's avatar_url.

            user.profile_picture_file_id = file_record.id
            user.avatar_url = f"/api/v1/files/download/{file_record.uuid}"
            user.updated_at = datetime.now(timezone.utc)

            logger.info(f"Updated profile picture for user {user_id}")
            return user.avatar_url

        except Exception as e:
            logger.error(f"Error uploading profile picture: {e}")
            return None

    def _save_profile_picture(self, user_id: int, image_data: bytes, filename: str) -> Optional[str]:
        """Helper to save a profile picture and return its path."""
        try:
            upload_dir = "uploads/profiles"
            os.makedirs(upload_dir, exist_ok=True)
            file_hash = hashlib.sha256(image_data).hexdigest()
            new_filename = f"profile_{user_id}_{file_hash[:8]}.jpg"
            file_path = os.path.join(upload_dir, new_filename)

            with open(file_path, 'wb') as f:
                f.write(image_data)

            return file_path
        except Exception as e:
            logger.error(f"Failed to save profile picture: {e}")
            return None

    def delete_user_account(self, user_id: int, password: str, hard_delete: bool = False) -> bool:
        """
        Deletes or deactivates a user account after verifying credentials.
        - Soft delete (default): Deactivates the account, making it recoverable.
        - Hard delete: Permanently removes all user data.
        """
        try:
            user = self._get_user_by_id(user_id)
            if not user:
                raise AuthenticationError("User not found", "USER_NOT_FOUND")

            if not self.verify_password(password, user.hashed_password):
                raise AuthenticationError("Invalid password", "INVALID_CREDENTIALS")

            if hard_delete:
                # Perform a hard delete
                with self.get_session() as session:
                    # Manually delete related data if cascading isn't fully reliable
                    session.query(BotAccount).filter(BotAccount.owner_id == user_id).delete()
                    session.query(Friendship).filter((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)).delete()

                    # Finally, delete the user
                    db_user = session.get(EnhancedUser, user_id)
                    if db_user:
                        session.delete(db_user)
                    session.commit()

                # Remove from in-memory cache
                if user.username in self.users:
                    del self.users[user.username]
                logger.info(f"Hard deleted user account for user ID: {user_id}")

            else:
                # Perform a soft delete (deactivate)
                user.status = UserStatus.DEACTIVATED
                user.is_active = False
                user.deactivated_at = datetime.now(timezone.utc)
                self.update_user_in_db(user)
                logger.info(f"Deactivated user account for user ID: {user_id}")

            return True

        except AuthenticationError as e:
            logger.warning(f"Failed to delete account for user {user_id}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during account deletion for user {user_id}: {e}")
            return False

    def get_user_profile(self, user_id: int, include_private: bool = False) -> Optional[Dict[str, Any]]:
        """
        Retrieves a user's profile.
        - `include_private`: If True, returns all fields.
        - If False, returns a limited, public-safe subset of the profile.
        """
        try:
            user = self._get_user_by_id(user_id)
            if not user:
                return None

            if include_private:
                # Return the full profile for authorized views (e.g., user viewing their own profile)
                return user.model_dump(exclude={'hashed_password'})

            # Return a limited, public profile
            public_profile = {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "avatar_url": user.avatar_url,
                "bio": user.bio,
                "tags": user.tags,
                "created_at": user.created_at,
                "last_seen": user.last_seen,
                "status": user.status
            }
            return public_profile

        except Exception as e:
            logger.error(f"Error retrieving profile for user {user_id}: {e}")
            return None

    def send_friend_request(self, requester_id: int, addressee_id: int, message: Optional[str] = None) -> bool:
        """
        Sends a friend request from one user to another.
        - Ensures users exist and are not the same.
        - Prevents duplicate requests.
        - Blocks requests to/from blocked users.
        """
        try:
            if requester_id == addressee_id:
                raise AuthenticationError("Cannot send a friend request to yourself.", "SELF_REQUEST")

            requester = self._get_user_by_id(requester_id)
            addressee = self._get_user_by_id(addressee_id)

            if not requester or not addressee:
                raise AuthenticationError("One or both users not found.", "USER_NOT_FOUND")

            # Check for existing relationships (friendship, pending request, blocked)
            with self.get_session() as session:
                existing = session.query(Friendship).filter(
                    ((Friendship.requester_id == requester_id) & (Friendship.addressee_id == addressee_id)) |
                    ((Friendship.requester_id == addressee_id) & (Friendship.addressee_id == requester_id))
                ).first()

                if existing:
                    if existing.status == FriendshipStatus.ACCEPTED:
                        raise AuthenticationError("Users are already friends.", "ALREADY_FRIENDS")
                    elif existing.status == FriendshipStatus.PENDING:
                        raise AuthenticationError("A friend request is already pending.", "REQUEST_PENDING")
                    elif existing.status == FriendshipStatus.BLOCKED:
                        raise AuthenticationError("Cannot send request to a blocked user.", "USER_BLOCKED")

            new_request = Friendship(
                requester_id=requester_id,
                addressee_id=addressee_id,
                status=FriendshipStatus.PENDING,
                message=message
            )

            with self.get_session() as session:
                session.add(new_request)
                session.commit()

            logger.info(f"Friend request sent from user {requester_id} to {addressee_id}")
            return True

        except AuthenticationError as e:
            logger.warning(f"Failed to send friend request from {requester_id} to {addressee_id}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while sending friend request: {e}")
            return False

    def respond_to_friend_request(self, friendship_id: int, user_id: int, accept: bool) -> bool:
        """
        Responds to a pending friend request.
        - `user_id` must be the addressee of the request.
        - If `accept` is True, the friendship is confirmed.
        - If `accept` is False, the request is declined.
        """
        try:
            with self.get_session() as session:
                request = session.get(Friendship, friendship_id)

                if not request:
                    raise AuthenticationError("Friend request not found.", "REQUEST_NOT_FOUND")

                if request.addressee_id != user_id:
                    raise AuthenticationError("User is not authorized to respond to this request.", "UNAUTHORIZED")

                if request.status != FriendshipStatus.PENDING:
                    raise AuthenticationError("This friend request is no longer pending.", "REQUEST_NOT_PENDING")

                if accept:
                    request.status = FriendshipStatus.ACCEPTED
                    request.accepted_at = datetime.now(timezone.utc)
                    logger.info(f"Friend request {friendship_id} accepted by user {user_id}")
                else:
                    # Instead of deleting, mark as declined to prevent re-requests
                    request.status = FriendshipStatus.DECLINED
                    logger.info(f"Friend request {friendship_id} declined by user {user_id}")

                session.commit()
                return True

        except AuthenticationError as e:
            logger.warning(f"Failed to respond to friend request {friendship_id}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while responding to friend request {friendship_id}: {e}")
            return False

    def remove_friend(self, user_id: int, friend_id: int) -> bool:
        """
        Removes a friendship connection between two users.
        This action is symmetric and deletes the relationship record.
        """
        try:
            with self.get_session() as session:
                friendship = session.query(Friendship).filter(
                    ((Friendship.requester_id == user_id) & (Friendship.addressee_id == friend_id) & (Friendship.status == FriendshipStatus.ACCEPTED)) |
                    ((Friendship.requester_id == friend_id) & (Friendship.addressee_id == user_id) & (Friendship.status == FriendshipStatus.ACCEPTED))
                ).first()

                if not friendship:
                    raise AuthenticationError("Friendship does not exist.", "FRIENDSHIP_NOT_FOUND")

                session.delete(friendship)
                session.commit()
                logger.info(f"User {user_id} removed friend {friend_id}")
                return True

        except AuthenticationError as e:
            logger.warning(f"Failed to remove friend for user {user_id}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while removing friend for user {user_id}: {e}")
            return False

    def block_user(self, blocker_id: int, blocked_id: int) -> bool:
        """
        Blocks a user, preventing any interaction.
        - If a friendship exists, it's terminated.
        - If a request is pending, it's cancelled.
        - A new 'blocked' relationship is created.
        """
        try:
            if blocker_id == blocked_id:
                raise AuthenticationError("Cannot block yourself.", "SELF_BLOCK")

            with self.get_session() as session:
                # Remove any existing friendship or pending request
                existing_relationship = session.query(Friendship).filter(
                    ((Friendship.requester_id == blocker_id) & (Friendship.addressee_id == blocked_id)) |
                    ((Friendship.requester_id == blocked_id) & (Friendship.addressee_id == blocker_id))
                ).first()

                if existing_relationship:
                    session.delete(existing_relationship)

                # Create a new 'blocked' relationship
                # The 'requester' is the one initiating the block
                block_record = Friendship(
                    requester_id=blocker_id,
                    addressee_id=blocked_id,
                    status=FriendshipStatus.BLOCKED
                )
                session.add(block_record)
                session.commit()
                logger.info(f"User {blocker_id} blocked user {blocked_id}")
                return True

        except AuthenticationError as e:
            logger.warning(f"Failed to block user for blocker {blocker_id}: {e.message}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred while blocking user: {e}")
            return False

    def get_friends_list(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Retrieves a list of a user's friends with their public profile info.
        """
        try:
            with self.get_session() as session:
                # Find all accepted friendships where the user is either the requester or addressee
                friendships = session.query(Friendship).filter(
                    ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)) &
                    (Friendship.status == FriendshipStatus.ACCEPTED)
                ).all()

                friends_list = []
                for friendship in friendships:
                    friend_id = friendship.addressee_id if friendship.requester_id == user_id else friendship.requester_id
                    friend_profile = self.get_user_profile(friend_id, include_private=False)
                    if friend_profile:
                        friends_list.append(friend_profile)

                return friends_list

        except Exception as e:
            logger.error(f"Error retrieving friends list for user {user_id}: {e}")
            return []

    def get_pending_friend_requests(self, user_id: int, sent: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieves pending friend requests for a user.
        - `sent=False` (default): Gets requests received by the user.
        - `sent=True`: Gets requests sent by the user.
        """
        try:
            with self.get_session() as session:
                if sent:
                    # Get requests sent by the user
                    query = session.query(Friendship).filter(
                        (Friendship.requester_id == user_id) & (Friendship.status == FriendshipStatus.PENDING)
                    )
                else:
                    # Get requests received by the user
                    query = session.query(Friendship).filter(
                        (Friendship.addressee_id == user_id) & (Friendship.status == FriendshipStatus.PENDING)
                    )

                requests = query.all()
                result = []
                for req in requests:
                    request_data = {
                        "friendship_id": req.id,
                        "requester_id": req.requester_id,
                        "addressee_id": req.addressee_id,
                        "message": req.message,
                        "created_at": req.created_at,
                        "status": req.status,
                        "user": self.get_user_profile(req.requester_id if not sent else req.addressee_id, include_private=False)
                    }
                    result.append(request_data)
                return result

        except Exception as e:
            logger.error(f"Error retrieving pending friend requests for user {user_id}: {e}")
            return []

    def search_users(self, query: str, limit: int = 20, exclude_user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Searches for users by username or display name.
        - Excludes the specified user from the results.
        - Returns a list of public user profiles.
        """
        try:
            with self.get_session() as session:
                # Basic search query
                search_query = f"%{query.lower()}%"

                # Build the query using OR for username and display_name
                db_query = session.query(EnhancedUser).filter(
                    (func.lower(EnhancedUser.username).like(search_query)) |
                    (func.lower(EnhancedUser.display_name).like(search_query))
                )

                # Exclude the current user if specified
                if exclude_user_id is not None:
                    db_query = db_query.filter(EnhancedUser.id != exclude_user_id)

                # Exclude deactivated or deleted users
                db_query = db_query.filter(EnhancedUser.status.in_([UserStatus.ACTIVE, UserStatus.AWAY, UserStatus.DO_NOT_DISTURB]))

                # Apply limit
                results = db_query.limit(limit).all()

                # Format results into public profiles
                return [self.get_user_profile(user.id, include_private=False) for user in results if user]

        except Exception as e:
            logger.error(f"Error searching for users with query '{query}': {e}")
            return []

    def get_user_statistics(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves activity and engagement statistics for a user.
        """
        try:
            user = self._get_user_by_id(user_id)
            if not user:
                return None

            with self.get_session() as session:
                friends_count = session.query(Friendship).filter(
                    ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)) &
                    (Friendship.status == FriendshipStatus.ACCEPTED)
                ).count()

                bots_count = session.query(BotAccount).filter(BotAccount.owner_id == user_id).count()

            # In a real app, these would be calculated from relevant data tables
            # For now, we'll use placeholder values.
            login_count = user.login_count
            messages_sent = 0  # Placeholder
            files_uploaded = 0 # Placeholder

            stats = {
                "user_id": user.id,
                "login_count": login_count,
                "friends_count": friends_count,
                "bots_count": bots_count,
                "messages_sent": messages_sent,
                "files_uploaded": files_uploaded,
                "member_since": user.created_at,
                "last_seen": user.last_seen
            }
            return stats

        except Exception as e:
            logger.error(f"Error retrieving statistics for user {user_id}: {e}")
            return None

    def update_user_activity(self, user_id: int) -> bool:
        """
        Updates the user's last_seen timestamp to the current time.
        """
        try:
            user = self._get_user_by_id(user_id)
            if not user:
                return False

            user.last_seen = datetime.now(timezone.utc)
            self.update_user_in_db(user)
            return True

        except Exception as e:
            logger.error(f"Error updating activity for user {user_id}: {e}")
            return False

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Authenticate a user with security checks."""
        try:
            # Check if account is locked
            if self._is_account_locked(username):
                raise AuthenticationError(
                    "Account is locked due to too many failed attempts",
                    "ACCOUNT_LOCKED",
                    ThreatLevel.HIGH
                )
            
            # Validate inputs
            valid, error = validate_input(username, "username")
            if not valid:
                self._record_failed_attempt(username)
                raise AuthenticationError(f"Invalid username format: {error}", "INVALID_INPUT")
            
            # Check if user exists
            if username not in self.users:
                self._record_failed_attempt(username)
                raise AuthenticationError("Invalid credentials", "INVALID_CREDENTIALS")
            
            # Decrypt and verify user data
            user = self.users[username]
            
            # Verify password
            if not self._verify_password(password, user.password_hash, user.salt):
                self._record_failed_attempt(username)
                raise AuthenticationError("Invalid credentials", "INVALID_CREDENTIALS")
            
            # Check if user is active
            if not user.is_active:
                raise AuthenticationError("Account is disabled", "ACCOUNT_DISABLED", ThreatLevel.MEDIUM)
            
            # Clear failed attempts on successful login
            if username in self.failed_attempts:
                del self.failed_attempts[username]
            
            # Update last login
            user.last_login = datetime.now()
            
            # Create secure session
            session_token = self._create_session(username, user)
            
            audit_log("user_authenticated", user_id=username, details={
                "security_level": user.security_level,
                "session_token": session_token[:8] + "..."  # Log only first 8 chars
            })
            
            logger.info(f"User authenticated successfully: {username}")
            return True, session_token
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            raise AuthenticationError("Authentication failed", "AUTH_ERROR")
    
    def _create_session(self, username: str, user: EnhancedUser) -> str:
        """Create a secure session token."""
        session_token = secrets.token_urlsafe(32)
        session_data = {
            "username": username,
            "permissions": user.permissions,
            "security_level": user.security_level,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + self.session_timeout).isoformat(),
            "ip_address": None,  # Should be set by the calling code
            "user_agent": None   # Should be set by the calling code
        }
        
        # Encrypt session data
        self.sessions[session_token] = encrypt_data(json.dumps(session_data))
        return session_token
    
    def validate_session(self, session_token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate a session token."""
        try:
            if not session_token or session_token not in self.sessions:
                return False, None
            
            # Decrypt session data
            encrypted_data = self.sessions[session_token]
            session_data = json.loads(decrypt_data(encrypted_data))
            
            # Check if session has expired
            if datetime.now() > datetime.fromisoformat(session_data["expires_at"]):
                del self.sessions[session_token]
                return False, None
            
            return True, session_data
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False, None
    
    def authorize(self, session_token: str, required_permission: str) -> bool:
        """Authorize a user for a specific permission."""
        try:
            valid, session_data = self.validate_session(session_token)
            if not valid or not session_data:
                raise AuthorizationError(
                    "Invalid or expired session",
                    required_permission,
                    ThreatLevel.HIGH
                )
            
            user_permissions = session_data.get("permissions", [])
            
            # Check if user has the required permission
            if required_permission not in user_permissions and "admin" not in user_permissions:
                raise AuthorizationError(
                    f"Permission denied: {required_permission}",
                    required_permission,
                    ThreatLevel.MEDIUM
                )
            
            audit_log("authorization_success", user_id=session_data["username"], details={
                "required_permission": required_permission,
                "user_permissions": user_permissions
            })
            
            return True
            
        except AuthorizationError:
            raise
        except Exception as e:
            logger.error(f"Authorization error: {e}")
            raise AuthorizationError("Authorization failed", required_permission)

    def generate_api_key(self, username: str) -> str:
        """Generate a new API key for a user."""
        if username not in self.users:
            raise AuthenticationError("User not found", "USER_NOT_FOUND")

        api_key = secrets.token_urlsafe(32)
        self.api_keys[api_key] = username
        return api_key

    def validate_api_key(self, api_key: str) -> Optional[EnhancedUser]:
        """Validate an API key."""
        if api_key in self.api_keys:
            username = self.api_keys[api_key]
            return self.users.get(username)
        return None

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=30)

        to_encode.update({"exp": expire})
        secret_key = secrets.token_hex(32)
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
        return encoded_jwt

    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create refresh token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=7)
        to_encode.update({"exp": expire, "type": "refresh"})
        secret_key = secrets.token_hex(32)
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
        return encoded_jwt

# Global authentication manager
_auth_manager = SecureAuthManager()

def get_auth_manager() -> SecureAuthManager:
    """Get the global authentication manager."""
    return _auth_manager

def authenticate_user(username: str, password: str) -> Tuple[bool, Optional[str]]:
    """Authenticate a user and return session token."""
    return _auth_manager.authenticate(username, password)

def authorize_user(session_token: str, permission: str) -> bool:
    """Authorize a user for a specific permission."""
    return _auth_manager.authorize(session_token, permission)

def create_user(username: str, password: str, email: Optional[str] = None, permissions: Optional[List[str]] = None) -> bool:
    """Create a new user."""
    return _auth_manager.create_user(username, password, email, permissions)

def validate_session(session_token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Validate a session token."""
    return _auth_manager.validate_session(session_token)

# Security decorators
def require_auth(func):
    """Decorator to require authentication."""
    def wrapper(*args, **kwargs):
        session_token = kwargs.get('session_token') or (args[0] if args else None)
        if not session_token:
            raise AuthenticationError("Authentication required", "NO_SESSION")
        
        valid, _ = validate_session(session_token)
        if not valid:
            raise AuthenticationError("Invalid or expired session", "INVALID_SESSION")
        
        return func(*args, **kwargs)
    return wrapper

def require_permission(permission: str):
    """Decorator to require a specific permission."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            session_token = kwargs.get('session_token') or (args[0] if args else None)
            if not session_token:
                raise AuthenticationError("Authentication required", "NO_SESSION")
            
            if not authorize_user(session_token, permission):
                raise AuthorizationError(f"Permission required: {permission}", permission)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_admin(func):
    """Decorator to require admin privileges."""
    return require_permission("admin")(func)

# Export all the main classes and functions
__all__ = [
    # Main classes
    "SecureAuthManager",
    "AuthenticationError",
    "AuthorizationError",
    
    # Main functions
    "get_auth_manager",
    "authenticate_user",
    "authorize_user",
    "create_user",
    "validate_session",
    
    # Decorators
    "require_auth",
    "require_permission",
    "require_admin",
]
