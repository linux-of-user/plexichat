import hashlib
import io
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
from fastapi import HTTPException, status
from PIL import Image
from sqlmodel import Session, select

from plexichat.app.logger_config import logger
from plexichat.app.models.enhanced_models import (
    AccountType,
    BotAccount,
    BotType,
    Comprehensive,
    EnhancedUser,
    FileRecord,
    Friendship,
    FriendshipStatus,
    Handles,
    PlexiChat.,
    UserStatus,
    """,
    account,
    and,
    for,
    friends,
    from,
    import,
    management,
    operations.,
    plexichat.app.models.files,
    profiles,
    service,
    user,
)


class UserManagementService:
    """Service for comprehensive user management operations."""
    
    def __init__(self, session: Session):
        self.session = session
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        display_name: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        bio: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> EnhancedUser:
        """Create a new user with comprehensive profile information."""
        try:
            # Check if username or email already exists
            existing_user = self.session.exec(
                select(EnhancedUser).where(
                    (EnhancedUser.username == username) | (EnhancedUser.email == email)
                )
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    raise HTTPException(status_code=400, detail="Username already exists")
                else:
                    raise HTTPException(status_code=400, detail="Email already exists")
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user
            user = EnhancedUser(
                username=username,
                email=email,
                password_hash=password_hash,
                display_name=display_name or username,
                first_name=first_name,
                last_name=last_name,
                bio=bio,
                tags=tags or [],
                status=UserStatus.ACTIVE
            )
            
            self.session.add(user)
            self.session.commit()
            self.session.refresh(user)
            
            logger.info(f"Created new user: {username} (ID: {user.id})")
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error creating user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )

    async def create_bot_account(
        self,
        owner_id: int,
        bot_name: str,
        bot_description: str,
        bot_type: BotType = BotType.GENERAL,
        permissions: Optional[Dict[str, Any]] = None,
        rate_limits: Optional[Dict[str, Any]] = None
    ) -> Tuple[EnhancedUser, BotAccount]:
        """Create a new bot account with regulation and advanced features."""
        try:
            # Verify owner exists and has permission to create bots
            owner = self.session.exec(
                select(EnhancedUser).where(EnhancedUser.id == owner_id)
            ).first()

            if not owner:
                raise HTTPException(status_code=404, detail="Owner not found")

            # Check bot creation limits (max 5 bots per user)
            existing_bots = self.session.exec(
                select(EnhancedUser).where(
                    (EnhancedUser.bot_owner_id == owner_id) &
                    (EnhancedUser.account_type == AccountType.BOT)
                )
            ).all()

            if len(existing_bots) >= 5:
                raise HTTPException(
                    status_code=400,
                    detail="Maximum bot limit reached (5 bots per user)"
                )

            # Generate unique bot username
            base_username = f"bot_{bot_name.lower().replace(' ', '_')}"
            username = base_username
            counter = 1

            while self.session.exec(
                select(EnhancedUser).where(EnhancedUser.username == username)
            ).first():
                username = f"{base_username}_{counter}"
                counter += 1

            # Generate bot token and secret
            bot_token = secrets.token_urlsafe(32)
            bot_secret = secrets.token_urlsafe(16)

            # Create bot user account
            bot_user = EnhancedUser(
                username=username,
                email=f"{username}@bot.plexichat.local",
                password_hash="",  # Bots don't use passwords
                display_name=bot_name,
                account_type=AccountType.BOT,
                bot_type=bot_type,
                bot_owner_id=owner_id,
                bot_token=bot_token,
                bot_description=bot_description,
                bot_verified=False,
                status=UserStatus.ACTIVE,
                is_verified=False
            )

            self.session.add(bot_user)
            self.session.commit()
            self.session.refresh(bot_user)

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
                is_approved=False
            )

            self.session.add(bot_account)
            self.session.commit()
            self.session.refresh(bot_account)

            logger.info(f"Created bot account: {bot_name} (ID: {bot_user.id}) for owner: {owner.username}")
            return bot_user, bot_account

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error creating bot account: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create bot account"
            )

    async def update_bot_permissions(
        self,
        bot_id: int,
        owner_id: int,
        permissions: Dict[str, Any]
    ) -> BotAccount:
        """Update bot permissions with owner verification."""
        try:
            bot_account = self.session.exec(
                select(BotAccount).join(EnhancedUser).where(
                    (BotAccount.user_id == bot_id) &
                    (EnhancedUser.bot_owner_id == owner_id)
                )
            ).first()

            if not bot_account:
                raise HTTPException(status_code=404, detail="Bot not found or access denied")

            # Validate permissions
            allowed_permissions = {
                "send_messages", "read_messages", "manage_messages",
                "kick_members", "ban_members", "administrator",
                "manage_channels", "manage_server", "view_audit_log"
            }

            for perm in permissions.keys():
                if perm not in allowed_permissions:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid permission: {perm}"
                    )

            bot_account.permissions = permissions
            bot_account.updated_at = datetime.now(timezone.utc)

            self.session.commit()
            self.session.refresh(bot_account)

            logger.info(f"Updated permissions for bot: {bot_account.bot_name} (ID: {bot_id})")
            return bot_account

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error updating bot permissions: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update bot permissions"
            )

    async def get_user_bots(self, owner_id: int) -> List[Dict[str, Any]]:
        """Get all bots owned by a user."""
        try:
            bots = self.session.exec(
                select(EnhancedUser, BotAccount).join(BotAccount).where(
                    EnhancedUser.bot_owner_id == owner_id
                )
            ).all()

            bot_list = []
            for bot_user, bot_account in bots:
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
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve bots"
            )

    async def delete_bot_account(self, bot_id: int, owner_id: int) -> bool:
        """Delete a bot account with owner verification."""
        try:
            bot_user = self.session.exec(
                select(EnhancedUser).where(
                    (EnhancedUser.id == bot_id) &
                    (EnhancedUser.bot_owner_id == owner_id) &
                    (EnhancedUser.account_type == AccountType.BOT)
                )
            ).first()

            if not bot_user:
                raise HTTPException(status_code=404, detail="Bot not found or access denied")

            # Delete bot account record
            bot_account = self.session.exec(
                select(BotAccount).where(BotAccount.user_id == bot_id)
            ).first()

            if bot_account:
                self.session.delete(bot_account)

            # Delete bot user
            self.session.delete(bot_user)
            self.session.commit()

            logger.info(f"Deleted bot account: {bot_user.username} (ID: {bot_id})")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error deleting bot account: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete bot account"
            )
    
    async def update_user_profile(
        self,
        user_id: int,
        updates: Dict[str, Any]
    ) -> EnhancedUser:
        """Update user profile information."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Update allowed fields
            allowed_fields = {
                'display_name', 'first_name', 'last_name', 'bio', 'phone_number',
                'timezone', 'language', 'tags', 'custom_status', 'pronouns'
            }
            
            for field, value in updates.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)
            
            user.updated_at = datetime.now(timezone.utc)
            
            self.session.commit()
            self.session.refresh(user)
            
            logger.info(f"Updated profile for user {user_id}")
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error updating user profile: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )
    
    async def update_user_email(
        self,
        user_id: int,
        new_email: str,
        password: str
    ) -> bool:
        """Update user email with password verification."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                raise HTTPException(status_code=400, detail="Invalid password")
            
            # Check if email is already in use
            existing_user = self.session.exec(
                select(EnhancedUser).where(
                    (EnhancedUser.email == new_email) & (EnhancedUser.id != user_id)
                )
            ).first()
            
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already in use")
            
            user.email = new_email
            user.is_verified = False  # Require re-verification
            user.email_verified_at = None
            user.updated_at = datetime.now(timezone.utc)
            
            self.session.commit()
            
            logger.info(f"Updated email for user {user_id}")
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error updating user email: {e}")
            return False
    
    async def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str
    ) -> bool:
        """Change user password with current password verification."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Verify current password
            if not bcrypt.checkpw(current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
                raise HTTPException(status_code=400, detail="Invalid current password")
            
            # Hash new password
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            user.password_hash = new_password_hash
            user.password_changed_at = datetime.now(timezone.utc)
            user.updated_at = datetime.now(timezone.utc)
            
            self.session.commit()
            
            logger.info(f"Changed password for user {user_id}")
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error changing password: {e}")
            return False
    
    async def upload_profile_picture(
        self,
        user_id: int,
        file_data: bytes,
        filename: str,
        mime_type: str
    ) -> Optional[str]:
        """Upload and set user profile picture."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Validate image
            if not mime_type.startswith('image/'):
                raise HTTPException(status_code=400, detail="File must be an image")
            
            # Process image (resize, optimize)
            image = Image.open(io.BytesIO(file_data))
            
            # Resize to reasonable dimensions
            max_size = (512, 512)
            image.thumbnail(max_size, Image.Resampling.LANCZOS)
            
            # Convert to RGB if necessary
            if image.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', image.size, (255, 255, 255))
                if image.mode == 'P':
                    image = image.convert('RGBA')
                background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
                image = background
            
            # Save processed image
            output = io.BytesIO()
            image.save(output, format='JPEG', quality=85, optimize=True)
            processed_data = output.getvalue()
            
            # Create file record
            file_hash = hashlib.sha256(processed_data).hexdigest()
            processed_filename = f"profile_{user_id}_{file_hash[:8]}.jpg"
            
            # Save to uploads directory
            upload_dir = "uploads/profiles"
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, processed_filename)
            
            with open(file_path, 'wb') as f:
                f.write(processed_data)
            
            # Create file record
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
            
            self.session.add(file_record)
            self.session.commit()
            self.session.refresh(file_record)
            
            # Update user profile
            user.profile_picture_file_id = file_record.id
            user.avatar_url = f"/api/v1/files/download/{file_record.uuid}"
            user.updated_at = datetime.now(timezone.utc)
            
            self.session.commit()
            
            logger.info(f"Updated profile picture for user {user_id}")
            return user.avatar_url
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error uploading profile picture: {e}")
            return None
    
    async def delete_user_account(
        self,
        user_id: int,
        password: str,
        hard_delete: bool = False
    ) -> bool:
        """Delete user account (soft delete by default)."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                raise HTTPException(status_code=400, detail="Invalid password")
            
            if hard_delete:
                # Hard delete - remove from database
                self.session.delete(user)
                logger.info(f"Hard deleted user account {user_id}")
            else:
                # Soft delete - mark as deleted
                user.status = UserStatus.DELETED
                user.deleted_at = datetime.now(timezone.utc)
                user.email = f"deleted_{user.id}_{user.email}"  # Prevent email conflicts
                user.username = f"deleted_{user.id}_{user.username}"  # Prevent username conflicts
                logger.info(f"Soft deleted user account {user_id}")
            
            self.session.commit()
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error deleting user account: {e}")
            return False
    
    async def get_user_profile(
        self,
        user_id: int,
        include_private: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Get user profile information."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user or user.status == UserStatus.DELETED:
                return None
            
            profile = {
                "id": user.id,
                "uuid": user.uuid,
                "username": user.username,
                "display_name": user.display_name,
                "avatar_url": user.avatar_url,
                "bio": user.bio,
                "tags": user.tags,
                "custom_status": user.custom_status,
                "pronouns": user.pronouns,
                "status": user.status.value,
                "is_verified": user.is_verified,
                "created_at": user.created_at,
                "last_activity_at": user.last_activity_at
            }
            
            if include_private:
                profile.update({
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "phone_number": user.phone_number,
                    "timezone": user.timezone,
                    "language": user.language,
                    "two_factor_enabled": user.two_factor_enabled,
                    "email_verified_at": user.email_verified_at,
                    "login_count": user.login_count,
                    "message_count": user.message_count
                })
            
            return profile
            
        except Exception as e:
            logger.error(f"Error getting user profile: {e}")
            return None

    # Friend Management Methods
    async def send_friend_request(
        self,
        requester_id: int,
        addressee_id: int,
        message: Optional[str] = None
    ) -> bool:
        """Send a friend request."""
        try:
            if requester_id == addressee_id:
                raise HTTPException(status_code=400, detail="Cannot send friend request to yourself")

            # Check if users exist
            requester = self.session.get(EnhancedUser, requester_id)
            addressee = self.session.get(EnhancedUser, addressee_id)

            if not requester or not addressee:
                raise HTTPException(status_code=404, detail="User not found")

            # Check if friendship already exists
            existing_friendship = self.session.exec(
                select(Friendship).where(
                    ((Friendship.requester_id == requester_id) & (Friendship.addressee_id == addressee_id)) |
                    ((Friendship.requester_id == addressee_id) & (Friendship.addressee_id == requester_id))
                )
            ).first()

            if existing_friendship:
                if existing_friendship.status == FriendshipStatus.ACCEPTED:
                    raise HTTPException(status_code=400, detail="Already friends")
                elif existing_friendship.status == FriendshipStatus.PENDING:
                    raise HTTPException(status_code=400, detail="Friend request already pending")
                elif existing_friendship.status == FriendshipStatus.BLOCKED:
                    raise HTTPException(status_code=400, detail="Cannot send friend request")

            # Create friend request
            friendship = Friendship(
                requester_id=requester_id,
                addressee_id=addressee_id,
                status=FriendshipStatus.PENDING,
                message=message
            )

            self.session.add(friendship)
            self.session.commit()

            logger.info(f"Friend request sent from {requester_id} to {addressee_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error sending friend request: {e}")
            return False

    async def respond_to_friend_request(
        self,
        friendship_id: int,
        user_id: int,
        accept: bool
    ) -> bool:
        """Accept or decline a friend request."""
        try:
            friendship = self.session.get(Friendship, friendship_id)
            if not friendship:
                raise HTTPException(status_code=404, detail="Friend request not found")

            # Check if user is the addressee
            if friendship.addressee_id != user_id:
                raise HTTPException(status_code=403, detail="Cannot respond to this friend request")

            # Check if request is still pending
            if friendship.status != FriendshipStatus.PENDING:
                raise HTTPException(status_code=400, detail="Friend request is no longer pending")

            # Update status
            friendship.status = FriendshipStatus.ACCEPTED if accept else FriendshipStatus.DECLINED
            friendship.responded_at = datetime.now(timezone.utc)

            self.session.commit()

            action = "accepted" if accept else "declined"
            logger.info(f"Friend request {friendship_id} {action} by user {user_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error responding to friend request: {e}")
            return False

    async def remove_friend(
        self,
        user_id: int,
        friend_id: int
    ) -> bool:
        """Remove a friend (delete friendship)."""
        try:
            friendship = self.session.exec(
                select(Friendship).where(
                    ((Friendship.requester_id == user_id) & (Friendship.addressee_id == friend_id)) |
                    ((Friendship.requester_id == friend_id) & (Friendship.addressee_id == user_id))
                ).where(Friendship.status == FriendshipStatus.ACCEPTED)
            ).first()

            if not friendship:
                raise HTTPException(status_code=404, detail="Friendship not found")

            self.session.delete(friendship)
            self.session.commit()

            logger.info(f"Friendship removed between {user_id} and {friend_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error removing friend: {e}")
            return False

    async def block_user(
        self,
        blocker_id: int,
        blocked_id: int
    ) -> bool:
        """Block a user."""
        try:
            if blocker_id == blocked_id:
                raise HTTPException(status_code=400, detail="Cannot block yourself")

            # Check if friendship exists
            existing_friendship = self.session.exec(
                select(Friendship).where(
                    ((Friendship.requester_id == blocker_id) & (Friendship.addressee_id == blocked_id)) |
                    ((Friendship.requester_id == blocked_id) & (Friendship.addressee_id == blocker_id))
                )
            ).first()

            if existing_friendship:
                existing_friendship.status = FriendshipStatus.BLOCKED
                existing_friendship.responded_at = datetime.now(timezone.utc)
            else:
                # Create new blocked relationship
                friendship = Friendship(
                    requester_id=blocker_id,
                    addressee_id=blocked_id,
                    status=FriendshipStatus.BLOCKED
                )
                self.session.add(friendship)

            self.session.commit()

            logger.info(f"User {blocker_id} blocked user {blocked_id}")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error blocking user: {e}")
            return False

    async def get_friends_list(
        self,
        user_id: int
    ) -> List[Dict[str, Any]]:
        """Get user's friends list."""
        try:
            friendships = self.session.exec(
                select(Friendship).where(
                    ((Friendship.requester_id == user_id) | (Friendship.addressee_id == user_id)) &
                    (Friendship.status == FriendshipStatus.ACCEPTED)
                )
            ).all()

            friends = []
            for friendship in friendships:
                friend_id = friendship.addressee_id if friendship.requester_id == user_id else friendship.requester_id
                friend = self.session.get(EnhancedUser, friend_id)

                if friend and friend.status != UserStatus.DELETED:
                    friends.append({
                        "id": friend.id,
                        "uuid": friend.uuid,
                        "username": friend.username,
                        "display_name": friend.display_name,
                        "avatar_url": friend.avatar_url,
                        "status": friend.status.value,
                        "last_activity_at": friend.last_activity_at,
                        "friendship_date": friendship.responded_at
                    })

            return friends

        except Exception as e:
            logger.error(f"Error getting friends list: {e}")
            return []

    async def get_pending_friend_requests(
        self,
        user_id: int,
        sent: bool = False
    ) -> List[Dict[str, Any]]:
        """Get pending friend requests (received or sent)."""
        try:
            if sent:
                # Requests sent by user
                friendships = self.session.exec(
                    select(Friendship).where(
                        (Friendship.requester_id == user_id) &
                        (Friendship.status == FriendshipStatus.PENDING)
                    )
                ).all()

                requests = []
                for friendship in friendships:
                    addressee = self.session.get(EnhancedUser, friendship.addressee_id)
                    if addressee and addressee.status != UserStatus.DELETED:
                        requests.append({
                            "friendship_id": friendship.id,
                            "user": {
                                "id": addressee.id,
                                "uuid": addressee.uuid,
                                "username": addressee.username,
                                "display_name": addressee.display_name,
                                "avatar_url": addressee.avatar_url
                            },
                            "message": friendship.message,
                            "requested_at": friendship.requested_at
                        })
            else:
                # Requests received by user
                friendships = self.session.exec(
                    select(Friendship).where(
                        (Friendship.addressee_id == user_id) &
                        (Friendship.status == FriendshipStatus.PENDING)
                    )
                ).all()

                requests = []
                for friendship in friendships:
                    requester = self.session.get(EnhancedUser, friendship.requester_id)
                    if requester and requester.status != UserStatus.DELETED:
                        requests.append({
                            "friendship_id": friendship.id,
                            "user": {
                                "id": requester.id,
                                "uuid": requester.uuid,
                                "username": requester.username,
                                "display_name": requester.display_name,
                                "avatar_url": requester.avatar_url
                            },
                            "message": friendship.message,
                            "requested_at": friendship.requested_at
                        })

            return requests

        except Exception as e:
            logger.error(f"Error getting pending friend requests: {e}")
            return []

    async def search_users(
        self,
        query: str,
        limit: int = 20,
        exclude_user_id: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Search for users by username or display name."""
        try:
            # Build search query
            search_pattern = f"%{query.lower()}%"
            statement = select(EnhancedUser).where(
                (EnhancedUser.status != UserStatus.DELETED) &
                (
                    EnhancedUser.username.ilike(search_pattern) |
                    EnhancedUser.display_name.ilike(search_pattern)
                )
            )

            if exclude_user_id:
                statement = statement.where(EnhancedUser.id != exclude_user_id)

            statement = statement.limit(limit)
            users = self.session.exec(statement).all()

            results = []
            for user in users:
                results.append({
                    "id": user.id,
                    "uuid": user.uuid,
                    "username": user.username,
                    "display_name": user.display_name,
                    "avatar_url": user.avatar_url,
                    "bio": user.bio,
                    "tags": user.tags,
                    "status": user.status.value,
                    "is_verified": user.is_verified,
                    "last_activity_at": user.last_activity_at
                })

            return results

        except Exception as e:
            logger.error(f"Error searching users: {e}")
            return []

    async def get_user_statistics(
        self,
        user_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get user statistics and activity metrics."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user or user.status == UserStatus.DELETED:
                return None

            # Get friend count
            friends_count = len(await self.get_friends_list(user_id))

            # Get pending requests count
            pending_received = len(await self.get_pending_friend_requests(user_id, sent=False))
            pending_sent = len(await self.get_pending_friend_requests(user_id, sent=True))

            return {
                "user_id": user_id,
                "login_count": user.login_count,
                "message_count": user.message_count,
                "friends_count": friends_count,
                "pending_friend_requests": {
                    "received": pending_received,
                    "sent": pending_sent
                },
                "account_age_days": (datetime.now(timezone.utc) - user.created_at).days,
                "last_activity_at": user.last_activity_at,
                "is_verified": user.is_verified,
                "two_factor_enabled": user.two_factor_enabled
            }

        except Exception as e:
            logger.error(f"Error getting user statistics: {e}")
            return None

    async def update_user_activity(
        self,
        user_id: int
    ) -> bool:
        """Update user's last activity timestamp."""
        try:
            user = self.session.get(EnhancedUser, user_id)
            if not user:
                return False

            user.last_activity_at = datetime.now(timezone.utc)
            self.session.commit()

            return True

        except Exception as e:
            logger.error(f"Error updating user activity: {e}")
            return False
