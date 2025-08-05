# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


from plexichat.app.logger_config import logger
from plexichat.core.config import settings
from plexichat.core.config import settings
from plexichat.core.config import settings
from plexichat.core.config import settings

"""
Comprehensive Social & Friends System for PlexiChat.
Implements friend requests, friend lists, social features, and peer-to-peer messaging.
"""

class FriendshipStatus(Enum):
    """Status of friendship between users."""
    PENDING = "pending"          # Friend request sent, awaiting response
    ACCEPTED = "accepted"        # Friends
    BLOCKED = "blocked"          # User blocked
    DECLINED = "declined"        # Friend request declined
    CANCELLED = "cancelled"      # Friend request cancelled


class SocialActivityType(Enum):
    """Types of social activities."""
    FRIEND_REQUEST_SENT = "friend_request_sent"
    FRIEND_REQUEST_RECEIVED = "friend_request_received"
    FRIEND_ADDED = "friend_added"
    FRIEND_REMOVED = "friend_removed"
    USER_BLOCKED = "user_blocked"
    USER_UNBLOCKED = "user_unblocked"
    STATUS_UPDATED = "status_updated"
    PROFILE_UPDATED = "profile_updated"


class UserStatus(Enum):
    """User online status."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"
    OFFLINE = "offline"


@dataclass
class Friendship:
    """Represents a friendship or friend request."""
    friendship_id: str
    requester_id: int
    recipient_id: int
    status: FriendshipStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    message: Optional[str] = None  # Optional message with friend request
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class UserProfile:
    """Extended user profile for social features."""
    user_id: int
    display_name: str
    bio: Optional[str] = None
    status: UserStatus = UserStatus.OFFLINE
    status_message: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None
    birthday: Optional[datetime] = None
    joined_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    privacy_settings: Optional[Dict[str, Any]] = None
    social_links: Optional[Dict[str, str]] = None
    badges: Optional[List[str]] = None

    def __post_init__(self):
        if self.joined_at is None:
joined_at = datetime.now()
datetime = datetime.now()
        if self.privacy_settings is None:
            self.privacy_settings = {
                "show_online_status": True,
                "allow_friend_requests": True,
                "show_last_seen": True,
                "show_birthday": False,
                "show_location": False
            }


@dataclass
class SocialActivity:
    """Represents a social activity/event."""
    activity_id: str
    user_id: int
    activity_type: SocialActivityType
    target_user_id: Optional[int] = None
    data: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
created_at = datetime.now()
datetime = datetime.now()


class SocialService:
    """Comprehensive social and friends service."""

    def __init__(self):
        self.friendships: Dict[str, Friendship] = {}
        self.user_profiles: Dict[int, UserProfile] = {}
        self.social_activities: Dict[str, SocialActivity] = {}
        self.blocked_users: Dict[int, Set[int]] = {}  # user_id -> set of blocked user_ids

        # Load existing data
        self._load_social_data()

        logger.info(" Social service initialized")

    def _load_social_data(self):
        """Load social data from storage."""
        try:
            # In a real implementation, this would load from database
            logger.info(" Loaded social data")
        except Exception as e:
            logger.error(f"Failed to load social data: {e}")

    def _save_social_data(self):
        """Save social data to storage."""
        try:
            # In a real implementation, this would save to database
            logger.info(" Saved social data")
        except Exception as e:
            logger.error(f"Failed to save social data: {e}")

    def _generate_friendship_id(self, user1_id: int, user2_id: int) -> str:
        """Generate a unique friendship ID."""
        # Ensure consistent ordering
        min_id, max_id = min(user1_id, user2_id), max(user1_id, user2_id)
        return f"friendship_{min_id}_{max_id}"

    def _generate_activity_id(self) -> str:
        """Generate a unique activity ID."""
        return f"activity_{int(time.time() * 1000)}_{time.time_ns() % 1000000}"

    def create_user_profile():
        self,
        user_id: int,
        display_name: str,
        bio: Optional[str] = None,
        privacy_settings: Optional[Dict[str, Any]] = None
    ) -> UserProfile:
        """Create or update a user profile."""
        try:
            existing_profile = self.user_profiles.get(user_id)

            if existing_profile:
                # Update existing profile
                existing_profile.display_name = display_name
                if bio is not None:
                    existing_profile.bio = bio
                if privacy_settings:
                    existing_profile.privacy_from plexichat.core.config import settings
settings.update(privacy_settings)
                profile = existing_profile
            else:
                # Create new profile
                profile = UserProfile()
                    user_id=user_id,
                    display_name=display_name,
                    bio=bio,
                    privacy_settings=privacy_settings
                )
                self.user_profiles[user_id] = profile

            self._save_social_data()

            # Log activity
            self._log_activity()
                user_id=user_id,
                activity_type=SocialActivityType.PROFILE_UPDATED,
                data={"display_name": display_name}
            )

            logger.info(f" Created/updated profile for user {user_id}")
            return profile

        except Exception as e:
            logger.error(f"Failed to create user profile: {e}")
            raise

    def get_user_profile(self, user_id: int) -> Optional[UserProfile]:
        """Get a user's profile."""
        return self.user_profiles.get(user_id)

    def update_user_status():
        self,
        user_id: int,
        status: UserStatus,
        status_message: Optional[str] = None
    ) -> bool:
        """Update a user's online status."""
        try:
            profile = self.user_profiles.get(user_id)
            if not profile:
                # Create basic profile if it doesn't exist
                profile = UserProfile(user_id=user_id, display_name=f"User{user_id}")
                self.user_profiles[user_id] = profile

            old_status = profile.status
            profile.status = status
            profile.status_message = status_message
            profile.from datetime import datetime
last_seen = datetime.now()
datetime = datetime.now()

            self._save_social_data()

            # Log activity if status changed
            if old_status != status:
                self._log_activity()
                    user_id=user_id,
                    activity_type=SocialActivityType.STATUS_UPDATED,
                    data={"old_status": old_status.value, "new_status": status.value}
                )

            logger.info(f" Updated status for user {user_id}: {status.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to update user status: {e}")
            return False

    def send_friend_request():
        self,
        requester_id: int,
        recipient_id: int,
        message: Optional[str] = None
    ) -> Optional[str]:
        """Send a friend request."""
        try:
            if requester_id == recipient_id:
                raise ValueError("Cannot send friend request to yourself")

            # Check if users are blocked
            if self.is_user_blocked(requester_id, recipient_id):
                raise ValueError("Cannot send friend request to blocked user")

            # Check if recipient allows friend requests
            recipient_profile = self.get_user_profile(recipient_id)
            if (recipient_profile and)
                not recipient_profile.privacy_from plexichat.core.config import settings
settings.get("allow_friend_requests", True)):
                raise ValueError("User does not accept friend requests")

            friendship_id = self._generate_friendship_id(requester_id, recipient_id)

            # Check if friendship already exists
            existing_friendship = self.friendships.get(friendship_id)
            if existing_friendship:
                if existing_friendship.status == FriendshipStatus.ACCEPTED:
                    raise ValueError("Users are already friends")
                elif existing_friendship.status == FriendshipStatus.PENDING:
                    raise ValueError("Friend request already pending")
                elif existing_friendship.status == FriendshipStatus.BLOCKED:
                    raise ValueError("Cannot send friend request to blocked user")

            # Create friendship
            friendship = Friendship()
                friendship_id=friendship_id,
                requester_id=requester_id,
                recipient_id=recipient_id,
                status=FriendshipStatus.PENDING,
created_at = datetime.now()
datetime = datetime.now(),
                message=message
            )

            self.friendships[friendship_id] = friendship
            self._save_social_data()

            # Log activities
            self._log_activity()
                user_id=requester_id,
                activity_type=SocialActivityType.FRIEND_REQUEST_SENT,
                target_user_id=recipient_id,
                data={"friendship_id": friendship_id}
            )

            self._log_activity()
                user_id=recipient_id,
                activity_type=SocialActivityType.FRIEND_REQUEST_RECEIVED,
                target_user_id=requester_id,
                data={"friendship_id": friendship_id, "message": message}
            )

            logger.info(f" Friend request sent from {requester_id} to {recipient_id}")
            return friendship_id

        except Exception as e:
            logger.error(f"Failed to send friend request: {e}")
            return None

    def respond_to_friend_request():
        self,
        friendship_id: str,
        user_id: int,
        accept: bool
    ) -> bool:
        """Respond to a friend request (accept or decline)."""
        try:
            friendship = self.friendships.get(friendship_id)
            if not friendship:
                raise ValueError("Friend request not found")

            if friendship.recipient_id != user_id:
                raise ValueError("Only the recipient can respond to this request")

            if friendship.status != FriendshipStatus.PENDING:
                raise ValueError("Friend request is not pending")

            # Update friendship status
            if accept:
                friendship.status = FriendshipStatus.ACCEPTED
                activity_type = SocialActivityType.FRIEND_ADDED
                logger.info(f" Friend request accepted: {friendship.requester_id} <-> {friendship.recipient_id}")
            else:
                friendship.status = FriendshipStatus.DECLINED
                activity_type = SocialActivityType.FRIEND_REMOVED
                logger.info(f" Friend request declined: {friendship.requester_id} -> {friendship.recipient_id}")

            friendship.from datetime import datetime
updated_at = datetime.now()
datetime = datetime.now()
            self._save_social_data()

            # Log activities for both users
            self._log_activity()
                user_id=friendship.requester_id,
                activity_type=activity_type,
                target_user_id=friendship.recipient_id,
                data={"friendship_id": friendship_id, "accepted": accept}
            )

            self._log_activity()
                user_id=friendship.recipient_id,
                activity_type=activity_type,
                target_user_id=friendship.requester_id,
                data={"friendship_id": friendship_id, "accepted": accept}
            )

            return True

        except Exception as e:
            logger.error(f"Failed to respond to friend request: {e}")
            return False

    def remove_friend(self, user_id: int, friend_id: int) -> bool:
        """Remove a friend."""
        try:
            friendship_id = self._generate_friendship_id(user_id, friend_id)
            friendship = self.friendships.get(friendship_id)

            if not friendship or friendship.status != FriendshipStatus.ACCEPTED:
                raise ValueError("Users are not friends")

            # Remove friendship
            del self.friendships[friendship_id]
            self._save_social_data()

            # Log activities
            self._log_activity()
                user_id=user_id,
                activity_type=SocialActivityType.FRIEND_REMOVED,
                target_user_id=friend_id,
                data={"friendship_id": friendship_id}
            )

            self._log_activity()
                user_id=friend_id,
                activity_type=SocialActivityType.FRIEND_REMOVED,
                target_user_id=user_id,
                data={"friendship_id": friendship_id}
            )

            logger.info(f" Friendship removed: {user_id} <-> {friend_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove friend: {e}")
            return False

    def block_user(self, user_id: int, blocked_user_id: int) -> bool:
        """Block a user."""
        try:
            if user_id == blocked_user_id:
                raise ValueError("Cannot block yourself")

            # Add to blocked users
            if user_id not in self.blocked_users:
                self.blocked_users[user_id] = set()

            self.blocked_users[user_id].add(blocked_user_id)

            # Remove any existing friendship
            friendship_id = self._generate_friendship_id(user_id, blocked_user_id)
            if friendship_id in self.friendships:
                del self.friendships[friendship_id]

            self._save_social_data()

            # Log activity
            self._log_activity()
                user_id=user_id,
                activity_type=SocialActivityType.USER_BLOCKED,
                target_user_id=blocked_user_id
            )

            logger.info(f" User {user_id} blocked user {blocked_user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to block user: {e}")
            return False

    def unblock_user(self, user_id: int, blocked_user_id: int) -> bool:
        """Unblock a user."""
        try:
            if user_id not in self.blocked_users:
                return False

            if blocked_user_id not in self.blocked_users[user_id]:
                return False

            self.blocked_users[user_id].remove(blocked_user_id)

            # Clean up empty sets
            if not self.blocked_users[user_id]:
                del self.blocked_users[user_id]

            self._save_social_data()

            # Log activity
            self._log_activity()
                user_id=user_id,
                activity_type=SocialActivityType.USER_UNBLOCKED,
                target_user_id=blocked_user_id
            )

            logger.info(f" User {user_id} unblocked user {blocked_user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to unblock user: {e}")
            return False

    def is_user_blocked(self, user_id: int, other_user_id: int) -> bool:
        """Check if a user is blocked by another user."""
        return ()
            other_user_id in self.blocked_users.get(user_id, set()) or
            user_id in self.blocked_users.get(other_user_id, set())
        )

    def are_friends(self, user1_id: int, user2_id: int) -> bool:
        """Check if two users are friends."""
        friendship_id = self._generate_friendship_id(user1_id, user2_id)
        friendship = self.friendships.get(friendship_id)
        return friendship is not None and friendship.status == FriendshipStatus.ACCEPTED

    def get_friends_list(self, user_id: int) -> List[Dict[str, Any]]:
        """Get a user's friends list."""
        friends = []

        for friendship in self.friendships.values():
            if friendship.status != FriendshipStatus.ACCEPTED:
                continue

            friend_id = None
            if friendship.requester_id == user_id:
                friend_id = friendship.recipient_id
            elif friendship.recipient_id == user_id:
                friend_id = friendship.requester_id

            if friend_id:
                friend_profile = self.get_user_profile(friend_id)
                friends.append({)
                    "user_id": friend_id,
                    "display_name": friend_profile.display_name if friend_profile else f"User{friend_id}",
                    "status": friend_profile.status.value if friend_profile else UserStatus.OFFLINE.value,
                    "status_message": friend_profile.status_message if friend_profile else None,
                    "avatar_url": friend_profile.avatar_url if friend_profile else None,
                    "last_seen": friend_profile.last_seen.isoformat() if friend_profile and friend_profile.last_seen else None,
                    "friendship_since": friendship.updated_at.isoformat() if friendship.updated_at else friendship.created_at.isoformat()
                })

        # Sort by online status and display name
        friends.sort(key=lambda f: (f["status"] != "online", f["display_name"]))
        return friends

    def get_friend_requests(self, user_id: int) -> Dict[str, List[Dict[str, Any]]]:
        """Get pending friend requests for a user."""
        sent_requests = []
        received_requests = []

        for friendship in self.friendships.values():
            if friendship.status != FriendshipStatus.PENDING:
                continue

            if friendship.requester_id == user_id:
                # Requests sent by this user
                recipient_profile = self.get_user_profile(friendship.recipient_id)
                sent_requests.append({)
                    "friendship_id": friendship.friendship_id,
                    "user_id": friendship.recipient_id,
                    "display_name": recipient_profile.display_name if recipient_profile else f"User{friendship.recipient_id}",
                    "avatar_url": recipient_profile.avatar_url if recipient_profile else None,
                    "message": friendship.message,
                    "sent_at": friendship.created_at.isoformat()
                })

            elif friendship.recipient_id == user_id:
                # Requests received by this user
                requester_profile = self.get_user_profile(friendship.requester_id)
                received_requests.append({)
                    "friendship_id": friendship.friendship_id,
                    "user_id": friendship.requester_id,
                    "display_name": requester_profile.display_name if requester_profile else f"User{friendship.requester_id}",
                    "avatar_url": requester_profile.avatar_url if requester_profile else None,
                    "message": friendship.message,
                    "received_at": friendship.created_at.isoformat()
                })

        return {}
            "sent": sent_requests,
            "received": received_requests
        }

    def _log_activity():
        self,
        user_id: int,
        activity_type: SocialActivityType,
        target_user_id: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None
    ):
        """Log a social activity."""
        try:
            activity_id = self._generate_activity_id()

            activity = SocialActivity()
                activity_id=activity_id,
                user_id=user_id,
                activity_type=activity_type,
                target_user_id=target_user_id,
                data=data
            )

            self.social_activities[activity_id] = activity

            # Keep only recent activities (last 1000)
            if len(self.social_activities) > 1000:
                # Remove oldest activities
                sorted_activities = sorted()
                    self.social_activities.items(),
                    key=lambda x: x[1].created_at
                )

                for activity_id, _ in sorted_activities[:-1000]:
                    del self.social_activities[activity_id]

        except Exception as e:
            logger.error(f"Failed to log social activity: {e}")

    def get_social_feed(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get social activity feed for a user."""
        try:
            # Get activities for user and their friends
            friend_ids = {friend["user_id"] for friend in self.get_friends_list(user_id)}
            relevant_user_ids = friend_ids | {user_id}

            relevant_activities = [
                activity for activity in self.social_activities.values()
                if activity.user_id in relevant_user_ids
            ]

            # Sort by creation time (newest first)
            relevant_activities.sort(key=lambda a: a.created_at, reverse=True)

            # Format activities
            feed = []
            for activity in relevant_activities[:limit]:
                user_profile = self.get_user_profile(activity.user_id)
                target_profile = None
                if activity.target_user_id:
                    target_profile = self.get_user_profile(activity.target_user_id)

                feed.append({)
                    "activity_id": activity.activity_id,
                    "type": activity.activity_type.value,
                    "user": {
                        "id": activity.user_id,
                        "display_name": user_profile.display_name if user_profile else f"User{activity.user_id}",
                        "avatar_url": user_profile.avatar_url if user_profile else None
                    },
                    "target_user": {
                        "id": activity.target_user_id,
                        "display_name": target_profile.display_name if target_profile else f"User{activity.target_user_id}",
                        "avatar_url": target_profile.avatar_url if target_profile else None
                    } if activity.target_user_id else None,
                    "data": activity.data,
                    "created_at": activity.created_at.isoformat()
                })

            return feed

        except Exception as e:
            logger.error(f"Failed to get social feed: {e}")
            return []

    def search_users(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search for users by display name."""
        try:
            query_lower = query.lower()
            matching_users = []

            for user_id, profile in self.user_profiles.items():
                if query_lower in profile.display_name.lower():
                    matching_users.append({)
                        "user_id": user_id,
                        "display_name": profile.display_name,
                        "bio": profile.bio,
                        "avatar_url": profile.avatar_url,
                        "status": profile.status.value,
                        "last_seen": profile.last_seen.isoformat() if profile.last_seen else None
                    })

            # Sort by display name
            matching_users.sort(key=lambda u: u["display_name"])
            return matching_users[:limit]

        except Exception as e:
            logger.error(f"Failed to search users: {e}")
            return []

    def get_social_statistics(self) -> Dict[str, Any]:
        """Get social system statistics."""
        try:
            total_users = len(self.user_profiles)
            total_friendships = len([f for f in self.friendships.values() if f.status == FriendshipStatus.ACCEPTED])
            pending_requests = len([f for f in self.friendships.values() if f.status == FriendshipStatus.PENDING])

            # Online users
            online_users = len([)
                p for p in self.user_profiles.values()
                if p.status in [UserStatus.ONLINE, UserStatus.AWAY, UserStatus.BUSY]
            ])

            # Activity counts
            activity_counts = {}
            for activity in self.social_activities.values():
                activity_type = activity.activity_type.value
                activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1

            return {}
                "total_users": total_users,
                "online_users": online_users,
                "total_friendships": total_friendships,
                "pending_friend_requests": pending_requests,
                "total_blocked_users": sum(len(blocked_set) for blocked_set in self.blocked_users.values()),
                "activity_counts": activity_counts,
                "last_updated": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get social statistics: {e}")
            return {}}


# Global social service instance
social_service = SocialService()
