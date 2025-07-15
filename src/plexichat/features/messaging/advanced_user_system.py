import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


"""
PlexiChat Advanced User System

Comprehensive user management with Discord/Telegram/WhatsApp Business feature parity:
- Rich user profiles with custom fields
- Advanced user tags and categorization
- User tiers, badges, and achievements
- Business profiles and verification
- Subscription management
- Activity tracking and analytics
"""

logger = logging.getLogger(__name__)


class UserTier(Enum):
    """User tier levels."""

    FREE = "free"
    PREMIUM = "premium"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    VIP = "vip"


class UserStatus(Enum):
    """User online status."""

    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    INVISIBLE = "invisible"
    OFFLINE = "offline"


class BadgeType(Enum):
    """User badge types."""

    VERIFIED = "verified"
    PREMIUM = "premium"
    DEVELOPER = "developer"
    MODERATOR = "moderator"
    ADMIN = "admin"
    EARLY_ADOPTER = "early_adopter"
    CONTRIBUTOR = "contributor"
    SUPPORTER = "supporter"
    CUSTOM = "custom"


@dataclass
class UserBadge:
    """User badge representation."""

    badge_id: str
    badge_type: BadgeType
    name: str
    description: str
    icon_url: Optional[str] = None
    color: str = "#007bff"
    earned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    is_visible: bool = True


@dataclass
class UserTag:
    """User tag for categorization."""

    tag_id: str
    name: str
    color: str
    description: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_system: bool = False


@dataclass
class BusinessProfile:
    """Business profile information."""

    business_name: str
    business_type: str
    industry: str
    description: str
    website: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    logo_url: Optional[str] = None
    verified: bool = False
    verification_date: Optional[datetime] = None
    business_hours: Dict[str, str] = field(default_factory=dict)
    social_links: Dict[str, str] = field(default_factory=dict)


@dataclass
class UserSubscription:
    """User subscription information."""

    subscription_id: str
    tier: UserTier
    started_at: datetime
    expires_at: Optional[datetime] = None
    auto_renew: bool = True
    payment_method: Optional[str] = None
    features: List[str] = field(default_factory=list)
    usage_limits: Dict[str, int] = field(default_factory=dict)
    is_active: bool = True


@dataclass
class UserActivity:
    """User activity tracking."""

    last_seen: datetime
    last_message: Optional[datetime] = None
    total_messages: int = 0
    total_voice_minutes: int = 0
    total_video_minutes: int = 0
    files_shared: int = 0
    groups_joined: int = 0
    channels_created: int = 0
    login_streak: int = 0
    achievements_earned: int = 0


@dataclass
class RichUserProfile:
    """Rich user profile with advanced features."""

    user_id: str
    username: str
    display_name: str
    email: str

    # Basic profile
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    bio: Optional[str] = None
    location: Optional[str] = None
    timezone: str = "UTC"
    language: str = "en"

    # Status and presence
    status: UserStatus = UserStatus.OFFLINE
    custom_status: Optional[str] = None
    status_emoji: Optional[str] = None

    # User tier and subscription
    tier: UserTier = UserTier.FREE
    subscription: Optional[UserSubscription] = None

    # Badges and achievements
    badges: List[UserBadge] = field(default_factory=list)
    tags: List[UserTag] = field(default_factory=list)

    # Business profile (if applicable)
    business_profile: Optional[BusinessProfile] = None

    # Activity and analytics
    activity: UserActivity = field(
        default_factory=lambda: UserActivity(last_seen=datetime.now(timezone.utc))
    )

    # Custom fields
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    # Privacy settings
    privacy_settings: Dict[str, bool] = field(
        default_factory=lambda: {
            "show_online_status": True,
            "show_last_seen": True,
            "allow_direct_messages": True,
            "show_profile_to_public": True,
            "show_activity": False,
        }
    )

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_badge(self, badge: UserBadge):
        """Add badge to user."""
        # Remove existing badge of same type
        self.badges = [b for b in self.badges if b.badge_type != badge.badge_type]
        self.badges.append(badge)
        self.updated_at = datetime.now(timezone.utc)

    def remove_badge(self, badge_type: BadgeType):
        """Remove badge from user."""
        self.badges = [b for b in self.badges if b.badge_type != badge_type]
        self.updated_at = datetime.now(timezone.utc)

    def add_tag(self, tag: UserTag):
        """Add tag to user."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.updated_at = datetime.now(timezone.utc)

    def remove_tag(self, tag_id: str):
        """Remove tag from user."""
        self.tags = [t for t in self.tags if t.tag_id != tag_id]
        self.updated_at = datetime.now(timezone.utc)

    def update_activity(self, activity_type: str, **kwargs):
        """Update user activity."""
        now = datetime.now(timezone.utc)
        self.activity.last_seen = now

        if activity_type == "message":
            self.activity.last_message = now
            self.activity.total_messages += 1
        elif activity_type == "voice":
            minutes = kwargs.get("minutes", 0)
            self.activity.total_voice_minutes += minutes
        elif activity_type == "video":
            minutes = kwargs.get("minutes", 0)
            self.activity.total_video_minutes += minutes
        elif activity_type == "file_share":
            self.activity.files_shared += 1

        self.updated_at = now

    def get_display_badges(self) -> List[UserBadge]:
        """Get visible badges for display."""
        return [
            b
            for b in self.badges
            if b.is_visible
            and (b.expires_at is None or b.expires_at > datetime.now(timezone.utc))
        ]

    def is_premium(self) -> bool:
        """Check if user has premium features."""
        return self.tier in [
            UserTier.PREMIUM,
            UserTier.BUSINESS,
            UserTier.ENTERPRISE,
            UserTier.VIP,
        ]

    def is_business(self) -> bool:
        """Check if user has business profile."""
        return self.business_profile is not None and self.business_profile.verified

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "avatar_url": self.avatar_url,
            "banner_url": self.banner_url,
            "bio": self.bio,
            "location": self.location,
            "status": self.status.value,
            "custom_status": self.custom_status,
            "status_emoji": self.status_emoji,
            "tier": self.tier.value,
            "badges": [
                {
                    "type": b.badge_type.value,
                    "name": b.name,
                    "description": b.description,
                    "icon_url": b.icon_url,
                    "color": b.color,
                }
                for b in self.get_display_badges()
            ],
            "tags": [
                {"id": t.tag_id, "name": t.name, "color": t.color} for t in self.tags
            ],
            "is_premium": self.is_premium(),
            "is_business": self.is_business(),
            "business_profile": (
                {
                    "name": self.business_profile.business_name,
                    "type": self.business_profile.business_type,
                    "verified": self.business_profile.verified,
                }
                if self.business_profile
                else None
            ),
            "created_at": self.created_at.isoformat(),
            "custom_fields": self.custom_fields,
        }


class AdvancedUserManager:
    """Advanced user management system."""

    def __init__(self):
        self.users: Dict[str, RichUserProfile] = {}
        self.user_tags: Dict[str, UserTag] = {}
        self.active_sessions: Dict[str, datetime] = {}

        # Load default badges and tags
        self._initialize_default_badges()
        self._initialize_default_tags()

    def _initialize_default_badges(self):
        """Initialize default badge types."""
        self.default_badges = {
            BadgeType.VERIFIED: UserBadge(
                badge_id="verified",
                badge_type=BadgeType.VERIFIED,
                name="Verified",
                description="Verified user account",
                color="#1da1f2",
            ),
            BadgeType.PREMIUM: UserBadge(
                badge_id="premium",
                badge_type=BadgeType.PREMIUM,
                name="Premium",
                description="Premium subscriber",
                color="#ffd700",
            ),
            BadgeType.DEVELOPER: UserBadge(
                badge_id="developer",
                badge_type=BadgeType.DEVELOPER,
                name="Developer",
                description="PlexiChat developer",
                color="#7289da",
            ),
        }

    def _initialize_default_tags(self):
        """Initialize default user tags."""
        default_tags = [
            UserTag(
                "new_user",
                "New User",
                "#28a745",
                "Recently joined user",
                is_system=True,
            ),
            UserTag(
                "active", "Active", "#17a2b8", "Highly active user", is_system=True
            ),
            UserTag("vip", "VIP", "#dc3545", "VIP member", is_system=True),
            UserTag(
                "beta_tester",
                "Beta Tester",
                "#6f42c1",
                "Beta testing participant",
                is_system=True,
            ),
        ]

        for tag in default_tags:
            self.user_tags[tag.tag_id] = tag

    async def create_user_profile(self, user_data: Dict[str, Any]) -> RichUserProfile:
        """Create rich user profile."""
        profile = RichUserProfile(
            user_id=user_data["user_id"],
            username=user_data["username"],
            display_name=user_data.get("display_name", user_data["username"]),
            email=user_data["email"],
        )

        # Add default tags for new users
        new_user_tag = self.user_tags.get("new_user")
        if new_user_tag:
            profile.add_tag(new_user_tag)

        self.users[profile.user_id] = profile
        logger.info(f"Created user profile: {profile.username}")
        return profile

    async def update_user_status(
        self, user_id: str, status: UserStatus, custom_status: Optional[str] = None
    ):
        """Update user status."""
        if user_id in self.users:
            user = self.users[user_id]
            user.status = status
            user.custom_status = custom_status
            user.updated_at = datetime.now(timezone.utc)

            # Track active session
            if status == UserStatus.ONLINE:
                self.active_sessions[user_id] = datetime.now(timezone.utc)
            elif user_id in self.active_sessions:
                del self.active_sessions[user_id]

    async def award_badge(self, user_id: str, badge_type: BadgeType) -> bool:
        """Award badge to user."""
        if user_id in self.users and badge_type in self.default_badges:
            badge = self.default_badges[badge_type]
            self.users[user_id].add_badge(badge)
            return True
        return False

    async def upgrade_user_tier(self, user_id: str, new_tier: UserTier) -> bool:
        """Upgrade user tier."""
        if user_id in self.users:
            user = self.users[user_id]
            user.tier = new_tier
            user.updated_at = datetime.now(timezone.utc)

            # Award premium badge if applicable
            if new_tier in [UserTier.PREMIUM, UserTier.BUSINESS, UserTier.ENTERPRISE]:
                await self.award_badge(user_id, BadgeType.PREMIUM)

            return True
        return False

    def get_user_profile(self, user_id: str) -> Optional[RichUserProfile]:
        """Get user profile."""
        return self.users.get(user_id)

    def search_users(
        self, query: str, filters: Dict[str, Any] = None
    ) -> List[RichUserProfile]:
        """Search users with filters."""
        results = []
        filters = filters or {}

        for user in self.users.values():
            # Text search
            if (
                query.lower() in user.username.lower()
                or query.lower() in user.display_name.lower()
            ):
                # Apply filters
                if filters.get("tier") and user.tier != UserTier(filters["tier"]):
                    continue
                if filters.get("verified_only") and not any(
                    b.badge_type == BadgeType.VERIFIED for b in user.badges
                ):
                    continue
                if filters.get("business_only") and not user.is_business():
                    continue

                results.append(user)

        return results

    def get_online_users(self) -> List[RichUserProfile]:
        """Get currently online users."""
        online_users = []
        for user_id, last_seen in self.active_sessions.items():
            if user_id in self.users:
                # Consider user online if seen within last 5 minutes
                if datetime.now(timezone.utc) - last_seen < timedelta(minutes=5):
                    online_users.append(self.users[user_id])
        return online_users

    def get_user_analytics(self) -> Dict[str, Any]:
        """Get user system analytics."""
        total_users = len(self.users)
        online_users = len(self.get_online_users())

        tier_breakdown = {}
        for user in self.users.values():
            tier = user.tier.value
            tier_breakdown[tier] = tier_breakdown.get(tier, 0) + 1

        return {
            "total_users": total_users,
            "online_users": online_users,
            "tier_breakdown": tier_breakdown,
            "verified_users": sum(
                1
                for u in self.users.values()
                if any(b.badge_type == BadgeType.VERIFIED for b in u.badges)
            ),
            "business_users": sum(1 for u in self.users.values() if u.is_business()),
            "premium_users": sum(1 for u in self.users.values() if u.is_premium()),
        }


# Global advanced user manager instance
advanced_user_manager = AdvancedUserManager()
