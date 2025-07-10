"""
Advanced User Profile System for NetLink

This system provides:
- Comprehensive user profiles with rich metadata
- User tiers and badge system (alpha tester, beta tester, etc.)
- Subscription level management
- Profile customization and preferences
- Achievement tracking and rewards
- Social features and reputation system
- Profile backup integration
"""

import asyncio
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import aiofiles
from app.logger_config import logger

class UserTier(Enum):
    """User tier levels with associated privileges."""
    GUEST = "guest"
    BASIC = "basic"
    PREMIUM = "premium"
    VIP = "vip"
    ALPHA_TESTER = "alpha_tester"
    BETA_TESTER = "beta_tester"
    DEVELOPER = "developer"
    MODERATOR = "moderator"
    ADMIN = "admin"

class BadgeType(Enum):
    """Types of badges users can earn."""
    ACHIEVEMENT = "achievement"
    MILESTONE = "milestone"
    SPECIAL_EVENT = "special_event"
    CONTRIBUTION = "contribution"
    TESTING = "testing"
    SOCIAL = "social"
    SYSTEM = "system"

class SubscriptionStatus(Enum):
    """Subscription status levels."""
    FREE = "free"
    TRIAL = "trial"
    ACTIVE = "active"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"

@dataclass
class Badge:
    """User badge with metadata."""
    badge_id: str
    name: str
    description: str
    badge_type: BadgeType
    
    # Visual properties
    icon: str = "🏆"
    color: str = "#FFD700"
    rarity: str = "common"  # common, uncommon, rare, epic, legendary
    
    # Requirements and rewards
    requirements: Dict[str, Any] = field(default_factory=dict)
    rewards: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    display_order: int = 0

@dataclass
class UserBadge:
    """Badge earned by a user."""
    badge_id: str
    user_id: int
    earned_date: datetime
    
    # Progress and context
    progress_data: Dict[str, Any] = field(default_factory=dict)
    earned_context: str = ""
    
    # Display settings
    is_displayed: bool = True
    display_priority: int = 0

@dataclass
class UserSubscription:
    """User subscription information."""
    user_id: int
    subscription_tier: str
    status: SubscriptionStatus
    
    # Timing
    start_date: datetime
    end_date: Optional[datetime] = None
    last_payment_date: Optional[datetime] = None
    next_billing_date: Optional[datetime] = None
    
    # Features and limits
    features_enabled: List[str] = field(default_factory=list)
    usage_limits: Dict[str, int] = field(default_factory=dict)
    
    # Payment and billing
    payment_method: Optional[str] = None
    billing_cycle: str = "monthly"  # monthly, yearly, lifetime
    amount_paid: float = 0.0
    currency: str = "USD"
    
    # External integration
    external_subscription_id: Optional[str] = None
    payment_provider: Optional[str] = None

@dataclass
class UserProfile:
    """Comprehensive user profile."""
    user_id: int
    username: str
    
    # Basic information
    display_name: Optional[str] = None
    email: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    
    # User tier and status
    tier: UserTier = UserTier.BASIC
    tier_upgraded_date: Optional[datetime] = None
    reputation_score: int = 0
    
    # Profile customization
    theme_preference: str = "default"
    language_preference: str = "en"
    timezone: str = "UTC"
    
    # Privacy settings
    profile_visibility: str = "public"  # public, friends, private
    show_online_status: bool = True
    allow_direct_messages: bool = True
    
    # Activity and engagement
    join_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_active: Optional[datetime] = None
    total_login_count: int = 0
    total_messages_sent: int = 0
    total_files_shared: int = 0
    
    # Achievements and progress
    badges_earned: List[UserBadge] = field(default_factory=list)
    achievements_unlocked: List[str] = field(default_factory=list)
    experience_points: int = 0
    level: int = 1
    
    # Social features
    friends_list: List[int] = field(default_factory=list)
    blocked_users: List[int] = field(default_factory=list)
    favorite_channels: List[str] = field(default_factory=list)
    
    # Subscription and premium features
    subscription: Optional[UserSubscription] = None
    premium_features_used: Dict[str, int] = field(default_factory=dict)
    
    # Custom fields and metadata
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    profile_tags: List[str] = field(default_factory=list)
    
    # System metadata
    profile_version: int = 1
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    backup_enabled: bool = True

class AdvancedProfileSystem:
    """Advanced user profile management system."""
    
    def __init__(self, profiles_root: str = "profiles"):
        self.profiles_root = Path(profiles_root)
        self.profiles_root.mkdir(exist_ok=True)
        
        # Initialize directories
        self.profiles_dir = self.profiles_root / "users"
        self.badges_dir = self.profiles_root / "badges"
        self.achievements_dir = self.profiles_root / "achievements"
        
        for directory in [self.profiles_dir, self.badges_dir, self.achievements_dir]:
            directory.mkdir(exist_ok=True)
        
        # In-memory caches
        self.profiles: Dict[int, UserProfile] = {}
        self.badges: Dict[str, Badge] = {}
        self.tier_privileges: Dict[UserTier, Dict[str, Any]] = {}
        
        # System configuration
        self.config = {
            "max_badges_per_user": 50,
            "max_friends_per_user": 1000,
            "experience_per_level": 1000,
            "reputation_decay_days": 30,
            "profile_backup_enabled": True,
            "auto_tier_upgrades": True
        }
        
        # Initialize system
        asyncio.create_task(self._initialize_system())
        
        logger.info("Advanced Profile System initialized")
    
    async def _initialize_system(self):
        """Initialize the profile system with default badges and tier privileges."""
        await self._create_default_badges()
        await self._setup_tier_privileges()
        await self._load_existing_profiles()
    
    async def _create_default_badges(self):
        """Create default badges for the system."""
        default_badges = [
            # Testing badges
            Badge(
                badge_id="alpha_tester",
                name="Alpha Tester",
                description="Participated in alpha testing phase",
                badge_type=BadgeType.TESTING,
                icon="🔬",
                color="#FF6B6B",
                rarity="rare",
                requirements={"tier": "alpha_tester"},
                rewards={"experience_points": 500, "reputation": 100}
            ),
            Badge(
                badge_id="beta_tester",
                name="Beta Tester",
                description="Participated in beta testing phase",
                badge_type=BadgeType.TESTING,
                icon="🧪",
                color="#4ECDC4",
                rarity="uncommon",
                requirements={"tier": "beta_tester"},
                rewards={"experience_points": 250, "reputation": 50}
            ),
            
            # Achievement badges
            Badge(
                badge_id="first_message",
                name="First Steps",
                description="Sent your first message",
                badge_type=BadgeType.ACHIEVEMENT,
                icon="👋",
                color="#45B7D1",
                rarity="common",
                requirements={"messages_sent": 1},
                rewards={"experience_points": 50}
            ),
            Badge(
                badge_id="chatty",
                name="Chatty",
                description="Sent 1000 messages",
                badge_type=BadgeType.MILESTONE,
                icon="💬",
                color="#96CEB4",
                rarity="uncommon",
                requirements={"messages_sent": 1000},
                rewards={"experience_points": 200, "reputation": 25}
            ),
            Badge(
                badge_id="social_butterfly",
                name="Social Butterfly",
                description="Made 50 friends",
                badge_type=BadgeType.SOCIAL,
                icon="🦋",
                color="#FFEAA7",
                rarity="rare",
                requirements={"friends_count": 50},
                rewards={"experience_points": 300, "reputation": 50}
            ),
            
            # Special badges
            Badge(
                badge_id="early_adopter",
                name="Early Adopter",
                description="Joined NetLink in its early days",
                badge_type=BadgeType.SPECIAL_EVENT,
                icon="🌟",
                color="#DDA0DD",
                rarity="epic",
                requirements={"join_before": "2024-12-31"},
                rewards={"experience_points": 1000, "reputation": 200}
            ),
            Badge(
                badge_id="contributor",
                name="Contributor",
                description="Made significant contributions to NetLink",
                badge_type=BadgeType.CONTRIBUTION,
                icon="🤝",
                color="#FF7675",
                rarity="legendary",
                requirements={"contributions": 10},
                rewards={"experience_points": 2000, "reputation": 500}
            )
        ]
        
        for badge in default_badges:
            self.badges[badge.badge_id] = badge
            await self._save_badge(badge)
    
    async def _setup_tier_privileges(self):
        """Setup privileges for each user tier."""
        self.tier_privileges = {
            UserTier.GUEST: {
                "max_messages_per_day": 10,
                "max_file_size_mb": 1,
                "can_create_channels": False,
                "can_use_premium_features": False,
                "api_rate_limit": 100,
                "storage_quota_mb": 10
            },
            UserTier.BASIC: {
                "max_messages_per_day": 1000,
                "max_file_size_mb": 10,
                "can_create_channels": True,
                "can_use_premium_features": False,
                "api_rate_limit": 1000,
                "storage_quota_mb": 100
            },
            UserTier.PREMIUM: {
                "max_messages_per_day": 10000,
                "max_file_size_mb": 100,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "api_rate_limit": 5000,
                "storage_quota_mb": 1000,
                "priority_support": True,
                "custom_themes": True
            },
            UserTier.VIP: {
                "max_messages_per_day": -1,  # Unlimited
                "max_file_size_mb": 500,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "api_rate_limit": 10000,
                "storage_quota_mb": 5000,
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True
            },
            UserTier.ALPHA_TESTER: {
                "max_messages_per_day": -1,
                "max_file_size_mb": 1000,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "can_access_alpha_features": True,
                "api_rate_limit": 20000,
                "storage_quota_mb": 10000,
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True,
                "testing_privileges": True
            },
            UserTier.BETA_TESTER: {
                "max_messages_per_day": -1,
                "max_file_size_mb": 500,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "can_access_beta_features": True,
                "api_rate_limit": 15000,
                "storage_quota_mb": 5000,
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True,
                "testing_privileges": True
            },
            UserTier.DEVELOPER: {
                "max_messages_per_day": -1,
                "max_file_size_mb": 2000,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "can_access_dev_features": True,
                "api_rate_limit": 50000,
                "storage_quota_mb": 50000,
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True,
                "development_access": True,
                "api_access": True
            },
            UserTier.MODERATOR: {
                "max_messages_per_day": -1,
                "max_file_size_mb": 1000,
                "can_create_channels": True,
                "can_use_premium_features": True,
                "can_moderate": True,
                "api_rate_limit": 25000,
                "storage_quota_mb": 20000,
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True,
                "moderation_tools": True
            },
            UserTier.ADMIN: {
                "max_messages_per_day": -1,
                "max_file_size_mb": -1,  # Unlimited
                "can_create_channels": True,
                "can_use_premium_features": True,
                "can_moderate": True,
                "can_administrate": True,
                "api_rate_limit": -1,  # Unlimited
                "storage_quota_mb": -1,  # Unlimited
                "priority_support": True,
                "custom_themes": True,
                "exclusive_features": True,
                "admin_tools": True,
                "system_access": True
            }
        }
    
    async def _load_existing_profiles(self):
        """Load existing user profiles from disk."""
        try:
            for profile_file in self.profiles_dir.glob("*.json"):
                user_id = int(profile_file.stem.replace("profile_", ""))
                await self._load_user_profile(user_id)
                
        except Exception as e:
            logger.error(f"Failed to load existing profiles: {e}")
    
    async def create_user_profile(self, 
                                user_id: int,
                                username: str,
                                initial_data: Optional[Dict[str, Any]] = None) -> UserProfile:
        """Create a new user profile."""
        try:
            if user_id in self.profiles:
                raise ValueError(f"Profile already exists for user {user_id}")
            
            # Create profile with initial data
            profile = UserProfile(
                user_id=user_id,
                username=username
            )
            
            # Apply initial data if provided
            if initial_data:
                for key, value in initial_data.items():
                    if hasattr(profile, key):
                        setattr(profile, key, value)
            
            # Set default tier based on initial data
            if initial_data and "tier" in initial_data:
                try:
                    profile.tier = UserTier(initial_data["tier"])
                    profile.tier_upgraded_date = datetime.now(timezone.utc)
                except ValueError:
                    profile.tier = UserTier.BASIC
            
            # Award initial badges
            await self._award_initial_badges(profile)
            
            # Store profile
            self.profiles[user_id] = profile
            await self._save_user_profile(user_id)
            
            logger.info(f"Created profile for user {user_id} ({username}) with tier {profile.tier.value}")
            return profile
            
        except Exception as e:
            logger.error(f"Failed to create profile for user {user_id}: {e}")
            raise
    
    async def _award_initial_badges(self, profile: UserProfile):
        """Award initial badges to a new user."""
        try:
            # Award tier-specific badges
            if profile.tier == UserTier.ALPHA_TESTER:
                await self._award_badge(profile.user_id, "alpha_tester", "Initial alpha tester status")
            elif profile.tier == UserTier.BETA_TESTER:
                await self._award_badge(profile.user_id, "beta_tester", "Initial beta tester status")
            
            # Award early adopter badge if applicable
            early_adopter_cutoff = datetime(2024, 12, 31, tzinfo=timezone.utc)
            if profile.join_date <= early_adopter_cutoff:
                await self._award_badge(profile.user_id, "early_adopter", "Joined during early adoption period")
                
        except Exception as e:
            logger.error(f"Failed to award initial badges to user {profile.user_id}: {e}")
    
    async def get_user_profile(self, user_id: int) -> Optional[UserProfile]:
        """Get user profile by ID."""
        if user_id not in self.profiles:
            await self._load_user_profile(user_id)
        
        return self.profiles.get(user_id)
    
    async def update_user_profile(self, 
                                user_id: int,
                                updates: Dict[str, Any]) -> bool:
        """Update user profile with new data."""
        try:
            profile = await self.get_user_profile(user_id)
            if not profile:
                return False
            
            # Track tier changes
            old_tier = profile.tier
            
            # Apply updates
            for key, value in updates.items():
                if hasattr(profile, key):
                    if key == "tier" and isinstance(value, str):
                        try:
                            new_tier = UserTier(value)
                            profile.tier = new_tier
                            if new_tier != old_tier:
                                profile.tier_upgraded_date = datetime.now(timezone.utc)
                                await self._handle_tier_change(profile, old_tier, new_tier)
                        except ValueError:
                            logger.warning(f"Invalid tier value: {value}")
                    else:
                        setattr(profile, key, value)
            
            # Update metadata
            profile.last_updated = datetime.now(timezone.utc)
            profile.profile_version += 1
            
            # Save changes
            await self._save_user_profile(user_id)
            
            logger.info(f"Updated profile for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update profile for user {user_id}: {e}")
            return False

    async def _handle_tier_change(self, profile: UserProfile, old_tier: UserTier, new_tier: UserTier):
        """Handle tier change events and award appropriate badges."""
        try:
            # Award tier-specific badges
            if new_tier == UserTier.ALPHA_TESTER and "alpha_tester" not in [b.badge_id for b in profile.badges_earned]:
                await self._award_badge(profile.user_id, "alpha_tester", f"Upgraded to {new_tier.value}")
            elif new_tier == UserTier.BETA_TESTER and "beta_tester" not in [b.badge_id for b in profile.badges_earned]:
                await self._award_badge(profile.user_id, "beta_tester", f"Upgraded to {new_tier.value}")

            logger.info(f"User {profile.user_id} tier changed from {old_tier.value} to {new_tier.value}")

        except Exception as e:
            logger.error(f"Failed to handle tier change for user {profile.user_id}: {e}")

    async def _award_badge(self, user_id: int, badge_id: str, context: str = ""):
        """Award a badge to a user."""
        try:
            profile = await self.get_user_profile(user_id)
            if not profile:
                return False

            # Check if user already has this badge
            if badge_id in [b.badge_id for b in profile.badges_earned]:
                return False

            # Check if badge exists
            if badge_id not in self.badges:
                logger.warning(f"Badge {badge_id} does not exist")
                return False

            badge = self.badges[badge_id]

            # Check requirements
            if not await self._check_badge_requirements(profile, badge):
                return False

            # Award the badge
            user_badge = UserBadge(
                badge_id=badge_id,
                user_id=user_id,
                earned_date=datetime.now(timezone.utc),
                earned_context=context
            )

            profile.badges_earned.append(user_badge)

            # Apply badge rewards
            if badge.rewards:
                if "experience_points" in badge.rewards:
                    profile.experience_points += badge.rewards["experience_points"]
                    await self._check_level_up(profile)

                if "reputation" in badge.rewards:
                    profile.reputation_score += badge.rewards["reputation"]

            # Save profile
            await self._save_user_profile(user_id)

            logger.info(f"Awarded badge '{badge.name}' to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to award badge {badge_id} to user {user_id}: {e}")
            return False

    async def _check_badge_requirements(self, profile: UserProfile, badge: Badge) -> bool:
        """Check if user meets badge requirements."""
        try:
            requirements = badge.requirements

            # Check tier requirement
            if "tier" in requirements:
                required_tier = UserTier(requirements["tier"])
                if profile.tier != required_tier:
                    return False

            # Check message count
            if "messages_sent" in requirements:
                if profile.total_messages_sent < requirements["messages_sent"]:
                    return False

            # Check friends count
            if "friends_count" in requirements:
                if len(profile.friends_list) < requirements["friends_count"]:
                    return False

            # Check join date
            if "join_before" in requirements:
                cutoff_date = datetime.fromisoformat(requirements["join_before"]).replace(tzinfo=timezone.utc)
                if profile.join_date > cutoff_date:
                    return False

            # Check contributions (custom field)
            if "contributions" in requirements:
                contributions = profile.custom_fields.get("contributions", 0)
                if contributions < requirements["contributions"]:
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to check badge requirements: {e}")
            return False

    async def _check_level_up(self, profile: UserProfile):
        """Check if user should level up based on experience points."""
        try:
            required_xp = profile.level * self.config["experience_per_level"]

            while profile.experience_points >= required_xp:
                profile.level += 1
                profile.experience_points -= required_xp
                required_xp = profile.level * self.config["experience_per_level"]

                logger.info(f"User {profile.user_id} leveled up to level {profile.level}")

                # Award level milestone badges if they exist
                level_badge_id = f"level_{profile.level}"
                if level_badge_id in self.badges:
                    await self._award_badge(profile.user_id, level_badge_id, f"Reached level {profile.level}")

        except Exception as e:
            logger.error(f"Failed to check level up for user {profile.user_id}: {e}")

    async def update_user_activity(self, user_id: int, activity_data: Dict[str, Any]):
        """Update user activity and check for badge eligibility."""
        try:
            profile = await self.get_user_profile(user_id)
            if not profile:
                return

            # Update activity counters
            if "messages_sent" in activity_data:
                profile.total_messages_sent += activity_data["messages_sent"]

                # Check message-related badges
                if profile.total_messages_sent == 1:
                    await self._award_badge(user_id, "first_message", "Sent first message")
                elif profile.total_messages_sent >= 1000:
                    await self._award_badge(user_id, "chatty", "Sent 1000 messages")

            if "files_shared" in activity_data:
                profile.total_files_shared += activity_data["files_shared"]

            if "login" in activity_data:
                profile.total_login_count += 1
                profile.last_active = datetime.now(timezone.utc)

            # Update experience points for activity
            xp_gained = 0
            if "messages_sent" in activity_data:
                xp_gained += activity_data["messages_sent"] * 5
            if "files_shared" in activity_data:
                xp_gained += activity_data["files_shared"] * 10
            if "login" in activity_data:
                xp_gained += 10

            if xp_gained > 0:
                profile.experience_points += xp_gained
                await self._check_level_up(profile)

            # Save profile
            await self._save_user_profile(user_id)

        except Exception as e:
            logger.error(f"Failed to update activity for user {user_id}: {e}")

    async def get_user_privileges(self, user_id: int) -> Dict[str, Any]:
        """Get user privileges based on tier and subscription."""
        try:
            profile = await self.get_user_profile(user_id)
            if not profile:
                return self.tier_privileges.get(UserTier.GUEST, {})

            # Get base privileges from tier
            privileges = self.tier_privileges.get(profile.tier, {}).copy()

            # Apply subscription modifications
            if profile.subscription and profile.subscription.status == SubscriptionStatus.ACTIVE:
                # Apply subscription-specific limits
                if profile.subscription.usage_limits:
                    privileges.update(profile.subscription.usage_limits)

                # Enable subscription features
                if profile.subscription.features_enabled:
                    for feature in profile.subscription.features_enabled:
                        privileges[f"can_use_{feature}"] = True

            return privileges

        except Exception as e:
            logger.error(f"Failed to get privileges for user {user_id}: {e}")
            return {}

    async def _save_user_profile(self, user_id: int):
        """Save user profile to disk."""
        try:
            if user_id not in self.profiles:
                return

            profile = self.profiles[user_id]
            profile_path = self.profiles_dir / f"profile_{user_id}.json"

            # Convert to serializable format
            profile_dict = {
                "user_id": profile.user_id,
                "username": profile.username,
                "display_name": profile.display_name,
                "email": profile.email,
                "avatar_url": profile.avatar_url,
                "bio": profile.bio,
                "tier": profile.tier.value,
                "tier_upgraded_date": profile.tier_upgraded_date.isoformat() if profile.tier_upgraded_date else None,
                "reputation_score": profile.reputation_score,
                "theme_preference": profile.theme_preference,
                "language_preference": profile.language_preference,
                "timezone": profile.timezone,
                "profile_visibility": profile.profile_visibility,
                "show_online_status": profile.show_online_status,
                "allow_direct_messages": profile.allow_direct_messages,
                "join_date": profile.join_date.isoformat(),
                "last_active": profile.last_active.isoformat() if profile.last_active else None,
                "total_login_count": profile.total_login_count,
                "total_messages_sent": profile.total_messages_sent,
                "total_files_shared": profile.total_files_shared,
                "badges_earned": [
                    {
                        "badge_id": badge.badge_id,
                        "earned_date": badge.earned_date.isoformat(),
                        "progress_data": badge.progress_data,
                        "earned_context": badge.earned_context,
                        "is_displayed": badge.is_displayed,
                        "display_priority": badge.display_priority
                    }
                    for badge in profile.badges_earned
                ],
                "achievements_unlocked": profile.achievements_unlocked,
                "experience_points": profile.experience_points,
                "level": profile.level,
                "friends_list": profile.friends_list,
                "blocked_users": profile.blocked_users,
                "favorite_channels": profile.favorite_channels,
                "subscription": {
                    "subscription_tier": profile.subscription.subscription_tier,
                    "status": profile.subscription.status.value,
                    "start_date": profile.subscription.start_date.isoformat(),
                    "end_date": profile.subscription.end_date.isoformat() if profile.subscription.end_date else None,
                    "features_enabled": profile.subscription.features_enabled,
                    "usage_limits": profile.subscription.usage_limits,
                    "billing_cycle": profile.subscription.billing_cycle,
                    "amount_paid": profile.subscription.amount_paid,
                    "currency": profile.subscription.currency,
                    "external_subscription_id": profile.subscription.external_subscription_id,
                    "payment_provider": profile.subscription.payment_provider
                } if profile.subscription else None,
                "premium_features_used": profile.premium_features_used,
                "custom_fields": profile.custom_fields,
                "profile_tags": profile.profile_tags,
                "profile_version": profile.profile_version,
                "last_updated": profile.last_updated.isoformat(),
                "backup_enabled": profile.backup_enabled
            }

            async with aiofiles.open(profile_path, 'w') as f:
                await f.write(json.dumps(profile_dict, indent=2))

        except Exception as e:
            logger.error(f"Failed to save profile for user {user_id}: {e}")

    async def _load_user_profile(self, user_id: int):
        """Load user profile from disk."""
        try:
            profile_path = self.profiles_dir / f"profile_{user_id}.json"

            if not profile_path.exists():
                return

            async with aiofiles.open(profile_path, 'r') as f:
                profile_dict = json.loads(await f.read())

            # Convert from serializable format
            profile = UserProfile(
                user_id=profile_dict["user_id"],
                username=profile_dict["username"]
            )

            # Load basic fields
            for key in ["display_name", "email", "avatar_url", "bio", "reputation_score",
                       "theme_preference", "language_preference", "timezone", "profile_visibility",
                       "show_online_status", "allow_direct_messages", "total_login_count",
                       "total_messages_sent", "total_files_shared", "achievements_unlocked",
                       "experience_points", "level", "friends_list", "blocked_users",
                       "favorite_channels", "premium_features_used", "custom_fields",
                       "profile_tags", "profile_version", "backup_enabled"]:
                if key in profile_dict and profile_dict[key] is not None:
                    setattr(profile, key, profile_dict[key])

            # Load tier
            if "tier" in profile_dict:
                profile.tier = UserTier(profile_dict["tier"])

            # Load dates
            if "tier_upgraded_date" in profile_dict and profile_dict["tier_upgraded_date"]:
                profile.tier_upgraded_date = datetime.fromisoformat(profile_dict["tier_upgraded_date"])

            if "join_date" in profile_dict:
                profile.join_date = datetime.fromisoformat(profile_dict["join_date"])

            if "last_active" in profile_dict and profile_dict["last_active"]:
                profile.last_active = datetime.fromisoformat(profile_dict["last_active"])

            if "last_updated" in profile_dict:
                profile.last_updated = datetime.fromisoformat(profile_dict["last_updated"])

            # Load badges
            if "badges_earned" in profile_dict:
                profile.badges_earned = [
                    UserBadge(
                        badge_id=badge_data["badge_id"],
                        user_id=user_id,
                        earned_date=datetime.fromisoformat(badge_data["earned_date"]),
                        progress_data=badge_data.get("progress_data", {}),
                        earned_context=badge_data.get("earned_context", ""),
                        is_displayed=badge_data.get("is_displayed", True),
                        display_priority=badge_data.get("display_priority", 0)
                    )
                    for badge_data in profile_dict["badges_earned"]
                ]

            # Load subscription
            if "subscription" in profile_dict and profile_dict["subscription"]:
                sub_data = profile_dict["subscription"]
                subscription = UserSubscription(
                    user_id=user_id,
                    subscription_tier=sub_data["subscription_tier"],
                    status=SubscriptionStatus(sub_data["status"]),
                    start_date=datetime.fromisoformat(sub_data["start_date"])
                )

                if sub_data.get("end_date"):
                    subscription.end_date = datetime.fromisoformat(sub_data["end_date"])

                subscription.features_enabled = sub_data.get("features_enabled", [])
                subscription.usage_limits = sub_data.get("usage_limits", {})
                subscription.billing_cycle = sub_data.get("billing_cycle", "monthly")
                subscription.amount_paid = sub_data.get("amount_paid", 0.0)
                subscription.currency = sub_data.get("currency", "USD")
                subscription.external_subscription_id = sub_data.get("external_subscription_id")
                subscription.payment_provider = sub_data.get("payment_provider")

                profile.subscription = subscription

            self.profiles[user_id] = profile

        except Exception as e:
            logger.error(f"Failed to load profile for user {user_id}: {e}")

    async def _save_badge(self, badge: Badge):
        """Save badge definition to disk."""
        try:
            badge_path = self.badges_dir / f"{badge.badge_id}.json"

            badge_dict = {
                "badge_id": badge.badge_id,
                "name": badge.name,
                "description": badge.description,
                "badge_type": badge.badge_type.value,
                "icon": badge.icon,
                "color": badge.color,
                "rarity": badge.rarity,
                "requirements": badge.requirements,
                "rewards": badge.rewards,
                "created_date": badge.created_date.isoformat(),
                "is_active": badge.is_active,
                "display_order": badge.display_order
            }

            async with aiofiles.open(badge_path, 'w') as f:
                await f.write(json.dumps(badge_dict, indent=2))

        except Exception as e:
            logger.error(f"Failed to save badge {badge.badge_id}: {e}")

    def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        return {
            "total_profiles": len(self.profiles),
            "total_badges": len(self.badges),
            "tier_distribution": {
                tier.value: sum(1 for p in self.profiles.values() if p.tier == tier)
                for tier in UserTier
            },
            "badge_distribution": {
                badge_type.value: sum(1 for b in self.badges.values() if b.badge_type == badge_type)
                for badge_type in BadgeType
            },
            "subscription_stats": {
                status.value: sum(1 for p in self.profiles.values()
                                if p.subscription and p.subscription.status == status)
                for status in SubscriptionStatus
            }
        }

# Global advanced profile system instance
advanced_profile_system = AdvancedProfileSystem()
