# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

# Enhanced plugin marketplace with better error handling
# Improved security validation
# Better plugin compatibility checking
# Enhanced user experience with progress indicators

import asyncio
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles
import aiohttp

from ..core.logging import get_logger

from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path

"""
PlexiChat Plugin Marketplace Service

Comprehensive plugin marketplace with discovery, ratings, reviews, categories,
external service integrations, and developer tools.
"""

logger = get_logger(__name__)


class WebhookEvent(Enum):
    """Webhook event types for marketplace notifications."""
    PLUGIN_PUBLISHED = "plugin.published"
    PLUGIN_UPDATED = "plugin.updated"
    PLUGIN_INSTALLED = "plugin.installed"
    PLUGIN_DELETED = "plugin.deleted"
    REVIEW_ADDED = "review.added"
    REVIEW_UPDATED = "review.updated"
    REVIEW_DELETED = "review.deleted"
    DEVELOPER_REGISTERED = "developer.registered"


@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration."""
    endpoint_id: str
    url: str
    secret: str
    events: List[WebhookEvent]
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_triggered: Optional[datetime] = None
    success_count: int = 0
    failure_count: int = 0


@dataclass
class WebhookDelivery:
    """Webhook delivery attempt record."""
    delivery_id: str
    endpoint_id: str
    event: WebhookEvent
    payload: Dict[str, Any]
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    delivered_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PluginCategory(Enum):
    """Plugin categories for marketplace organization."""
    COMMUNICATION = "communication"
    SECURITY = "security"
    PRODUCTIVITY = "productivity"
    ENTERTAINMENT = "entertainment"
    DEVELOPMENT = "development"
    INTEGRATION = "integration"
    UTILITY = "utility"
    AI_ML = "ai_ml"
    BACKUP = "backup"
    MONITORING = "monitoring"
    CUSTOMIZATION = "customization"
    OTHER = "other"


class PluginRating(Enum):
    """Plugin rating levels."""
    ONE_STAR = 1
    TWO_STAR = 2
    THREE_STAR = 3
    FOUR_STAR = 4
    FIVE_STAR = 5


@dataclass
class PluginMarketplaceInfo:
    """Extended plugin information for marketplace."""
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    author_email: str
    category: PluginCategory
    tags: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"
    price: float = 0.0  # 0.0 for free plugins
    currency: str = "USD"
    
    # Marketplace specific
    download_count: int = 0
    rating_average: float = 0.0
    rating_count: int = 0
    reviews_count: int = 0
    featured: bool = False
    verified: bool = False
    
    # Compatibility
    min_plexichat_version: str = "3.0.0"
    max_plexichat_version: Optional[str] = None
    supported_platforms: List[str] = field(default_factory=lambda: ["windows", "linux", "macos"])
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_download: Optional[datetime] = None
    
    # Files
    download_url: str = ""
    icon_url: Optional[str] = None
    screenshots: List[str] = field(default_factory=list)
    changelog: str = ""
    
    # Security
    checksum: str = ""
    signature: Optional[str] = None
    security_scan_passed: bool = False
    security_scan_date: Optional[datetime] = None


@dataclass
class PluginReview:
    """Plugin review information."""
    review_id: str
    plugin_id: str
    user_id: str
    username: str
    rating: PluginRating
    title: str
    content: str
    helpful_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_purchase: bool = False


@dataclass
class PluginDeveloper:
    """Plugin developer information."""
    developer_id: str
    username: str
    email: str
    display_name: str
    bio: Optional[str] = None
    website: Optional[str] = None
    avatar_url: Optional[str] = None
    verified: bool = False
    plugins_count: int = 0
    total_downloads: int = 0
    average_rating: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PluginMarketplaceService:
    """Comprehensive plugin marketplace service."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()
        self.data_dir = from pathlib import Path
Path(self.config.get("data_dir", "data/plugin_marketplace"))
        self.cache_dir = from pathlib import Path
Path(self.config.get("cache_dir", "data/plugin_marketplace/cache"))
        
        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Data storage
        self.plugins: Dict[str, PluginMarketplaceInfo] = {}
        self.reviews: Dict[str, List[PluginReview]] = {}
        self.developers: Dict[str, PluginDeveloper] = {}

        # Webhook system
        self.webhook_endpoints: Dict[str, WebhookEndpoint] = {}
        self.webhook_deliveries: List[WebhookDelivery] = []

        # Cache
        self.search_cache: Dict[str, Any] = {}
        self.category_cache: Dict[str, List[str]] = {}

        # External services
        self.external_repositories = self.config.get("external_repositories", [])
        
        # Statistics
        self.stats = {
            "total_plugins": 0,
            "total_downloads": 0,
            "total_reviews": 0,
            "active_developers": 0,
            "featured_plugins": 0
        }
        
        logger.info(" Plugin Marketplace Service initialized")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default marketplace configuration."""
        return {
            "data_dir": "data/plugin_marketplace",
            "cache_dir": "data/plugin_marketplace/cache",
            "cache_ttl": 3600,  # 1 hour
            "max_search_results": 50,
            "featured_plugins_limit": 10,
            "external_repositories": [
                {
                    "name": "PlexiChat Official",
                    "url": "https://plugins.plexichat.example.com/api/v1",
                    "trusted": True,
                    "enabled": True
                }
            ],
            "webhook_endpoints": {
                "plugin_published": "/webhooks/plugin/published",
                "plugin_updated": "/webhooks/plugin/updated",
                "plugin_deleted": "/webhooks/plugin/deleted"
            },
            "security": {
                "require_signature": True,
                "auto_scan_enabled": True,
                "quarantine_suspicious": True
            },
            "oauth": {
                "enabled": True,
                "client_id": "plexichat_marketplace",
                "scopes": ["plugin:publish", "plugin:manage", "reviews:write"]
            }
        }
    
    async def initialize(self) -> bool:
        """Initialize the marketplace service."""
        try:
            logger.info(" Initializing Plugin Marketplace...")
            
            # Load existing data
            await self._load_marketplace_data()
            
            # Sync with external repositories
            await self._sync_external_repositories()
            
            # Update statistics
            await self._update_statistics()
            
            logger.info(" Plugin Marketplace initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f" Failed to initialize Plugin Marketplace: {e}")
            return False
    
    async def search_plugins(self, query: str = "", category: Optional[PluginCategory] = None,
                           tags: List[str] = None, sort_by: str = "relevance",
                           limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        """Search plugins in the marketplace."""
        try:
            # Create cache key
            cache_key = hashlib.md5(
                f"{query}_{category}_{tags}_{sort_by}_{limit}_{offset}".encode()
            ).hexdigest()
            
            # Check cache
            if cache_key in self.search_cache:
                cached_result = self.search_cache[cache_key]
                if datetime.now(timezone.utc) - cached_result["timestamp"] < timedelta(seconds=self.config["cache_ttl"]):
                    return cached_result["data"]
            
            # Perform search
            results = []
            for plugin in self.plugins.values():
                if self._matches_search_criteria(plugin, query, category, tags):
                    results.append(plugin)
            
            # Sort results
            results = self._sort_search_results(results, sort_by)
            
            # Apply pagination
            total_count = len(results)
            results = results[offset:offset + limit]
            
            # Prepare response
            response = {
                "plugins": [self._plugin_to_dict(plugin) for plugin in results],
                "total_count": total_count,
                "page_size": limit,
                "page_offset": offset,
                "has_more": offset + limit < total_count,
                "search_query": query,
                "category": category.value if category else None,
                "tags": tags or [],
                "sort_by": sort_by
            }
            
            # Cache result
            self.search_cache[cache_key] = {
                "data": response,
                "timestamp": datetime.now(timezone.utc)
            }
            
            return response
            
        except Exception as e:
            logger.error(f"Plugin search failed: {e}")
            return {
                "plugins": [],
                "total_count": 0,
                "error": str(e)
            }
    
    async def get_plugin_details(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific plugin."""
        try:
            if plugin_id not in self.plugins:
                return None
            
            plugin = self.plugins[plugin_id]
            plugin_dict = self._plugin_to_dict(plugin)
            
            # Add reviews
            plugin_dict["reviews"] = [
                self._review_to_dict(review) 
                for review in self.reviews.get(plugin_id, [])
            ]
            
            # Add developer info
            developer = self._find_developer_by_plugin(plugin_id)
            if developer:
                plugin_dict["developer"] = self._developer_to_dict(developer)
            
            # Add related plugins
            plugin_dict["related_plugins"] = await self._get_related_plugins(plugin_id)
            
            return plugin_dict
            
        except Exception as e:
            logger.error(f"Failed to get plugin details for {plugin_id}: {e}")
            return None
    
    async def get_featured_plugins(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get featured plugins for the marketplace homepage."""
        try:
            featured = [
                plugin for plugin in self.plugins.values() 
                if plugin.featured
            ]
            
            # Sort by rating and download count
            featured.sort(
                key=lambda p: (p.rating_average, p.download_count),
                reverse=True
            )
            
            return [
                self._plugin_to_dict(plugin) 
                for plugin in featured[:limit]
            ]
            
        except Exception as e:
            logger.error(f"Failed to get featured plugins: {e}")
            return []
    
    async def get_categories(self) -> Dict[str, Any]:
        """Get plugin categories with counts."""
        try:
            categories = {}
            
            for category in PluginCategory:
                count = sum(
                    1 for plugin in self.plugins.values() 
                    if plugin.category == category
                )
                categories[category.value] = {
                    "name": category.value.replace("_", " ").title(),
                    "count": count,
                    "icon": self._get_category_icon(category)
                }
            
            return categories
            
        except Exception as e:
            logger.error(f"Failed to get categories: {e}")
            return {}
    
    # Remote plugin installation removed - plugins managed locally through WebUI
    
    async def add_review(self, plugin_id: str, user_id: str, username: str,
                        rating: PluginRating, title: str, content: str) -> Dict[str, Any]:
        """Add a review for a plugin."""
        try:
            if plugin_id not in self.plugins:
                return {"success": False, "error": "Plugin not found"}
            
            # Create review
            review = PluginReview(
                review_id=str(uuid.uuid4()),
                plugin_id=plugin_id,
                user_id=user_id,
                username=username,
                rating=rating,
                title=title,
                content=content
            )
            
            # Add to reviews
            if plugin_id not in self.reviews:
                self.reviews[plugin_id] = []
            
            self.reviews[plugin_id].append(review)
            
            # Update plugin rating
            await self._update_plugin_rating(plugin_id)
            
            # Save data
            await self._save_marketplace_data()

            # Send webhook notification
            await self.trigger_webhook(WebhookEvent.REVIEW_ADDED, {
                "review_id": review.review_id,
                "plugin_id": plugin_id,
                "plugin_name": self.plugins[plugin_id].name,
                "user_id": user_id,
                "username": username,
                "rating": rating.value,
                "title": title,
                "timestamp": review.created_at.isoformat()
            })

            return {
                "success": True,
                "review_id": review.review_id,
                "message": "Review added successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to add review: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_marketplace_statistics(self) -> Dict[str, Any]:
        """Get marketplace statistics."""
        await self._update_statistics()
        return {
            "statistics": self.stats,
            "categories": await self.get_categories(),
            "recent_plugins": await self._get_recent_plugins(5),
            "top_rated": await self._get_top_rated_plugins(5),
            "most_downloaded": await self._get_most_downloaded_plugins(5)
        }
    
    def _matches_search_criteria(self, plugin: PluginMarketplaceInfo, query: str,
                                category: Optional[PluginCategory], tags: List[str]) -> bool:
        """Check if plugin matches search criteria."""
        # Category filter
        if category and plugin.category != category:
            return False
        
        # Tags filter
        if tags and not any(tag in plugin.tags for tag in tags):
            return False
        
        # Query filter
        if query:
            query_lower = query.lower()
            if not any(query_lower in field.lower() for field in [
                plugin.name, plugin.description, plugin.author
            ] + plugin.tags):
                return False
        
        return True
    
    def _sort_search_results(self, results: List[PluginMarketplaceInfo], sort_by: str) -> List[PluginMarketplaceInfo]:
        """Sort search results by specified criteria."""
        if sort_by == "name":
            return sorted(results, key=lambda p: p.name.lower())
        elif sort_by == "rating":
            return sorted(results, key=lambda p: p.rating_average, reverse=True)
        elif sort_by == "downloads":
            return sorted(results, key=lambda p: p.download_count, reverse=True)
        elif sort_by == "newest":
            return sorted(results, key=lambda p: p.created_at, reverse=True)
        elif sort_by == "updated":
            return sorted(results, key=lambda p: p.updated_at, reverse=True)
        else:  # relevance (default)
            return sorted(results, key=lambda p: (p.featured, p.rating_average, p.download_count), reverse=True)
    
    def _plugin_to_dict(self, plugin: PluginMarketplaceInfo) -> Dict[str, Any]:
        """Convert plugin info to dictionary."""
        return {
            "plugin_id": plugin.plugin_id,
            "name": plugin.name,
            "version": plugin.version,
            "description": plugin.description,
            "author": plugin.author,
            "category": plugin.category.value,
            "tags": plugin.tags,
            "homepage": plugin.homepage,
            "repository": plugin.repository,
            "license": plugin.license,
            "price": plugin.price,
            "currency": plugin.currency,
            "download_count": plugin.download_count,
            "rating_average": plugin.rating_average,
            "rating_count": plugin.rating_count,
            "reviews_count": plugin.reviews_count,
            "featured": plugin.featured,
            "verified": plugin.verified,
            "min_plexichat_version": plugin.min_plexichat_version,
            "max_plexichat_version": plugin.max_plexichat_version,
            "supported_platforms": plugin.supported_platforms,
            "created_at": plugin.created_at.isoformat(),
            "updated_at": plugin.updated_at.isoformat(),
            "last_download": plugin.last_download.isoformat() if plugin.last_download else None,
            "download_url": plugin.download_url,
            "icon_url": plugin.icon_url,
            "screenshots": plugin.screenshots,
            "changelog": plugin.changelog,
            "checksum": plugin.checksum,
            "security_scan_passed": plugin.security_scan_passed,
            "security_scan_date": plugin.security_scan_date.isoformat() if plugin.security_scan_date else None
        }

    def _review_to_dict(self, review: PluginReview) -> Dict[str, Any]:
        """Convert review to dictionary."""
        return {
            "review_id": review.review_id,
            "plugin_id": review.plugin_id,
            "user_id": review.user_id,
            "username": review.username,
            "rating": review.rating.value,
            "title": review.title,
            "content": review.content,
            "helpful_count": review.helpful_count,
            "created_at": review.created_at.isoformat(),
            "updated_at": review.updated_at.isoformat(),
            "verified_purchase": review.verified_purchase
        }

    def _developer_to_dict(self, developer: PluginDeveloper) -> Dict[str, Any]:
        """Convert developer to dictionary."""
        return {
            "developer_id": developer.developer_id,
            "username": developer.username,
            "display_name": developer.display_name,
            "bio": developer.bio,
            "website": developer.website,
            "avatar_url": developer.avatar_url,
            "verified": developer.verified,
            "plugins_count": developer.plugins_count,
            "total_downloads": developer.total_downloads,
            "average_rating": developer.average_rating,
            "created_at": developer.created_at.isoformat()
        }

    def _find_developer_by_plugin(self, plugin_id: str) -> Optional[PluginDeveloper]:
        """Find developer by plugin ID."""
        if plugin_id not in self.plugins:
            return None

        plugin = self.plugins[plugin_id]
        for developer in self.developers.values():
            if developer.email == plugin.author_email:
                return developer

        return None

    def _get_category_icon(self, category: PluginCategory) -> str:
        """Get icon for plugin category."""
        icons = {
            PluginCategory.COMMUNICATION: "",
            PluginCategory.SECURITY: "",
            PluginCategory.PRODUCTIVITY: "",
            PluginCategory.ENTERTAINMENT: "",
            PluginCategory.DEVELOPMENT: "",
            PluginCategory.INTEGRATION: "",
            PluginCategory.UTILITY: "",
            PluginCategory.AI_ML: "",
            PluginCategory.BACKUP: "",
            PluginCategory.MONITORING: "",
            PluginCategory.CUSTOMIZATION: "",
            PluginCategory.OTHER: ""
        }
        return icons.get(category, "")

    async def _get_related_plugins(self, plugin_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get plugins related to the specified plugin."""
        try:
            if plugin_id not in self.plugins:
                return []

            current_plugin = self.plugins[plugin_id]
            related = []

            # Find plugins with similar tags or category
            for pid, plugin in self.plugins.items():
                if pid == plugin_id:
                    continue

                score = 0

                # Same category
                if plugin.category == current_plugin.category:
                    score += 3

                # Common tags
                common_tags = set(plugin.tags) & set(current_plugin.tags)
                score += len(common_tags) * 2

                # Same author
                if plugin.author == current_plugin.author:
                    score += 1

                if score > 0:
                    related.append((score, plugin))

            # Sort by score and return top results
            related.sort(key=lambda x: x[0], reverse=True)
            return [
                self._plugin_to_dict(plugin)
                for _, plugin in related[:limit]
            ]

        except Exception as e:
            logger.error(f"Failed to get related plugins: {e}")
            return []

    async def _update_plugin_rating(self, plugin_id: str):
        """Update plugin rating based on reviews."""
        try:
            if plugin_id not in self.plugins or plugin_id not in self.reviews:
                return

            plugin = self.plugins[plugin_id]
            reviews = self.reviews[plugin_id]

            if not reviews:
                plugin.rating_average = 0.0
                plugin.rating_count = 0
                plugin.reviews_count = 0
                return

            # Calculate average rating
            total_rating = sum(review.rating.value for review in reviews)
            plugin.rating_average = total_rating / len(reviews)
            plugin.rating_count = len(reviews)
            plugin.reviews_count = len(reviews)
            plugin.updated_at = datetime.now(timezone.utc)

        except Exception as e:
            logger.error(f"Failed to update plugin rating: {e}")

    async def _download_plugin(self, plugin: PluginMarketplaceInfo) -> Dict[str, Any]:
        """Download plugin file from repository."""
        try:
            if not plugin.download_url:
                return {"success": False, "error": "No download URL available"}

            # Create temporary file
            temp_file = self.cache_dir / f"{plugin.plugin_id}_{plugin.version}.zip"

            # Download file
            async with aiohttp.ClientSession() as session:
                async with session.get(plugin.download_url) as response:
                    if response.status != 200:
                        return {"success": False, "error": f"Download failed: HTTP {response.status}"}

                    async with aiofiles.open(temp_file, 'wb') as f:
                        async for chunk in response.content.iter_chunked(8192):
                            await f.write(chunk)

            # Verify checksum if available
            if plugin.checksum:
                file_checksum = await self._calculate_file_checksum(temp_file)
                if file_checksum != plugin.checksum:
                    temp_file.unlink(missing_ok=True)
                    return {"success": False, "error": "Checksum verification failed"}

            return {
                "success": True,
                "file_path": temp_file,
                "message": "Plugin downloaded successfully"
            }

        except Exception as e:
            logger.error(f"Failed to download plugin: {e}")
            return {"success": False, "error": str(e)}

    async def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file."""
        try:
            hash_sha256 = hashlib.sha256()
            async with aiofiles.open(file_path, 'rb') as f:
                while chunk := await f.read(8192):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum: {e}")
            return ""

    async def _send_webhook(self, event_type: str, data: Dict[str, Any]):
        """Send webhook notification."""
        try:
            if event_type not in self.webhook_endpoints:
                return

            webhook_url = self.webhook_endpoints[event_type]
            payload = {
                "event": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.debug(f"Webhook sent successfully: {event_type}")
                    else:
                        logger.warning(f"Webhook failed: {event_type} - HTTP {response.status}")

        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")

    async def _update_statistics(self):
        """Update marketplace statistics."""
        try:
            self.stats = {
                "total_plugins": len(self.plugins),
                "total_downloads": sum(plugin.download_count for plugin in self.plugins.values()),
                "total_reviews": sum(len(reviews) for reviews in self.reviews.values()),
                "active_developers": len(self.developers),
                "featured_plugins": sum(1 for plugin in self.plugins.values() if plugin.featured)
            }
        except Exception as e:
            logger.error(f"Failed to update statistics: {e}")

    async def _get_recent_plugins(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recently added plugins."""
        try:
            recent = sorted(
                self.plugins.values(),
                key=lambda p: p.created_at,
                reverse=True
            )
            return [self._plugin_to_dict(plugin) for plugin in recent[:limit]]
        except Exception as e:
            logger.error(f"Failed to get recent plugins: {e}")
            return []

    async def _get_top_rated_plugins(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top-rated plugins."""
        try:
            top_rated = sorted(
                [p for p in self.plugins.values() if p.rating_count >= 3],
                key=lambda p: p.rating_average,
                reverse=True
            )
            return [self._plugin_to_dict(plugin) for plugin in top_rated[:limit]]
        except Exception as e:
            logger.error(f"Failed to get top-rated plugins: {e}")
            return []

    async def _get_most_downloaded_plugins(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get most downloaded plugins."""
        try:
            most_downloaded = sorted(
                self.plugins.values(),
                key=lambda p: p.download_count,
                reverse=True
            )
            return [self._plugin_to_dict(plugin) for plugin in most_downloaded[:limit]]
        except Exception as e:
            logger.error(f"Failed to get most downloaded plugins: {e}")
            return []

    async def _load_marketplace_data(self):
        """Load marketplace data from storage."""
        try:
            # Load plugins
            plugins_file = self.data_dir / "plugins.json"
            if plugins_file.exists():
                async with aiofiles.open(plugins_file, 'r') as f:
                    plugins_data = json.loads(await f.read())

                for plugin_data in plugins_data:
                    plugin = self._dict_to_plugin(plugin_data)
                    self.plugins[plugin.plugin_id] = plugin

            # Load reviews
            reviews_file = self.data_dir / "reviews.json"
            if reviews_file.exists():
                async with aiofiles.open(reviews_file, 'r') as f:
                    reviews_data = json.loads(await f.read())

                for plugin_id, plugin_reviews in reviews_data.items():
                    self.reviews[plugin_id] = [
                        self._dict_to_review(review_data)
                        for review_data in plugin_reviews
                    ]

            # Load developers
            developers_file = self.data_dir / "developers.json"
            if developers_file.exists():
                async with aiofiles.open(developers_file, 'r') as f:
                    developers_data = json.loads(await f.read())

                for dev_data in developers_data:
                    developer = self._dict_to_developer(dev_data)
                    self.developers[developer.developer_id] = developer

            logger.info(f" Loaded {len(self.plugins)} plugins, {len(self.developers)} developers")

        except Exception as e:
            logger.error(f"Failed to load marketplace data: {e}")

    async def _save_marketplace_data(self):
        """Save marketplace data to storage."""
        try:
            # Save plugins
            plugins_data = [self._plugin_to_dict(plugin) for plugin in self.plugins.values()]
            plugins_file = self.data_dir / "plugins.json"
            async with aiofiles.open(plugins_file, 'w') as f:
                await f.write(json.dumps(plugins_data, indent=2, default=str))

            # Save reviews
            reviews_data = {}
            for plugin_id, plugin_reviews in self.reviews.items():
                reviews_data[plugin_id] = [
                    self._review_to_dict(review)
                    for review in plugin_reviews
                ]

            reviews_file = self.data_dir / "reviews.json"
            async with aiofiles.open(reviews_file, 'w') as f:
                await f.write(json.dumps(reviews_data, indent=2, default=str))

            # Save developers
            developers_data = [self._developer_to_dict(dev) for dev in self.developers.values()]
            developers_file = self.data_dir / "developers.json"
            async with aiofiles.open(developers_file, 'w') as f:
                await f.write(json.dumps(developers_data, indent=2, default=str))

            logger.debug(" Marketplace data saved successfully")

        except Exception as e:
            logger.error(f"Failed to save marketplace data: {e}")

    def _dict_to_plugin(self, data: Dict[str, Any]) -> PluginMarketplaceInfo:
        """Convert dictionary to plugin info."""
        return PluginMarketplaceInfo(
            plugin_id=data["plugin_id"],
            name=data["name"],
            version=data["version"],
            description=data["description"],
            author=data["author"],
            author_email=data.get("author_email", ""),
            category=PluginCategory(data["category"]),
            tags=data.get("tags", []),
            homepage=data.get("homepage"),
            repository=data.get("repository"),
            license=data.get("license", "Unknown"),
            price=data.get("price", 0.0),
            currency=data.get("currency", "USD"),
            download_count=data.get("download_count", 0),
            rating_average=data.get("rating_average", 0.0),
            rating_count=data.get("rating_count", 0),
            reviews_count=data.get("reviews_count", 0),
            featured=data.get("featured", False),
            verified=data.get("verified", False),
            min_plexichat_version=data.get("min_plexichat_version", "3.0.0"),
            max_plexichat_version=data.get("max_plexichat_version"),
            supported_platforms=data.get("supported_platforms", ["windows", "linux", "macos"]),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"],
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data["updated_at"], str) else data["updated_at"],
            last_download=datetime.fromisoformat(data["last_download"]) if data.get("last_download") else None,
            download_url=data.get("download_url", ""),
            icon_url=data.get("icon_url"),
            screenshots=data.get("screenshots", []),
            changelog=data.get("changelog", ""),
            checksum=data.get("checksum", ""),
            signature=data.get("signature"),
            security_scan_passed=data.get("security_scan_passed", False),
            security_scan_date=datetime.fromisoformat(data["security_scan_date"]) if data.get("security_scan_date") else None
        )

    def _dict_to_review(self, data: Dict[str, Any]) -> PluginReview:
        """Convert dictionary to review."""
        return PluginReview(
            review_id=data["review_id"],
            plugin_id=data["plugin_id"],
            user_id=data["user_id"],
            username=data["username"],
            rating=PluginRating(data["rating"]),
            title=data["title"],
            content=data["content"],
            helpful_count=data.get("helpful_count", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"],
            updated_at=datetime.fromisoformat(data["updated_at"]) if isinstance(data["updated_at"], str) else data["updated_at"],
            verified_purchase=data.get("verified_purchase", False)
        )

    def _dict_to_developer(self, data: Dict[str, Any]) -> PluginDeveloper:
        """Convert dictionary to developer."""
        return PluginDeveloper(
            developer_id=data["developer_id"],
            username=data["username"],
            email=data["email"],
            display_name=data["display_name"],
            bio=data.get("bio"),
            website=data.get("website"),
            avatar_url=data.get("avatar_url"),
            verified=data.get("verified", False),
            plugins_count=data.get("plugins_count", 0),
            total_downloads=data.get("total_downloads", 0),
            average_rating=data.get("average_rating", 0.0),
            created_at=datetime.fromisoformat(data["created_at"]) if isinstance(data["created_at"], str) else data["created_at"]
        )

    async def _sync_external_repositories(self):
        """Sync plugins from external repositories."""
        try:
            for repo in self.external_repositories:
                if not repo.get("enabled", True):
                    continue

                logger.info(f" Syncing with repository: {repo['name']}")

                try:
                    async with aiohttp.ClientSession() as session:
                        # Get plugin list
                        async with session.get(f"{repo['url']}/plugins") as response:
                            if response.status != 200:
                                logger.warning(f"Failed to sync with {repo['name']}: HTTP {response.status}")
                                continue

                            plugins_data = await response.json()

                            for plugin_data in plugins_data.get("plugins", []):
                                await self._sync_external_plugin(plugin_data, repo)

                except Exception as e:
                    logger.error(f"Failed to sync with {repo['name']}: {e}")

            # Save updated data
            await self._save_marketplace_data()

        except Exception as e:
            logger.error(f"Failed to sync external repositories: {e}")

    async def _sync_external_plugin(self, plugin_data: Dict[str, Any], repo: Dict[str, Any]):
        """Sync a single plugin from external repository."""
        try:
            plugin_id = plugin_data.get("plugin_id") or plugin_data.get("id")
            if not plugin_id:
                return

            # Check if plugin exists and needs update
            existing_plugin = self.plugins.get(plugin_id)
            remote_version = plugin_data.get("version", "1.0.0")

            if existing_plugin and existing_plugin.version == remote_version:
                return  # Already up to date

            # Convert external plugin data to our format
            plugin = PluginMarketplaceInfo(
                plugin_id=plugin_id,
                name=plugin_data.get("name", "Unknown Plugin"),
                version=remote_version,
                description=plugin_data.get("description", ""),
                author=plugin_data.get("author", "Unknown"),
                author_email=plugin_data.get("author_email", ""),
                category=PluginCategory(plugin_data.get("category", "other")),
                tags=plugin_data.get("tags", []),
                homepage=plugin_data.get("homepage"),
                repository=plugin_data.get("repository"),
                license=plugin_data.get("license", "Unknown"),
                price=plugin_data.get("price", 0.0),
                download_count=plugin_data.get("download_count", 0),
                rating_average=plugin_data.get("rating_average", 0.0),
                rating_count=plugin_data.get("rating_count", 0),
                featured=plugin_data.get("featured", False) and repo.get("trusted", False),
                verified=repo.get("trusted", False),
                download_url=plugin_data.get("download_url", ""),
                icon_url=plugin_data.get("icon_url"),
                screenshots=plugin_data.get("screenshots", []),
                changelog=plugin_data.get("changelog", ""),
                checksum=plugin_data.get("checksum", ""),
                security_scan_passed=plugin_data.get("security_scan_passed", False)
            )

            self.plugins[plugin_id] = plugin
            logger.debug(f" Synced plugin: {plugin.name} v{plugin.version}")

        except Exception as e:
            logger.error(f"Failed to sync external plugin: {e}")

    # Webhook System Methods
    async def register_webhook(self, url: str, events: List[str], secret: str = None) -> Dict[str, Any]:
        """Register a new webhook endpoint."""
        try:
            # Validate events
            valid_events = []
            for event in events:
                try:
                    valid_events.append(WebhookEvent(event))
                except ValueError:
                    return {"success": False, "error": f"Invalid event: {event}"}

            # Generate endpoint ID and secret
            endpoint_id = f"webhook_{secrets.token_urlsafe(16)}"
            webhook_secret = secret or secrets.token_urlsafe(32)

            # Create webhook endpoint
            endpoint = WebhookEndpoint(
                endpoint_id=endpoint_id,
                url=url,
                secret=webhook_secret,
                events=valid_events
            )

            self.webhook_endpoints[endpoint_id] = endpoint
            await self._save_marketplace_data()

            logger.info(f" Registered webhook endpoint: {url}")

            return {
                "success": True,
                "endpoint_id": endpoint_id,
                "secret": webhook_secret,
                "events": [event.value for event in valid_events]
            }

        except Exception as e:
            logger.error(f"Failed to register webhook: {e}")
            return {"success": False, "error": str(e)}

    async def trigger_webhook(self, event: WebhookEvent, payload: Dict[str, Any]):
        """Trigger webhook notifications for an event."""
        try:
            # Find matching endpoints
            matching_endpoints = [
                endpoint for endpoint in self.webhook_endpoints.values()
                if event in endpoint.events and endpoint.is_active
            ]

            if not matching_endpoints:
                return

            # Send webhooks asynchronously
            tasks = []
            for endpoint in matching_endpoints:
                task = asyncio.create_task(self._send_webhook(endpoint, event, payload))
                tasks.append(task)

            # Wait for all webhooks to complete
            await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            logger.error(f"Failed to trigger webhooks: {e}")

    async def _send_webhook(self, endpoint: WebhookEndpoint, event: WebhookEvent, payload: Dict[str, Any]):
        """Send a single webhook notification."""
        delivery_id = f"delivery_{secrets.token_urlsafe(16)}"

        try:
            # Prepare webhook payload
            webhook_payload = {
                "event": event.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": payload
            }

            # Generate signature
            signature = self._generate_webhook_signature(
                json.dumps(webhook_payload, sort_keys=True),
                endpoint.secret
            )

            # Send HTTP request
            headers = {
                "Content-Type": "application/json",
                "X-PlexiChat-Event": event.value,
                "X-PlexiChat-Signature": signature,
                "X-PlexiChat-Delivery": delivery_id,
                "User-Agent": "PlexiChat-Marketplace/1.0"
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint.url,
                    json=webhook_payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_body = await response.text()

                    # Record delivery
                    delivery = WebhookDelivery(
                        delivery_id=delivery_id,
                        endpoint_id=endpoint.endpoint_id,
                        event=event,
                        payload=webhook_payload,
                        status_code=response.status,
                        response_body=response_body[:1000],  # Limit response body size
                        delivered_at=datetime.now(timezone.utc)
                    )

                    self.webhook_deliveries.append(delivery)

                    # Update endpoint statistics
                    endpoint.last_triggered = datetime.now(timezone.utc)
                    if 200 <= response.status < 300:
                        endpoint.success_count += 1
                        logger.debug(f" Webhook delivered: {endpoint.url} ({response.status})")
                    else:
                        endpoint.failure_count += 1
                        logger.warning(f" Webhook failed: {endpoint.url} ({response.status})")

        except Exception as e:
            # Record failed delivery
            delivery = WebhookDelivery(
                delivery_id=delivery_id,
                endpoint_id=endpoint.endpoint_id,
                event=event,
                payload=payload,
                error_message=str(e)
            )

            self.webhook_deliveries.append(delivery)
            endpoint.failure_count += 1

            logger.error(f" Webhook delivery failed: {endpoint.url} - {e}")

    def _generate_webhook_signature(self, payload: str, secret: str) -> str:
        """Generate HMAC signature for webhook payload."""
        signature = hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

    async def get_webhook_endpoints(self) -> List[Dict[str, Any]]:
        """Get all registered webhook endpoints."""
        return [
            {
                "endpoint_id": endpoint.endpoint_id,
                "url": endpoint.url,
                "events": [event.value for event in endpoint.events],
                "is_active": endpoint.is_active,
                "created_at": endpoint.created_at.isoformat(),
                "last_triggered": endpoint.last_triggered.isoformat() if endpoint.last_triggered else None,
                "success_count": endpoint.success_count,
                "failure_count": endpoint.failure_count
            }
            for endpoint in self.webhook_endpoints.values()
        ]

    async def get_webhook_deliveries(self, endpoint_id: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get webhook delivery history."""
        deliveries = self.webhook_deliveries

        if endpoint_id:
            deliveries = [d for d in deliveries if d.endpoint_id == endpoint_id]

        # Sort by creation time (newest first) and limit
        deliveries = sorted(deliveries, key=lambda d: d.created_at, reverse=True)[:limit]

        return [
            {
                "delivery_id": delivery.delivery_id,
                "endpoint_id": delivery.endpoint_id,
                "event": delivery.event.value,
                "status_code": delivery.status_code,
                "error_message": delivery.error_message,
                "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
                "created_at": delivery.created_at.isoformat()
            }
            for delivery in deliveries
        ]


# Global service instance
_marketplace_service: Optional[PluginMarketplaceService] = None


def get_plugin_marketplace_service() -> PluginMarketplaceService:
    """Get the global plugin marketplace service instance."""
    global _marketplace_service
    if _marketplace_service is None:
        _marketplace_service = PluginMarketplaceService()
    return _marketplace_service


async def initialize_plugin_marketplace() -> bool:
    """Initialize the plugin marketplace service."""
    service = get_plugin_marketplace_service()
    return await service.initialize()
