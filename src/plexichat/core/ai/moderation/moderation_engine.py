"""
Advanced AI Moderation Engine
Supports multiple AI providers, custom training, and progressive learning.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
import hashlib
import json
import logging
from pathlib import Path
import time
from typing import Any

try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger(__name__)


class ModerationAction(str, Enum):
    """Moderation actions."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"
    DELETE = "delete"
    QUARANTINE = "quarantine"
    WARN_USER = "warn_user"
    TIMEOUT_USER = "timeout_user"
    BAN_USER = "ban_user"


class ModerationSeverity(str, Enum):
    """Moderation severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModerationCategory(str, Enum):
    """Content moderation categories."""

    SPAM = "spam"
    HARASSMENT = "harassment"
    HATE_SPEECH = "hate_speech"
    VIOLENCE = "violence"
    SEXUAL_CONTENT = "sexual_content"
    ILLEGAL_CONTENT = "illegal_content"
    MISINFORMATION = "misinformation"
    SELF_HARM = "self_harm"
    DOXXING = "doxxing"
    COPYRIGHT = "copyright"
    PHISHING = "phishing"
    MALWARE = "malware"
    CLEAN = "clean"


@dataclass
class ModerationResult:
    """Result of content moderation."""

    content_id: str
    confidence_score: float  # 0.0 to 1.0
    recommended_action: ModerationAction
    severity: ModerationSeverity
    categories: list[ModerationCategory]
    reasoning: str
    metadata: dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    model_used: str = "default"
    requires_human_review: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_id": self.content_id,
            "confidence_score": self.confidence_score,
            "recommended_action": self.recommended_action.value,
            "severity": self.severity.value,
            "categories": [cat.value for cat in self.categories],
            "reasoning": self.reasoning,
            "metadata": self.metadata,
            "processing_time_ms": self.processing_time_ms,
            "model_used": self.model_used,
            "requires_human_review": self.requires_human_review,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ModerationConfig:
    """Moderation configuration."""

    provider: str
    model_name: str
    api_key: str
    endpoint_url: str
    confidence_threshold: float = 0.8
    auto_action_threshold: float = 0.95
    human_review_threshold: float = 0.7
    timeout_seconds: int = 30
    max_retries: int = 3
    custom_prompts: dict[str, str] = field(default_factory=dict)
    enabled_categories: list[ModerationCategory] | None = None

    def __post_init__(self):
        if self.enabled_categories is None:
            self.enabled_categories = list(ModerationCategory)


class ModerationEngine:
    """Advanced AI moderation engine with multiple provider support."""

    def __init__(self, config_path: str = "config/moderation_config.json"):
        """Initialize the moderation engine."""
        self.config_path = Path(config_path)
        self.configs: dict[str, ModerationConfig] = {}
        self.session: Any | None = None  # aiohttp.ClientSession
        self.db_path = Path("data/moderation.db")
        self.data_service = None
        self.load_config()
        self._init_database()

    def load_config(self):
        """Load moderation configuration."""
        if self.config_path and self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                    for name, config_data in data.get("providers", {}).items():
                        self.configs[name] = ModerationConfig(**config_data)
                logger.info(f"Loaded {len(self.configs)} moderation providers")
            except Exception as e:
                logger.error(f"Failed to load moderation config: {e}")
        else:
            logger.warning("No moderation config found, using defaults")
            self._create_default_config()

    def _create_default_config(self):
        """Create default configuration."""
        default_config = ModerationConfig(
            provider="openai",
            model_name="text-moderation-latest",
            api_key="",
            endpoint_url="https://api.openai.com/v1/moderations",
        )
        self.configs["default"] = default_config

    def _init_database(self):
        """Initialize the database connection."""
        try:
            from plexichat.features.ai.moderation.moderation_data_service import (
                ModerationDataService,
            )

            self.data_service = ModerationDataService()
        except ImportError:
            logger.warning("ModerationDataService not available")
            self.data_service = None

    async def moderate_content(
        self,
        content: str,
        content_id: str,
        provider: str = "default",
        user_id: str | None = None,
    ) -> ModerationResult:
        """Moderate content using specified provider."""
        start_time = time.time()

        try:
            # Check cache first
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            if self.data_service:
                cached_result = await self._get_cached_result(content_hash)
                if cached_result:
                    logger.debug(f"Using cached moderation result for {content_id}")
                    return cached_result

            # Get provider config
            config = self.configs.get(provider, self.configs.get("default"))
            if not config:
                raise ValueError(f"No configuration found for provider: {provider}")

            # Perform moderation
            result = await self._moderate_with_provider(content, content_id, config)

            # Calculate processing time
            result.processing_time_ms = (time.time() - start_time) * 1000

            # Cache result
            if self.data_service:
                await self._cache_result(content_hash, result)

            return result

        except Exception as e:
            logger.error(f"Moderation failed for {content_id}: {e}")
            # Return safe default
            return ModerationResult(
                content_id=content_id,
                confidence_score=0.0,
                recommended_action=ModerationAction.FLAG,
                severity=ModerationSeverity.MEDIUM,
                categories=[ModerationCategory.CLEAN],
                reasoning=f"Moderation failed: {e!s}",
                processing_time_ms=(time.time() - start_time) * 1000,
                requires_human_review=True,
            )

    async def _moderate_with_provider(
        self, content: str, content_id: str, config: ModerationConfig
    ) -> ModerationResult:
        """Moderate content with specific provider."""
        if config.provider == "openai":
            return await self._moderate_with_openai(content, content_id, config)
        elif config.provider == "custom":
            return await self._moderate_with_custom(content, content_id, config)
        else:
            raise ValueError(f"Unsupported provider: {config.provider}")

    async def _moderate_with_openai(
        self, content: str, content_id: str, config: ModerationConfig
    ) -> ModerationResult:
        """Moderate content using OpenAI API."""
        if not aiohttp:
            raise ImportError("aiohttp is required for OpenAI moderation")

        headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }

        payload = {"input": content}

        if not self.session:
            self.session = aiohttp.ClientSession()

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with self.session.post(
                config.endpoint_url, headers=headers, json=payload, timeout=timeout
            ) as response:
                response.raise_for_status()
                data = await response.json()

                return self._parse_openai_response(data, content_id, config.model_name)

        except Exception as e:
            logger.error(f"OpenAI moderation API error: {e}")
            raise

    async def _moderate_with_custom(
        self, content: str, content_id: str, config: ModerationConfig
    ) -> ModerationResult:
        """Moderate content using custom provider."""
        # Implement custom moderation logic here
        # For now, return a basic analysis
        return ModerationResult(
            content_id=content_id,
            confidence_score=0.5,
            recommended_action=ModerationAction.ALLOW,
            severity=ModerationSeverity.LOW,
            categories=[ModerationCategory.CLEAN],
            reasoning="Custom moderation not implemented",
            model_used=config.model_name,
        )

    def _parse_openai_response(
        self, data: dict[str, Any], content_id: str, model_name: str
    ) -> ModerationResult:
        """Parse OpenAI moderation response."""
        try:
            results = data.get("results", [{}])[0]
            flagged = results.get("flagged", False)
            categories = results.get("categories", {})
            category_scores = results.get("category_scores", {})

            # Determine action based on flagged status
            action = ModerationAction.BLOCK if flagged else ModerationAction.ALLOW

            # Determine severity based on highest score
            max_score = max(category_scores.values()) if category_scores else 0.0
            if max_score > 0.8:
                severity = ModerationSeverity.CRITICAL
            elif max_score > 0.6:
                severity = ModerationSeverity.HIGH
            elif max_score > 0.4:
                severity = ModerationSeverity.MEDIUM
            else:
                severity = ModerationSeverity.LOW

            # Map categories
            detected_categories = []
            for category, detected in categories.items():
                if detected:
                    # Map OpenAI categories to our categories
                    if category == "hate":
                        detected_categories.append(ModerationCategory.HATE_SPEECH)
                    elif category == "harassment":
                        detected_categories.append(ModerationCategory.HARASSMENT)
                    elif category == "violence":
                        detected_categories.append(ModerationCategory.VIOLENCE)
                    elif category == "sexual":
                        detected_categories.append(ModerationCategory.SEXUAL_CONTENT)
                    elif category == "self-harm":
                        detected_categories.append(ModerationCategory.SELF_HARM)

            if not detected_categories:
                detected_categories = [ModerationCategory.CLEAN]

            return ModerationResult(
                content_id=content_id,
                confidence_score=max_score,
                recommended_action=action,
                severity=severity,
                categories=detected_categories,
                reasoning=f"OpenAI moderation: flagged={flagged}, max_score={max_score:.3f}",
                model_used=model_name,
                requires_human_review=flagged and max_score < 0.9,
            )

        except Exception as e:
            logger.error(f"Failed to parse OpenAI response: {e}")
            raise

    async def _get_cached_result(self, content_hash: str) -> ModerationResult | None:
        """Get cached moderation result."""
        if not self.data_service:
            return None

        try:
            return await self.data_service.get_latest_moderation_result_by_hash(content_hash)  # type: ignore
        except Exception as e:
            logger.error(f"Failed to get cached result: {e}")
            return None

    async def _cache_result(self, content_hash: str, result: ModerationResult):
        """Cache moderation result."""
        if not self.data_service:
            return

        try:
            await self.data_service.add_moderation_result(content_hash, result)  # type: ignore
        except Exception as e:
            logger.error(f"Failed to cache result: {e}")

    async def close(self):
        """Close the moderation engine and cleanup resources."""
        if self.session:
            await self.session.close()
            self.session = None
