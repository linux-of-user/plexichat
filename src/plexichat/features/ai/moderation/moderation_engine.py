import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path

"""
Advanced AI Moderation Engine
Supports multiple AI providers, custom training, and progressive learning.
"""

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
    categories: List[ModerationCategory]
    reasoning: str
    metadata: Dict[str, Any]
    processing_time_ms: float
    model_used: str
    requires_human_review: bool
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
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
            "timestamp": self.timestamp.isoformat()
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
    custom_prompts: Dict[str, str] = None
    enabled_categories: Optional[List[ModerationCategory]] = None
    
    def __post_init__(self):
        if self.custom_prompts is None:
            self.custom_prompts = {}
        if self.enabled_categories is None:
            self.enabled_categories = list(ModerationCategory)

class ModerationEngine:
    """Advanced AI moderation engine with multiple provider support."""
    
    def __init__(self, config_path: str = "config/moderation_config.json"):
        self.from pathlib import Path
config_path = Path()(config_path)
        self.configs: Dict[str, ModerationConfig] = {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.from pathlib import Path
db_path = Path()("data/moderation.db")
        self.load_config()
        self._init_database()
        
    def load_config(self):
        """Load moderation configuration."""
        if self.config_path.exists() if self.config_path else False:
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    for name, config_data in data.get("providers", {}).items():
                        self.configs[name] = ModerationConfig(**config_data)
                logger.info(f"Loaded {len(self.configs)} moderation providers")
            except Exception as e:
                logger.error(f"Failed to load moderation config: {e}")
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration."""
        default_config = {
            "providers": {
                "openai": {
                    "provider": "openai",
                    "model_name": "gpt-4",
                    "api_key": "your-openai-api-key",
                    "endpoint_url": "https://api.openai.com/v1/chat/completions",
                    "confidence_threshold": 0.8,
                    "auto_action_threshold": 0.95,
                    "human_review_threshold": 0.7
                },
                "local": {
                    "provider": "local",
                    "model_name": "custom-moderation-model",
                    "api_key": "",
                    "endpoint_url": "http://localhost:8080/moderate",
                    "confidence_threshold": 0.7,
                    "auto_action_threshold": 0.9,
                    "human_review_threshold": 0.6
                }
            }
        }
        
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        logger.info("Created default moderation configuration")
    
    def _init_database(self):
        """Initialize moderation database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS moderation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_id TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    recommended_action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    reasoning TEXT,
                    metadata TEXT,
                    processing_time_ms REAL,
                    model_used TEXT,
                    requires_human_review BOOLEAN,
                    timestamp TEXT NOT NULL,
                    user_feedback TEXT,
                    human_reviewed BOOLEAN DEFAULT FALSE,
                    human_decision TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_hash ON moderation_results(content_hash)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON moderation_results(timestamp)
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    confidence REAL,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
        
        logger.info("Moderation database initialized")

    async def moderate_content(
        self,
        content: str,
        content_id: str,
        content_type: str = "text",
        provider: str = "openai",
        metadata: Optional[Dict[str, Any]] = None
    ) -> ModerationResult:
        """Moderate content using specified AI provider."""
        start_time = time.time()

        if provider not in self.configs:
            raise ValueError(f"Unknown moderation provider: {provider}")

        config = self.configs[provider]
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Check cache first
        cached_result = self._get_cached_result(content_hash)
        if cached_result:
            logger.info(f"Using cached moderation result for content {content_id}")
            return cached_result

        try:
            if config.provider == "openai":
                result = await self._moderate_with_openai(content, content_id, config, metadata)
            elif config.provider == "local":
                result = await self._moderate_with_local_model(content, content_id, config, metadata)
            else:
                result = await self._moderate_with_custom_provider(content, content_id, config, metadata)

            # Store result in database
            self._store_result(result, content_hash)

            processing_time = (time.time() - start_time) * 1000
            result.processing_time_ms = processing_time

            logger.info(f"Moderated content {content_id}: {result.recommended_action.value} (confidence: {result.confidence_score:.2f})")
            return result

        except Exception as e:
            logger.error(f"Moderation failed for content {content_id}: {e}")
            # Return safe default
            return ModerationResult(
                content_id=content_id,
                confidence_score=0.5,
                recommended_action=ModerationAction.FLAG,
                severity=ModerationSeverity.MEDIUM,
                categories=[ModerationCategory.CLEAN],
                reasoning=f"Moderation failed: {str(e)}",
                metadata={"error": str(e)},
                processing_time_ms=(time.time() - start_time) * 1000,
                model_used=f"{provider}:error",
                requires_human_review=True,
                timestamp=datetime.now(timezone.utc)
            )

    async def _moderate_with_openai(
        self,
        content: str,
        content_id: str,
        config: ModerationConfig,
        metadata: Optional[Dict[str, Any]]
    ) -> ModerationResult:
        """Moderate content using OpenAI."""
        if not self.session:
            self.session = aiohttp.ClientSession()

        prompt = self._get_moderation_prompt("openai", content)

        payload = {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": content}
            ],
            "temperature": 0.1,
            "max_tokens": 500
        }

        headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json"
        }

        async with self.session.post(
            config.endpoint_url,
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)
        ) as response:
            if response.status == 200:
                data = await response.json()
                content_text = data["choices"][0]["message"]["content"]
                return self._parse_moderation_response(content_text, content_id, config.model_name)
            else:
                raise Exception(f"OpenAI API error: {response.status}")

    async def _moderate_with_local_model(
        self,
        content: str,
        content_id: str,
        config: ModerationConfig,
        metadata: Optional[Dict[str, Any]]
    ) -> ModerationResult:
        """Moderate content using local model."""
        if not self.session:
            self.session = aiohttp.ClientSession()

        payload = {
            "content": content,
            "content_id": content_id,
            "metadata": metadata or {}
        }

        async with self.session.post(
            config.endpoint_url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)
        ) as response:
            if response.status == 200:
                data = await response.json()
                return ModerationResult(
                    content_id=content_id,
                    confidence_score=data.get("confidence", 0.5),
                    recommended_action=ModerationAction(data.get("action", "flag")),
                    severity=ModerationSeverity(data.get("severity", "medium")),
                    categories=[ModerationCategory(cat) for cat in data.get("categories", ["clean"])],
                    reasoning=data.get("reasoning", "Local model analysis"),
                    metadata=data.get("metadata", {}),
                    processing_time_ms=0,
                    model_used=config.model_name,
                    requires_human_review=data.get("requires_human_review", False),
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                raise Exception(f"Local model API error: {response.status}")

    def _get_moderation_prompt(self, provider: str, content: str) -> str:
        """Get moderation prompt for provider."""
        base_prompt = """You are an AI content moderator. Analyze the following content and provide a JSON response with:
        - confidence: float (0.0-1.0) indicating confidence in your assessment
        - action: one of [allow, flag, block, delete, quarantine, warn_user, timeout_user, ban_user]
        - severity: one of [low, medium, high, critical]
        - categories: list of applicable categories from [spam, harassment, hate_speech, violence, sexual_content, illegal_content, misinformation, self_harm, doxxing, copyright, phishing, malware, clean]
        - reasoning: brief explanation of your decision
        - requires_human_review: boolean indicating if human review is needed

        Content to analyze:"""

        return base_prompt

    def _parse_moderation_response(self, response_text: str, content_id: str, model_name: str) -> ModerationResult:
        """Parse AI moderation response."""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                # Fallback parsing
                data = {
                    "confidence": 0.5,
                    "action": "flag",
                    "severity": "medium",
                    "categories": ["clean"],
                    "reasoning": response_text,
                    "requires_human_review": True
                }

            return ModerationResult(
                content_id=content_id,
                confidence_score=float(data.get("confidence", 0.5)),
                recommended_action=ModerationAction(data.get("action", "flag")),
                severity=ModerationSeverity(data.get("severity", "medium")),
                categories=[ModerationCategory(cat) for cat in data.get("categories", ["clean"])],
                reasoning=data.get("reasoning", "AI analysis"),
                metadata=data.get("metadata", {}),
                processing_time_ms=0,
                model_used=model_name,
                requires_human_review=data.get("requires_human_review", False),
                timestamp=datetime.now(timezone.utc)
            )

        except Exception as e:
            logger.error(f"Failed to parse moderation response: {e}")
            return ModerationResult(
                content_id=content_id,
                confidence_score=0.5,
                recommended_action=ModerationAction.FLAG,
                severity=ModerationSeverity.MEDIUM,
                categories=[ModerationCategory.CLEAN],
                reasoning=f"Parse error: {str(e)}",
                metadata={"raw_response": response_text, "parse_error": str(e)},
                processing_time_ms=0,
                model_used=model_name,
                requires_human_review=True,
                timestamp=datetime.now(timezone.utc)
            )

    def _get_cached_result(self, content_hash: str) -> Optional[ModerationResult]:
        """Get cached moderation result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT * FROM moderation_results WHERE content_hash = ? ORDER BY created_at DESC LIMIT 1",
                    (content_hash,)
                )
                row = cursor.fetchone()
                if row:
                    return self._row_to_result(row)
        except Exception as e:
            logger.error(f"Failed to get cached result: {e}")
        return None

    def _store_result(self, result: ModerationResult, content_hash: str):
        """Store moderation result in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO moderation_results (
                        content_id, content_hash, confidence_score, recommended_action,
                        severity, categories, reasoning, metadata, processing_time_ms,
                        model_used, requires_human_review, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.content_id,
                    content_hash,
                    result.confidence_score,
                    result.recommended_action.value,
                    result.severity.value,
                    json.dumps([cat.value for cat in result.categories]),
                    result.reasoning,
                    json.dumps(result.metadata),
                    result.processing_time_ms,
                    result.model_used,
                    result.requires_human_review,
                    result.timestamp.isoformat()
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store moderation result: {e}")

    def _row_to_result(self, row) -> ModerationResult:
        """Convert database row to ModerationResult."""
        return ModerationResult(
            content_id=row[1],
            confidence_score=row[3],
            recommended_action=ModerationAction(row[4]),
            severity=ModerationSeverity(row[5]),
            categories=[ModerationCategory(cat) for cat in json.loads(row[6])],
            reasoning=row[7],
            metadata=json.loads(row[8]) if row[8] else {},
            processing_time_ms=row[9],
            model_used=row[10],
            requires_human_review=bool(row[11]),
            timestamp=datetime.fromisoformat(row[12])
        )

    async def get_moderation_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get moderation statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT
                        COUNT(*) as total_moderations,
                        AVG(confidence_score) as avg_confidence,
                        COUNT(CASE WHEN requires_human_review THEN 1 END) as human_reviews_needed,
                        COUNT(CASE WHEN human_reviewed THEN 1 END) as human_reviewed,
                        recommended_action,
                        COUNT(*) as action_count
                    FROM moderation_results
                    WHERE datetime(timestamp) >= datetime('now', '-{} days')
                    GROUP BY recommended_action
                """.format(days))

                results = cursor.fetchall()

                stats = {
                    "total_moderations": 0,
                    "avg_confidence": 0.0,
                    "human_reviews_needed": 0,
                    "human_reviewed": 0,
                    "actions": {}
                }

                for row in results:
                    stats["total_moderations"] += row[5]
                    stats["avg_confidence"] = row[1] if row[1] else 0.0
                    stats["human_reviews_needed"] += row[2]
                    stats["human_reviewed"] += row[3]
                    stats["actions"][row[4]] = row[5]

                return stats

        except Exception as e:
            logger.error(f"Failed to get moderation stats: {e}")
            return {"error": str(e)}

    async def cleanup(self):
        """Cleanup resources."""
        if self.session:
            await if self.session: self.session.close()
