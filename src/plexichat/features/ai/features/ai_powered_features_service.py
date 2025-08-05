# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:

    import numpy as np

except ImportError:

    np = None
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from plexichat.core.logging import get_logger
from ...services.base_service import BaseService, ServiceState
from ..core.ai_abstraction_layer import AIAbstractionLayer, AIRequest

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

"""
PlexiChat AI-Powered Features Service

Comprehensive AI-powered features including smart summarization, content suggestions,
sentiment analysis, semantic search, and automated moderation with multiple AI providers.
"""

logger = get_logger(__name__)


class FeatureType(str, Enum):
    """AI feature types."""
    SUMMARIZATION = "summarization"
    CONTENT_SUGGESTIONS = "content_suggestions"
    SENTIMENT_ANALYSIS = "sentiment_analysis"
    SEMANTIC_SEARCH = "semantic_search"
    AUTOMATED_MODERATION = "automated_moderation"
    TOPIC_DETECTION = "topic_detection"
    LANGUAGE_DETECTION = "language_detection"
    SMART_REPLIES = "smart_replies"


class SentimentType(str, Enum):
    """Sentiment analysis types."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    MIXED = "mixed"


class ModerationAction(str, Enum):
    """Moderation actions."""
    APPROVE = "approve"
    FLAG = "flag"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class SummarizationResult:
    """Summarization result data structure."""
    summary_id: str
    original_text: str
    summary: str
    summary_type: str  # "brief", "detailed", "bullet_points"
    confidence_score: float
    processing_time_ms: float
    word_count_original: int
    word_count_summary: int
    compression_ratio: float
    key_topics: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContentSuggestion:
    """Content suggestion data structure."""
    suggestion_id: str
    context: str
    suggestion: str
    suggestion_type: str  # "completion", "improvement", "alternative"
    confidence_score: float
    relevance_score: float
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SentimentAnalysisResult:
    """Sentiment analysis result data structure."""
    analysis_id: str
    text: str
    sentiment: SentimentType
    confidence_score: float
    emotion_scores: Dict[str, float] = field(default_factory=dict)
    key_phrases: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SemanticSearchResult:
    """Semantic search result data structure."""
    result_id: str
    content: str
    similarity_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    highlighted_text: Optional[str] = None


@dataclass
class ModerationResult:
    """Automated moderation result data structure."""
    moderation_id: str
    content: str
    action: ModerationAction
    confidence_score: float
    violation_categories: List[str] = field(default_factory=list)
    severity_score: float = 0.0
    explanation: Optional[str] = None
    processing_time_ms: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AIPoweredFeaturesService(BaseService):
    """AI-powered features service with comprehensive functionality."""

    def __init__(self, config_path: Optional[Path] = None):
        super().__init__("ai_powered_features")

        # Configuration management
        self.config_path = config_path or from pathlib import Path
Path("config/ai_powered_features.yaml")

        # AI abstraction layer
        self.ai_layer = AIAbstractionLayer()

        # Feature storage
        self.summarization_cache: Dict[str, SummarizationResult] = {}
        self.content_suggestions_cache: Dict[str, List[ContentSuggestion]] = {}
        self.sentiment_cache: Dict[str, SentimentAnalysisResult] = {}
        self.semantic_index: Dict[str, Dict[str, Any]] = {}
        self.moderation_cache: Dict[str, ModerationResult] = {}

        # Semantic search components
        self.tfidf_vectorizer = TfidfVectorizer(max_features=10000, stop_words='english')
        self.document_vectors = None
        self.document_metadata: List[Dict[str, Any]] = []

        # Performance tracking
        self.feature_stats: Dict[str, Dict[str, Any]] = {
            feature.value: {
                "requests": 0,
                "successes": 0,
                "failures": 0,
                "avg_processing_time": 0.0,
                "total_processing_time": 0.0
            } for feature in FeatureType
        }

        # Load configuration
        self.load_configuration()

    def _get_default_configuration(self) -> Dict[str, Any]:
        """Get default configuration for AI-powered features."""
        return {}
            # General Settings
            "enabled": True,
            "debug_mode": False,
            "cache_enabled": True,
            "cache_ttl_hours": 24,
            "max_cache_size": 10000,

            # AI Provider Settings
            "ai_providers": {
                "primary": "openai",
                "fallback": ["anthropic", "google", "ollama"],
                "timeout_seconds": 30,
                "max_retries": 3,
                "rate_limit_per_minute": 100
            },

            # Summarization Settings
            "summarization": {
                "enabled": True,
                "max_input_length": 50000,
                "min_input_length": 100,
                "summary_types": ["brief", "detailed", "bullet_points"],
                "default_type": "brief",
                "max_summary_length": 500,
                "compression_ratio_target": 0.3,
                "include_key_topics": True,
                "model_preference": ["gpt-4", "claude-3-sonnet", "gemini-pro"]
            },

            # Content Suggestions Settings
            "content_suggestions": {
                "enabled": True,
                "suggestion_types": ["completion", "improvement", "alternative"],
                "max_suggestions": 5,
                "min_confidence": 0.7,
                "context_window": 1000,
                "personalization_enabled": True,
                "learning_enabled": True
            },

            # Sentiment Analysis Settings
            "sentiment_analysis": {
                "enabled": True,
                "include_emotions": True,
                "emotion_categories": ["joy", "anger", "fear", "sadness", "surprise", "disgust"],
                "extract_key_phrases": True,
                "batch_processing": True,
                "confidence_threshold": 0.6
            },

            # Semantic Search Settings
            "semantic_search": {
                "enabled": True,
                "index_update_interval_hours": 6,
                "max_results": 20,
                "similarity_threshold": 0.3,
                "enable_highlighting": True,
                "search_fields": ["content", "title", "description"],
                "boost_recent_content": True,
                "embedding_model": "text-embedding-ada-002"
            },

            # Automated Moderation Settings
            "automated_moderation": {
                "enabled": True,
                "auto_action_threshold": 0.9,
                "review_threshold": 0.7,
                "violation_categories": [
                    "hate_speech", "harassment", "spam", "violence",
                    "sexual_content", "misinformation", "copyright"
                ],
                "severity_levels": ["low", "medium", "high", "critical"],
                "human_review_required": True,
                "appeal_system_enabled": True
            },

            # Performance Settings
            "performance": {
                "batch_size": 10,
                "parallel_processing": True,
                "max_concurrent_requests": 5,
                "memory_limit_mb": 1024,
                "disk_cache_enabled": True,
                "compression_enabled": True
            },

            # Privacy Settings
            "privacy": {
                "anonymize_data": True,
                "data_retention_days": 30,
                "encrypt_cache": True,
                "audit_logging": True,
                "user_consent_required": True,
                "data_minimization": True
            }
        }

    async def start(self) -> bool:
        """Start the AI-powered features service."""
        try:
            logger.info("Starting AI-powered features service...")

            # Initialize AI layer
            await self.if ai_layer and hasattr(ai_layer, "initialize"): ai_layer.initialize()

            # Initialize semantic search index
            await self._initialize_semantic_search()

            # Start background tasks
            await self._start_background_tasks()

            self.state = ServiceState.RUNNING
            logger.info("AI-powered features service started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start AI-powered features service: {e}")
            self.state = ServiceState.ERROR
            return False

    async def stop(self) -> bool:
        """Stop the AI-powered features service."""
        try:
            logger.info("Stopping AI-powered features service...")

            # Stop background tasks
            await self._stop_background_tasks()

            # Save cache to disk
            await self._save_cache_to_disk()

            self.state = ServiceState.STOPPED
            logger.info("AI-powered features service stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to stop AI-powered features service: {e}")
            return False

    # Summarization Methods

    async def create_summary()
        self,
        text: str,
        summary_type: str = "brief",
        user_id: Optional[str] = None,
        max_length: Optional[int] = None
    ) -> SummarizationResult:
        """Create a summary of the given text."""
        start_time = time.time()

        try:
            # Validate input
            if len(text) < self.config["summarization"]["min_input_length"]:
                raise ValueError("Text too short for summarization")

            if len(text) > self.config["summarization"]["max_input_length"]:
                text = text[:self.config["summarization"]["max_input_length"]]

            # Check cache
            cache_key = hashlib.sha256(f"{text}:{summary_type}".encode()).hexdigest()
            if cache_key in self.summarization_cache:
                cached_result = self.summarization_cache[cache_key]
                self._update_feature_stats(FeatureType.SUMMARIZATION, True, time.time() - start_time)
                return cached_result

            # Create AI request
            prompt = self._create_summarization_prompt(text, summary_type, max_length)

            ai_request = AIRequest()
                prompt=prompt,
                user_id=user_id or "system",
                model_id=self.config["summarization"]["model_preference"][0],
                max_tokens=max_length or self.config["summarization"]["max_summary_length"],
                temperature=0.3
            )

            # Get AI response
            response = await self.ai_layer.process_request(ai_request)

            if not response.success:
                raise Exception(f"AI request failed: {response.error}")

            # Parse response
            summary = response.content.strip()

            # Extract key topics if enabled
            key_topics = []
            if self.config["summarization"]["include_key_topics"]:
                key_topics = await self._extract_key_topics(text)

            # Create result
            result = SummarizationResult()
                summary_id=str(uuid.uuid4()),
                original_text=text,
                summary=summary,
                summary_type=summary_type,
                confidence_score=0.85,  # Would be calculated based on model response
                processing_time_ms=(time.time() - start_time) * 1000,
                word_count_original=len(text.split()),
                word_count_summary=len(summary.split()),
                compression_ratio=len(summary.split()) / len(text.split()),
                key_topics=key_topics
            )

            # Cache result
            if self.config["cache_enabled"]:
                self.summarization_cache[cache_key] = result

            self._update_feature_stats(FeatureType.SUMMARIZATION, True, time.time() - start_time)
            return result

        except Exception as e:
            logger.error(f"Summarization failed: {e}")
            self._update_feature_stats(FeatureType.SUMMARIZATION, False, time.time() - start_time)
            raise

    def _create_summarization_prompt(self, text: str, summary_type: str, max_length: Optional[int]) -> str:
        """Create a prompt for text summarization."""
        length_instruction = f" in no more than {max_length} words" if max_length else ""

        if summary_type == "brief":
            return f"Please provide a brief, concise summary of the following text{length_instruction}:\n\n{text}\n\nSummary:"
        elif summary_type == "detailed":
            return f"Please provide a detailed summary that captures all key points of the following text{length_instruction}:\n\n{text}\n\nDetailed Summary:"
        elif summary_type == "bullet_points":
            return f"Please summarize the following text as bullet points{length_instruction}:\n\n{text}\n\nBullet Point Summary:"
        else:
            return f"Please summarize the following text{length_instruction}:\n\n{text}\n\nSummary:"

    async def _extract_key_topics(self, text: str) -> List[str]:
        """Extract key topics from text using AI."""
        try:
            prompt = f"Extract the 3-5 most important topics or themes from the following text. Return only the topics as a comma-separated list:\n\n{text}\n\nKey topics:"

            ai_request = AIRequest()
                prompt=prompt,
                user_id="system",
                model_id=self.config["summarization"]["model_preference"][0],
                max_tokens=100,
                temperature=0.2
            )

            response = await self.ai_layer.process_request(ai_request)

            if response.success:
                topics = [topic.strip() for topic in response.content.split(',')]
                return topics[:5]  # Limit to 5 topics

        except Exception as e:
            logger.warning(f"Failed to extract key topics: {e}")

        return []

    # Content Suggestions Methods

    async def generate_content_suggestions()
        self,
        context: str,
        suggestion_type: str = "completion",
        user_id: Optional[str] = None,
        max_suggestions: int = 3
    ) -> List[ContentSuggestion]:
        """Generate content suggestions based on context."""
        start_time = time.time()

        try:
            # Check cache
            cache_key = hashlib.sha256(f"{context}:{suggestion_type}".encode()).hexdigest()
            if cache_key in self.content_suggestions_cache:
                cached_suggestions = self.content_suggestions_cache[cache_key]
                self._update_feature_stats(FeatureType.CONTENT_SUGGESTIONS, True, time.time() - start_time)
                return cached_suggestions[:max_suggestions]

            # Create AI request
            prompt = self._create_content_suggestion_prompt(context, suggestion_type, max_suggestions)

            ai_request = AIRequest()
                prompt=prompt,
                user_id=user_id or "system",
                model_id="gpt-4",
                max_tokens=500,
                temperature=0.7
            )

            # Get AI response
            response = await self.ai_layer.process_request(ai_request)

            if not response.success:
                raise Exception(f"AI request failed: {response.error}")

            # Parse suggestions
            suggestions = self._parse_content_suggestions(response.content, context, suggestion_type)

            # Cache results
            if self.config["cache_enabled"]:
                self.content_suggestions_cache[cache_key] = suggestions

            self._update_feature_stats(FeatureType.CONTENT_SUGGESTIONS, True, time.time() - start_time)
            return suggestions[:max_suggestions]

        except Exception as e:
            logger.error(f"Content suggestion generation failed: {e}")
            self._update_feature_stats(FeatureType.CONTENT_SUGGESTIONS, False, time.time() - start_time)
            raise

    def _create_content_suggestion_prompt(self, context: str, suggestion_type: str, max_suggestions: int) -> str:
        """Create a prompt for content suggestions."""
        if suggestion_type == "completion":
            return f"Based on the following context, suggest {max_suggestions} ways to complete or continue the text. Each suggestion should be on a new line starting with '- ':\n\nContext: {context}\n\nSuggestions:"
        elif suggestion_type == "improvement":
            return f"Suggest {max_suggestions} ways to improve the following text. Each suggestion should be on a new line starting with '- ':\n\nText: {context}\n\nImprovement suggestions:"
        elif suggestion_type == "alternative":
            return f"Provide {max_suggestions} alternative ways to express the following text. Each alternative should be on a new line starting with '- ':\n\nOriginal: {context}\n\nAlternatives:"
        else:
            return f"Provide {max_suggestions} content suggestions for: {context}\n\nSuggestions:"

    def _parse_content_suggestions(self, response: str, context: str, suggestion_type: str) -> List[ContentSuggestion]:
        """Parse AI response into content suggestions."""
        suggestions = []
        lines = response.strip().split('\n')

        for i, line in enumerate(lines):
            if line.strip().startswith('- '):
                suggestion_text = line.strip()[2:].strip()
                if suggestion_text:
                    suggestion = ContentSuggestion()
                        suggestion_id=str(uuid.uuid4()),
                        context=context,
                        suggestion=suggestion_text,
                        suggestion_type=suggestion_type,
                        confidence_score=0.8 - (i * 0.1),  # Decreasing confidence
                        relevance_score=0.9 - (i * 0.05)   # Decreasing relevance
                    )
                    suggestions.append(suggestion)

        return suggestions

    # Sentiment Analysis Methods

    async def analyze_sentiment()
        self,
        text: str,
        user_id: Optional[str] = None,
        include_emotions: bool = True
    ) -> SentimentAnalysisResult:
        """Analyze sentiment of the given text."""
        start_time = time.time()

        try:
            # Check cache
            cache_key = hashlib.sha256(text.encode()).hexdigest()
            if cache_key in self.sentiment_cache:
                cached_result = self.sentiment_cache[cache_key]
                self._update_feature_stats(FeatureType.SENTIMENT_ANALYSIS, True, time.time() - start_time)
                return cached_result

            # Create AI request
            prompt = self._create_sentiment_analysis_prompt(text, include_emotions)

            ai_request = AIRequest()
                prompt=prompt,
                user_id=user_id or "system",
                model_id="gpt-4",
                max_tokens=300,
                temperature=0.1
            )

            # Get AI response
            response = await self.ai_layer.process_request(ai_request)

            if not response.success:
                raise Exception(f"AI request failed: {response.error}")

            # Parse sentiment analysis
            result = self._parse_sentiment_response(response.content, text)
            result.processing_time_ms = (time.time() - start_time) * 1000

            # Cache result
            if self.config["cache_enabled"]:
                self.sentiment_cache[cache_key] = result

            self._update_feature_stats(FeatureType.SENTIMENT_ANALYSIS, True, time.time() - start_time)
            return result

        except Exception as e:
            logger.error(f"Sentiment analysis failed: {e}")
            self._update_feature_stats(FeatureType.SENTIMENT_ANALYSIS, False, time.time() - start_time)
            raise

    def _create_sentiment_analysis_prompt(self, text: str, include_emotions: bool) -> str:
        """Create a prompt for sentiment analysis."""
        base_prompt = f"Analyze the sentiment of the following text and provide the result in JSON format:\n\nText: {text}\n\n"

        if include_emotions:
            return base_prompt + """Please provide:
1. Overall sentiment (positive, negative, neutral, or mixed)
2. Confidence score (0.0 to 1.0)
3. Emotion scores for: joy, anger, fear, sadness, surprise, disgust (0.0 to 1.0 each)
4. Key phrases that indicate sentiment

Format as JSON:
{
  "sentiment": "positive|negative|neutral|mixed",
  "confidence": 0.85,
  "emotions": {
    "joy": 0.7,
    "anger": 0.1,
    "fear": 0.0,
    "sadness": 0.0,
    "surprise": 0.2,
    "disgust": 0.0
  },
  "key_phrases": ["phrase1", "phrase2"]
}"""
        else:
            return base_prompt + """Please provide:
1. Overall sentiment (positive, negative, neutral, or mixed)
2. Confidence score (0.0 to 1.0)

Format as JSON:
{
  "sentiment": "positive|negative|neutral|mixed",
  "confidence": 0.85
}"""

    def _parse_sentiment_response(self, response: str, original_text: str) -> SentimentAnalysisResult:
        """Parse AI response into sentiment analysis result."""
        try:
            # Try to parse JSON response
            data = json.loads(response.strip())

            sentiment_map = {
                "positive": SentimentType.POSITIVE,
                "negative": SentimentType.NEGATIVE,
                "neutral": SentimentType.NEUTRAL,
                "mixed": SentimentType.MIXED
            }

            sentiment = sentiment_map.get(data.get("sentiment", "neutral"), SentimentType.NEUTRAL)
            confidence = float(data.get("confidence", 0.5))
            emotions = data.get("emotions", {})
            key_phrases = data.get("key_phrases", [])

            return SentimentAnalysisResult()
                analysis_id=str(uuid.uuid4()),
                text=original_text,
                sentiment=sentiment,
                confidence_score=confidence,
                emotion_scores=emotions,
                key_phrases=key_phrases
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse sentiment response: {e}")
            # Fallback to basic sentiment detection
            response_lower = response.lower()
            if "positive" in response_lower:
                sentiment = SentimentType.POSITIVE
            elif "negative" in response_lower:
                sentiment = SentimentType.NEGATIVE
            elif "mixed" in response_lower:
                sentiment = SentimentType.MIXED
            else:
                sentiment = SentimentType.NEUTRAL

            return SentimentAnalysisResult()
                analysis_id=str(uuid.uuid4()),
                text=original_text,
                sentiment=sentiment,
                confidence_score=0.5
            )

    # Semantic Search Methods

    async def add_to_semantic_index()
        self,
        content_id: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add content to the semantic search index."""
        try:
            # Store content and metadata
            self.semantic_index[content_id] = {
                "content": content,
                "metadata": metadata or {},
                "indexed_at": datetime.now(timezone.utc),
                "word_count": len(content.split())
            }

            # Update document metadata for vectorization
            self.document_metadata.append({)
                "id": content_id,
                "content": content,
                "metadata": metadata or {}
            })

            # Rebuild vectors if we have enough documents
            if len(self.document_metadata) % 100 == 0:  # Rebuild every 100 documents
                await self._rebuild_semantic_vectors()

            return True

        except Exception as e:
            logger.error(f"Failed to add content to semantic index: {e}")
            return False

    async def semantic_search()
        self,
        query: str,
        max_results: int = 10,
        similarity_threshold: float = 0.3,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[SemanticSearchResult]:
        """Perform semantic search on indexed content."""
        try:
            if not self.document_vectors or len(self.document_metadata) == 0:
                return []

            # Vectorize query
            query_vector = self.tfidf_vectorizer.transform([query])

            # Calculate similarities
            similarities = cosine_similarity(query_vector, self.document_vectors).flatten()

            # Get top results
            top_indices = np.argsort(similarities)[::-1]

            results = []
            for idx in top_indices:
                if len(results) >= max_results:
                    break

                similarity = similarities[idx]
                if similarity < similarity_threshold:
                    continue

                doc_metadata = self.document_metadata[idx]

                # Apply filters if provided
                if filters and not self._matches_filters(doc_metadata["metadata"], filters):
                    continue

                # Create highlighted text
                highlighted_text = self._highlight_text(doc_metadata["content"], query)

                result = SemanticSearchResult()
                    result_id=doc_metadata["id"],
                    content=doc_metadata["content"],
                    similarity_score=float(similarity),
                    metadata=doc_metadata["metadata"],
                    highlighted_text=highlighted_text
                )
                results.append(result)

            self._update_feature_stats(FeatureType.SEMANTIC_SEARCH, True, 0)
            return results

        except Exception as e:
            logger.error(f"Semantic search failed: {e}")
            self._update_feature_stats(FeatureType.SEMANTIC_SEARCH, False, 0)
            return []

    async def _rebuild_semantic_vectors(self):
        """Rebuild semantic search vectors."""
        try:
            if not self.document_metadata:
                return

            # Extract content for vectorization
            documents = [doc["content"] for doc in self.document_metadata]

            # Fit and transform documents
            self.document_vectors = self.tfidf_vectorizer.fit_transform(documents)

            logger.info(f"Rebuilt semantic vectors for {len(documents)} documents")

        except Exception as e:
            logger.error(f"Failed to rebuild semantic vectors: {e}")

    def _matches_filters(self, metadata: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if metadata matches the provided filters."""
        for key, value in filters.items():
            if key not in metadata or metadata[key] != value:
                return False
        return True

    def _highlight_text(self, text: str, query: str) -> str:
        """Highlight query terms in text."""
        query_words = query.lower().split()
        highlighted = text

        for word in query_words:
            if len(word) > 2:  # Only highlight words longer than 2 characters
                highlighted = highlighted.replace()
                    word, f"<mark>{word}</mark>",
                    # Case-insensitive replacement would be more complex
                )

        return highlighted

    # Automated Moderation Methods

    async def moderate_content()
        self,
        content: str,
        content_id: Optional[str] = None,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ModerationResult:
        """Perform automated content moderation."""
        start_time = time.time()

        try:
            content_id = content_id or str(uuid.uuid4())

            # Check cache
            cache_key = hashlib.sha256(content.encode()).hexdigest()
            if cache_key in self.moderation_cache:
                cached_result = self.moderation_cache[cache_key]
                self._update_feature_stats(FeatureType.AUTOMATED_MODERATION, True, time.time() - start_time)
                return cached_result

            # Create AI request for moderation
            prompt = self._create_moderation_prompt(content)

            ai_request = AIRequest()
                prompt=prompt,
                user_id=user_id or "system",
                model_id="gpt-4",
                max_tokens=400,
                temperature=0.1
            )

            # Get AI response
            response = await self.ai_layer.process_request(ai_request)

            if not response.success:
                raise Exception(f"AI request failed: {response.error}")

            # Parse moderation result
            result = self._parse_moderation_response(response.content, content, content_id)
            result.processing_time_ms = (time.time() - start_time) * 1000

            # Cache result
            if self.config["cache_enabled"]:
                self.moderation_cache[cache_key] = result

            self._update_feature_stats(FeatureType.AUTOMATED_MODERATION, True, time.time() - start_time)
            return result

        except Exception as e:
            logger.error(f"Content moderation failed: {e}")
            self._update_feature_stats(FeatureType.AUTOMATED_MODERATION, False, time.time() - start_time)
            raise

    def _create_moderation_prompt(self, content: str) -> str:
        """Create a prompt for content moderation."""
        categories = self.config["automated_moderation"]["violation_categories"]

        return f"""Analyze the following content for policy violations and provide a moderation decision in JSON format:

Content: {content}

Check for these violation categories: {', '.join(categories)}

Provide your analysis in this JSON format:
{{
  "action": "approve|flag|block|review",
  "confidence": 0.85,
  "violation_categories": ["category1", "category2"],
  "severity_score": 0.7,
  "explanation": "Brief explanation of the decision"
}}

Guidelines:
- "approve": Content is safe and complies with policies
- "flag": Content may violate policies, needs human review
- "block": Content clearly violates policies and should be blocked
- "review": Uncertain, requires human review
- Confidence: 0.0 to 1.0 (how confident you are in the decision)
- Severity: 0.0 to 1.0 (how severe any violations are)
"""

    def _parse_moderation_response(self, response: str, content: str, content_id: str) -> ModerationResult:
        """Parse AI response into moderation result."""
        try:
            # Try to parse JSON response
            data = json.loads(response.strip())

            action_map = {
                "approve": ModerationAction.APPROVE,
                "flag": ModerationAction.FLAG,
                "block": ModerationAction.BLOCK,
                "review": ModerationAction.REVIEW
            }

            action = action_map.get(data.get("action", "review"), ModerationAction.REVIEW)
            confidence = float(data.get("confidence", 0.5))
            violation_categories = data.get("violation_categories", [])
            severity_score = float(data.get("severity_score", 0.0))
            explanation = data.get("explanation", "")

            return ModerationResult()
                moderation_id=str(uuid.uuid4()),
                content=content,
                action=action,
                confidence_score=confidence,
                violation_categories=violation_categories,
                severity_score=severity_score,
                explanation=explanation
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse moderation response: {e}")
            # Fallback to safe default
            return ModerationResult()
                moderation_id=str(uuid.uuid4()),
                content=content,
                action=ModerationAction.REVIEW,
                confidence_score=0.5,
                explanation="Failed to parse AI response, defaulting to human review"
            )

    # Utility Methods

    def _update_feature_stats(self, feature_type: FeatureType, success: bool, processing_time: float):
        """Update feature statistics."""
        stats = self.feature_stats[feature_type.value]
        stats["requests"] += 1

        if success:
            stats["successes"] += 1
        else:
            stats["failures"] += 1

        stats["total_processing_time"] += processing_time
        stats["avg_processing_time"] = stats["total_processing_time"] / stats["requests"]

    async def _initialize_semantic_search(self):
        """Initialize semantic search components."""
        try:
            # Load existing index if available
            await self._load_semantic_index()

            # Rebuild vectors if we have documents
            if self.document_metadata:
                await self._rebuild_semantic_vectors()

            logger.info("Semantic search initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize semantic search: {e}")

    async def _load_semantic_index(self):
        """Load semantic index from disk."""
        try:
            from pathlib import Path
index_file = Path
Path("data/semantic_index.json")
            if index_file.exists():
                with open(index_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.semantic_index = data.get("index", {})
                    self.document_metadata = data.get("metadata", [])
                    logger.info(f"Loaded semantic index with {len(self.semantic_index)} documents")
        except Exception as e:
            logger.warning(f"Failed to load semantic index: {e}")

    async def _save_semantic_index(self):
        """Save semantic index to disk."""
        try:
            from pathlib import Path
index_file = Path
Path("data/semantic_index.json")
            index_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "index": self.semantic_index,
                "metadata": self.document_metadata,
                "saved_at": datetime.now(timezone.utc).isoformat()
            }

            with open(index_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)

            logger.info("Semantic index saved successfully")

        except Exception as e:
            logger.error(f"Failed to save semantic index: {e}")

    async def _start_background_tasks(self):
        """Start background tasks."""
        try:
            # Start cache cleanup task
            asyncio.create_task(self._cache_cleanup_task())

            # Start index update task
            asyncio.create_task(self._index_update_task())

            # Start statistics reporting task
            asyncio.create_task(self._stats_reporting_task())

            logger.info("Background tasks started")

        except Exception as e:
            logger.error(f"Failed to start background tasks: {e}")

    async def _stop_background_tasks(self):
        """Stop background tasks."""
        # Tasks will be cancelled when the event loop stops
        logger.info("Background tasks stopped")

    async def _cache_cleanup_task(self):
        """Background task to clean up expired cache entries."""
        while self.state == ServiceState.RUNNING:
            try:
                await asyncio.sleep(3600)  # Run every hour

                current_time = datetime.now(timezone.utc)
                ttl_hours = self.config["cache_ttl_hours"]

                # Clean summarization cache
                expired_keys = []
                for key, result in self.summarization_cache.items():
                    if (current_time - result.created_at).total_seconds() > ttl_hours * 3600:
                        expired_keys.append(key)

                for key in expired_keys:
                    del self.summarization_cache[key]

                # Clean other caches similarly
                self._clean_cache_by_age(self.content_suggestions_cache, ttl_hours)
                self._clean_cache_by_age(self.sentiment_cache, ttl_hours)
                self._clean_cache_by_age(self.moderation_cache, ttl_hours)

                if expired_keys:
                    logger.info(f"Cleaned {len(expired_keys)} expired cache entries")

            except Exception as e:
                logger.error(f"Cache cleanup task error: {e}")

    def _clean_cache_by_age(self, cache: Dict[str, Any], ttl_hours: int):
        """Clean cache entries older than TTL."""
        current_time = datetime.now(timezone.utc)
        expired_keys = []

        for key, item in cache.items():
            if hasattr(item, 'created_at'):
                if (current_time - item.created_at).total_seconds() > ttl_hours * 3600:
                    expired_keys.append(key)
            elif isinstance(item, list) and item and hasattr(item[0], 'created_at'):
                if (current_time - item[0].created_at).total_seconds() > ttl_hours * 3600:
                    expired_keys.append(key)

        for key in expired_keys:
            del cache[key]

    async def _index_update_task(self):
        """Background task to update semantic search index."""
        while self.state == ServiceState.RUNNING:
            try:
                update_interval = self.config["semantic_search"]["index_update_interval_hours"]
                await asyncio.sleep(update_interval * 3600)

                # Rebuild vectors
                await self._rebuild_semantic_vectors()

                # Save index to disk
                await self._save_semantic_index()

                logger.info("Semantic search index updated")

            except Exception as e:
                logger.error(f"Index update task error: {e}")

    async def _stats_reporting_task(self):
        """Background task to report statistics."""
        while self.state == ServiceState.RUNNING:
            try:
                await asyncio.sleep(1800)  # Report every 30 minutes

                total_requests = sum(stats["requests"] for stats in self.feature_stats.values())
                total_successes = sum(stats["successes"] for stats in self.feature_stats.values())

                if total_requests > 0:
                    success_rate = (total_successes / total_requests) * 100
                    logger.info(f"AI Features Stats: {total_requests} requests, {success_rate:.1f}% success rate")

            except Exception as e:
                logger.error(f"Stats reporting task error: {e}")

    async def _save_cache_to_disk(self):
        """Save all caches to disk."""
        try:
            from pathlib import Path
cache_dir = Path
Path("data/ai_features_cache")
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Save semantic index
            await self._save_semantic_index()

            # Save feature statistics
            stats_file = cache_dir / "feature_stats.json"
            with open(stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.feature_stats, f, indent=2)

            logger.info("AI features cache saved to disk")

        except Exception as e:
            logger.error(f"Failed to save cache to disk: {e}")

    # Public API Methods

    async def get_feature_statistics(self) -> Dict[str, Any]:
        """Get comprehensive feature statistics."""
        return {}
            "feature_stats": self.feature_stats.copy(),
            "cache_sizes": {
                "summarization": len(self.summarization_cache),
                "content_suggestions": len(self.content_suggestions_cache),
                "sentiment": len(self.sentiment_cache),
                "semantic_index": len(self.semantic_index),
                "moderation": len(self.moderation_cache)
            },
            "semantic_search": {
                "indexed_documents": len(self.document_metadata),
                "index_size": len(self.semantic_index)
            },
            "service_state": self.state.value,
            "uptime_seconds": (datetime.now(timezone.utc) - self.start_time).total_seconds() if hasattr(self, 'start_time') else 0
        }

    async def clear_cache(self, feature_type: Optional[str] = None):
        """Clear cache for specific feature or all features."""
        if feature_type:
            if feature_type == "summarization":
                self.summarization_cache.clear()
            elif feature_type == "content_suggestions":
                self.content_suggestions_cache.clear()
            elif feature_type == "sentiment":
                self.sentiment_cache.clear()
            elif feature_type == "moderation":
                self.moderation_cache.clear()
            elif feature_type == "semantic_search":
                self.semantic_index.clear()
                self.document_metadata.clear()
                self.document_vectors = None
        else:
            # Clear all caches
            self.summarization_cache.clear()
            self.content_suggestions_cache.clear()
            self.sentiment_cache.clear()
            self.moderation_cache.clear()
            self.semantic_index.clear()
            self.document_metadata.clear()
            self.document_vectors = None

        logger.info(f"Cleared cache for: {feature_type or 'all features'}")

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on AI-powered features."""
        health_status = {
            "service_state": self.state.value,
            "ai_layer_healthy": await self.ai_layer.health_check() if self.ai_layer else False,
            "features_enabled": {
                "summarization": self.config["summarization"]["enabled"],
                "content_suggestions": self.config["content_suggestions"]["enabled"],
                "sentiment_analysis": self.config["sentiment_analysis"]["enabled"],
                "semantic_search": self.config["semantic_search"]["enabled"],
                "automated_moderation": self.config["automated_moderation"]["enabled"]
            },
            "cache_health": {
                "summarization_cache_size": len(self.summarization_cache),
                "content_suggestions_cache_size": len(self.content_suggestions_cache),
                "sentiment_cache_size": len(self.sentiment_cache),
                "moderation_cache_size": len(self.moderation_cache),
                "semantic_index_size": len(self.semantic_index)
            },
            "performance": {
                "total_requests": sum(stats["requests"] for stats in self.feature_stats.values()),
                "total_successes": sum(stats["successes"] for stats in self.feature_stats.values()),
                "avg_processing_times": {
                    feature: stats["avg_processing_time"]
                    for feature, stats in self.feature_stats.items()
                }
            }
        }

        return health_status
