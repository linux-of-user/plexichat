"""
PlexiChat AI-Powered Features Service

Comprehensive AI-powered features including smart summarization, content suggestions,
sentiment analysis, semantic search, and automated moderation with multiple AI providers.
"""

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

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    TfidfVectorizer = None
    cosine_similarity = None

try:
    from plexichat.core.logging import get_logger  # type: ignore
except ImportError:
    import logging
    def get_logger(name):
        return logging.getLogger(name)

try:
    from plexichat.infrastructure.services.base_service import BaseService, ServiceState  # type: ignore
except ImportError:
    # Fallback base service
    class ServiceState:
        STOPPED = "stopped"
        STARTING = "starting"
        RUNNING = "running"
        STOPPING = "stopping"
        ERROR = "error"

    class BaseService:
        def __init__(self):
            self.state = ServiceState.STOPPED

        async def start(self):
            self.state = ServiceState.STARTING

        async def stop(self):
            self.state = ServiceState.STOPPING

from plexichat.features.ai.core.ai_abstraction_layer import AIAbstractionLayer, AIRequest

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
    """Moderation action types."""
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"
    REVIEW = "review"


@dataclass
class SummarizationResult:
    """Summarization result data structure."""
    summary_id: str
    original_text: str
    summary: str
    summary_type: str
    compression_ratio: float
    key_points: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContentSuggestion:
    """Content suggestion data structure."""
    suggestion_id: str
    content: str
    suggestion_type: str
    confidence_score: float
    context: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
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


class AIPoweredFeaturesService(BaseService):  # type: ignore
    """AI-powered features service for PlexiChat."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the AI features service."""
        super().__init__()
        self.config = config or {}
        self.ai_layer = AIAbstractionLayer()
        self.cache: Dict[str, Any] = {}
        self.vectorizer: Optional[Any] = None
        self.document_vectors: Optional[Any] = None
        self.documents: List[str] = []
        
        # Initialize components
        self._initialize_vectorizer()
        
    def _initialize_vectorizer(self):
        """Initialize the text vectorizer for semantic search."""
        if SKLEARN_AVAILABLE and TfidfVectorizer:
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )
        else:
            logger.warning("scikit-learn not available, semantic search will be limited")
    
    async def start(self) -> None:
        """Start the AI features service."""
        try:
            await super().start()
            # Initialize AI layer if it has an initialize method
            if hasattr(self.ai_layer, 'initialize'):
                await self.ai_layer.initialize()  # type: ignore
            self.state = ServiceState.RUNNING
            logger.info("AI Features Service started successfully")
        except Exception as e:
            logger.error(f"Failed to start AI Features Service: {e}")
            self.state = ServiceState.ERROR
            raise
    
    async def stop(self) -> None:
        """Stop the AI features service."""
        try:
            self.state = ServiceState.STOPPING
            # Shutdown AI layer if it has a shutdown method
            if hasattr(self.ai_layer, 'shutdown'):
                await self.ai_layer.shutdown()  # type: ignore
            await super().stop()
            self.state = ServiceState.STOPPED
            logger.info("AI Features Service stopped successfully")
        except Exception as e:
            logger.error(f"Failed to stop AI Features Service: {e}")
            self.state = ServiceState.ERROR
            raise
    
    async def smart_summarization(
        self,
        text: str,
        summary_type: str = "brief",
        max_length: Optional[int] = None,
        user_id: Optional[str] = None
    ) -> SummarizationResult:
        """Generate intelligent summaries using AI."""
        start_time = time.time()
        
        try:
            # Validate input
            if not text or len(text.strip()) < 10:
                raise ValueError("Text too short for summarization")
            
            # Create cache key
            cache_key = hashlib.md5(f"{text}_{summary_type}_{max_length}".encode()).hexdigest()
            
            # Check cache
            if cache_key in self.cache:
                logger.debug("Returning cached summarization result")
                return self.cache[cache_key]
            
            # Prepare AI request
            prompt = self._build_summarization_prompt(text, summary_type, max_length)
            
            ai_request = AIRequest(
                prompt=prompt,
                model_id=self.config.get("summarization_model", "gpt-3.5-turbo"),
                user_id=user_id or "system",
                parameters={
                    "max_tokens": max_length or 150,
                    "temperature": 0.3
                }
            )
            
            # Process with AI
            response = await self.ai_layer.process_request(ai_request)
            
            if not getattr(response, 'success', True):
                error_msg = getattr(response, 'error', 'Unknown error')
                raise Exception(f"AI request failed: {error_msg}")
            
            # Create result
            result = SummarizationResult(
                summary_id=str(uuid.uuid4()),
                original_text=text,
                summary=response.content,
                summary_type=summary_type,
                compression_ratio=len(response.content) / len(text),
                processing_time_ms=(time.time() - start_time) * 1000
            )
            
            # Cache result
            self.cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Summarization failed: {e}")
            raise
    
    def _build_summarization_prompt(self, text: str, summary_type: str, max_length: Optional[int]) -> str:
        """Build the summarization prompt."""
        length_instruction = f" in approximately {max_length} words" if max_length else ""
        
        prompts = {
            "brief": f"Provide a brief summary of the following text{length_instruction}:\n\n{text}",
            "detailed": f"Provide a detailed summary of the following text{length_instruction}:\n\n{text}",
            "bullet": f"Summarize the following text as bullet points{length_instruction}:\n\n{text}",
            "executive": f"Provide an executive summary of the following text{length_instruction}:\n\n{text}"
        }
        
        return prompts.get(summary_type, prompts["brief"])
    
    async def analyze_sentiment(
        self,
        text: str,
        user_id: Optional[str] = None
    ) -> SentimentAnalysisResult:
        """Analyze sentiment of text using AI."""
        start_time = time.time()
        
        try:
            # Validate input
            if not text or len(text.strip()) < 3:
                raise ValueError("Text too short for sentiment analysis")
            
            # Prepare AI request
            prompt = f"Analyze the sentiment of this text and respond with JSON containing 'sentiment' (positive/negative/neutral/mixed), 'confidence' (0-1), and 'emotions' (dict of emotion scores):\n\n{text}"
            
            ai_request = AIRequest(
                prompt=prompt,
                model_id=self.config.get("sentiment_model", "gpt-3.5-turbo"),
                user_id=user_id or "system",
                parameters={
                    "max_tokens": 200,
                    "temperature": 0.1
                }
            )
            
            # Process with AI
            response = await self.ai_layer.process_request(ai_request)
            
            if not getattr(response, 'success', True):
                error_msg = getattr(response, 'error', 'Unknown error')
                raise Exception(f"AI request failed: {error_msg}")
            
            # Parse response
            try:
                result_data = json.loads(response.content)
                sentiment = SentimentType(result_data.get("sentiment", "neutral"))
                confidence = float(result_data.get("confidence", 0.5))
                emotions = result_data.get("emotions", {})
            except (json.JSONDecodeError, ValueError):
                # Fallback to simple parsing
                sentiment = SentimentType.NEUTRAL
                confidence = 0.5
                emotions = {}
            
            # Create result
            result = SentimentAnalysisResult(
                analysis_id=str(uuid.uuid4()),
                text=text,
                sentiment=sentiment,
                confidence_score=confidence,
                emotion_scores=emotions,
                processing_time_ms=(time.time() - start_time) * 1000
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Sentiment analysis failed: {e}")
            raise
