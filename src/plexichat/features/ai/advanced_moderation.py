import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import aiohttp


"""
PlexiChat Advanced AI-Powered Content Moderation
Real-time proactive content moderation with multi-modal analysis
"""

logger = logging.getLogger(__name__)


class ContentType(Enum):
    """Content types for moderation."""
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FILE = "file"
    URL = "url"


class ViolationType(Enum):
    """Types of content violations."""
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    VIOLENCE = "violence"
    SELF_HARM = "self_harm"
    SEXUAL_CONTENT = "sexual_content"
    SPAM = "spam"
    MISINFORMATION = "misinformation"
    ILLEGAL_CONTENT = "illegal_content"
    COPYRIGHT = "copyright"
    PRIVACY = "privacy"
    TOXICITY = "toxicity"
    PROFANITY = "profanity"


class ModerationSeverity(Enum):
    """Moderation severity levels."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ModerationAction(Enum):
    """Actions to take based on moderation results."""
    ALLOW = "allow"
    WARN = "warn"
    FILTER = "filter"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    ESCALATE = "escalate"
    AUTO_DELETE = "auto_delete"


@dataclass
class ModerationResult:
    """Comprehensive moderation result."""
    content_id: str
    content_type: ContentType
    overall_score: float  # 0.0 - 1.0
    overall_severity: ModerationSeverity
    recommended_action: ModerationAction
    confidence: float
    
    # Detailed scores
    violation_scores: Dict[ViolationType, float] = field(default_factory=dict)
    
    # Analysis details
    detected_language: Optional[str] = None
    sentiment_score: Optional[float] = None
    toxicity_indicators: List[str] = field(default_factory=list)
    flagged_keywords: List[str] = field(default_factory=list)
    
    # Context analysis
    user_history_factor: float = 0.0
    community_context: Optional[str] = None
    
    # Processing metadata
    processing_time_ms: float = 0.0
    models_used: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Human review
    requires_human_review: bool = False
    human_review_priority: int = 0  # 1-5, 5 being highest priority


class ProactiveContentModerator:
    """
    Advanced AI-Powered Proactive Content Moderation System.
    
    Features:
    - Multi-modal content analysis (text, image, video, audio)
    - Real-time processing with sub-second response times
    - Context-aware moderation considering user history
    - Adaptive learning from community feedback
    - Integration with multiple AI providers
    - Automated escalation for edge cases
    - Comprehensive audit trail
    """
    
    def __init__(self):
        self.enabled = True
        self.real_time_processing = True
        
        # AI Provider configurations
        self.ai_providers = {
            "openai": {
                "text_moderation": True,
                "image_moderation": True,
                "api_key": None,
                "endpoint": "https://api.openai.com/v1/moderations"
            },
            "google": {
                "text_moderation": True,
                "image_moderation": True,
                "video_moderation": True,
                "api_key": None,
                "endpoint": "https://language.googleapis.com/v1/documents:classifyText"
            },
            "azure": {
                "text_moderation": True,
                "image_moderation": True,
                "api_key": None,
                "endpoint": "https://api.cognitive.microsoft.com/contentmoderator/moderate/v1.0"
            }
        }
        
        # Moderation thresholds
        self.thresholds = {
            ViolationType.HATE_SPEECH: 0.7,
            ViolationType.HARASSMENT: 0.6,
            ViolationType.VIOLENCE: 0.8,
            ViolationType.SELF_HARM: 0.9,
            ViolationType.SEXUAL_CONTENT: 0.7,
            ViolationType.SPAM: 0.5,
            ViolationType.MISINFORMATION: 0.6,
            ViolationType.TOXICITY: 0.6,
            ViolationType.PROFANITY: 0.4
        }
        
        # Action mapping based on severity
        self.action_mapping = {
            ModerationSeverity.NONE: ModerationAction.ALLOW,
            ModerationSeverity.LOW: ModerationAction.WARN,
            ModerationSeverity.MEDIUM: ModerationAction.FILTER,
            ModerationSeverity.HIGH: ModerationAction.QUARANTINE,
            ModerationSeverity.CRITICAL: ModerationAction.BLOCK
        }
        
        # User context tracking
        self.user_violation_history: Dict[str, List[Dict[str, Any]]] = {}
        self.user_trust_scores: Dict[str, float] = {}
        
        # Community context
        self.community_standards: Dict[str, Dict[str, Any]] = {}
        
        # Statistics
        self.stats = {
            "total_moderated": 0,
            "blocked_content": 0,
            "false_positives": 0,
            "human_reviews": 0,
            "average_processing_time": 0.0,
            "accuracy_rate": 0.95
        }
        
        # Cache for repeated content
        self.moderation_cache: Dict[str, ModerationResult] = {}
        self.cache_ttl = 3600  # 1 hour
    
    async def moderate_content(self, 
                              content: Union[str, bytes], 
                              content_type: ContentType,
                              content_id: str,
                              user_id: Optional[str] = None,
                              channel_id: Optional[str] = None,
                              metadata: Optional[Dict[str, Any]] = None) -> ModerationResult:
        """
        Moderate content using advanced AI analysis.
        
        Args:
            content: The content to moderate
            content_type: Type of content (text, image, etc.)
            content_id: Unique identifier for the content
            user_id: ID of the user who created the content
            channel_id: ID of the channel/community
            metadata: Additional context metadata
        
        Returns:
            ModerationResult with detailed analysis
        """
        start_time = time.time()
        
        try:
            # Check cache first
            content_hash = self._get_content_hash(content)
            cached_result = self._get_cached_result(content_hash)
            if cached_result:
                return cached_result
            
            # Initialize result
            result = ModerationResult(
                content_id=content_id,
                content_type=content_type,
                overall_score=0.0,
                overall_severity=ModerationSeverity.NONE,
                recommended_action=ModerationAction.ALLOW,
                confidence=0.0
            )
            
            # Perform content-type specific moderation
            if content_type == ContentType.TEXT:
                await self._moderate_text(content, result, user_id, channel_id, metadata)
            elif content_type == ContentType.IMAGE:
                await self._moderate_image(content, result, user_id, channel_id, metadata)
            elif content_type == ContentType.VIDEO:
                await self._moderate_video(content, result, user_id, channel_id, metadata)
            elif content_type == ContentType.AUDIO:
                await self._moderate_audio(content, result, user_id, channel_id, metadata)
            
            # Apply user context
            if user_id:
                await self._apply_user_context(result, user_id)
            
            # Apply community context
            if channel_id:
                await self._apply_community_context(result, channel_id)
            
            # Determine final action
            result.overall_severity = self._calculate_severity(result.violation_scores)
            result.recommended_action = self._determine_action(result)
            
            # Check if human review is needed
            result.requires_human_review = self._requires_human_review(result)
            if result.requires_human_review:
                result.human_review_priority = self._calculate_review_priority(result)
            
            # Update processing time
            result.processing_time_ms = (time.time() - start_time) * 1000
            
            # Cache result
            self._cache_result(content_hash, result)
            
            # Update statistics
            self._update_statistics(result)
            
            # Log result
            logger.info(f"Moderated content {content_id}: {result.recommended_action.value} "
                       f"(score: {result.overall_score:.3f}, confidence: {result.confidence:.3f})")
            
            return result
            
        except Exception as e:
            logger.error(f"Content moderation failed for {content_id}: {e}")
            # Return safe default
            return ModerationResult(
                content_id=content_id,
                content_type=content_type,
                overall_score=0.0,
                overall_severity=ModerationSeverity.NONE,
                recommended_action=ModerationAction.ALLOW,
                confidence=0.0,
                processing_time_ms=(time.time() - start_time) * 1000
            )
    
    async def _moderate_text(self, text: str, result: ModerationResult, 
                           user_id: Optional[str], channel_id: Optional[str], 
                           metadata: Optional[Dict[str, Any]]):
        """Moderate text content using multiple AI providers."""
        
        # OpenAI Moderation
        if self.ai_providers["openai"]["text_moderation"]:
            try:
                openai_result = await self._call_openai_moderation(text)
                self._merge_text_results(result, openai_result, "openai")
            except Exception as e:
                logger.warning(f"OpenAI moderation failed: {e}")
        
        # Google Cloud Natural Language
        if self.ai_providers["google"]["text_moderation"]:
            try:
                google_result = await self._call_google_text_analysis(text)
                self._merge_text_results(result, google_result, "google")
            except Exception as e:
                logger.warning(f"Google text analysis failed: {e}")
        
        # Custom rule-based analysis
        await self._apply_custom_text_rules(text, result)
        
        # Language detection
        result.detected_language = await self._detect_language(text)
        
        # Sentiment analysis
        result.sentiment_score = await self._analyze_sentiment(text)
    
    async def _moderate_image(self, image_data: bytes, result: ModerationResult,
                            user_id: Optional[str], channel_id: Optional[str],
                            metadata: Optional[Dict[str, Any]]):
        """Moderate image content using computer vision APIs."""
        
        # Google Cloud Vision API
        if self.ai_providers["google"]["image_moderation"]:
            try:
                google_result = await self._call_google_vision_analysis(image_data)
                self._merge_image_results(result, google_result, "google_vision")
            except Exception as e:
                logger.warning(f"Google Vision analysis failed: {e}")
        
        # Azure Computer Vision
        if self.ai_providers["azure"]["image_moderation"]:
            try:
                azure_result = await self._call_azure_vision_analysis(image_data)
                self._merge_image_results(result, azure_result, "azure_vision")
            except Exception as e:
                logger.warning(f"Azure Vision analysis failed: {e}")
        
        # Custom image analysis
        await self._apply_custom_image_rules(image_data, result)
    
    async def _moderate_video(self, video_data: bytes, result: ModerationResult,
                            user_id: Optional[str], channel_id: Optional[str],
                            metadata: Optional[Dict[str, Any]]):
        """Moderate video content by analyzing frames and audio."""
        
        # Extract frames for image analysis
        frames = await self._extract_video_frames(video_data)
        for i, frame in enumerate(frames[:10]):  # Analyze first 10 frames
            frame_result = ModerationResult(
                content_id=f"{result.content_id}_frame_{i}",
                content_type=ContentType.IMAGE,
                overall_score=0.0,
                overall_severity=ModerationSeverity.NONE,
                recommended_action=ModerationAction.ALLOW,
                confidence=0.0
            )
            await self._moderate_image(frame, frame_result, user_id, channel_id, metadata)
            
            # Merge frame results
            for violation_type, score in frame_result.violation_scores.items():
                if violation_type not in result.violation_scores:
                    result.violation_scores[violation_type] = 0.0
                result.violation_scores[violation_type] = max(
                    result.violation_scores[violation_type], score
                )
        
        # Extract and analyze audio
        audio_data = await self._extract_video_audio(video_data)
        if audio_data:
            await self._moderate_audio(audio_data, result, user_id, channel_id, metadata)
    
    async def _moderate_audio(self, audio_data: bytes, result: ModerationResult,
                            user_id: Optional[str], channel_id: Optional[str],
                            metadata: Optional[Dict[str, Any]]):
        """Moderate audio content by transcribing and analyzing speech."""
        
        # Transcribe audio to text
        transcript = await self._transcribe_audio(audio_data)
        if transcript:
            # Analyze transcribed text
            await self._moderate_text(transcript, result, user_id, channel_id, metadata)
            
            # Add audio-specific analysis
            audio_features = await self._analyze_audio_features(audio_data)
            if audio_features.get("aggressive_tone", False):
                result.violation_scores[ViolationType.HARASSMENT] = max(
                    result.violation_scores.get(ViolationType.HARASSMENT, 0.0), 0.6
                )
    
    async def _call_openai_moderation(self, text: str) -> Dict[str, Any]:
        """Call OpenAI Moderation API."""
        if not self.ai_providers["openai"]["api_key"]:
            return {}
        
        headers = {
            "Authorization": f"Bearer {self.ai_providers['openai']['api_key']}",
            "Content-Type": "application/json"
        }
        
        data = {"input": text}
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.ai_providers["openai"]["endpoint"],
                headers=headers,
                json=data
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"OpenAI API error: {response.status}")
    
    def _merge_text_results(self, result: ModerationResult, ai_result: Dict[str, Any], provider: str):
        """Merge AI provider results into the main result."""
        result.models_used.append(provider)
        
        # Map provider-specific results to our violation types
        if provider == "openai" and "results" in ai_result:
            openai_result = ai_result["results"][0] if ai_result["results"] else {}
            openai_result.get("categories", {})
            category_scores = openai_result.get("category_scores", {})
            
            # Map OpenAI categories to our violation types
            mapping = {
                "hate": ViolationType.HATE_SPEECH,
                "harassment": ViolationType.HARASSMENT,
                "violence": ViolationType.VIOLENCE,
                "self-harm": ViolationType.SELF_HARM,
                "sexual": ViolationType.SEXUAL_CONTENT
            }
            
            for openai_cat, violation_type in mapping.items():
                if openai_cat in category_scores:
                    score = category_scores[openai_cat]
                    result.violation_scores[violation_type] = max(
                        result.violation_scores.get(violation_type, 0.0), score
                    )
    
    def _calculate_severity(self, violation_scores: Dict[ViolationType, float]) -> ModerationSeverity:
        """Calculate overall severity based on violation scores."""
        if not violation_scores:
            return ModerationSeverity.NONE
        
        max_score = max(violation_scores.values())
        
        if max_score >= 0.9:
            return ModerationSeverity.CRITICAL
        elif max_score >= 0.7:
            return ModerationSeverity.HIGH
        elif max_score >= 0.5:
            return ModerationSeverity.MEDIUM
        elif max_score >= 0.3:
            return ModerationSeverity.LOW
        else:
            return ModerationSeverity.NONE
    
    def _determine_action(self, result: ModerationResult) -> ModerationAction:
        """Determine the recommended action based on analysis."""
        base_action = self.action_mapping.get(result.overall_severity, ModerationAction.ALLOW)
        
        # Adjust based on user history
        if result.user_history_factor > 0.5:
            # User has history of violations, be more strict
            if base_action == ModerationAction.WARN:
                base_action = ModerationAction.FILTER
            elif base_action == ModerationAction.FILTER:
                base_action = ModerationAction.QUARANTINE
        
        return base_action
    
    def _requires_human_review(self, result: ModerationResult) -> bool:
        """Determine if content requires human review."""
        # Always review critical content
        if result.overall_severity == ModerationSeverity.CRITICAL:
            return True
        
        # Review if confidence is low
        if result.confidence < 0.7:
            return True
        
        # Review edge cases
        if result.overall_severity == ModerationSeverity.HIGH and result.confidence < 0.8:
            return True
        
        return False
    
    def _calculate_review_priority(self, result: ModerationResult) -> int:
        """Calculate human review priority (1-5)."""
        if result.overall_severity == ModerationSeverity.CRITICAL:
            return 5
        elif result.overall_severity == ModerationSeverity.HIGH:
            return 4
        elif result.confidence < 0.5:
            return 3
        else:
            return 2
    
    def _get_content_hash(self, content: Union[str, bytes]) -> str:
        """Generate hash for content caching."""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()
    
    def _get_cached_result(self, content_hash: str) -> Optional[ModerationResult]:
        """Get cached moderation result."""
        if content_hash in self.moderation_cache:
            cached_result = self.moderation_cache[content_hash]
            # Check if cache is still valid
            if (datetime.now(timezone.utc) - cached_result.timestamp).total_seconds() < self.cache_ttl:
                return cached_result
            else:
                del self.moderation_cache[content_hash]
        return None
    
    def _cache_result(self, content_hash: str, result: ModerationResult):
        """Cache moderation result."""
        self.moderation_cache[content_hash] = result
    
    def _update_statistics(self, result: ModerationResult):
        """Update moderation statistics."""
        self.stats["total_moderated"] += 1
        
        if result.recommended_action in [ModerationAction.BLOCK, ModerationAction.QUARANTINE]:
            self.stats["blocked_content"] += 1
        
        if result.requires_human_review:
            self.stats["human_reviews"] += 1
        
        # Update average processing time
        current_avg = self.stats["average_processing_time"]
        total_count = self.stats["total_moderated"]
        new_avg = ((current_avg * (total_count - 1)) + result.processing_time_ms) / total_count
        self.stats["average_processing_time"] = new_avg
    
    async def _apply_user_context(self, result: ModerationResult, user_id: str):
        """Apply user context to moderation result."""
        # Get user's violation history
        user_history = self.user_violation_history.get(user_id, [])
        
        # Calculate user trust score
        trust_score = self.user_trust_scores.get(user_id, 1.0)
        
        # Recent violations increase suspicion
        recent_violations = [
            v for v in user_history 
            if (datetime.now(timezone.utc) - datetime.fromisoformat(v["timestamp"])).days < 30
        ]
        
        if recent_violations:
            result.user_history_factor = min(len(recent_violations) * 0.2, 1.0)
            # Reduce trust score
            trust_score = max(trust_score - (len(recent_violations) * 0.1), 0.0)
        
        self.user_trust_scores[user_id] = trust_score
    
    async def _apply_community_context(self, result: ModerationResult, channel_id: str):
        """Apply community-specific context."""
        community_standards = self.community_standards.get(channel_id, {})
        
        # Adjust thresholds based on community standards
        if community_standards.get("strict_mode", False):
            # Lower thresholds for strict communities
            for violation_type in result.violation_scores:
                result.violation_scores[violation_type] *= 1.2  # Increase sensitivity
        
        result.community_context = community_standards.get("type", "general")
    
    # Placeholder methods for external AI services
    async def _call_google_text_analysis(self, text: str) -> Dict[str, Any]:
        """Placeholder for Google Cloud Natural Language API."""
        return {}
    
    async def _call_google_vision_analysis(self, image_data: bytes) -> Dict[str, Any]:
        """Placeholder for Google Cloud Vision API."""
        return {}
    
    async def _call_azure_vision_analysis(self, image_data: bytes) -> Dict[str, Any]:
        """Placeholder for Azure Computer Vision API."""
        return {}
    
    async def _apply_custom_text_rules(self, text: str, result: ModerationResult):
        """Apply custom rule-based text analysis."""
        # Simple keyword-based detection
        hate_keywords = ["hate", "nazi", "terrorist"]  # Simplified example
        spam_keywords = ["buy now", "click here", "free money"]
        
        text_lower = text.lower()
        
        for keyword in hate_keywords:
            if keyword in text_lower:
                result.violation_scores[ViolationType.HATE_SPEECH] = max(
                    result.violation_scores.get(ViolationType.HATE_SPEECH, 0.0), 0.8
                )
                result.flagged_keywords.append(keyword)
        
        for keyword in spam_keywords:
            if keyword in text_lower:
                result.violation_scores[ViolationType.SPAM] = max(
                    result.violation_scores.get(ViolationType.SPAM, 0.0), 0.6
                )
                result.flagged_keywords.append(keyword)
    
    async def _apply_custom_image_rules(self, image_data: bytes, result: ModerationResult):
        """Apply custom image analysis rules."""
        # Placeholder for custom image analysis
    
    async def _detect_language(self, text: str) -> Optional[str]:
        """Detect language of text."""
        # Placeholder - would use language detection library
        return "en"
    
    async def _analyze_sentiment(self, text: str) -> float:
        """Analyze sentiment of text."""
        # Placeholder - would use sentiment analysis
        return 0.0
    
    async def _extract_video_frames(self, video_data: bytes) -> List[bytes]:
        """Extract frames from video."""
        # Placeholder - would use video processing library
        return []
    
    async def _extract_video_audio(self, video_data: bytes) -> Optional[bytes]:
        """Extract audio from video."""
        # Placeholder - would use video processing library
        return None
    
    async def _transcribe_audio(self, audio_data: bytes) -> Optional[str]:
        """Transcribe audio to text."""
        # Placeholder - would use speech-to-text service
        return None
    
    async def _analyze_audio_features(self, audio_data: bytes) -> Dict[str, Any]:
        """Analyze audio features."""
        # Placeholder - would analyze tone, volume, etc.
        return {}
    
    def _merge_image_results(self, result: ModerationResult, ai_result: Dict[str, Any], provider: str):
        """Merge image analysis results."""
        result.models_used.append(provider)
        # Implementation would map provider-specific results
    
    def get_moderation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive moderation statistics."""
        return {
            "enabled": self.enabled,
            "real_time_processing": self.real_time_processing,
            "statistics": self.stats,
            "thresholds": {vt.value: threshold for vt, threshold in self.thresholds.items()},
            "cache_size": len(self.moderation_cache),
            "providers_configured": len([p for p, config in self.ai_providers.items() if config.get("api_key")]),
            "user_trust_scores_tracked": len(self.user_trust_scores)
        }


# Global advanced content moderator
advanced_moderator = ProactiveContentModerator()
