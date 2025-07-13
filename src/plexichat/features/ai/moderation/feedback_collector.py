import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .moderation_engine import ModerationAction, ModerationCategory, ModerationSeverity
from .training_system import ModerationTrainingSystem, TrainingDataSource

            import hashlib

"""
AI Moderation Feedback Collector
Collects and processes user feedback for improving moderation accuracy.
"""

logger = logging.getLogger(__name__)

class FeedbackType(str, Enum):
    """Type of feedback."""
    CORRECTION = "correction"
    CONFIRMATION = "confirmation"
    REPORT = "report"
    APPEAL = "appeal"

class FeedbackSource(str, Enum):
    """Source of feedback."""
    USER_INTERFACE = "user_interface"
    API_ENDPOINT = "api_endpoint"
    AUTOMATED_REVIEW = "automated_review"
    HUMAN_MODERATOR = "human_moderator"

@dataclass
class ModerationFeedback:
    """Moderation feedback data."""
    content_id: str
    user_id: str
    feedback_type: FeedbackType
    source: FeedbackSource
    original_action: ModerationAction
    suggested_action: ModerationAction
    confidence: float
    reasoning: str
    categories: List[ModerationCategory]
    severity: ModerationSeverity
    metadata: Dict[str, Any]
    created_at: datetime
    processed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_id": self.content_id,
            "user_id": self.user_id,
            "feedback_type": self.feedback_type.value,
            "source": self.source.value,
            "original_action": self.original_action.value,
            "suggested_action": self.suggested_action.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "categories": [cat.value for cat in self.categories],
            "severity": self.severity.value,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "processed": self.processed
        }

class FeedbackCollector:
    """Collects and processes moderation feedback."""
    
    def __init__(self, data_path: str = "data/moderation_feedback"):
        self.data_path = from pathlib import Path
Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.data_path / "feedback.db"
        self.training_system = ModerationTrainingSystem()
        
        self._init_database()
    
    def _init_database(self):
        """Initialize feedback database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    feedback_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    original_action TEXT NOT NULL,
                    suggested_action TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT,
                    categories TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    processed BOOLEAN DEFAULT FALSE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_content_id ON feedback(content_id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_id ON feedback(user_id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_processed ON feedback(processed)
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS content_cache (
                    content_id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            conn.commit()
        
        logger.info("Feedback database initialized")
    
    async def submit_feedback(
        self,
        content_id: str,
        user_id: str,
        feedback_type: FeedbackType,
        source: FeedbackSource,
        original_action: ModerationAction,
        suggested_action: ModerationAction,
        confidence: float,
        reasoning: str,
        categories: List[ModerationCategory],
        severity: ModerationSeverity,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Submit moderation feedback."""
        try:
            feedback = ModerationFeedback(
                content_id=content_id,
                user_id=user_id,
                feedback_type=feedback_type,
                source=source,
                original_action=original_action,
                suggested_action=suggested_action,
                confidence=confidence,
                reasoning=reasoning,
                categories=categories,
                severity=severity,
                metadata=metadata or {},
                created_at=datetime.now(timezone.utc)
            )
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO feedback (
                        content_id, user_id, feedback_type, source, original_action,
                        suggested_action, confidence, reasoning, categories, severity,
                        metadata, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    feedback.content_id,
                    feedback.user_id,
                    feedback.feedback_type.value,
                    feedback.source.value,
                    feedback.original_action.value,
                    feedback.suggested_action.value,
                    feedback.confidence,
                    feedback.reasoning,
                    json.dumps([cat.value for cat in feedback.categories]),
                    feedback.severity.value,
                    json.dumps(feedback.metadata),
                    feedback.created_at.isoformat()
                ))
                conn.commit()
            
            logger.info(f"Feedback submitted: {content_id} by {user_id}")
            
            # Process feedback immediately if it's a correction
            if feedback_type == FeedbackType.CORRECTION:
                await self._process_correction_feedback(feedback)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to submit feedback: {e}")
            return False
    
    async def _process_correction_feedback(self, feedback: ModerationFeedback):
        """Process correction feedback for training."""
        try:
            # Get the original content
            content = await self._get_content(feedback.content_id)
            if not content:
                logger.warning(f"Content not found for feedback: {feedback.content_id}")
                return
            
            # Add to training data
            success = self.training_system.add_training_data(
                content=content,
                label=feedback.suggested_action,
                confidence=feedback.confidence,
                categories=feedback.categories,
                severity=feedback.severity,
                source=TrainingDataSource.USER_FEEDBACK,
                metadata={
                    "original_action": feedback.original_action.value,
                    "user_id": feedback.user_id,
                    "reasoning": feedback.reasoning,
                    "feedback_source": feedback.source.value
                }
            )
            
            if success:
                # Mark feedback as processed
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "UPDATE feedback SET processed = TRUE WHERE content_id = ? AND user_id = ?",
                        (feedback.content_id, feedback.user_id)
                    )
                    conn.commit()
                
                logger.info(f"Processed correction feedback for {feedback.content_id}")
            
        except Exception as e:
            logger.error(f"Failed to process correction feedback: {e}")
    
    async def _get_content(self, content_id: str) -> Optional[str]:
        """Get content by ID from cache."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT content FROM content_cache WHERE content_id = ?",
                    (content_id,)
                )
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            logger.error(f"Failed to get content {content_id}: {e}")
            return None
    
    async def cache_content(self, content_id: str, content: str):
        """Cache content for feedback processing."""
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO content_cache (content_id, content, content_hash, created_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    content_id,
                    content,
                    content_hash,
                    datetime.now(timezone.utc).isoformat()
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to cache content {content_id}: {e}")
    
    async def get_feedback_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get feedback statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_feedback,
                        COUNT(CASE WHEN processed THEN 1 END) as processed_feedback,
                        feedback_type,
                        COUNT(*) as type_count,
                        AVG(confidence) as avg_confidence
                    FROM feedback 
                    WHERE datetime(created_at) >= datetime('now', '-{} days')
                    GROUP BY feedback_type
                """.format(days))
                
                results = cursor.fetchall()
                
                stats = {
                    "total_feedback": 0,
                    "processed_feedback": 0,
                    "feedback_types": {},
                    "avg_confidence": 0.0
                }
                
                for row in results:
                    stats["total_feedback"] += row[3]
                    stats["processed_feedback"] += row[1]
                    stats["feedback_types"][row[2]] = {
                        "count": row[3],
                        "avg_confidence": row[4]
                    }
                
                # Get user participation stats
                cursor = conn.execute("""
                    SELECT COUNT(DISTINCT user_id) as unique_users
                    FROM feedback
                    WHERE datetime(created_at) >= datetime('now', '-{} days')
                """.format(days))
                
                user_row = cursor.fetchone()
                stats["unique_users"] = user_row[0] if user_row else 0
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get feedback stats: {e}")
            return {"error": str(e)}
    
    async def get_user_feedback_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get feedback history for a user."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT * FROM feedback 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (user_id, limit))
                
                rows = cursor.fetchall()
                
                feedback_list = []
                for row in rows:
                    feedback_list.append({
                        "id": row[0],
                        "content_id": row[1],
                        "feedback_type": row[3],
                        "original_action": row[5],
                        "suggested_action": row[6],
                        "confidence": row[7],
                        "reasoning": row[8],
                        "categories": json.loads(row[9]),
                        "severity": row[10],
                        "created_at": row[12],
                        "processed": bool(row[13])
                    })
                
                return feedback_list
                
        except Exception as e:
            logger.error(f"Failed to get user feedback history: {e}")
            return []
