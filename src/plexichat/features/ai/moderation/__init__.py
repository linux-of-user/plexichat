# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
try:
    from plexichat.features.ai.moderation.feedback_collector import (
        FeedbackCollector,  # type: ignore
    )
except ImportError:
    FeedbackCollector = None

try:
    from plexichat.features.ai.moderation.moderation_engine import (
        ModerationEngine,  # type: ignore
    )
except ImportError:
    ModerationEngine = None

# Define basic enums that might be missing
from enum import Enum


class ModerationAction(str, Enum):
    """Moderation action types."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"
    REVIEW = "review"


class ModerationSeverity(str, Enum):
    """Moderation severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModerationCategory(str, Enum):
    """Moderation categories."""

    SPAM = "spam"
    HARASSMENT = "harassment"
    HATE_SPEECH = "hate_speech"
    VIOLENCE = "violence"
    ADULT_CONTENT = "adult_content"
    MISINFORMATION = "misinformation"


__all__ = ["ModerationAction", "ModerationCategory", "ModerationSeverity"]

if FeedbackCollector:
    __all__.append("FeedbackCollector")
if ModerationEngine:
    __all__.append("ModerationEngine")
