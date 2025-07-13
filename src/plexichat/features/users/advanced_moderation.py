"""
Advanced moderation models with AI-powered capabilities and human review system.
Supports fine-grained access control and configurable moderation endpoints.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Index, Text
from sqlmodel import JSON, Column, Field, Relationship, SQLModel


class ModerationAction(str, Enum):
    """Types of moderation actions."""
    APPROVE = "approve"
    REJECT = "reject"
    FLAG = "flag"
    WARN = "warn"
    MUTE = "mute"
    BAN = "ban"
    DELETE = "delete"
    EDIT = "edit"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"


class ModerationSeverity(str, Enum):
    """Severity levels for moderation actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModerationStatus(str, Enum):
    """Status of moderation items."""
    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    APPEALED = "appealed"


class ModerationSource(str, Enum):
    """Source of moderation action."""
    AI_AUTOMATIC = "ai_automatic"
    AI_ASSISTED = "ai_assisted"
    HUMAN_MANUAL = "human_manual"
    USER_REPORT = "user_report"
    SYSTEM_AUTOMATIC = "system_automatic"
    FILTER_TRIGGERED = "filter_triggered"


class AIModelProvider(str, Enum):
    """AI model providers for moderation."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    HUGGINGFACE = "huggingface"
    CUSTOM = "custom"
    LOCAL = "local"


class ModerationConfiguration(SQLModel, table=True):
    """Server-specific moderation configuration."""
    __tablename__ = "moderation_configurations"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Configuration identification
    server_id: Optional[str] = Field(max_length=255, index=True)  # For multi-server support
    config_name: str = Field(max_length=255, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))
    
    # AI Moderation Settings
    ai_moderation_enabled: bool = Field(default=False)
    ai_provider: Optional[AIModelProvider] = Field(default=None)
    ai_model_name: Optional[str] = Field(max_length=255)
    ai_endpoint_url: Optional[str] = Field(max_length=500)
    ai_api_key_hash: Optional[str] = Field(max_length=128)  # Hashed API key
    ai_confidence_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    ai_auto_action_threshold: float = Field(default=0.95, ge=0.0, le=1.0)
    
    # Human Review Settings
    human_review_enabled: bool = Field(default=True)
    require_human_review_for_ai: bool = Field(default=True)
    escalation_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    
    # Content Types to Moderate
    moderate_messages: bool = Field(default=True)
    moderate_files: bool = Field(default=True)
    moderate_usernames: bool = Field(default=True)
    moderate_profiles: bool = Field(default=True)
    
    # Action Permissions
    allowed_actions: List[str] = Field(default=[], sa_column=Column(JSON))
    auto_actions: List[str] = Field(default=[], sa_column=Column(JSON))
    
    # Rate Limiting
    max_requests_per_minute: int = Field(default=100, ge=1)
    max_concurrent_reviews: int = Field(default=10, ge=1)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: int = Field(foreign_key="users_enhanced.id")
    
    # Configuration data
    ai_model_config: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    custom_rules: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Status
    is_active: bool = Field(default=True, index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_moderation_config_server', 'server_id', 'is_active'),
        Index('idx_moderation_config_ai', 'ai_moderation_enabled', 'ai_provider'),
    )


class ModerationItem(SQLModel, table=True):
    """Items requiring moderation review."""
    __tablename__ = "moderation_items"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Item identification
    content_type: str = Field(max_length=50, index=True)  # message, file, user, etc.
    content_id: int = Field(index=True)
    server_id: Optional[str] = Field(max_length=255, index=True)
    
    # Content details
    content_text: Optional[str] = Field(sa_column=Column(Text))
    content_metadata: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Moderation details
    status: ModerationStatus = Field(default=ModerationStatus.PENDING, index=True)
    severity: ModerationSeverity = Field(default=ModerationSeverity.MEDIUM, index=True)
    source: ModerationSource = Field(index=True)
    
    # AI Analysis
    ai_confidence_score: Optional[float] = Field(ge=0.0, le=1.0)
    ai_recommendation: Optional[ModerationAction] = Field()
    ai_reasoning: Optional[str] = Field(sa_column=Column(Text))
    ai_model_used: Optional[str] = Field(max_length=255)
    ai_analysis_data: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Human Review
    assigned_moderator_id: Optional[int] = Field(foreign_key="users_enhanced.id", index=True)
    human_decision: Optional[ModerationAction] = Field()
    human_reasoning: Optional[str] = Field(sa_column=Column(Text))
    human_notes: Optional[str] = Field(sa_column=Column(Text))
    
    # Final Decision
    final_action: Optional[ModerationAction] = Field(index=True)
    final_decision_by: Optional[int] = Field(foreign_key="users_enhanced.id")
    action_taken_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    reviewed_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    resolved_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Priority and escalation
    priority_score: float = Field(default=0.5, ge=0.0, le=1.0)
    escalated: bool = Field(default=False, index=True)
    escalated_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    escalated_by: Optional[int] = Field(foreign_key="users_enhanced.id")
    
    # Appeal information
    appeal_count: int = Field(default=0)
    last_appeal_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Relationships
    assigned_moderator: Optional["EnhancedUser"] = Relationship()
    final_decision_user: Optional["EnhancedUser"] = Relationship()
    
    # Indexes
    __table_args__ = (
        Index('idx_moderation_item_content', 'content_type', 'content_id'),
        Index('idx_moderation_item_status', 'status', 'created_at'),
        Index('idx_moderation_item_priority', 'priority_score', 'created_at'),
        Index('idx_moderation_item_ai', 'ai_confidence_score', 'ai_recommendation'),
    )


class ModerationRule(SQLModel, table=True):
    """Custom moderation rules and filters."""
    __tablename__ = "moderation_rules"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Rule identification
    rule_name: str = Field(max_length=255, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))
    server_id: Optional[str] = Field(max_length=255, index=True)
    
    # Rule configuration
    rule_type: str = Field(max_length=50, index=True)  # keyword, regex, ai_prompt, etc.
    rule_pattern: str = Field(sa_column=Column(Text))
    case_sensitive: bool = Field(default=False)
    
    # Actions
    trigger_action: ModerationAction = Field()
    severity: ModerationSeverity = Field(default=ModerationSeverity.MEDIUM)
    auto_execute: bool = Field(default=False)
    
    # Conditions
    content_types: List[str] = Field(default=[], sa_column=Column(JSON))
    user_roles: List[str] = Field(default=[], sa_column=Column(JSON))
    time_conditions: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Status and metrics
    is_active: bool = Field(default=True, index=True)
    trigger_count: int = Field(default=0)
    last_triggered_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: int = Field(foreign_key="users_enhanced.id")
    
    # Rule data
    rule_config: Optional[Dict[str, Any]] = Field(sa_column=Column(JSON))
    
    # Indexes
    __table_args__ = (
        Index('idx_moderation_rule_server', 'server_id', 'is_active'),
        Index('idx_moderation_rule_type', 'rule_type', 'is_active'),
    )


class ModerationAppeal(SQLModel, table=True):
    """Appeals for moderation decisions."""
    __tablename__ = "moderation_appeals"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Appeal details
    moderation_item_id: int = Field(foreign_key="moderation_items.id", index=True)
    appealed_by: int = Field(foreign_key="users_enhanced.id", index=True)
    appeal_reason: str = Field(sa_column=Column(Text))
    appeal_evidence: Optional[str] = Field(sa_column=Column(Text))
    
    # Review
    status: ModerationStatus = Field(default=ModerationStatus.PENDING, index=True)
    reviewed_by: Optional[int] = Field(foreign_key="users_enhanced.id")
    review_decision: Optional[str] = Field(max_length=50)
    review_notes: Optional[str] = Field(sa_column=Column(Text))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Relationships
    moderation_item: Optional[ModerationItem] = Relationship()
    appellant: Optional["EnhancedUser"] = Relationship()
    reviewer: Optional["EnhancedUser"] = Relationship()


class AIModelEndpoint(SQLModel, table=True):
    """AI model endpoints for moderation."""
    __tablename__ = "ai_model_endpoints"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Endpoint details
    endpoint_name: str = Field(max_length=255, index=True)
    provider: AIModelProvider = Field(index=True)
    model_name: str = Field(max_length=255)
    endpoint_url: str = Field(max_length=500)
    
    # Authentication
    api_key_hash: Optional[str] = Field(max_length=128)
    auth_headers: Optional[Dict[str, str]] = Field(sa_column=Column(JSON))
    
    # Configuration
    request_format: Dict[str, Any] = Field(sa_column=Column(JSON))
    response_format: Dict[str, Any] = Field(sa_column=Column(JSON))
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_retries: int = Field(default=3, ge=0, le=10)
    
    # Capabilities
    supported_content_types: List[str] = Field(default=[], sa_column=Column(JSON))
    supported_languages: List[str] = Field(default=[], sa_column=Column(JSON))
    
    # Performance metrics
    average_response_time_ms: Optional[float] = Field(ge=0)
    success_rate: Optional[float] = Field(ge=0, le=1)
    last_used_at: Optional[datetime] = Field(sa_column=Column(DateTime))
    total_requests: int = Field(default=0)
    
    # Status
    is_active: bool = Field(default=True, index=True)
    health_status: str = Field(default="unknown", max_length=50)
    last_health_check: Optional[datetime] = Field(sa_column=Column(DateTime))
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: int = Field(foreign_key="users_enhanced.id")
    
    # Indexes
    __table_args__ = (
        Index('idx_ai_endpoint_provider', 'provider', 'is_active'),
        Index('idx_ai_endpoint_health', 'health_status', 'last_health_check'),
    )


class ModerationWorkflow(SQLModel, table=True):
    """Moderation workflow definitions."""
    __tablename__ = "moderation_workflows"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True, index=True)
    
    # Workflow details
    workflow_name: str = Field(max_length=255, index=True)
    description: Optional[str] = Field(sa_column=Column(Text))
    server_id: Optional[str] = Field(max_length=255, index=True)
    
    # Workflow steps
    steps: List[Dict[str, Any]] = Field(sa_column=Column(JSON))
    conditions: Dict[str, Any] = Field(sa_column=Column(JSON))
    
    # Configuration
    auto_assign: bool = Field(default=True)
    escalation_rules: Dict[str, Any] = Field(sa_column=Column(JSON))
    sla_hours: Optional[int] = Field(ge=1)
    
    # Status
    is_active: bool = Field(default=True, index=True)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: int = Field(foreign_key="users_enhanced.id")
