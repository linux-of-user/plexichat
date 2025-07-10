"""
Powerful Content Filtering System
Advanced rule-based content filtering with configurable rules and smart detection.
"""

import re
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Pattern
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger("netlink.filters.content")

class FilterAction(Enum):
    """Filter actions."""
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    MODERATE = "moderate"
    FLAG = "flag"

class FilterType(Enum):
    """Filter types."""
    KEYWORD = "keyword"
    REGEX = "regex"
    PATTERN = "pattern"
    SENTIMENT = "sentiment"
    LENGTH = "length"
    SPAM = "spam"
    PROFANITY = "profanity"
    CUSTOM = "custom"

class FilterSeverity(Enum):
    """Filter severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class FilterRule:
    """Individual filter rule."""
    id: str
    name: str
    description: str
    type: FilterType
    severity: FilterSeverity
    action: FilterAction
    pattern: str
    enabled: bool = True
    case_sensitive: bool = False
    whole_word: bool = False
    score: int = 1
    tags: List[str] = None
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class FilterResult:
    """Filter result."""
    blocked: bool
    action: FilterAction
    matched_rules: List[str]
    score: int
    reason: str
    suggestions: List[str] = None
    
    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []

class ContentFilter:
    """Advanced content filtering system."""
    
    def __init__(self):
        self.config_dir = Path("config/filters")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.rules_file = self.config_dir / "filter_rules.json"
        self.config_file = self.config_dir / "filter_config.json"
        self.stats_file = self.config_dir / "filter_stats.json"
        
        # Filter rules storage
        self.rules: Dict[str, FilterRule] = {}
        self.compiled_patterns: Dict[str, Pattern] = {}
        
        # Configuration
        self.config = {
            "enabled": True,
            "default_action": FilterAction.WARN.value,
            "score_threshold": 5,
            "auto_moderate_threshold": 10,
            "learning_enabled": True,
            "whitelist_enabled": True,
            "case_sensitive_default": False,
            "whole_word_default": True
        }
        
        # Statistics
        self.stats = {
            "total_messages_filtered": 0,
            "messages_blocked": 0,
            "messages_warned": 0,
            "messages_flagged": 0,
            "rules_triggered": {},
            "false_positives": 0,
            "last_reset": datetime.now().isoformat()
        }
        
        # Load existing data
        self.load_config()
        self.load_rules()
        self.load_stats()
        
        # Initialize default rules if none exist
        if not self.rules:
            self.create_default_rules()
    
    def create_default_rules(self):
        """Create default filter rules."""
        default_rules = [
            # Profanity filters
            {
                "name": "Basic Profanity",
                "description": "Common profanity and offensive language",
                "type": FilterType.KEYWORD,
                "severity": FilterSeverity.MEDIUM,
                "action": FilterAction.WARN,
                "pattern": r"\b(fuck|shit|damn|hell|bitch|asshole|bastard)\b",
                "tags": ["profanity", "offensive"]
            },
            {
                "name": "Severe Profanity",
                "description": "Severe offensive language and slurs",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.HIGH,
                "action": FilterAction.BLOCK,
                "pattern": r"\b(n[i1]gg[ae]r|f[a4]gg[o0]t|c[u0]nt|wh[o0]re)\b",
                "tags": ["profanity", "slurs", "severe"]
            },
            
            # Spam filters
            {
                "name": "Excessive Caps",
                "description": "Messages with excessive capital letters",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.LOW,
                "action": FilterAction.WARN,
                "pattern": r"[A-Z]{10,}",
                "tags": ["spam", "caps"]
            },
            {
                "name": "Repeated Characters",
                "description": "Messages with excessive repeated characters",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.LOW,
                "action": FilterAction.WARN,
                "pattern": r"(.)\1{5,}",
                "tags": ["spam", "repetition"]
            },
            {
                "name": "URL Spam",
                "description": "Messages with multiple URLs",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.MEDIUM,
                "action": FilterAction.MODERATE,
                "pattern": r"(https?://[^\s]+.*){3,}",
                "tags": ["spam", "urls"]
            },
            
            # Security filters
            {
                "name": "Phishing Attempts",
                "description": "Common phishing keywords",
                "type": FilterType.KEYWORD,
                "severity": FilterSeverity.HIGH,
                "action": FilterAction.BLOCK,
                "pattern": r"\b(click here|verify account|suspended account|urgent action|limited time)\b",
                "tags": ["security", "phishing"]
            },
            {
                "name": "Malicious Links",
                "description": "Suspicious link patterns",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.HIGH,
                "action": FilterAction.BLOCK,
                "pattern": r"(bit\.ly|tinyurl|t\.co|goo\.gl)/[a-zA-Z0-9]+",
                "tags": ["security", "links"]
            },
            
            # Content quality filters
            {
                "name": "Too Short",
                "description": "Messages that are too short",
                "type": FilterType.LENGTH,
                "severity": FilterSeverity.LOW,
                "action": FilterAction.WARN,
                "pattern": "min:3",
                "tags": ["quality", "length"]
            },
            {
                "name": "Too Long",
                "description": "Messages that are too long",
                "type": FilterType.LENGTH,
                "severity": FilterSeverity.LOW,
                "action": FilterAction.WARN,
                "pattern": "max:2000",
                "tags": ["quality", "length"]
            },
            
            # Harassment filters
            {
                "name": "Personal Attacks",
                "description": "Personal attacks and harassment",
                "type": FilterType.KEYWORD,
                "severity": FilterSeverity.HIGH,
                "action": FilterAction.MODERATE,
                "pattern": r"\b(kill yourself|kys|die|hate you|stupid|idiot|moron)\b",
                "tags": ["harassment", "personal"]
            },
            {
                "name": "Threats",
                "description": "Threatening language",
                "type": FilterType.REGEX,
                "severity": FilterSeverity.CRITICAL,
                "action": FilterAction.BLOCK,
                "pattern": r"\b(i will kill|gonna hurt|beat you up|find you|come for you)\b",
                "tags": ["threats", "violence"]
            }
        ]
        
        for rule_data in default_rules:
            rule_id = hashlib.md5(rule_data["name"].encode()).hexdigest()[:8]
            
            rule = FilterRule(
                id=rule_id,
                name=rule_data["name"],
                description=rule_data["description"],
                type=rule_data["type"],
                severity=rule_data["severity"],
                action=rule_data["action"],
                pattern=rule_data["pattern"],
                tags=rule_data["tags"]
            )
            
            self.rules[rule_id] = rule
            self._compile_pattern(rule)
        
        self.save_rules()
        logger.info(f"Created {len(default_rules)} default filter rules")
    
    def filter_content(self, content: str, context: Dict[str, Any] = None) -> FilterResult:
        """Filter content and return result."""
        if not self.config["enabled"]:
            return FilterResult(
                blocked=False,
                action=FilterAction.ALLOW,
                matched_rules=[],
                score=0,
                reason="Filtering disabled"
            )
        
        matched_rules = []
        total_score = 0
        highest_action = FilterAction.ALLOW
        reasons = []
        suggestions = []
        
        # Apply each enabled rule
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            if self._rule_matches(rule, content, context):
                matched_rules.append(rule.id)
                total_score += rule.score
                
                # Track highest severity action
                if self._action_priority(rule.action) > self._action_priority(highest_action):
                    highest_action = rule.action
                
                reasons.append(f"{rule.name}: {rule.description}")
                
                # Add suggestions based on rule type
                if rule.type == FilterType.PROFANITY:
                    suggestions.append("Consider using more appropriate language")
                elif rule.type == FilterType.SPAM:
                    suggestions.append("Avoid repetitive or excessive content")
                elif rule.type == FilterType.LENGTH:
                    if "min:" in rule.pattern:
                        suggestions.append("Please provide more detailed content")
                    elif "max:" in rule.pattern:
                        suggestions.append("Please shorten your message")
                
                # Update statistics
                if rule.id not in self.stats["rules_triggered"]:
                    self.stats["rules_triggered"][rule.id] = 0
                self.stats["rules_triggered"][rule.id] += 1
        
        # Determine final action based on score and thresholds
        final_action = highest_action
        blocked = False
        
        if total_score >= self.config["auto_moderate_threshold"]:
            final_action = FilterAction.BLOCK
            blocked = True
        elif total_score >= self.config["score_threshold"]:
            if highest_action == FilterAction.ALLOW:
                final_action = FilterAction.WARN
        
        # Update statistics
        self.stats["total_messages_filtered"] += 1
        if blocked:
            self.stats["messages_blocked"] += 1
        elif final_action == FilterAction.WARN:
            self.stats["messages_warned"] += 1
        elif final_action == FilterAction.FLAG:
            self.stats["messages_flagged"] += 1
        
        self.save_stats()
        
        return FilterResult(
            blocked=blocked,
            action=final_action,
            matched_rules=matched_rules,
            score=total_score,
            reason="; ".join(reasons) if reasons else "Content passed all filters",
            suggestions=list(set(suggestions))
        )
    
    def _rule_matches(self, rule: FilterRule, content: str, context: Dict[str, Any] = None) -> bool:
        """Check if a rule matches the content."""
        try:
            if rule.type == FilterType.LENGTH:
                return self._check_length_rule(rule, content)
            elif rule.type == FilterType.KEYWORD:
                return self._check_keyword_rule(rule, content)
            elif rule.type == FilterType.REGEX or rule.type == FilterType.PATTERN:
                return self._check_regex_rule(rule, content)
            elif rule.type == FilterType.SENTIMENT:
                return self._check_sentiment_rule(rule, content)
            elif rule.type == FilterType.SPAM:
                return self._check_spam_rule(rule, content)
            elif rule.type == FilterType.PROFANITY:
                return self._check_profanity_rule(rule, content)
            elif rule.type == FilterType.CUSTOM:
                return self._check_custom_rule(rule, content, context)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking rule {rule.id}: {e}")
            return False
    
    def _check_length_rule(self, rule: FilterRule, content: str) -> bool:
        """Check length-based rules."""
        content_length = len(content.strip())
        
        if rule.pattern.startswith("min:"):
            min_length = int(rule.pattern.split(":")[1])
            return content_length < min_length
        elif rule.pattern.startswith("max:"):
            max_length = int(rule.pattern.split(":")[1])
            return content_length > max_length
        
        return False
    
    def _check_keyword_rule(self, rule: FilterRule, content: str) -> bool:
        """Check keyword-based rules."""
        search_content = content if rule.case_sensitive else content.lower()
        pattern = rule.pattern if rule.case_sensitive else rule.pattern.lower()
        
        if rule.whole_word:
            # Use word boundaries
            import re
            flags = 0 if rule.case_sensitive else re.IGNORECASE
            return bool(re.search(rf"\b{re.escape(pattern)}\b", content, flags))
        else:
            return pattern in search_content
    
    def _check_regex_rule(self, rule: FilterRule, content: str) -> bool:
        """Check regex-based rules."""
        if rule.id not in self.compiled_patterns:
            self._compile_pattern(rule)
        
        pattern = self.compiled_patterns.get(rule.id)
        if pattern:
            return bool(pattern.search(content))
        
        return False
    
    def _check_sentiment_rule(self, rule: FilterRule, content: str) -> bool:
        """Check sentiment-based rules (placeholder for future implementation)."""
        # This would integrate with sentiment analysis libraries
        return False
    
    def _check_spam_rule(self, rule: FilterRule, content: str) -> bool:
        """Check spam-based rules."""
        # Implement spam detection logic
        return self._check_regex_rule(rule, content)
    
    def _check_profanity_rule(self, rule: FilterRule, content: str) -> bool:
        """Check profanity-based rules."""
        return self._check_regex_rule(rule, content)
    
    def _check_custom_rule(self, rule: FilterRule, content: str, context: Dict[str, Any] = None) -> bool:
        """Check custom rules (placeholder for future implementation)."""
        # This would allow for custom Python code execution
        return False
    
    def _compile_pattern(self, rule: FilterRule):
        """Compile regex pattern for rule."""
        try:
            flags = 0
            if not rule.case_sensitive:
                flags |= re.IGNORECASE
            
            if rule.type == FilterType.KEYWORD and rule.whole_word:
                pattern = rf"\b{re.escape(rule.pattern)}\b"
            else:
                pattern = rule.pattern
            
            self.compiled_patterns[rule.id] = re.compile(pattern, flags)
            
        except re.error as e:
            logger.error(f"Error compiling pattern for rule {rule.id}: {e}")
    
    def _action_priority(self, action: FilterAction) -> int:
        """Get priority level for action."""
        priorities = {
            FilterAction.ALLOW: 0,
            FilterAction.WARN: 1,
            FilterAction.FLAG: 2,
            FilterAction.MODERATE: 3,
            FilterAction.BLOCK: 4
        }
        return priorities.get(action, 0)
    
    def add_rule(self, rule_data: Dict[str, Any]) -> str:
        """Add a new filter rule."""
        rule_id = hashlib.md5(f"{rule_data['name']}{time.time()}".encode()).hexdigest()[:8]
        
        rule = FilterRule(
            id=rule_id,
            name=rule_data["name"],
            description=rule_data["description"],
            type=FilterType(rule_data["type"]),
            severity=FilterSeverity(rule_data["severity"]),
            action=FilterAction(rule_data["action"]),
            pattern=rule_data["pattern"],
            enabled=rule_data.get("enabled", True),
            case_sensitive=rule_data.get("case_sensitive", self.config["case_sensitive_default"]),
            whole_word=rule_data.get("whole_word", self.config["whole_word_default"]),
            score=rule_data.get("score", 1),
            tags=rule_data.get("tags", [])
        )
        
        self.rules[rule_id] = rule
        self._compile_pattern(rule)
        self.save_rules()
        
        logger.info(f"Added new filter rule: {rule.name} ({rule_id})")
        return rule_id
    
    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing filter rule."""
        if rule_id not in self.rules:
            return False
        
        rule = self.rules[rule_id]
        
        # Update fields
        for field, value in updates.items():
            if hasattr(rule, field):
                if field in ["type", "severity", "action"]:
                    # Handle enum fields
                    if field == "type":
                        setattr(rule, field, FilterType(value))
                    elif field == "severity":
                        setattr(rule, field, FilterSeverity(value))
                    elif field == "action":
                        setattr(rule, field, FilterAction(value))
                else:
                    setattr(rule, field, value)
        
        rule.updated_at = datetime.now()
        
        # Recompile pattern if changed
        if "pattern" in updates or "case_sensitive" in updates or "whole_word" in updates:
            self._compile_pattern(rule)
        
        self.save_rules()
        logger.info(f"Updated filter rule: {rule.name} ({rule_id})")
        return True
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a filter rule."""
        if rule_id not in self.rules:
            return False
        
        rule_name = self.rules[rule_id].name
        del self.rules[rule_id]
        
        if rule_id in self.compiled_patterns:
            del self.compiled_patterns[rule_id]
        
        self.save_rules()
        logger.info(f"Deleted filter rule: {rule_name} ({rule_id})")
        return True
    
    def get_rules(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get filter rules with optional filtering."""
        rules = list(self.rules.values())
        
        if filters:
            if "enabled" in filters:
                rules = [r for r in rules if r.enabled == filters["enabled"]]
            if "type" in filters:
                rules = [r for r in rules if r.type.value == filters["type"]]
            if "severity" in filters:
                rules = [r for r in rules if r.severity.value == filters["severity"]]
            if "action" in filters:
                rules = [r for r in rules if r.action.value == filters["action"]]
            if "tags" in filters:
                filter_tags = filters["tags"] if isinstance(filters["tags"], list) else [filters["tags"]]
                rules = [r for r in rules if any(tag in r.tags for tag in filter_tags)]
        
        return [self._rule_to_dict(rule) for rule in rules]
    
    def _rule_to_dict(self, rule: FilterRule) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        data = asdict(rule)
        data["type"] = rule.type.value
        data["severity"] = rule.severity.value
        data["action"] = rule.action.value
        data["created_at"] = rule.created_at.isoformat()
        data["updated_at"] = rule.updated_at.isoformat()
        return data
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get filter statistics."""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset filter statistics."""
        self.stats = {
            "total_messages_filtered": 0,
            "messages_blocked": 0,
            "messages_warned": 0,
            "messages_flagged": 0,
            "rules_triggered": {},
            "false_positives": 0,
            "last_reset": datetime.now().isoformat()
        }
        self.save_stats()
    
    def load_config(self):
        """Load filter configuration."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
            except Exception as e:
                logger.error(f"Error loading filter config: {e}")
    
    def save_config(self):
        """Save filter configuration."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving filter config: {e}")
    
    def load_rules(self):
        """Load filter rules."""
        if self.rules_file.exists():
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)
                    
                for rule_data in rules_data:
                    rule = FilterRule(
                        id=rule_data["id"],
                        name=rule_data["name"],
                        description=rule_data["description"],
                        type=FilterType(rule_data["type"]),
                        severity=FilterSeverity(rule_data["severity"]),
                        action=FilterAction(rule_data["action"]),
                        pattern=rule_data["pattern"],
                        enabled=rule_data.get("enabled", True),
                        case_sensitive=rule_data.get("case_sensitive", False),
                        whole_word=rule_data.get("whole_word", False),
                        score=rule_data.get("score", 1),
                        tags=rule_data.get("tags", []),
                        created_at=datetime.fromisoformat(rule_data["created_at"]),
                        updated_at=datetime.fromisoformat(rule_data["updated_at"])
                    )
                    
                    self.rules[rule.id] = rule
                    self._compile_pattern(rule)
                    
            except Exception as e:
                logger.error(f"Error loading filter rules: {e}")
    
    def save_rules(self):
        """Save filter rules."""
        try:
            rules_data = [self._rule_to_dict(rule) for rule in self.rules.values()]
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error saving filter rules: {e}")
    
    def load_stats(self):
        """Load filter statistics."""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r', encoding='utf-8') as f:
                    saved_stats = json.load(f)
                    self.stats.update(saved_stats)
            except Exception as e:
                logger.error(f"Error loading filter stats: {e}")
    
    def save_stats(self):
        """Save filter statistics."""
        try:
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving filter stats: {e}")

# Global content filter instance
content_filter = ContentFilter()
