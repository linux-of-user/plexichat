"""
Advanced Username Filtering System
Powerful rules-based username validation with whitelist/blacklist and smart rules.
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

logger = logging.getLogger("netlink.filters.username")

class UsernameAction(Enum):
    """Username validation actions."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    SUGGEST_ALTERNATIVE = "suggest_alternative"

class RuleType(Enum):
    """Username rule types."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    PATTERN = "pattern"
    LENGTH = "length"
    PROFANITY = "profanity"
    RESERVED = "reserved"
    SIMILARITY = "similarity"
    CUSTOM = "custom"

@dataclass
class UsernameRule:
    """Username validation rule."""
    id: str
    name: str
    description: str
    type: RuleType
    action: UsernameAction
    pattern: str
    enabled: bool = True
    case_sensitive: bool = False
    priority: int = 1
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
class UsernameValidationResult:
    """Username validation result."""
    valid: bool
    action: UsernameAction
    matched_rules: List[str]
    reason: str
    suggestions: List[str] = None
    score: int = 0
    
    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []

class UsernameFilter:
    """Advanced username filtering and validation system."""
    
    def __init__(self):
        self.config_dir = Path("config/filters")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.rules_file = self.config_dir / "username_rules.json"
        self.whitelist_file = self.config_dir / "username_whitelist.json"
        self.blacklist_file = self.config_dir / "username_blacklist.json"
        self.reserved_file = self.config_dir / "reserved_usernames.json"
        self.config_file = self.config_dir / "username_config.json"
        
        # Rules and lists
        self.rules: Dict[str, UsernameRule] = {}
        self.whitelist: List[str] = []
        self.blacklist: List[str] = []
        self.reserved_usernames: List[str] = []
        self.compiled_patterns: Dict[str, Pattern] = {}
        
        # Configuration
        self.config = {
            "enabled": True,
            "min_length": 3,
            "max_length": 20,
            "allow_numbers": True,
            "allow_underscores": True,
            "allow_hyphens": True,
            "allow_dots": False,
            "require_letter_start": True,
            "case_sensitive": False,
            "whitelist_override": True,
            "suggestion_count": 5,
            "similarity_threshold": 0.8
        }
        
        # Load existing data
        self.load_config()
        self.load_rules()
        self.load_lists()
        
        # Initialize default rules if none exist
        if not self.rules:
            self.create_default_rules()
    
    def create_default_rules(self):
        """Create default username validation rules."""
        default_rules = [
            # Length rules
            {
                "name": "Minimum Length",
                "description": "Username must be at least 3 characters",
                "type": RuleType.LENGTH,
                "action": UsernameAction.DENY,
                "pattern": "min:3",
                "priority": 10,
                "tags": ["length", "basic"]
            },
            {
                "name": "Maximum Length",
                "description": "Username must not exceed 20 characters",
                "type": RuleType.LENGTH,
                "action": UsernameAction.DENY,
                "pattern": "max:20",
                "priority": 10,
                "tags": ["length", "basic"]
            },
            
            # Character pattern rules
            {
                "name": "Valid Characters",
                "description": "Username can only contain letters, numbers, underscores, and hyphens",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"^[a-zA-Z0-9_-]+$",
                "priority": 9,
                "tags": ["pattern", "characters"]
            },
            {
                "name": "Must Start with Letter",
                "description": "Username must start with a letter",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"^[a-zA-Z]",
                "priority": 8,
                "tags": ["pattern", "start"]
            },
            {
                "name": "No Consecutive Special Characters",
                "description": "Username cannot have consecutive underscores or hyphens",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"[_-]{2,}",
                "priority": 7,
                "tags": ["pattern", "special"]
            },
            {
                "name": "No Leading/Trailing Special Characters",
                "description": "Username cannot start or end with special characters",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"^[_-]|[_-]$",
                "priority": 7,
                "tags": ["pattern", "special"]
            },
            
            # Profanity rules
            {
                "name": "Basic Profanity",
                "description": "Username cannot contain basic profanity",
                "type": RuleType.PROFANITY,
                "action": UsernameAction.DENY,
                "pattern": r"\b(fuck|shit|damn|hell|bitch|ass)\b",
                "priority": 6,
                "tags": ["profanity", "offensive"]
            },
            {
                "name": "Severe Profanity",
                "description": "Username cannot contain severe profanity or slurs",
                "type": RuleType.PROFANITY,
                "action": UsernameAction.DENY,
                "pattern": r"\b(n[i1]gg[ae]r|f[a4]gg[o0]t|c[u0]nt|wh[o0]re)\b",
                "priority": 10,
                "tags": ["profanity", "slurs", "severe"]
            },
            
            # Reserved usernames
            {
                "name": "System Reserved",
                "description": "Username cannot be a system reserved word",
                "type": RuleType.RESERVED,
                "action": UsernameAction.DENY,
                "pattern": "system_reserved",
                "priority": 10,
                "tags": ["reserved", "system"]
            },
            
            # Quality rules
            {
                "name": "No All Numbers",
                "description": "Username cannot be all numbers",
                "type": RuleType.PATTERN,
                "action": UsernameAction.SUGGEST_ALTERNATIVE,
                "pattern": r"^\d+$",
                "priority": 3,
                "tags": ["quality", "numbers"]
            },
            {
                "name": "Discourage Leetspeak",
                "description": "Discourage excessive leetspeak",
                "type": RuleType.PATTERN,
                "action": UsernameAction.SUGGEST_ALTERNATIVE,
                "pattern": r"[0-9]{3,}|[xX]{2,}",
                "priority": 2,
                "tags": ["quality", "leetspeak"]
            }
        ]
        
        # Default reserved usernames
        self.reserved_usernames = [
            "admin", "administrator", "root", "system", "user", "guest", "test",
            "api", "www", "mail", "email", "support", "help", "info", "contact",
            "about", "home", "index", "login", "logout", "register", "signup",
            "signin", "profile", "account", "settings", "config", "dashboard",
            "moderator", "mod", "staff", "team", "official", "netlink",
            "null", "undefined", "none", "empty", "void", "anonymous", "anon"
        ]
        
        for rule_data in default_rules:
            rule_id = hashlib.md5(rule_data["name"].encode()).hexdigest()[:8]
            
            rule = UsernameRule(
                id=rule_id,
                name=rule_data["name"],
                description=rule_data["description"],
                type=rule_data["type"],
                action=rule_data["action"],
                pattern=rule_data["pattern"],
                priority=rule_data["priority"],
                tags=rule_data["tags"]
            )
            
            self.rules[rule_id] = rule
            self._compile_pattern(rule)
        
        self.save_rules()
        self.save_lists()
        logger.info(f"Created {len(default_rules)} default username rules")
    
    def validate_username(self, username: str, context: Dict[str, Any] = None) -> UsernameValidationResult:
        """Validate a username against all rules."""
        if not self.config["enabled"]:
            return UsernameValidationResult(
                valid=True,
                action=UsernameAction.ALLOW,
                matched_rules=[],
                reason="Username validation disabled"
            )
        
        # Normalize username
        check_username = username if self.config["case_sensitive"] else username.lower()
        
        # Check whitelist first (if enabled and override is true)
        if self.config["whitelist_override"] and self._is_whitelisted(check_username):
            return UsernameValidationResult(
                valid=True,
                action=UsernameAction.ALLOW,
                matched_rules=["whitelist"],
                reason="Username is whitelisted"
            )
        
        # Check blacklist
        if self._is_blacklisted(check_username):
            return UsernameValidationResult(
                valid=False,
                action=UsernameAction.DENY,
                matched_rules=["blacklist"],
                reason="Username is blacklisted"
            )
        
        # Apply rules in priority order
        matched_rules = []
        highest_action = UsernameAction.ALLOW
        reasons = []
        suggestions = []
        
        # Sort rules by priority (higher priority first)
        sorted_rules = sorted(self.rules.values(), key=lambda r: r.priority, reverse=True)
        
        for rule in sorted_rules:
            if not rule.enabled:
                continue
            
            if self._rule_matches(rule, username, context):
                matched_rules.append(rule.id)
                reasons.append(f"{rule.name}: {rule.description}")
                
                # Update highest action
                if self._action_priority(rule.action) > self._action_priority(highest_action):
                    highest_action = rule.action
                
                # Generate suggestions for certain rule types
                if rule.action == UsernameAction.SUGGEST_ALTERNATIVE:
                    suggestions.extend(self._generate_suggestions(username, rule))
                
                # If we hit a DENY rule, stop processing
                if rule.action == UsernameAction.DENY:
                    break
        
        # Generate additional suggestions if needed
        if highest_action in [UsernameAction.DENY, UsernameAction.SUGGEST_ALTERNATIVE]:
            suggestions.extend(self._generate_general_suggestions(username))
            suggestions = list(set(suggestions))[:self.config["suggestion_count"]]
        
        valid = highest_action == UsernameAction.ALLOW
        
        return UsernameValidationResult(
            valid=valid,
            action=highest_action,
            matched_rules=matched_rules,
            reason="; ".join(reasons) if reasons else "Username is valid",
            suggestions=suggestions
        )
    
    def _rule_matches(self, rule: UsernameRule, username: str, context: Dict[str, Any] = None) -> bool:
        """Check if a rule matches the username."""
        try:
            check_username = username if rule.case_sensitive else username.lower()
            
            if rule.type == RuleType.LENGTH:
                return self._check_length_rule(rule, username)
            elif rule.type == RuleType.PATTERN:
                return not self._check_pattern_rule(rule, check_username)  # Invert for validation
            elif rule.type == RuleType.PROFANITY:
                return self._check_profanity_rule(rule, check_username)
            elif rule.type == RuleType.RESERVED:
                return self._check_reserved_rule(rule, check_username)
            elif rule.type == RuleType.SIMILARITY:
                return self._check_similarity_rule(rule, check_username, context)
            elif rule.type == RuleType.WHITELIST:
                return not self._is_whitelisted(check_username)  # Invert for validation
            elif rule.type == RuleType.BLACKLIST:
                return self._is_blacklisted(check_username)
            elif rule.type == RuleType.CUSTOM:
                return self._check_custom_rule(rule, username, context)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking username rule {rule.id}: {e}")
            return False
    
    def _check_length_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check length-based rules."""
        username_length = len(username)
        
        if rule.pattern.startswith("min:"):
            min_length = int(rule.pattern.split(":")[1])
            return username_length < min_length
        elif rule.pattern.startswith("max:"):
            max_length = int(rule.pattern.split(":")[1])
            return username_length > max_length
        
        return False
    
    def _check_pattern_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check pattern-based rules."""
        if rule.id not in self.compiled_patterns:
            self._compile_pattern(rule)
        
        pattern = self.compiled_patterns.get(rule.id)
        if pattern:
            return bool(pattern.search(username))
        
        return False
    
    def _check_profanity_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check profanity-based rules."""
        return self._check_pattern_rule(rule, username)
    
    def _check_reserved_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check reserved username rules."""
        if rule.pattern == "system_reserved":
            return username.lower() in [name.lower() for name in self.reserved_usernames]
        
        return False
    
    def _check_similarity_rule(self, rule: UsernameRule, username: str, context: Dict[str, Any] = None) -> bool:
        """Check similarity-based rules."""
        # This would check against existing usernames for similarity
        # Placeholder for future implementation
        return False
    
    def _check_custom_rule(self, rule: UsernameRule, username: str, context: Dict[str, Any] = None) -> bool:
        """Check custom rules."""
        # Placeholder for custom rule execution
        return False
    
    def _is_whitelisted(self, username: str) -> bool:
        """Check if username is whitelisted."""
        check_list = [name.lower() for name in self.whitelist] if not self.config["case_sensitive"] else self.whitelist
        check_username = username.lower() if not self.config["case_sensitive"] else username
        return check_username in check_list
    
    def _is_blacklisted(self, username: str) -> bool:
        """Check if username is blacklisted."""
        check_list = [name.lower() for name in self.blacklist] if not self.config["case_sensitive"] else self.blacklist
        check_username = username.lower() if not self.config["case_sensitive"] else username
        return check_username in check_list
    
    def _generate_suggestions(self, username: str, rule: UsernameRule) -> List[str]:
        """Generate suggestions based on rule type."""
        suggestions = []
        
        if rule.type == RuleType.LENGTH:
            if "min:" in rule.pattern:
                min_length = int(rule.pattern.split(":")[1])
                if len(username) < min_length:
                    # Add numbers or characters to reach minimum
                    for i in range(1, 4):
                        suggestions.append(f"{username}{i}")
                        suggestions.append(f"{username}_user")
            elif "max:" in rule.pattern:
                max_length = int(rule.pattern.split(":")[1])
                if len(username) > max_length:
                    # Truncate username
                    suggestions.append(username[:max_length])
                    suggestions.append(username[:max_length-1] + "1")
        
        elif rule.type == RuleType.PATTERN:
            if "^\d+$" in rule.pattern:  # All numbers
                suggestions.append(f"user_{username}")
                suggestions.append(f"{username}_user")
                suggestions.append(f"player_{username}")
        
        return suggestions
    
    def _generate_general_suggestions(self, username: str) -> List[str]:
        """Generate general username suggestions."""
        suggestions = []
        base_username = re.sub(r'[^a-zA-Z0-9]', '', username)[:15]
        
        if base_username:
            # Add numbers
            for i in range(1, 10):
                suggestions.append(f"{base_username}{i}")
            
            # Add common suffixes
            suffixes = ["_user", "_player", "_gamer", "123", "2024", "_new"]
            for suffix in suffixes:
                suggestion = f"{base_username}{suffix}"
                if len(suggestion) <= self.config["max_length"]:
                    suggestions.append(suggestion)
            
            # Add prefixes
            prefixes = ["user_", "player_", "the_"]
            for prefix in prefixes:
                suggestion = f"{prefix}{base_username}"
                if len(suggestion) <= self.config["max_length"]:
                    suggestions.append(suggestion)
        
        return suggestions[:self.config["suggestion_count"]]
    
    def _compile_pattern(self, rule: UsernameRule):
        """Compile regex pattern for rule."""
        try:
            flags = 0
            if not rule.case_sensitive:
                flags |= re.IGNORECASE
            
            self.compiled_patterns[rule.id] = re.compile(rule.pattern, flags)
            
        except re.error as e:
            logger.error(f"Error compiling pattern for username rule {rule.id}: {e}")
    
    def _action_priority(self, action: UsernameAction) -> int:
        """Get priority level for action."""
        priorities = {
            UsernameAction.ALLOW: 0,
            UsernameAction.SUGGEST_ALTERNATIVE: 1,
            UsernameAction.REQUIRE_APPROVAL: 2,
            UsernameAction.DENY: 3
        }
        return priorities.get(action, 0)
    
    def add_to_whitelist(self, username: str) -> bool:
        """Add username to whitelist."""
        if username not in self.whitelist:
            self.whitelist.append(username)
            self.save_lists()
            logger.info(f"Added {username} to whitelist")
            return True
        return False
    
    def remove_from_whitelist(self, username: str) -> bool:
        """Remove username from whitelist."""
        if username in self.whitelist:
            self.whitelist.remove(username)
            self.save_lists()
            logger.info(f"Removed {username} from whitelist")
            return True
        return False
    
    def add_to_blacklist(self, username: str) -> bool:
        """Add username to blacklist."""
        if username not in self.blacklist:
            self.blacklist.append(username)
            self.save_lists()
            logger.info(f"Added {username} to blacklist")
            return True
        return False
    
    def remove_from_blacklist(self, username: str) -> bool:
        """Remove username from blacklist."""
        if username in self.blacklist:
            self.blacklist.remove(username)
            self.save_lists()
            logger.info(f"Removed {username} from blacklist")
            return True
        return False
    
    def get_lists(self) -> Dict[str, List[str]]:
        """Get all username lists."""
        return {
            "whitelist": self.whitelist.copy(),
            "blacklist": self.blacklist.copy(),
            "reserved": self.reserved_usernames.copy()
        }
    
    def load_config(self):
        """Load username filter configuration."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
            except Exception as e:
                logger.error(f"Error loading username config: {e}")
    
    def save_config(self):
        """Save username filter configuration."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving username config: {e}")
    
    def load_rules(self):
        """Load username rules."""
        if self.rules_file.exists():
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)
                    
                for rule_data in rules_data:
                    rule = UsernameRule(
                        id=rule_data["id"],
                        name=rule_data["name"],
                        description=rule_data["description"],
                        type=RuleType(rule_data["type"]),
                        action=UsernameAction(rule_data["action"]),
                        pattern=rule_data["pattern"],
                        enabled=rule_data.get("enabled", True),
                        case_sensitive=rule_data.get("case_sensitive", False),
                        priority=rule_data.get("priority", 1),
                        tags=rule_data.get("tags", []),
                        created_at=datetime.fromisoformat(rule_data["created_at"]),
                        updated_at=datetime.fromisoformat(rule_data["updated_at"])
                    )
                    
                    self.rules[rule.id] = rule
                    self._compile_pattern(rule)
                    
            except Exception as e:
                logger.error(f"Error loading username rules: {e}")
    
    def save_rules(self):
        """Save username rules."""
        try:
            rules_data = []
            for rule in self.rules.values():
                rule_dict = asdict(rule)
                rule_dict["type"] = rule.type.value
                rule_dict["action"] = rule.action.value
                rule_dict["created_at"] = rule.created_at.isoformat()
                rule_dict["updated_at"] = rule.updated_at.isoformat()
                rules_data.append(rule_dict)
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error saving username rules: {e}")
    
    def load_lists(self):
        """Load username lists."""
        # Load whitelist
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    self.whitelist = json.load(f)
            except Exception as e:
                logger.error(f"Error loading whitelist: {e}")
        
        # Load blacklist
        if self.blacklist_file.exists():
            try:
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    self.blacklist = json.load(f)
            except Exception as e:
                logger.error(f"Error loading blacklist: {e}")
        
        # Load reserved usernames
        if self.reserved_file.exists():
            try:
                with open(self.reserved_file, 'r', encoding='utf-8') as f:
                    self.reserved_usernames = json.load(f)
            except Exception as e:
                logger.error(f"Error loading reserved usernames: {e}")
    
    def save_lists(self):
        """Save username lists."""
        try:
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(self.whitelist, f, indent=2, ensure_ascii=False)
            
            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(self.blacklist, f, indent=2, ensure_ascii=False)
            
            with open(self.reserved_file, 'w', encoding='utf-8') as f:
                json.dump(self.reserved_usernames, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"Error saving username lists: {e}")

"""
Advanced Username Filtering System
Powerful rules-based username validation with whitelist/blacklist and smart rules.
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

logger = logging.getLogger("netlink.filters.username")

class UsernameAction(Enum):
    """Username validation actions."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    SUGGEST_ALTERNATIVE = "suggest_alternative"

class RuleType(Enum):
    """Username rule types."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    PATTERN = "pattern"
    LENGTH = "length"
    PROFANITY = "profanity"
    RESERVED = "reserved"
    SIMILARITY = "similarity"
    CUSTOM = "custom"

@dataclass
class UsernameRule:
    """Username validation rule."""
    id: str
    name: str
    description: str
    type: RuleType
    action: UsernameAction
    pattern: str
    enabled: bool = True
    case_sensitive: bool = False
    priority: int = 1
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
class UsernameValidationResult:
    """Username validation result."""
    valid: bool
    action: UsernameAction
    matched_rules: List[str]
    reason: str
    suggestions: List[str] = None
    score: int = 0

    def __post_init__(self):
        if self.suggestions is None:
            self.suggestions = []

class UsernameFilter:
    """Advanced username filtering and validation system."""

    def __init__(self):
        self.config_dir = Path("config/filters")
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.rules_file = self.config_dir / "username_rules.json"
        self.whitelist_file = self.config_dir / "username_whitelist.json"
        self.blacklist_file = self.config_dir / "username_blacklist.json"
        self.reserved_file = self.config_dir / "reserved_usernames.json"
        self.config_file = self.config_dir / "username_config.json"

        # Rules and lists
        self.rules: Dict[str, UsernameRule] = {}
        self.whitelist: List[str] = []
        self.blacklist: List[str] = []
        self.reserved_usernames: List[str] = []
        self.compiled_patterns: Dict[str, Pattern] = {}

        # Configuration
        self.config = {
            "enabled": True,
            "min_length": 3,
            "max_length": 20,
            "allow_numbers": True,
            "allow_underscores": True,
            "allow_hyphens": True,
            "allow_dots": False,
            "require_letter_start": True,
            "case_sensitive": False,
            "whitelist_override": True,
            "suggestion_count": 5,
            "similarity_threshold": 0.8
        }

        # Load existing data
        self.load_config()
        self.load_rules()
        self.load_lists()

        # Initialize default rules if none exist
        if not self.rules:
            self.create_default_rules()

    def create_default_rules(self):
        """Create default username validation rules."""
        default_rules = [
            # Length rules
            {
                "name": "Minimum Length",
                "description": "Username must be at least 3 characters",
                "type": RuleType.LENGTH,
                "action": UsernameAction.DENY,
                "pattern": "min:3",
                "priority": 10,
                "tags": ["length", "basic"]
            },
            {
                "name": "Maximum Length",
                "description": "Username must not exceed 20 characters",
                "type": RuleType.LENGTH,
                "action": UsernameAction.DENY,
                "pattern": "max:20",
                "priority": 10,
                "tags": ["length", "basic"]
            },

            # Character pattern rules
            {
                "name": "Valid Characters",
                "description": "Username can only contain letters, numbers, underscores, and hyphens",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"^[a-zA-Z0-9_-]+$",
                "priority": 9,
                "tags": ["pattern", "characters"]
            },
            {
                "name": "Must Start with Letter",
                "description": "Username must start with a letter",
                "type": RuleType.PATTERN,
                "action": UsernameAction.DENY,
                "pattern": r"^[a-zA-Z]",
                "priority": 8,
                "tags": ["pattern", "start"]
            },

            # Profanity rules
            {
                "name": "Basic Profanity",
                "description": "Username cannot contain basic profanity",
                "type": RuleType.PROFANITY,
                "action": UsernameAction.DENY,
                "pattern": r"\b(fuck|shit|damn|hell|bitch|ass)\b",
                "priority": 6,
                "tags": ["profanity", "offensive"]
            },

            # Reserved usernames
            {
                "name": "System Reserved",
                "description": "Username cannot be a system reserved word",
                "type": RuleType.RESERVED,
                "action": UsernameAction.DENY,
                "pattern": "system_reserved",
                "priority": 10,
                "tags": ["reserved", "system"]
            }
        ]

        # Default reserved usernames
        self.reserved_usernames = [
            "admin", "administrator", "root", "system", "user", "guest", "test",
            "api", "www", "mail", "email", "support", "help", "info", "contact",
            "about", "home", "index", "login", "logout", "register", "signup",
            "signin", "profile", "account", "settings", "config", "dashboard",
            "moderator", "mod", "staff", "team", "official", "netlink",
            "null", "undefined", "none", "empty", "void", "anonymous", "anon"
        ]

        for rule_data in default_rules:
            rule_id = hashlib.md5(rule_data["name"].encode()).hexdigest()[:8]

            rule = UsernameRule(
                id=rule_id,
                name=rule_data["name"],
                description=rule_data["description"],
                type=rule_data["type"],
                action=rule_data["action"],
                pattern=rule_data["pattern"],
                priority=rule_data["priority"],
                tags=rule_data["tags"]
            )

            self.rules[rule_id] = rule
            self._compile_pattern(rule)

        self.save_rules()
        self.save_lists()
        logger.info(f"Created {len(default_rules)} default username rules")

    def validate_username(self, username: str, context: Dict[str, Any] = None) -> UsernameValidationResult:
        """Validate a username against all rules."""
        if not self.config["enabled"]:
            return UsernameValidationResult(
                valid=True,
                action=UsernameAction.ALLOW,
                matched_rules=[],
                reason="Username validation disabled"
            )

        # Normalize username
        check_username = username if self.config["case_sensitive"] else username.lower()

        # Check whitelist first (if enabled and override is true)
        if self.config["whitelist_override"] and self._is_whitelisted(check_username):
            return UsernameValidationResult(
                valid=True,
                action=UsernameAction.ALLOW,
                matched_rules=["whitelist"],
                reason="Username is whitelisted"
            )

        # Check blacklist
        if self._is_blacklisted(check_username):
            return UsernameValidationResult(
                valid=False,
                action=UsernameAction.DENY,
                matched_rules=["blacklist"],
                reason="Username is blacklisted"
            )

        # Apply rules in priority order
        matched_rules = []
        highest_action = UsernameAction.ALLOW
        reasons = []
        suggestions = []

        # Sort rules by priority (higher priority first)
        sorted_rules = sorted(self.rules.values(), key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if not rule.enabled:
                continue

            if self._rule_matches(rule, username, context):
                matched_rules.append(rule.id)
                reasons.append(f"{rule.name}: {rule.description}")

                # Update highest action
                if self._action_priority(rule.action) > self._action_priority(highest_action):
                    highest_action = rule.action

                # Generate suggestions for certain rule types
                if rule.action == UsernameAction.SUGGEST_ALTERNATIVE:
                    suggestions.extend(self._generate_suggestions(username, rule))

                # If we hit a DENY rule, stop processing
                if rule.action == UsernameAction.DENY:
                    break

        # Generate additional suggestions if needed
        if highest_action in [UsernameAction.DENY, UsernameAction.SUGGEST_ALTERNATIVE]:
            suggestions.extend(self._generate_general_suggestions(username))
            suggestions = list(set(suggestions))[:self.config["suggestion_count"]]

        valid = highest_action == UsernameAction.ALLOW

        return UsernameValidationResult(
            valid=valid,
            action=highest_action,
            matched_rules=matched_rules,
            reason="; ".join(reasons) if reasons else "Username is valid",
            suggestions=suggestions
        )

    def _rule_matches(self, rule: UsernameRule, username: str, context: Dict[str, Any] = None) -> bool:
        """Check if a rule matches the username."""
        try:
            check_username = username if rule.case_sensitive else username.lower()

            if rule.type == RuleType.LENGTH:
                return self._check_length_rule(rule, username)
            elif rule.type == RuleType.PATTERN:
                return not self._check_pattern_rule(rule, check_username)  # Invert for validation
            elif rule.type == RuleType.PROFANITY:
                return self._check_profanity_rule(rule, check_username)
            elif rule.type == RuleType.RESERVED:
                return self._check_reserved_rule(rule, check_username)
            elif rule.type == RuleType.WHITELIST:
                return not self._is_whitelisted(check_username)  # Invert for validation
            elif rule.type == RuleType.BLACKLIST:
                return self._is_blacklisted(check_username)

            return False

        except Exception as e:
            logger.error(f"Error checking username rule {rule.id}: {e}")
            return False

    def _check_length_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check length-based rules."""
        username_length = len(username)

        if rule.pattern.startswith("min:"):
            min_length = int(rule.pattern.split(":")[1])
            return username_length < min_length
        elif rule.pattern.startswith("max:"):
            max_length = int(rule.pattern.split(":")[1])
            return username_length > max_length

        return False

    def _check_pattern_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check pattern-based rules."""
        if rule.id not in self.compiled_patterns:
            self._compile_pattern(rule)

        pattern = self.compiled_patterns.get(rule.id)
        if pattern:
            return bool(pattern.search(username))

        return False

    def _check_profanity_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check profanity-based rules."""
        return self._check_pattern_rule(rule, username)

    def _check_reserved_rule(self, rule: UsernameRule, username: str) -> bool:
        """Check reserved username rules."""
        if rule.pattern == "system_reserved":
            return username.lower() in [name.lower() for name in self.reserved_usernames]

        return False

    def _is_whitelisted(self, username: str) -> bool:
        """Check if username is whitelisted."""
        check_list = [name.lower() for name in self.whitelist] if not self.config["case_sensitive"] else self.whitelist
        check_username = username.lower() if not self.config["case_sensitive"] else username
        return check_username in check_list

    def _is_blacklisted(self, username: str) -> bool:
        """Check if username is blacklisted."""
        check_list = [name.lower() for name in self.blacklist] if not self.config["case_sensitive"] else self.blacklist
        check_username = username.lower() if not self.config["case_sensitive"] else username
        return check_username in check_list

    def _generate_suggestions(self, username: str, rule: UsernameRule) -> List[str]:
        """Generate suggestions based on rule type."""
        suggestions = []

        if rule.type == RuleType.LENGTH:
            if "min:" in rule.pattern:
                min_length = int(rule.pattern.split(":")[1])
                if len(username) < min_length:
                    # Add numbers or characters to reach minimum
                    for i in range(1, 4):
                        suggestions.append(f"{username}{i}")
                        suggestions.append(f"{username}_user")

        return suggestions

    def _generate_general_suggestions(self, username: str) -> List[str]:
        """Generate general username suggestions."""
        suggestions = []
        base_username = re.sub(r'[^a-zA-Z0-9]', '', username)[:15]

        if base_username:
            # Add numbers
            for i in range(1, 10):
                suggestions.append(f"{base_username}{i}")

            # Add common suffixes
            suffixes = ["_user", "_player", "_gamer", "123", "2024", "_new"]
            for suffix in suffixes:
                suggestion = f"{base_username}{suffix}"
                if len(suggestion) <= self.config["max_length"]:
                    suggestions.append(suggestion)

        return suggestions[:self.config["suggestion_count"]]

    def _compile_pattern(self, rule: UsernameRule):
        """Compile regex pattern for rule."""
        try:
            flags = 0
            if not rule.case_sensitive:
                flags |= re.IGNORECASE

            self.compiled_patterns[rule.id] = re.compile(rule.pattern, flags)

        except re.error as e:
            logger.error(f"Error compiling pattern for username rule {rule.id}: {e}")

    def _action_priority(self, action: UsernameAction) -> int:
        """Get priority level for action."""
        priorities = {
            UsernameAction.ALLOW: 0,
            UsernameAction.SUGGEST_ALTERNATIVE: 1,
            UsernameAction.REQUIRE_APPROVAL: 2,
            UsernameAction.DENY: 3
        }
        return priorities.get(action, 0)

    def add_to_whitelist(self, username: str) -> bool:
        """Add username to whitelist."""
        if username not in self.whitelist:
            self.whitelist.append(username)
            self.save_lists()
            logger.info(f"Added {username} to whitelist")
            return True
        return False

    def remove_from_whitelist(self, username: str) -> bool:
        """Remove username from whitelist."""
        if username in self.whitelist:
            self.whitelist.remove(username)
            self.save_lists()
            logger.info(f"Removed {username} from whitelist")
            return True
        return False

    def add_to_blacklist(self, username: str) -> bool:
        """Add username to blacklist."""
        if username not in self.blacklist:
            self.blacklist.append(username)
            self.save_lists()
            logger.info(f"Added {username} to blacklist")
            return True
        return False

    def remove_from_blacklist(self, username: str) -> bool:
        """Remove username from blacklist."""
        if username in self.blacklist:
            self.blacklist.remove(username)
            self.save_lists()
            logger.info(f"Removed {username} from blacklist")
            return True
        return False

    def get_lists(self) -> Dict[str, List[str]]:
        """Get all username lists."""
        return {
            "whitelist": self.whitelist.copy(),
            "blacklist": self.blacklist.copy(),
            "reserved": self.reserved_usernames.copy()
        }

    def load_config(self):
        """Load username filter configuration."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
            except Exception as e:
                logger.error(f"Error loading username config: {e}")

    def save_config(self):
        """Save username filter configuration."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving username config: {e}")

    def load_rules(self):
        """Load username rules."""
        if self.rules_file.exists():
            try:
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)

                for rule_data in rules_data:
                    rule = UsernameRule(
                        id=rule_data["id"],
                        name=rule_data["name"],
                        description=rule_data["description"],
                        type=RuleType(rule_data["type"]),
                        action=UsernameAction(rule_data["action"]),
                        pattern=rule_data["pattern"],
                        enabled=rule_data.get("enabled", True),
                        case_sensitive=rule_data.get("case_sensitive", False),
                        priority=rule_data.get("priority", 1),
                        tags=rule_data.get("tags", []),
                        created_at=datetime.fromisoformat(rule_data["created_at"]),
                        updated_at=datetime.fromisoformat(rule_data["updated_at"])
                    )

                    self.rules[rule.id] = rule
                    self._compile_pattern(rule)

            except Exception as e:
                logger.error(f"Error loading username rules: {e}")

    def save_rules(self):
        """Save username rules."""
        try:
            rules_data = []
            for rule in self.rules.values():
                rule_dict = asdict(rule)
                rule_dict["type"] = rule.type.value
                rule_dict["action"] = rule.action.value
                rule_dict["created_at"] = rule.created_at.isoformat()
                rule_dict["updated_at"] = rule.updated_at.isoformat()
                rules_data.append(rule_dict)

            with open(self.rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Error saving username rules: {e}")

    def load_lists(self):
        """Load username lists."""
        # Load whitelist
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    self.whitelist = json.load(f)
            except Exception as e:
                logger.error(f"Error loading whitelist: {e}")

        # Load blacklist
        if self.blacklist_file.exists():
            try:
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    self.blacklist = json.load(f)
            except Exception as e:
                logger.error(f"Error loading blacklist: {e}")

        # Load reserved usernames
        if self.reserved_file.exists():
            try:
                with open(self.reserved_file, 'r', encoding='utf-8') as f:
                    self.reserved_usernames = json.load(f)
            except Exception as e:
                logger.error(f"Error loading reserved usernames: {e}")

    def save_lists(self):
        """Save username lists."""
        try:
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(self.whitelist, f, indent=2, ensure_ascii=False)

            with open(self.blacklist_file, 'w', encoding='utf-8') as f:
                json.dump(self.blacklist, f, indent=2, ensure_ascii=False)

            with open(self.reserved_file, 'w', encoding='utf-8') as f:
                json.dump(self.reserved_usernames, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Error saving username lists: {e}")

# Global username filter instance
username_filter = UsernameFilter()
