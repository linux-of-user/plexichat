"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Password Policy Configuration
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class PasswordComplexityLevel(Enum):
    """Password complexity levels."""

    BASIC = "basic"
    STANDARD = "standard"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class PasswordPolicyConfig:
    """Password policy configuration with validation rules."""

    # Basic requirements
    min_length: int = 12
    max_length: int = 128

    # Character requirements
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1

    # Complexity settings
    prevent_common_passwords: bool = True
    prevent_personal_info: bool = True
    complexity_score_threshold: int = 60

    # History and aging
    enable_history_check: bool = True
    password_history_count: int = 5
    max_age_days: int = 90
    min_age_hours: int = 24

    # Additional rules
    prevent_dictionary_words: bool = True
    prevent_sequential_patterns: bool = True
    prevent_repeated_chars: bool = True
    max_repeated_chars: int = 3

    # Custom rules
    custom_rules: Dict[str, Any] = None

    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.custom_rules is None:
            self.custom_rules = {}
        self._validate_configuration()

    def _validate_configuration(self):
        """Validate password policy configuration."""
        if self.min_length < 8:
            raise ValueError("Minimum password length must be at least 8 characters")
        if self.max_length < self.min_length:
            raise ValueError("Maximum password length must be greater than minimum")
        if self.complexity_score_threshold < 0 or self.complexity_score_threshold > 100:
            raise ValueError("Complexity score threshold must be between 0 and 100")
        if self.password_history_count < 0:
            raise ValueError("Password history count cannot be negative")
        if self.max_repeated_chars < 1:
            raise ValueError("Max repeated characters must be at least 1")

    @classmethod
    def from_complexity_level(
        cls, level: PasswordComplexityLevel
    ) -> "PasswordPolicyConfig":
        """Create policy configuration from complexity level."""
        base_configs = {
            PasswordComplexityLevel.BASIC: cls(
                min_length=8,
                require_uppercase=False,
                require_special_chars=False,
                complexity_score_threshold=30,
                prevent_common_passwords=False,
                prevent_dictionary_words=False,
            ),
            PasswordComplexityLevel.STANDARD: cls(
                min_length=10,
                require_uppercase=True,
                require_lowercase=True,
                require_numbers=True,
                require_special_chars=False,
                complexity_score_threshold=50,
            ),
            PasswordComplexityLevel.STRONG: cls(
                min_length=12,
                require_uppercase=True,
                require_lowercase=True,
                require_numbers=True,
                require_special_chars=True,
                min_special_chars=1,
                complexity_score_threshold=70,
            ),
            PasswordComplexityLevel.VERY_STRONG: cls(
                min_length=16,
                require_uppercase=True,
                require_lowercase=True,
                require_numbers=True,
                require_special_chars=True,
                min_special_chars=2,
                complexity_score_threshold=85,
                prevent_dictionary_words=True,
                prevent_sequential_patterns=True,
                prevent_repeated_chars=True,
                max_repeated_chars=2,
            ),
        }
        return base_configs[level]

    def get_requirements_description(self) -> List[str]:
        """Get human-readable list of password requirements."""
        requirements = []

        requirements.append(
            f"Password must be between {self.min_length} and {self.max_length} characters long"
        )

        if self.require_uppercase:
            requirements.append("Must contain at least one uppercase letter")
        if self.require_lowercase:
            requirements.append("Must contain at least one lowercase letter")
        if self.require_numbers:
            requirements.append("Must contain at least one number")
        if self.require_special_chars:
            requirements.append(
                f"Must contain at least {self.min_special_chars} special character(s)"
            )
        if self.prevent_common_passwords:
            requirements.append("Cannot be a common password")
        if self.prevent_personal_info:
            requirements.append("Cannot contain personal information")
        if self.prevent_dictionary_words:
            requirements.append("Cannot contain dictionary words")
        if self.prevent_sequential_patterns:
            requirements.append("Cannot contain sequential patterns (abc, 123, etc.)")
        if self.prevent_repeated_chars:
            requirements.append(
                f"Cannot have more than {self.max_repeated_chars} repeated characters"
            )

        return requirements

    def calculate_complexity_score(self, password: str) -> int:
        """Calculate password complexity score (0-100)."""
        score = 0

        # Length bonus
        score += min(len(password) * 2, 25)

        # Character variety
        if self.require_uppercase and any(c.isupper() for c in password):
            score += 10
        if self.require_lowercase and any(c.islower() for c in password):
            score += 10
        if self.require_numbers and any(c.isdigit() for c in password):
            score += 10
        if self.require_special_chars and any(not c.isalnum() for c in password):
            score += 15

        # Pattern penalties
        if self.prevent_repeated_chars:
            # Check for repeated characters
            for i in range(len(password) - self.max_repeated_chars + 1):
                if len(set(password[i : i + self.max_repeated_chars])) == 1:
                    score -= 10
                    break

        if self.prevent_sequential_patterns:
            # Check for sequential patterns
            sequential_patterns = [
                "abcdefghijklmnopqrstuvwxyz",
                "0123456789",
                "qwertyuiop",
                "asdfghjkl",
                "zxcvbnm",
            ]
            password_lower = password.lower()
            for pattern in sequential_patterns:
                for i in range(len(pattern) - 2):
                    if pattern[i : i + 3] in password_lower:
                        score -= 10
                        break

        return max(0, min(score, 100))

    def is_password_complex_enough(self, password: str) -> bool:
        """Check if password meets complexity requirements."""
        return (
            self.calculate_complexity_score(password) >= self.complexity_score_threshold
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "min_length": self.min_length,
            "max_length": self.max_length,
            "require_uppercase": self.require_uppercase,
            "require_lowercase": self.require_lowercase,
            "require_numbers": self.require_numbers,
            "require_special_chars": self.require_special_chars,
            "min_special_chars": self.min_special_chars,
            "prevent_common_passwords": self.prevent_common_passwords,
            "prevent_personal_info": self.prevent_personal_info,
            "complexity_score_threshold": self.complexity_score_threshold,
            "enable_history_check": self.enable_history_check,
            "password_history_count": self.password_history_count,
            "max_age_days": self.max_age_days,
            "min_age_hours": self.min_age_hours,
            "prevent_dictionary_words": self.prevent_dictionary_words,
            "prevent_sequential_patterns": self.prevent_sequential_patterns,
            "prevent_repeated_chars": self.prevent_repeated_chars,
            "max_repeated_chars": self.max_repeated_chars,
            "custom_rules": self.custom_rules,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordPolicyConfig":
        """Create configuration from dictionary."""
        return cls(**data)


__all__ = ["PasswordComplexityLevel", "PasswordPolicyConfig"]
