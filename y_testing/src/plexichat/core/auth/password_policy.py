#!/usr/bin/env python3
"""
import logging
import time
import warnings
Password Policy Manager

Implements comprehensive password policies including:
- Complexity requirements
- Password history
- Expiration policies
- Breach detection
- Strength scoring
"""

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

from plexichat.core.logging.unified_logging_manager import get_logger

logger = get_logger(__name__)


class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 1
    WEAK = 2
    FAIR = 3
    GOOD = 4
    STRONG = 5
    VERY_STRONG = 6


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_repeated_chars: int = 3
    max_sequential_chars: int = 3
    min_unique_chars: int = 4
    password_history_count: int = 12
    password_expiry_days: int = 90
    password_warning_days: int = 14
    check_common_passwords: bool = True
    check_breach_databases: bool = True
    min_strength_score: int = 3


@dataclass
class PasswordValidationResult:
    """Result of password validation."""
    is_valid: bool
    strength: PasswordStrength
    score: int
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class PasswordHistory:
    """Password history entry."""
    password_hash: str
    created_at: datetime
    salt: str


class PasswordPolicyManager:
    """Password policy manager."""

    def __init__(self, policy: Optional[PasswordPolicy] = None):
        self.policy = policy or PasswordPolicy()
        self.password_histories: Dict[str, List[PasswordHistory]] = {}

        # Load common passwords list
        self.common_passwords = self._load_common_passwords()

        # Load breach database hashes (placeholder)
        self.breach_hashes: Set[str] = set()

    def validate_password(self, password: str, user_id: str = None) -> PasswordValidationResult:
        """Validate password against policy."""
        errors = []
        warnings = []
        suggestions = []

        # Length checks
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters long")
            suggestions.append(f"Add {self.policy.min_length - len(password)} more characters")

        if len(password) > self.policy.max_length:
            errors.append(f"Password must not exceed {self.policy.max_length} characters")

        # Character type requirements
        if self.policy.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
            suggestions.append("Add an uppercase letter (A-Z)")

        if self.policy.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
            suggestions.append("Add a lowercase letter (a-z)")

        if self.policy.require_digits and not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one digit")
            suggestions.append("Add a number (0-9)")

        if self.policy.require_special_chars:
            special_pattern = f'[{re.escape(self.policy.special_chars)}]'
            if not re.search(special_pattern, password):
                errors.append("Password must contain at least one special character")
                suggestions.append(f"Add a special character ({self.policy.special_chars[:10]}...)")

        # Repeated characters check
        if self._has_too_many_repeated_chars(password):
            errors.append(f"Password cannot have more than {self.policy.max_repeated_chars} repeated characters")
            suggestions.append("Avoid repeating the same character too many times")

        # Sequential characters check
        if self._has_sequential_chars(password):
            errors.append(f"Password cannot contain sequential characters (abc, 123, etc.)")
            suggestions.append("Avoid sequential characters like 'abc' or '123'")

        # Unique characters check
        unique_chars = len(set(password.lower()))
        if unique_chars < self.policy.min_unique_chars:
            errors.append(f"Password must contain at least {self.policy.min_unique_chars} unique characters")
            suggestions.append(f"Add {self.policy.min_unique_chars - unique_chars} more unique characters")

        # Common password check
        if self.policy.check_common_passwords and self._is_common_password(password):
            errors.append("Password is too common and easily guessable")
            suggestions.append("Choose a more unique password")

        # Breach database check
        if self.policy.check_breach_databases and self._is_breached_password(password):
            errors.append("Password has been found in data breaches")
            suggestions.append("Choose a password that hasn't been compromised")

        # Password history check
        if user_id and self._is_in_password_history(password, user_id):
            errors.append("Password has been used recently")
            suggestions.append("Choose a password you haven't used before")

        # Calculate strength and score
        strength, score = self._calculate_password_strength(password)

        # Check minimum strength requirement
        if score < self.policy.min_strength_score:
            errors.append(f"Password strength is too low (score: {score}, required: {self.policy.min_strength_score})")
            suggestions.append("Make your password longer and more complex")

        # Additional warnings
        if len(password) < 12:
            warnings.append("Consider using a longer password for better security")

        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            warnings.append("Consider adding special characters for better security")

        is_valid = len(errors) == 0

        return PasswordValidationResult(
            is_valid=is_valid,
            strength=strength,
            score=score,
            errors=errors,
            warnings=warnings,
            suggestions=suggestions
        )

    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure password that meets policy requirements."""
        if length < self.policy.min_length:
            length = self.policy.min_length
        if length > self.policy.max_length:
            length = self.policy.max_length

        # Character sets
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        special = self.policy.special_chars

        # Ensure at least one character from each required set
        password_chars = []

        if self.policy.require_lowercase:
            password_chars.append(secrets.choice(lowercase))
        if self.policy.require_uppercase:
            password_chars.append(secrets.choice(uppercase))
        if self.policy.require_digits:
            password_chars.append(secrets.choice(digits))
        if self.policy.require_special_chars:
            password_chars.append(secrets.choice(special))

        # Fill remaining length with random characters from all sets
        all_chars = lowercase
        if self.policy.require_uppercase:
            all_chars += uppercase
        if self.policy.require_digits:
            all_chars += digits
        if self.policy.require_special_chars:
            all_chars += special

        for _ in range(length - len(password_chars)):
            password_chars.append(secrets.choice(all_chars))

        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def add_to_password_history(self, user_id: str, password: str):
        """Add password to user's history."""
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)

        if user_id not in self.password_histories:
            self.password_histories[user_id] = []

        history_entry = PasswordHistory(
            password_hash=password_hash,
            created_at=datetime.now(),
            salt=salt
        )

        self.password_histories[user_id].append(history_entry)

        # Keep only the required number of history entries
        if len(self.password_histories[user_id]) > self.policy.password_history_count:
            self.password_histories[user_id] = self.password_histories[user_id][-self.policy.password_history_count:]

    def is_password_expired(self, user_id: str, password_created_at: datetime) -> bool:
        """Check if password has expired."""
        if self.policy.password_expiry_days <= 0:
            return False

        expiry_date = password_created_at + timedelta(days=self.policy.password_expiry_days)
        return datetime.now() > expiry_date

    def get_password_expiry_warning(self, user_id: str, password_created_at: datetime) -> Optional[str]:
        """Get password expiry warning if applicable."""
        if self.policy.password_expiry_days <= 0:
            return None

        expiry_date = password_created_at + timedelta(days=self.policy.password_expiry_days)
        warning_date = expiry_date - timedelta(days=self.policy.password_warning_days)

        if datetime.now() >= warning_date:
            days_until_expiry = (expiry_date - datetime.now()).days
            if days_until_expiry <= 0:
                return "Your password has expired and must be changed"
            else:
                return f"Your password will expire in {days_until_expiry} days"

        return None

    def _calculate_password_strength(self, password: str) -> Tuple[PasswordStrength, int]:
        """Calculate password strength and score."""
        score = 0

        # Length scoring
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if len(password) >= 20:
            score += 1

        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[0-9]', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 1

        # Complexity scoring
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:  # 70% unique characters
            score += 1

        # Entropy scoring (simplified)
        if not self._has_too_many_repeated_chars(password):
            score += 1
        if not self._has_sequential_chars(password):
            score += 1
        if not self._is_common_password(password):
            score += 1

        # Convert score to strength enum
        if score <= 2:
            strength = PasswordStrength.VERY_WEAK
        elif score <= 4:
            strength = PasswordStrength.WEAK
        elif score <= 6:
            strength = PasswordStrength.FAIR
        elif score <= 8:
            strength = PasswordStrength.GOOD
        elif score <= 10:
            strength = PasswordStrength.STRONG
        else:
            strength = PasswordStrength.VERY_STRONG

        return strength, score

    def _has_too_many_repeated_chars(self, password: str) -> bool:
        """Check for too many repeated characters."""
        for i in range(len(password) - self.policy.max_repeated_chars):
            if len(set(password[i:i + self.policy.max_repeated_chars + 1])) == 1:
                return True
        return False

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters."""
        sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]

        password_lower = password.lower()

        for seq in sequences:
            for i in range(len(seq) - self.policy.max_sequential_chars):
                subseq = seq[i:i + self.policy.max_sequential_chars + 1]
                if subseq in password_lower or subseq[::-1] in password_lower:
                    return True

        return False

    def _is_common_password(self, password: str) -> bool:
        """Check if password is in common passwords list."""
        return password.lower() in self.common_passwords

    def _is_breached_password(self, password: str) -> bool:
        """Check if password is in breach database."""
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        return password_hash in self.breach_hashes

    def _is_in_password_history(self, password: str, user_id: str) -> bool:
        """Check if password is in user's history."""
        if user_id not in self.password_histories:
            return False

        for history_entry in self.password_histories[user_id]:
            if self._verify_password(password, history_entry.password_hash, history_entry.salt):
                return True

        return False

    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt."""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()

    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash."""
        return self._hash_password(password, salt) == password_hash

    def _load_common_passwords(self) -> Set[str]:
        """Load common passwords list."""
        # In production, load from a file containing common passwords
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman', 'michael',
            'football', 'baseball', 'liverpool', 'jordan', 'princess',
            'charlie', 'aa123456', 'donald', 'password1', 'qwerty123'
        }

        return common_passwords


# Global password policy manager
password_policy_manager = PasswordPolicyManager()


def get_password_policy_manager() -> PasswordPolicyManager:
    """Get the global password policy manager."""
    return password_policy_manager
