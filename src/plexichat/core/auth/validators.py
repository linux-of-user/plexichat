"""
NetLink Authentication Validators

Validation utilities for passwords, tokens, and authentication data.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Validation result."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    score: Optional[float] = None


class PasswordValidator:
    """Password strength and policy validator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Default password requirements
        self.min_length = self.config.get("min_length", 12)
        self.require_uppercase = self.config.get("require_uppercase", True)
        self.require_lowercase = self.config.get("require_lowercase", True)
        self.require_numbers = self.config.get("require_numbers", True)
        self.require_symbols = self.config.get("require_symbols", True)
        self.prevent_common_passwords = self.config.get("prevent_common_passwords", True)
        self.prevent_personal_info = self.config.get("prevent_personal_info", True)
        
        # Common passwords list (simplified)
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        }
    
    def validate_password(self, password: str, user_info: Dict[str, Any] = None) -> ValidationResult:
        """
        Validate password against policy requirements.
        
        Args:
            password: Password to validate
            user_info: User information for personal info checking
            
        Returns:
            ValidationResult: Validation result with errors and score
        """
        errors = []
        warnings = []
        score = 0.0
        
        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        else:
            score += min(len(password) / self.min_length, 2.0) * 20
        
        # Character requirements
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        elif re.search(r'[A-Z]', password):
            score += 15
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        elif re.search(r'[a-z]', password):
            score += 15
        
        if self.require_numbers and not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one number")
        elif re.search(r'[0-9]', password):
            score += 15
        
        if self.require_symbols and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        elif re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        
        # Common password check
        if self.prevent_common_passwords and password.lower() in self.common_passwords:
            errors.append("Password is too common")
        
        # Personal information check
        if self.prevent_personal_info and user_info:
            personal_info = [
                user_info.get("username", "").lower(),
                user_info.get("email", "").lower().split("@")[0],
                user_info.get("first_name", "").lower(),
                user_info.get("last_name", "").lower()
            ]
            
            for info in personal_info:
                if info and len(info) > 2 and info in password.lower():
                    errors.append("Password should not contain personal information")
                    break
        
        # Complexity bonus
        unique_chars = len(set(password))
        if unique_chars > len(password) * 0.7:
            score += 10
        
        # Pattern penalties
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            warnings.append("Avoid repeating characters")
            score -= 5
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):  # Sequential numbers
            warnings.append("Avoid sequential numbers")
            score -= 5
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):  # Sequential letters
            warnings.append("Avoid sequential letters")
            score -= 5
        
        # Normalize score
        score = max(0, min(100, score))
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            score=score
        )
    
    def get_password_strength(self, score: float) -> str:
        """Get password strength description."""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def suggest_improvements(self, password: str) -> List[str]:
        """Suggest password improvements."""
        suggestions = []
        
        if len(password) < self.min_length:
            suggestions.append(f"Make it at least {self.min_length} characters long")
        
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'[0-9]', password):
            suggestions.append("Add numbers")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Add special characters")
        
        if password.lower() in self.common_passwords:
            suggestions.append("Use a more unique password")
        
        return suggestions


class TokenValidator:
    """JWT token validator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
    
    def validate_token_format(self, token: str) -> ValidationResult:
        """Validate JWT token format."""
        errors = []
        warnings = []
        
        if not token:
            errors.append("Token is empty")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)
        
        # Check JWT format (header.payload.signature)
        parts = token.split('.')
        if len(parts) != 3:
            errors.append("Invalid JWT format")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)
        
        # Check base64 encoding
        import base64
        try:
            for i, part in enumerate(parts[:2]):  # Don't decode signature
                # Add padding if needed
                padded = part + '=' * (4 - len(part) % 4)
                base64.urlsafe_b64decode(padded)
        except Exception:
            errors.append("Invalid base64 encoding")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_token_claims(self, claims: Dict[str, Any]) -> ValidationResult:
        """Validate JWT token claims."""
        errors = []
        warnings = []
        
        # Required claims
        required_claims = ["sub", "iat", "exp", "jti"]
        for claim in required_claims:
            if claim not in claims:
                errors.append(f"Missing required claim: {claim}")
        
        # Expiration check
        if "exp" in claims:
            import time
            if claims["exp"] < time.time():
                errors.append("Token has expired")
        
        # Issued at check
        if "iat" in claims:
            import time
            if claims["iat"] > time.time() + 60:  # Allow 1 minute clock skew
                warnings.append("Token issued in the future")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )


class BiometricValidator:
    """Biometric data validator."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.min_quality_score = self.config.get("min_quality_score", 0.8)
    
    def validate_biometric_data(self, biometric_data: bytes, biometric_type: str) -> ValidationResult:
        """Validate biometric data."""
        errors = []
        warnings = []
        
        if not biometric_data:
            errors.append("Biometric data is empty")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)
        
        # Type-specific validation
        if biometric_type == "fingerprint":
            return self._validate_fingerprint(biometric_data)
        elif biometric_type == "face":
            return self._validate_face(biometric_data)
        elif biometric_type == "voice":
            return self._validate_voice(biometric_data)
        else:
            errors.append(f"Unsupported biometric type: {biometric_type}")
        
        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def _validate_fingerprint(self, data: bytes) -> ValidationResult:
        """Validate fingerprint data."""
        # Mock implementation
        return ValidationResult(valid=True, errors=[], warnings=[])
    
    def _validate_face(self, data: bytes) -> ValidationResult:
        """Validate face recognition data."""
        # Mock implementation
        return ValidationResult(valid=True, errors=[], warnings=[])
    
    def _validate_voice(self, data: bytes) -> ValidationResult:
        """Validate voice recognition data."""
        # Mock implementation
        return ValidationResult(valid=True, errors=[], warnings=[])
