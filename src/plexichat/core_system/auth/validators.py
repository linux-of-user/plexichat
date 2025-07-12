"""
PlexiChat Authentication Validators

ENHANCED to integrate with unified input validation framework.
Provides specialized validation for authentication-specific data.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# Import unified input validation
from ..security.input_validation import get_input_validator, InputType, ValidationLevel

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Validation result."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    score: Optional[float] = None


class PasswordValidator:
    """Password strength and policy validator - Enhanced with unified validation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.input_validator = get_input_validator()

        # Legacy compatibility - these are now handled by unified validator
        self.min_length = self.config.get("min_length", 12)
        self.require_uppercase = self.config.get("require_uppercase", True)
        self.require_lowercase = self.config.get("require_lowercase", True)
        self.require_numbers = self.config.get("require_numbers", True)
        self.require_symbols = self.config.get("require_symbols", True)
        self.prevent_common_passwords = self.config.get("prevent_common_passwords", True)
        self.prevent_personal_info = self.config.get("prevent_personal_info", True)

        # Common passwords list for validation
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty", "letmein",
            "welcome", "monkey", "1234567890", "abc123", "111111", "123123",
            "password1", "1234", "12345", "dragon", "master", "login"
        }
    
    def validate_password(self, password: str, user_info: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Validate password against policy requirements using unified validator.

        Args:
            password: Password to validate
            user_info: User information for personal info checking

        Returns:
            ValidationResult: Validation result with errors and score
        """
        try:
            # Extract username for unified validator
            username = None
            if user_info:
                username = user_info.get("username")

            # Use unified input validator for comprehensive password validation
            password_result = self.input_validator.validate_password(password, username)

            # Convert to legacy ValidationResult format for compatibility
            return ValidationResult(
                valid=password_result.is_valid,
                errors=password_result.errors,
                warnings=password_result.warnings,
                score=password_result.strength_score
            )

        except Exception as e:
            logger.error(f"Password validation error: {e}")
            return ValidationResult(
                valid=False,
                errors=[f"Password validation failed: {e}"],
                warnings=[],
                score=0.0
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
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
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
            for _, part in enumerate(parts[:2]):  # Don't decode signature
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
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
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
        # Mock implementation - data parameter is for future use
        _ = data  # Acknowledge parameter to avoid unused warning
        return ValidationResult(valid=True, errors=[], warnings=[])

    def _validate_face(self, data: bytes) -> ValidationResult:
        """Validate face recognition data."""
        # Mock implementation - data parameter is for future use
        _ = data  # Acknowledge parameter to avoid unused warning
        return ValidationResult(valid=True, errors=[], warnings=[])

    def _validate_voice(self, data: bytes) -> ValidationResult:
        """Validate voice recognition data."""
        # Mock implementation - data parameter is for future use
        _ = data  # Acknowledge parameter to avoid unused warning
        return ValidationResult(valid=True, errors=[], warnings=[])
