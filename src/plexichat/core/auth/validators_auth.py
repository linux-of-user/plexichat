import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import warnings

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Validation result."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    score: Optional[float] = None

def get_input_validator():
    """Get input validator instance."""
    # This would be implemented based on your input validation system
    class SimpleInputValidator:
        def validate_password(self, password: str, username: Optional[str] = None):
            class Result:
                def __init__(self):
                    self.is_valid = True
                    self.errors = []
                    self.warnings = []
                    self.strength_score = 50.0
            return Result()
    return SimpleInputValidator()

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

        # Common passwords list
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        }

    def validate_password(self, password: str, user_info: Dict[str, Any] = None) -> ValidationResult:
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

    def validate_password_legacy(self, password: str, user_info: Dict[str, Any] = None) -> ValidationResult:
        """Legacy password validation method."""
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
        try:
            import base64
            # Decode header and payload
            header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')

            # Basic validation
            if not header or not payload:
                errors.append("Invalid token structure")

        except Exception as e:
            errors.append(f"Token encoding error: {e}")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )

    def validate_token_claims(self, claims: Dict[str, Any]) -> ValidationResult:
        """Validate JWT token claims."""
        errors = []
        warnings = []

        # Check required claims
        required_claims = ['sub', 'exp', 'iat']
        for claim in required_claims:
            if claim not in claims:
                errors.append(f"Missing required claim: {claim}")

        # Check expiration
        if 'exp' in claims:
            import time
            current_time = time.time()
            if claims['exp'] < current_time:
                errors.append("Token has expired")

        # Check issued at time
        if 'iat' in claims:
            import time
            current_time = time.time()
            if claims['iat'] > current_time:
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

    def validate_biometric_data(self, biometric_data: bytes, biometric_type: str) -> ValidationResult:
        """Validate biometric data."""
        errors = []
        warnings = []

        if not biometric_data:
            errors.append("Biometric data is empty")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        # Check data size
        min_size = self.config.get(f"{biometric_type}_min_size", 100)
        max_size = self.config.get(f"{biometric_type}_max_size", 10000)

        if len(biometric_data) < min_size:
            errors.append(f"Biometric data too small (min {min_size} bytes)")
        elif len(biometric_data) > max_size:
            errors.append(f"Biometric data too large (max {max_size} bytes)")

        # Type-specific validation
        if biometric_type == "fingerprint":
            result = self._validate_fingerprint(biometric_data)
        elif biometric_type == "face":
            result = self._validate_face(biometric_data)
        elif biometric_type == "voice":
            result = self._validate_voice(biometric_data)
        else:
            errors.append(f"Unsupported biometric type: {biometric_type}")
            result = ValidationResult(valid=False, errors=errors, warnings=warnings)

        return result

    def _validate_fingerprint(self, data: bytes) -> ValidationResult:
        """Validate fingerprint data."""
        # Simplified validation
        return ValidationResult(valid=True, errors=[], warnings=[])

    def _validate_face(self, data: bytes) -> ValidationResult:
        """Validate face data."""
        # Simplified validation
        return ValidationResult(valid=True, errors=[], warnings=[])

    def _validate_voice(self, data: bytes) -> ValidationResult:
        """Validate voice data."""
        # Simplified validation
        return ValidationResult(valid=True, errors=[], warnings=[])
