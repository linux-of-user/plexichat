# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import html
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ...core.config import get_config
from ...core.logging import get_logger

from pathlib import Path

from pathlib import Path

"""
PlexiChat Unified Input Validation Framework - SINGLE SOURCE OF TRUTH

CONSOLIDATED from multiple input validation systems:
- features/security/input_sanitizer.py - REMOVED
- features/security/core/input_sanitization.py - REMOVED
- features/security/validators.py - REMOVED
- core_system/auth/validators.py - ENHANCED AND INTEGRATED

Features:
- Comprehensive input sanitization and validation
- Multi-level security policies (basic, standard, strict, paranoid)
- Type-specific validation (text, HTML, email, URL, JSON, etc.)
- SQL injection and XSS prevention
- Path traversal protection
- Command injection detection
- Password strength validation
- Token and authentication data validation
- Biometric data validation
- Universal API entry point validation
"""

logger = get_logger(__name__)


class InputType(Enum):
    """Input data types for validation."""
    TEXT = "text"
    HTML = "html"
    EMAIL = "email"
    URL = "url"
    USERNAME = "username"
    PASSWORD = "password"
    FILENAME = "filename"
    PATH = "path"
    JSON = "json"
    XML = "xml"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    SQL_QUERY = "sql_query"
    COMMAND = "command"
    TOKEN = "token"
    BIOMETRIC = "biometric"


class ValidationLevel(Enum):
    """Validation security levels."""
    BASIC = 1      # Basic checks only
    STANDARD = 2   # Standard security
    STRICT = 3     # High security
    PARANOID = 4   # Maximum security


class ThreatType(Enum):
    """Types of detected threats."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    MALICIOUS_CONTENT = "malicious_content"
    INVALID_FORMAT = "invalid_format"
    EXCESSIVE_LENGTH = "excessive_length"
    SUSPICIOUS_PATTERN = "suspicious_pattern"


@dataclass
class ValidationResult:
    """Comprehensive validation result."""
    original_value: Any
    sanitized_value: Any
    is_valid: bool
    is_safe: bool
    confidence_score: float = 0.0
    threats_detected: List[ThreatType] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    applied_rules: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original_value": str(self.original_value),
            "sanitized_value": str(self.sanitized_value),
            "is_valid": self.is_valid,
            "is_safe": self.is_safe,
            "confidence_score": self.confidence_score,
            "threats_detected": [t.value for t in self.threats_detected],
            "warnings": self.warnings,
            "errors": self.errors,
            "applied_rules": self.applied_rules,
            "processing_time_ms": self.processing_time_ms
        }


@dataclass
class PasswordValidationResult(ValidationResult):
    """Password-specific validation result."""
    strength_score: float = 0.0
    strength_level: str = "weak"
    requirements_met: Dict[str, bool] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)


class UnifiedInputValidator:
    """
    Unified Input Validation Framework - Single Source of Truth

    Consolidates all input validation and sanitization functionality with
    comprehensive threat detection and multi-level security policies.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Use attribute access or the correct method to get input_validation config
        plexi_config = get_config()
        self.config = config or getattr(plexi_config, "input_validation", {})
        self.initialized = False

        # Security patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\bUNION\s+SELECT\b)",
            r"(\b(EXEC|EXECUTE)\s*\()",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)",
            r"(\bINTO\s+OUTFILE\b)",
            r"(\bLOAD_FILE\b)"
        ]

        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<applet[^>]*>",
            r"<meta[^>]*>",
            r"<link[^>]*>",
            r"<style[^>]*>.*?</style>",
            r"expression\s*\(",
            r"url\s*\(",
            r"@import"
        ]

        self.command_injection_patterns = [
            r"[;&|`$(){}[\]\\]",
            r"\b(rm|del|format|fdisk|kill|shutdown|reboot|halt)\b",
            r"(>|>>|<|\|)",
            r"\$\{.*\}",
            r"`.*`",
            r"\$\(.*\)",
            r"\b(wget|curl|nc|netcat|telnet|ssh)\b",
            r"\b(chmod|chown|sudo|su)\b"
        ]

        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c",
            r"\.\.%252f",
            r"\.\.%255c"
        ]

        # Input type configurations
        self.max_lengths = {
            InputType.TEXT: self.config.get("max_text_length", 10000),
            InputType.HTML: self.config.get("max_html_length", 50000),
            InputType.USERNAME: self.config.get("max_username_length", 50),
            InputType.EMAIL: self.config.get("max_email_length", 254),
            InputType.URL: self.config.get("max_url_length", 2048),
            InputType.FILENAME: self.config.get("max_filename_length", 255),
            InputType.PASSWORD: self.config.get("max_password_length", 128),
            InputType.PHONE: self.config.get("max_phone_length", 20),
            InputType.DOMAIN: self.config.get("max_domain_length", 253),
            InputType.JSON: self.config.get("max_json_length", 100000),
            InputType.TOKEN: self.config.get("max_token_length", 1024)
        }

        self.allowed_chars = {
            InputType.USERNAME: r"[a-zA-Z0-9_\-\.@]",
            InputType.FILENAME: r"[a-zA-Z0-9_\-\.\s]",
            InputType.DOMAIN: r"[a-zA-Z0-9\-\.]",
            InputType.IP_ADDRESS: r"[0-9\.]",
            InputType.PHONE: r"[0-9\+\-\(\)\s]"
        }

        # Password validation configuration
        self.password_config = {
            "min_length": self.config.get("password_min_length", 12),
            "require_uppercase": self.config.get("password_require_uppercase", True),
            "require_lowercase": self.config.get("password_require_lowercase", True),
            "require_numbers": self.config.get("password_require_numbers", True),
            "require_symbols": self.config.get("password_require_symbols", True),
            "prevent_common": self.config.get("password_prevent_common", True),
            "prevent_personal": self.config.get("password_prevent_personal", True)
        }

        # Common passwords (simplified list)
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master",
            "123456789", "12345678", "12345", "1234567890",
            "abc123", "password1", "iloveyou", "princess", "rockyou"
        }

        # Compiled regex patterns for performance
        self._compiled_patterns = {}
        self._compile_patterns()

        logger.info("Unified Input Validator initialized")

    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        try:
            self._compiled_patterns = {
                "sql_injection": [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_injection_patterns],
                "xss": [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns],
                "command_injection": [re.compile(pattern, re.IGNORECASE) for pattern in self.command_injection_patterns],
                "path_traversal": [re.compile(pattern, re.IGNORECASE) for pattern in self.path_traversal_patterns]
            }
        except Exception as e:
            logger.error(f"Failed to compile validation patterns: {e}")

    async def initialize(self) -> bool:
        """Initialize the input validator."""
        try:
            self.initialized = True
            logger.info(" Unified Input Validator initialized successfully")
            return True
        except Exception as e:
            logger.error(f" Input Validator initialization failed: {e}")
            return False

    def validate(self,
                value: Any,
                input_type: InputType,
                level: ValidationLevel = ValidationLevel.STANDARD,
                context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Validate and sanitize input with comprehensive threat detection.

        Args:
            value: Input value to validate
            input_type: Type of input for specific validation rules
            level: Security level for validation
            context: Additional context for validation

        Returns:
            ValidationResult with detailed validation information
        """
        start_time = time.time()

        if not self.initialized:
            # Initialize synchronously if needed
            self.initialized = True

        original_value = value
        sanitized_value = value
        threats = []
        warnings = []
        errors = []
        applied_rules = []
        is_valid = True
        is_safe = True
        confidence_score = 1.0

        try:
            # Convert to string if needed
            if not isinstance(value, str):
                if value is None:
                    sanitized_value = ""
                else:
                    sanitized_value = str(value)
                applied_rules.append("string_conversion")

            # Length validation
            max_length = self.max_lengths.get(input_type, 10000)
            if len(sanitized_value) > max_length:
                sanitized_value = sanitized_value[:max_length]
                warnings.append(f"Input truncated to {max_length} characters")
                applied_rules.append("length_limit")
                confidence_score -= 0.1

            # Type-specific validation
            if input_type == InputType.EMAIL:
                sanitized_value, email_valid = self._validate_email(sanitized_value)
                if not email_valid:
                    errors.append("Invalid email format")
                    is_valid = False
                applied_rules.append("email_validation")

            elif input_type == InputType.URL:
                sanitized_value, url_valid = self._validate_url(sanitized_value)
                if not url_valid:
                    errors.append("Invalid URL format")
                    is_valid = False
                applied_rules.append("url_validation")

            elif input_type == InputType.PASSWORD:
                # Password validation is handled separately
                pass

            elif input_type == InputType.JSON:
                sanitized_value, json_valid = self._validate_json(sanitized_value)
                if not json_valid:
                    errors.append("Invalid JSON format")
                    is_valid = False
                applied_rules.append("json_validation")

            elif input_type == InputType.PATH:
                sanitized_value, path_valid = self._validate_path(sanitized_value)
                if not path_valid:
                    errors.append("Invalid or unsafe path")
                    is_valid = False
                applied_rules.append("path_validation")

            # Security threat detection
            if level.value >= ValidationLevel.STANDARD.value:
                # SQL injection detection
                if self._detect_sql_injection(sanitized_value):
                    threats.append(ThreatType.SQL_INJECTION)
                    is_safe = False
                    confidence_score -= 0.3
                    if level.value >= ValidationLevel.STRICT.value:
                        sanitized_value = self._remove_sql_patterns(sanitized_value)
                        applied_rules.append("sql_injection_removal")

                # XSS detection
                if self._detect_xss(sanitized_value):
                    threats.append(ThreatType.XSS)
                    is_safe = False
                    confidence_score -= 0.3
                    if level.value >= ValidationLevel.STRICT.value:
                        sanitized_value = self._sanitize_xss(sanitized_value)
                        applied_rules.append("xss_sanitization")

                # Command injection detection
                if self._detect_command_injection(sanitized_value):
                    threats.append(ThreatType.COMMAND_INJECTION)
                    is_safe = False
                    confidence_score -= 0.4
                    if level.value >= ValidationLevel.STRICT.value:
                        sanitized_value = self._remove_command_patterns(sanitized_value)
                        applied_rules.append("command_injection_removal")

                # Path traversal detection
                if self._detect_path_traversal(sanitized_value):
                    threats.append(ThreatType.PATH_TRAVERSAL)
                    is_safe = False
                    confidence_score -= 0.4
                    if level.value >= ValidationLevel.STRICT.value:
                        sanitized_value = self._remove_path_traversal(sanitized_value)
                        applied_rules.append("path_traversal_removal")

            # Final safety check
            if threats:
                if level.value >= ValidationLevel.PARANOID.value:
                    is_valid = False
                    errors.append(f"Security threats detected: {[t.value for t in threats]}")

            # Ensure confidence score is within bounds
            confidence_score = max(0.0, min(1.0, confidence_score))

        except Exception as e:
            logger.error(f"Validation error: {e}")
            errors.append(f"Validation failed: {e}")
            is_valid = False
            is_safe = False
            confidence_score = 0.0

        processing_time = (time.time() - start_time) * 1000  # Convert to milliseconds

        return ValidationResult(
            original_value=original_value,
            sanitized_value=sanitized_value,
            is_valid=is_valid,
            is_safe=is_safe,
            confidence_score=confidence_score,
            threats_detected=threats,
            warnings=warnings,
            errors=errors,
            applied_rules=applied_rules,
            processing_time_ms=processing_time
        )

    def validate_password(self, password: str, username: Optional[str] = None) -> PasswordValidationResult:
        """Validate password strength and security."""
        start_time = time.time()

        original_value = password
        sanitized_value = password
        threats = []
        warnings = []
        errors = []
        applied_rules = []
        requirements_met = {}
        suggestions = []
        strength_score = 0.0
        strength_level = "weak"

        try:
            # Basic validation
            if not password:
                errors.append("Password cannot be empty")
                return PasswordValidationResult(
                    original_value=original_value,
                    sanitized_value=sanitized_value,
                    is_valid=False,
                    is_safe=False,
                    errors=errors,
                    strength_score=0.0,
                    strength_level="invalid"
                )

            # Length requirement
            min_length = self.password_config["min_length"]
            requirements_met["min_length"] = len(password) >= min_length
            if not requirements_met["min_length"]:
                errors.append(f"Password must be at least {min_length} characters long")
                suggestions.append(f"Add {min_length - len(password)} more characters")
            else:
                strength_score += 20

            # Character requirements
            if self.password_config["require_uppercase"]:
                requirements_met["uppercase"] = bool(re.search(r'[A-Z]', password))
                if not requirements_met["uppercase"]:
                    errors.append("Password must contain at least one uppercase letter")
                    suggestions.append("Add uppercase letters (A-Z)")
                else:
                    strength_score += 15

            if self.password_config["require_lowercase"]:
                requirements_met["lowercase"] = bool(re.search(r'[a-z]', password))
                if not requirements_met["lowercase"]:
                    errors.append("Password must contain at least one lowercase letter")
                    suggestions.append("Add lowercase letters (a-z)")
                else:
                    strength_score += 15

            if self.password_config["require_numbers"]:
                requirements_met["numbers"] = bool(re.search(r'[0-9]', password))
                if not requirements_met["numbers"]:
                    errors.append("Password must contain at least one number")
                    suggestions.append("Add numbers (0-9)")
                else:
                    strength_score += 15

            if self.password_config["require_symbols"]:
                requirements_met["symbols"] = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
                if not requirements_met["symbols"]:
                    errors.append("Password must contain at least one special character")
                    suggestions.append("Add special characters (!@#$%^&*)")
                else:
                    strength_score += 15

            # Common password check
            word_lower = password.lower()
                requirements_met["not_common"] = password_lower not in self.common_passwords
                if not requirements_met["not_common"]:
                    errors.append("Password is too common")
                    suggestions.append("Use a more unique password")
                    threats.append(ThreatType.SUSPICIOUS_PATTERN)
                else:
                    strength_score += 10

            # Personal information check
            if self.password_config["prevent_personal"] and username:
                username_lower = username.lower()
                password_lower = password.lower()
                requirements_met["not_personal"] = username_lower not in password_lower
                if not requirements_met["not_personal"]:
                    errors.append("Password should not contain username")
                    suggestions.append("Avoid using your username in the password")
                    threats.append(ThreatType.SUSPICIOUS_PATTERN)
                else:
                    strength_score += 10

            # Additional strength factors
            # Character diversity
            unique_chars = len(set(password))
            if unique_chars >= len(password) * 0.7:
                strength_score += 5

            # Length bonus
            if len(password) >= 16:
                strength_score += 5
            if len(password) >= 20:
                strength_score += 5

            # Determine strength level
            if strength_score >= 90:
                strength_level = "very_strong"
            elif strength_score >= 75:
                strength_level = "strong"
            elif strength_score >= 60:
                strength_level = "moderate"
            elif strength_score >= 40:
                strength_level = "weak"
            else:
                strength_level = "very_weak"

            is_valid = len(errors) == 0
            is_safe = len(threats) == 0

        except Exception as e:
            logger.error(f"Password validation error: {e}")
            errors.append(f"Password validation failed: {e}")
            is_valid = False
            is_safe = False

        processing_time = (time.time() - start_time) * 1000

        return PasswordValidationResult(
            original_value=original_value,
            sanitized_value=sanitized_value,
            is_valid=is_valid,
            is_safe=is_safe,
            threats_detected=threats,
            warnings=warnings,
            errors=errors,
            applied_rules=applied_rules,
            processing_time_ms=processing_time,
            strength_score=strength_score,
            strength_level=strength_level,
            requirements_met=requirements_met,
            suggestions=suggestions
        )

    def validate_dict(self,
                     data: Dict[str, Any],
                     field_types: Dict[str, InputType],
                     level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, ValidationResult]:
        """Validate all fields in a dictionary."""
        results = {}

        for field, value in data.items():
            if field in field_types:
                results[field] = self.validate(value, field_types[field], level)
            else:
                # Default to text validation for unknown fields
                results[field] = self.validate(value, InputType.TEXT, level)

        return results

    def _validate_email(self, email: str) -> Tuple[str, bool]:
        """Validate and sanitize email address."""
        try:
            # Basic email regex
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if re.match(email_pattern, email):
                return email.lower().strip(), True
            return email, False
        except Exception:
            return email, False

    def _validate_url(self, url: str) -> Tuple[str, bool]:
        """Validate and sanitize URL."""
        try:
            # Basic URL validation
            url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
            if re.match(url_pattern, url, re.IGNORECASE):
                return url.strip(), True
            return url, False
        except Exception:
            return url, False

    def _validate_json(self, json_str: str) -> Tuple[str, bool]:
        """Validate and sanitize JSON."""
        try:
            parsed = json.loads(json_str)
            return json.dumps(parsed, separators=(',', ':')), True
        except (json.JSONDecodeError, ValueError):
            return json_str, False

    def _validate_path(self, path: str) -> Tuple[str, bool]:
        """Validate and sanitize file path."""
        try:
            # Check for path traversal
            if any(pattern in path for pattern in ['../', '..\\', '%2e%2e']):
                return path, False

            # Normalize path
            from pathlib import Path
normalized_path = Path
Path(path).resolve()
            return str(normalized_path), True
        except (OSError, ValueError):
            return path, False

    def _detect_sql_injection(self, value: str) -> bool:
        """Detect SQL injection patterns."""
        for pattern in self._compiled_patterns.get("sql_injection", []):
            if pattern.search(value):
                return True
        return False

    def _detect_xss(self, value: str) -> bool:
        """Detect XSS patterns."""
        for pattern in self._compiled_patterns.get("xss", []):
            if pattern.search(value):
                return True
        return False

    def _detect_command_injection(self, value: str) -> bool:
        """Detect command injection patterns."""
        for pattern in self._compiled_patterns.get("command_injection", []):
            if pattern.search(value):
                return True
        return False

    def _detect_path_traversal(self, value: str) -> bool:
        """Detect path traversal patterns."""
        for pattern in self._compiled_patterns.get("path_traversal", []):
            if pattern.search(value):
                return True
        return False

    def _remove_sql_patterns(self, value: str) -> str:
        """Remove SQL injection patterns."""
        for pattern in self._compiled_patterns.get("sql_injection", []):
            value = pattern.sub('', value)
        return value

    def _sanitize_xss(self, value: str) -> str:
        """Sanitize XSS patterns."""
        # HTML escape
        value = html.escape(value)
        # Remove dangerous patterns
        for pattern in self._compiled_patterns.get("xss", []):
            value = pattern.sub('', value)
        return value

    def _remove_command_patterns(self, value: str) -> str:
        """Remove command injection patterns."""
        for pattern in self._compiled_patterns.get("command_injection", []):
            value = pattern.sub('', value)
        return value

    def _remove_path_traversal(self, value: str) -> str:
        """Remove path traversal patterns."""
        for pattern in self._compiled_patterns.get("path_traversal", []):
            value = pattern.sub('', value)
        return value

    def get_status(self) -> Dict[str, Any]:
        """Get input validator status."""
        return {
            "initialized": self.initialized,
            "patterns_loaded": len(self._compiled_patterns),
            "supported_types": [t.value for t in InputType],
            "validation_levels": [l.value for l in ValidationLevel],
            "threat_types": [t.value for t in ThreatType],
            "max_lengths": {k.value: v for k, v in self.max_lengths.items()},
            "password_config": self.password_config
        }


# Global instance - SINGLE SOURCE OF TRUTH
_input_validator: Optional[UnifiedInputValidator] = None


def get_input_validator() -> UnifiedInputValidator:
    """Get the global input validator instance."""
    global _input_validator
    if _input_validator is None:
        _input_validator = UnifiedInputValidator()
    return _input_validator


# Export main components
__all__ = [
    "UnifiedInputValidator",
    "get_input_validator",
    "ValidationResult",
    "PasswordValidationResult",
    "InputType",
    "ValidationLevel",
    "ThreatType"
]
