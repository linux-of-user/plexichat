"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Core Validation
Essential validation functions for the entire application.
"""

from dataclasses import dataclass
import json
import re
from typing import Any

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Validation result."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    cleaned_data: dict[str, Any]


class Validator:
    """Core validation class."""

    @staticmethod
    def validate_string(
        value: Any,
        min_length: int = 0,
        max_length: int = 1000,
        pattern: str | None = None,
        required: bool = True,
    ) -> ValidationResult:
        """Validate string value."""
        errors = []
        warnings = []
        cleaned_data = {}

        # Check if required
        if required and (value is None or value == ""):
            errors.append("Field is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        # Convert to string if not None
        if value is not None:
            str_value = str(value).strip()
            cleaned_data["value"] = str_value

            # Check length
            if len(str_value) < min_length:
                errors.append(f"Must be at least {min_length} characters")
            if len(str_value) > max_length:
                errors.append(f"Must be no more than {max_length} characters")

            # Check pattern
            if pattern and not re.match(pattern, str_value):
                errors.append("Invalid format")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)

    @staticmethod
    def validate_email(email: str, required: bool = True) -> ValidationResult:
        """Validate email address."""
        errors = []
        warnings = []
        cleaned_data = {}

        if required and not email:
            errors.append("Email is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        if email:
            email = email.strip().lower()
            cleaned_data["value"] = email

            # Basic email pattern
            pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(pattern, email):
                errors.append("Invalid email format")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)

    @staticmethod
    def validate_integer(
        value: Any,
        min_value: int | None = None,
        max_value: int | None = None,
        required: bool = True,
    ) -> ValidationResult:
        """Validate integer value."""
        errors = []
        warnings = []
        cleaned_data = {}

        if required and value is None:
            errors.append("Field is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        if value is not None:
            try:
                int_value = int(value)
                cleaned_data["value"] = int_value

                if min_value is not None and int_value < min_value:
                    errors.append(f"Must be at least {min_value}")
                if max_value is not None and int_value > max_value:
                    errors.append(f"Must be no more than {max_value}")

            except (ValueError, TypeError):
                errors.append("Must be a valid integer")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)

    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> ValidationResult:
        """Validate password strength."""
        errors = []
        warnings = []
        cleaned_data = {}

        if not password:
            errors.append("Password is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        cleaned_data["value"] = password

        # Length check
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters")

        # Strength checks
        if not re.search(r"[a-z]", password):
            warnings.append("Password should contain lowercase letters")
        if not re.search(r"[A-Z]", password):
            warnings.append("Password should contain uppercase letters")
        if not re.search(r"\d", password):
            warnings.append("Password should contain numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            warnings.append("Password should contain special characters")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)

    @staticmethod
    def validate_filename(filename: str) -> ValidationResult:
        """Validate filename for security."""
        errors = []
        warnings = []
        cleaned_data = {}

        if not filename:
            errors.append("Filename is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        # Clean filename
        clean_name = filename.strip()
        cleaned_data["value"] = clean_name

        # Check for dangerous patterns
        dangerous_patterns = [
            r"\.\./",  # Directory traversal
            r'[<>:"/\\|?*]',  # Invalid characters
            r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$",  # Windows reserved names
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, clean_name, re.IGNORECASE):
                errors.append("Filename contains invalid characters")
                break

        # Length check
        if len(clean_name) > 255:
            errors.append("Filename too long")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)

    @staticmethod
    def validate_json(data: str) -> ValidationResult:
        """Validate JSON string."""
        errors = []
        warnings = []
        cleaned_data = {}

        if not data:
            errors.append("JSON data is required")
            return ValidationResult(False, errors, warnings, cleaned_data)

        try:
            parsed_data = json.loads(data)
            cleaned_data["value"] = parsed_data
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {e!s}")

        return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)


# Convenience functions
def validate_required_fields(
    data: dict[str, Any], required_fields: list[str]
) -> ValidationResult:
    """Validate that all required fields are present."""
    errors = []
    warnings = []
    cleaned_data = data.copy()

    for field in required_fields:
        if field not in data or data[field] is None or data[field] == "":
            errors.append(f"Field '{field}' is required")

    return ValidationResult(len(errors) == 0, errors, warnings, cleaned_data)


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input."""
    if not isinstance(text, str):
        text = str(text)

    # Remove control characters except newlines and tabs
    sanitized = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")

    # Limit length
    return sanitized[:max_length]


def is_safe_path(path: str, base_path: str = ".") -> bool:
    """Check if a path is safe (no directory traversal)."""
    import os

    try:
        # Resolve paths
        abs_base = os.path.abspath(base_path)
        abs_path = os.path.abspath(os.path.join(base_path, path))

        # Check if the resolved path is within the base path
        return abs_path.startswith(abs_base)
    except (ValueError, OSError):
        return False


# Global validator instance
validator = Validator()

__all__ = [
    "ValidationResult",
    "Validator",
    "is_safe_path",
    "sanitize_input",
    "validate_required_fields",
    "validator",
]
