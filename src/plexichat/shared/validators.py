"""
PlexiChat Shared Validators

Basic validation functions for the PlexiChat application.
"""

from collections.abc import Callable
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, cast
from urllib.parse import urlparse
import uuid

from plexichat.shared.exceptions import SecurityError, ValidationError

# Validation constants
MAX_USERNAME_LENGTH = 64
MAX_EMAIL_LENGTH = 254
PASSWORD_MIN_LENGTH = 12
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1GB
ALLOWED_IMAGE_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
ALLOWED_DOCUMENT_TYPES = {'application/pdf', 'text/plain', 'application/msword'}
def validate_required(value: Any, field_name: str) -> None:
    """Validate required field."""
    if value is None:
        raise ValidationError(f"{field_name} is required")

    if isinstance(value, str) and not value.strip():
        raise ValidationError(f"{field_name} cannot be empty")


def validate_string_length(value: str, field_name: str, min_length: int = 0, max_length: int | None = None) -> None:
    """Validate string length."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", details={"type": type(value).__name__})

    length = len(value)

    if length < min_length:
        raise ValidationError(f"{field_name} must be at least {min_length} characters long")

    if max_length and length > max_length:
        raise ValidationError(f"{field_name} must be at most {max_length} characters long")


def validate_email(email: str, field_name: str = "email") -> None:
    """Validate email address."""
    if not isinstance(email, str):
        raise ValidationError(f"{field_name} must be a string", details={"value": email})

    # Basic email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(pattern, email):
        raise ValidationError(f"Invalid {field_name} format", details={"value": email})

    validate_string_length(email, field_name, max_length=MAX_EMAIL_LENGTH)


def validate_username(username: str, field_name: str = "username") -> None:
    """Validate username."""
    validate_required(username, field_name)
    validate_string_length(username, field_name, min_length=3, max_length=MAX_USERNAME_LENGTH)

    # Username can only contain alphanumeric characters, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValidationError(f"{field_name} can only contain letters, numbers, underscores, and hyphens", details={"value": username})

    # Username cannot start or end with underscore or hyphen
    if username.startswith(('_', '-')) or username.endswith(('_', '-')):
        raise ValidationError(f"{field_name} cannot start or end with underscore or hyphen", details={"value": username})


def validate_password(password: str, field_name: str = "password") -> None:
    """Validate password strength."""
    validate_required(password, field_name)

    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(f"{field_name} must be at least {PASSWORD_MIN_LENGTH} characters long")

    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        raise ValidationError(f"{field_name} must contain at least one uppercase letter")

    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        raise ValidationError(f"{field_name} must contain at least one lowercase letter")

    # Check for at least one digit
    if not re.search(r'\d', password):
        raise ValidationError(f"{field_name} must contain at least one digit")

    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError(f"{field_name} must contain at least one special character")


def validate_uuid(value: str, field_name: str) -> None:
    """Validate UUID format."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", details={"value": value})

    try:
        uuid.UUID(value)
    except ValueError:
        raise ValidationError(f"Invalid {field_name} format", details={"value": value})


def validate_url(url: str, field_name: str = "url", schemes: list[str] | None = None) -> None:
    """Validate URL format."""
    if not isinstance(url, str):
        raise ValidationError(f"{field_name} must be a string", details={"value": url})

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError(f"Invalid {field_name} format", details={"value": url})

    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Invalid {field_name} format", details={"value": url})

    if schemes and parsed.scheme not in schemes:
        raise ValidationError(f"{field_name} scheme must be one of: {', '.join(schemes)}", details={"value": url})


def validate_integer(value: Any, field_name: str, min_value: int | None = None, max_value: int | None = None) -> None:
    """Validate integer value."""
    if not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer", details={"value": value})

    if min_value is not None and value < min_value:
        raise ValidationError(f"{field_name} must be at least {min_value}", details={"value": value})

    if max_value is not None and value > max_value:
        raise ValidationError(f"{field_name} must be at most {max_value}", details={"value": value})


def validate_float(value: Any, field_name: str, min_value: float | None = None, max_value: float | None = None) -> None:
    """Validate float value."""
    if not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a number", details={"value": value})

    value = float(value)

    if min_value is not None and value < min_value:
        raise ValidationError(f"{field_name} must be at least {min_value}", details={"value": value})

    if max_value is not None and value > max_value:
        raise ValidationError(f"{field_name} must be at most {max_value}", details={"value": value})


def validate_choice(value: Any, field_name: str, choices: list[Any]) -> None:
    """Validate that value is one of the allowed choices."""
    if value not in choices:
        raise ValidationError(f"{field_name} must be one of: {', '.join(map(str, choices))}", details={"value": value})


def validate_list(value: Any, field_name: str, min_length: int = 0, max_length: int | None = None, item_validator: Callable[[Any, str], None] | None = None) -> None:
    """Validate list value."""
    if not isinstance(value, list):
        raise ValidationError(f"{field_name} must be a list", details={"value": value})
    value = cast('list[Any]', value)
    length = len(value)

    if length < min_length:
        raise ValidationError(f"{field_name} must contain at least {min_length} items", details={"value": value})

    if max_length and length > max_length:
        raise ValidationError(f"{field_name} must contain at most {max_length} items", details={"value": value})

    if item_validator:
        for i, item in enumerate(value):
            try:
                item_validator(item, f"{field_name}[{i}]")
            except ValidationError as e:
                raise ValidationError(f"Invalid item at index {i}: {e.message}", details={"value": value})


def validate_dict(value: Any, field_name: str, required_keys: list[str] | None = None, allowed_keys: list[str] | None = None) -> None:
    """Validate dictionary value."""
    if not isinstance(value, dict):
        raise ValidationError(f"{field_name} must be a dictionary", details={"value": value})
    value = cast('dict[str, Any]', value)

    if required_keys:
        missing_keys = set(required_keys) - set(value.keys())
        if missing_keys:
            raise ValidationError(f"{field_name} is missing required keys: {', '.join(missing_keys)}", details={"value": value})

    if allowed_keys:
        invalid_keys = set(value.keys()) - set(allowed_keys)
        if invalid_keys:
            raise ValidationError(f"{field_name} contains invalid keys: {', '.join(invalid_keys)}", details={"value": value})


def validate_datetime(value: Any, field_name: str) -> None:
    """Validate datetime value."""
    if not isinstance(value, datetime):
        if isinstance(value, str):
            try:
                datetime.fromisoformat(value.replace('Z', '+00:00'))
                return
            except ValueError:
                pass

        raise ValidationError(f"{field_name} must be a valid datetime", details={"value": value})


def validate_file_extension(filename: str, field_name: str = "filename", allowed_types: list[str] | None = None) -> None:
    """Validate file extension."""
    if not isinstance(filename, str):
        raise ValidationError(f"{field_name} must be a string", details={"value": filename})

    file_path = Path(filename)
    extension = file_path.suffix.lower()

    if not extension:
        raise ValidationError(f"{field_name} must have a file extension", details={"value": filename})

    # Get all allowed extensions
    all_extensions = {".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif"}
    if allowed_types:
        all_extensions = set(allowed_types)

    if extension not in all_extensions:
        raise ValidationError(f"File extension '{extension}' is not allowed", details={"value": filename})


def validate_message_content(content: str, field_name: str = "content") -> None:
    """Validate message content."""
    validate_required(content, field_name)
    validate_string_length(content, field_name, min_length=1, max_length=MAX_USERNAME_LENGTH)

    # Check for potentially harmful content
    if re.search(r'<script[^>]*>.*?</script>', content, re.IGNORECASE | re.DOTALL):
        raise ValidationError(f"{field_name} contains potentially harmful content")


def validate_json(value: str, field_name: str) -> None:
    """Validate JSON string."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", details={"value": value})

    try:
        json.loads(value)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON in {field_name}: {e!s}", details={"value": value})


# Export all validators
__all__ = [
    'ALLOWED_DOCUMENT_TYPES',
    'ALLOWED_IMAGE_TYPES',
    'MAX_EMAIL_LENGTH',
    'MAX_FILE_SIZE',
    'MAX_UPLOAD_SIZE',
    'MAX_USERNAME_LENGTH',
    'PASSWORD_MIN_LENGTH',
    'SecurityError',
    'ValidationError',
    'validate_choice',
    'validate_datetime',
    'validate_dict',
    'validate_email',
    'validate_file_extension',
    'validate_float',
    'validate_integer',
    'validate_json',
    'validate_list',
    'validate_message_content',
    'validate_password',
    'validate_required',
    'validate_string_length',
    'validate_url',
    'validate_username',
    'validate_uuid'
]
