"""
import string
import time
import urllib.parse
PlexiChat Shared Validators

Common validation functions used across the application.
"""

import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from .constants import MAX_USERNAME_LENGTH, MAX_EMAIL_LENGTH, PASSWORD_MIN_LENGTH
from .exceptions import ValidationError


def validate_required(value: Any, field_name: str) -> None:
    """Validate that a value is not None or empty."""
    if value is None:
        raise ValidationError(f"{field_name} is required", field=field_name)

    if isinstance(value, str) and not value.strip():
        raise ValidationError(f"{field_name} cannot be empty", field=field_name)


def validate_string_length(value: str, field_name: str, min_length: int = 0, max_length: Optional[int] = None) -> None:
    """Validate string length."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=value)

    length = len(value)

    if length < min_length:
        raise ValidationError(f"{field_name} must be at least {min_length} characters long", field=field_name, value=value)

    if max_length and length > max_length:
        raise ValidationError(f"{field_name} must be at most {max_length} characters long", field=field_name, value=value)


def validate_email(email: str, field_name: str = "email") -> None:
    """Validate email address."""
    if not isinstance(email, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=email)

    # Basic email regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(pattern, email):
        raise ValidationError(f"Invalid {field_name} format", field=field_name, value=email)

    validate_string_length(email, field_name, max_length=MAX_EMAIL_LENGTH)


def validate_username(username: str, field_name: str = "username") -> None:
    """Validate username."""
    validate_required(username, field_name)
    validate_string_length(username, field_name, min_length=3, max_length=MAX_USERNAME_LENGTH)

    # Username can only contain alphanumeric characters, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValidationError(f"{field_name} can only contain letters, numbers, underscores, and hyphens", field=field_name, value=username)

    # Username cannot start or end with underscore or hyphen
    if username.startswith(('_', '-')) or username.endswith(('_', '-')):
        raise ValidationError(f"{field_name} cannot start or end with underscore or hyphen", field=field_name, value=username)


def validate_password(password: str, field_name: str = "password") -> None:
    """Validate password strength."""
    validate_required(password, field_name)

    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValidationError(f"{field_name} must be at least {PASSWORD_MIN_LENGTH} characters long", field=field_name)

    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        raise ValidationError(f"{field_name} must contain at least one uppercase letter", field=field_name)

    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        raise ValidationError(f"{field_name} must contain at least one lowercase letter", field=field_name)

    # Check for at least one digit
    if not re.search(r'\d', password):
        raise ValidationError(f"{field_name} must contain at least one digit", field=field_name)

    # Check for at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError(f"{field_name} must contain at least one special character", field=field_name)


def validate_uuid(value: str, field_name: str) -> None:
    """Validate UUID format."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=value)

    try:
        uuid.UUID(value)
    except ValueError:
        raise ValidationError(f"Invalid {field_name} format", field=field_name, value=value)


def validate_url(url: str, field_name: str = "url", schemes: Optional[List[str]] = None) -> None:
    """Validate URL format."""
    if not isinstance(url, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=url)

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValidationError(f"Invalid {field_name} format", field=field_name, value=url)

    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Invalid {field_name} format", field=field_name, value=url)

    if schemes and parsed.scheme not in schemes:
        raise ValidationError(f"{field_name} scheme must be one of: {', '.join(schemes)}", field=field_name, value=url)


def validate_integer(value: Any, field_name: str, min_value: Optional[int] = None, max_value: Optional[int] = None) -> None:
    """Validate integer value."""
    if not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer", field=field_name, value=value)

    if min_value is not None and value < min_value:
        raise ValidationError(f"{field_name} must be at least {min_value}", field=field_name, value=value)

    if max_value is not None and value > max_value:
        raise ValidationError(f"{field_name} must be at most {max_value}", field=field_name, value=value)


def validate_float(value: Any, field_name: str, min_value: Optional[float] = None, max_value: Optional[float] = None) -> None:
    """Validate float value."""
    if not isinstance(value, (int, float)):
        raise ValidationError(f"{field_name} must be a number", field=field_name, value=value)

    value = float(value)

    if min_value is not None and value < min_value:
        raise ValidationError(f"{field_name} must be at least {min_value}", field=field_name, value=value)

    if max_value is not None and value > max_value:
        raise ValidationError(f"{field_name} must be at most {max_value}", field=field_name, value=value)


def validate_choice(value: Any, field_name: str, choices: List[Any]) -> None:
    """Validate that value is one of the allowed choices."""
    if value not in choices:
        raise ValidationError(f"{field_name} must be one of: {', '.join(map(str, choices))}", field=field_name, value=value)


def validate_list(value: Any, field_name: str, min_length: int = 0, max_length: Optional[int] = None, item_validator: Optional[callable] = None) -> None:
    """Validate list value."""
    if not isinstance(value, list):
        raise ValidationError(f"{field_name} must be a list", field=field_name, value=value)

    length = len(value)

    if length < min_length:
        raise ValidationError(f"{field_name} must contain at least {min_length} items", field=field_name, value=value)

    if max_length and length > max_length:
        raise ValidationError(f"{field_name} must contain at most {max_length} items", field=field_name, value=value)

    if item_validator:
        for i, item in enumerate(value):
            try:
                item_validator(item, f"{field_name}[{i}]")
            except ValidationError as e:
                raise ValidationError(f"Invalid item at index {i}: {e.message}", field=field_name, value=value)


def validate_dict(value: Any, field_name: str, required_keys: Optional[List[str]] = None, allowed_keys: Optional[List[str]] = None) -> None:
    """Validate dictionary value."""
    if not isinstance(value, dict):
        raise ValidationError(f"{field_name} must be a dictionary", field=field_name, value=value)

    if required_keys:
        missing_keys = set(required_keys) - set(value.keys())
        if missing_keys:
            raise ValidationError(f"{field_name} is missing required keys: {', '.join(missing_keys)}", field=field_name, value=value)

    if allowed_keys:
        invalid_keys = set(value.keys()) - set(allowed_keys)
        if invalid_keys:
            raise ValidationError(f"{field_name} contains invalid keys: {', '.join(invalid_keys)}", field=field_name, value=value)


def validate_datetime(value: Any, field_name: str) -> None:
    """Validate datetime value."""
    if not isinstance(value, datetime):
        if isinstance(value, str):
            try:
                datetime.fromisoformat(value.replace('Z', '+00:00'))
                return
            except ValueError:
                pass

        raise ValidationError(f"{field_name} must be a valid datetime", field=field_name, value=value)


def validate_file_extension(filename: str, field_name: str = "filename", allowed_types: Optional[List[str]] = None) -> None:
    """Validate file extension."""
    if not isinstance(filename, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=filename)

    file_path = Path(filename)
    extension = file_path.suffix.lower()

    if not extension:
        raise ValidationError(f"{field_name} must have a file extension", field=field_name, value=filename)

    # Get all allowed extensions
    all_extensions = set()
    if allowed_types:
        for file_type in allowed_types:
            if file_type in [".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif"]:
                all_extensions.update([".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif"][file_type])
    else:
        for extensions in [".txt", ".pdf", ".doc", ".docx", ".jpg", ".png", ".gif"].values():
            all_extensions.update(extensions)

    if extension not in all_extensions:
        raise ValidationError(f"File extension '{extension}' is not allowed", field=field_name, value=filename)


def validate_message_content(content: str, field_name: str = "content") -> None:
    """Validate message content."""
    validate_required(content, field_name)
    validate_string_length(content, field_name, min_length=1, max_length=MAX_USERNAME_LENGTH)

    # Check for potentially harmful content
    if re.search(r'<script[^>]*>.*?</script>', content, re.IGNORECASE | re.DOTALL):
        raise ValidationError(f"{field_name} contains potentially harmful content", field=field_name)


def validate_json(value: str, field_name: str) -> None:
    """Validate JSON string."""
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string", field=field_name, value=value)

    try:
        import json
        json.loads(value)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON in {field_name}: {str(e)}", field=field_name, value=value)


# Export all validators
__all__ = [
    'validate_required',
    'validate_string_length',
    'validate_email',
    'validate_username',
    'validate_password',
    'validate_uuid',
    'validate_url',
    'validate_integer',
    'validate_float',
    'validate_choice',
    'validate_list',
    'validate_dict',
    'validate_datetime',
    'validate_file_extension',
    'validate_message_content',
    'validate_json',
]
