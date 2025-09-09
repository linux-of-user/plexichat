"""
PII Redaction Module for PlexiChat

This module provides functions to redact personally identifiable information (PII)
and sensitive data from logs and other outputs to ensure compliance with privacy regulations.
"""

import logging
import re
from typing import Any, Dict, List, Union

logger = logging.getLogger(__name__)

# Patterns for sensitive data that should be redacted
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "api_key": re.compile(r"\b[A-Za-z0-9]{32,}\b"),  # Generic API key pattern
    "password": re.compile(
        r'(?i)(password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    ),
    "token": re.compile(r"\b[A-Za-z0-9+/=]{20,}\b"),  # Base64-like tokens
}

# Fields that commonly contain sensitive data
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "key",
    "secret",
    "private_key",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_key",
    "api_secret",
    "database_url",
    "db_url",
    "connection_string",
    "credit_card",
    "cc_number",
    "ssn",
    "social_security",
    "phone",
    "email",
    "ip_address",
    "user_agent",
}


def redact_pii(
    data: Union[str, Dict, List, Any], max_length: int = 1000
) -> Union[str, Dict, List, Any]:
    """
    Redact personally identifiable information from data.

    Args:
        data: The data to redact (string, dict, list, or other types)
        max_length: Maximum length for string data before truncation

    Returns:
        Redacted data with sensitive information replaced with [REDACTED]
    """
    if isinstance(data, str):
        return _redact_string(data, max_length)
    elif isinstance(data, dict):
        return _redact_dict(data)
    elif isinstance(data, list):
        return _redact_list(data)
    else:
        # Convert to string and redact
        str_data = str(data)
        if len(str_data) > max_length:
            return f"[DATA_REDACTED_{len(str_data)}chars]"
        return _redact_string(str_data, max_length)


def _redact_string(text: str, max_length: int = 1000) -> str:
    """Redact sensitive information from a string."""
    if not text:
        return text

    # Truncate if too long
    if len(text) > max_length:
        return f"[DATA_REDACTED_{len(text)}chars]"

    redacted = text

    # Apply PII patterns
    for pattern_name, pattern in PII_PATTERNS.items():
        redacted = pattern.sub("[REDACTED]", redacted)

    # Redact common sensitive field patterns
    for field in SENSITIVE_FIELDS:
        # Case-insensitive replacement of field values
        field_pattern = re.compile(rf"(?i){re.escape(field)}\s*[:=]\s*([^\s,;\n]+)")
        redacted = field_pattern.sub(f"{field}: [REDACTED]", redacted)

    return redacted


def _redact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive information from a dictionary."""
    redacted = {}

    for key, value in data.items():
        # Check if key contains sensitive information
        key_lower = str(key).lower()
        if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = redact_pii(value)

    return redacted


def _redact_list(data: List[Any]) -> List[Any]:
    """Redact sensitive information from a list."""
    return [redact_pii(item) for item in data]


def sanitize_log_message(message: str, **kwargs) -> str:
    """
    Sanitize a log message by redacting PII and sensitive data.

    Args:
        message: The log message to sanitize
        **kwargs: Additional data to include in sanitization

    Returns:
        Sanitized log message
    """
    # Redact the message itself
    sanitized_message = redact_pii(message)

    # Redact any sensitive kwargs
    sanitized_kwargs = {}
    for key, value in kwargs.items():
        if any(sensitive in str(key).lower() for sensitive in SENSITIVE_FIELDS):
            sanitized_kwargs[key] = "[REDACTED]"
        else:
            sanitized_kwargs[key] = redact_pii(value)

    return sanitized_message, sanitized_kwargs


def is_sensitive_field(field_name: str) -> bool:
    """
    Check if a field name indicates it contains sensitive information.

    Args:
        field_name: The field name to check

    Returns:
        True if the field is considered sensitive
    """
    field_lower = str(field_name).lower()
    return any(sensitive in field_lower for sensitive in SENSITIVE_FIELDS)


# Export the main function
__all__ = ["redact_pii", "sanitize_log_message", "is_sensitive_field"]
