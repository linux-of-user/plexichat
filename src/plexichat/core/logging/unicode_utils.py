"""
Unicode sanitization utilities for logging.

This module provides functions to sanitize Unicode characters that may cause
encoding issues in Windows console environments.
"""

import re
from typing import Union


def sanitize_for_logging(text: Union[str, Any]) -> str:
    """
    Sanitize text for logging to ensure it's unicode-free and safe for Windows console output.

    This function removes or replaces Unicode characters that cause encoding issues
    in Windows console environments (cp1252 encoding).

    Args:
        text: The text to sanitize

    Returns:
        Sanitized text safe for logging
    """
    if not isinstance(text, str):
        text = str(text)

    # Replace common Unicode symbols with ASCII equivalents
    replacements = {
        '\U0001f510': '[LOCK]',      # lock emoji
        '\U0001f512': '[LOCK]',      # locked emoji
        '\U0001f513': '[UNLOCK]',    # unlocked emoji
        '\U0001f4a5': '[BOOM]',      # explosion emoji
        '\U0001f525': '[FIRE]',      # fire emoji
        '\U0001f680': '[ROCKET]',    # rocket emoji
        '\U0001f44d': '[THUMBSUP]',  # thumbs up emoji
        '\U0001f44e': '[THUMBSDOWN]', # thumbs down emoji
        '\U00002705': '[CHECK]',     # check mark
        '\U0000274c': '[CROSS]',     # cross mark
        '\U000026a0': '[WARNING]',   # warning sign
        '\U0001f6a8': '[ALERT]',     # siren emoji
        '\u2713': '[OK]',           # check mark
        '\u2717': '[X]',            # cross mark
        '\u2192': '->',             # right arrow
        '\u2190': '<-',             # left arrow
        '\u25b6': '[PLAY]',         # play button
        '\u25b7': '[PAUSE]',        # pause button
        '\u23f8': '[STOP]',         # stop button
        '\u2026': '...',            # ellipsis
        '\u2013': '-',              # en dash
        '\u2014': '--',             # em dash
        '\u2018': "'",              # left single quote
        '\u2019': "'",              # right single quote
        '\u201c': '"',              # left double quote
        '\u201d': '"',              # right double quote
    }

    # Apply specific replacements
    for unicode_char, replacement in replacements.items():
        text = text.replace(unicode_char, replacement)

    # Remove any remaining Unicode characters that might cause issues
    # Keep only ASCII characters and common Latin-1 characters
    try:
        # Try to encode as latin-1, which covers most Windows console safe characters
        encoded = text.encode('latin-1', errors='ignore')
        text = encoded.decode('latin-1')
    except (UnicodeEncodeError, UnicodeDecodeError):
        # If encoding fails, strip all non-ASCII characters
        text = re.sub(r'[^\x00-\x7F]+', '[UNICODE]', text)

    return text


def sanitize_log_message(message: str, *args, **kwargs) -> tuple:
    """
    Sanitize a log message and its arguments for safe output.

    Args:
        message: The log message format string
        *args: Positional arguments for the message
        **kwargs: Keyword arguments for the message

    Returns:
        Tuple of (sanitized_message, sanitized_args, sanitized_kwargs)
    """
    sanitized_message = sanitize_for_logging(message)
    sanitized_args = tuple(sanitize_for_logging(arg) for arg in args)

    # Sanitize kwargs values (keep keys as-is since they should be ASCII)
    sanitized_kwargs = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            sanitized_kwargs[key] = sanitize_for_logging(value)
        else:
            sanitized_kwargs[key] = value

    return sanitized_message, sanitized_args, sanitized_kwargs