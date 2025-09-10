#!/usr/bin/env python3
"""Isolated logging test - direct imports from unified_logger."""
import json
import logging
import re
from src.plexichat.core.logging.unified_logger import (
    redact_pii,
    sanitize_for_logging,
    DEFAULT_PII_PATTERNS,
    ColoredFormatter,
    StructuredFormatter,
)

def test_redact_pii():
    message = "User john.doe@example.com SSN 123-45-6789"
    redacted = redact_pii(message)
    assert "[REDACTED]" in redacted
    print("PASS: redact_pii works")

def test_sanitize_for_logging():
    message = "Test email@example.com ☃"
    sanitized = sanitize_for_logging(message)
    assert "[REDACTED]" in sanitized
    assert "☃" in sanitized
    print("PASS: sanitize_for_logging works")

def test_colored_formatter():
    formatter = ColoredFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test", (), None)
    output = formatter.format(record)
    assert "\033[32m" in output
    print("PASS: ColoredFormatter colors")

def test_structured_formatter():
    formatter = StructuredFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test", (), None)
    output = formatter.format(record)
    log_dict = json.loads(output)
    assert log_dict["level"] == "INFO"
    print("PASS: StructuredFormatter JSON")

print("Running isolated logging tests...")
test_redact_pii()
test_sanitize_for_logging()
test_colored_formatter()
test_structured_formatter()
print("All isolated tests passed - logging refactor successful!")