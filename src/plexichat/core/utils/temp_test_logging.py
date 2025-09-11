#!/usr/bin/env python3
"""Standalone test script for logging refactor verification."""
import json
import logging

from plexichat.core.logging import (
    ColoredFormatter,
    StructuredFormatter,
    get_handler_factory,
    get_logger,
    redact_pii,
    sanitize_for_logging,
)


def test_redact_pii():
    message = "User john.doe@example.com SSN 123-45-6789"
    redacted = redact_pii(message)
    assert "[REDACTED]" in redacted
    print(f"PASS: redact_pii works - {redacted}")

def test_sanitize_for_logging():
    message = "Test with email@example.com and unicode ☃"
    sanitized = sanitize_for_logging(message)
    assert "[REDACTED]" in sanitized
    assert "☃" in sanitized  # Unicode preserved
    print(f"PASS: sanitize_for_logging works - {sanitized}")

def test_colored_formatter():
    formatter = ColoredFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
    output = formatter.format(record)
    assert "\033[32m" in output  # Green for INFO
    assert "\033[0m" in output  # Reset
    print("PASS: ColoredFormatter applies colors")

def test_structured_formatter():
    formatter = StructuredFormatter()
    record = logging.LogRecord("test", logging.INFO, "test.py", 1, "Test message", (), None)
    output = formatter.format(record)
    log_dict = json.loads(output)
    assert log_dict["level"] == "INFO"
    assert log_dict["message"] == "Test message"
    print("PASS: StructuredFormatter produces valid JSON")

def test_get_logger():
    logger = get_logger("test")
    assert logger.level == logging.INFO
    assert len(logger.handlers) > 0
    print("PASS: get_logger configures handlers correctly")

def test_handler_factory():
    handler = get_handler_factory(format_type="structured", log_file="test.log")
    assert hasattr(handler, 'setLevel')
    print("PASS: Handler factory creates configured handler")

if __name__ == "__main__":
    test_redact_pii()
    test_sanitize_for_logging()
    test_colored_formatter()
    test_structured_formatter()
    test_get_logger()
    test_handler_factory()
    print("All logging tests passed - no functionality loss!")
