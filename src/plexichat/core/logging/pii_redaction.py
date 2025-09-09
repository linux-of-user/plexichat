"""
Thin wrapper for PII redaction - all functionality now in unified_logger.py
"""

from .unified_logger import is_sensitive_field, redact_pii, sanitize_log_message

__all__ = ["redact_pii", "sanitize_log_message", "is_sensitive_field"]
