"""
Thin wrapper for PII redaction - all functionality now in unified_logger.py
"""

from .unified_logger import redact_pii, sanitize_log_message, is_sensitive_field

__all__ = ["redact_pii", "sanitize_log_message", "is_sensitive_field"]
