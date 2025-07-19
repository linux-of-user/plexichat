# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import warnings
Enhanced Input Validation System
Provides comprehensive input validation and sanitization to prevent XSS, SQL injection, and other attacks.
"""

import re
import html
import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Input validation security levels."""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


class ThreatType(Enum):
    """Types of security threats."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    SCRIPT_INJECTION = "script_injection"
    HTML_INJECTION = "html_injection"


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: Any
    threats_detected: List[ThreatType]
    confidence_score: float
    warnings: List[str]
    original_value: Any


class EnhancedInputValidator:
    """Enhanced input validation with comprehensive threat detection."""

    def __init__(self):
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>.*?</style>',
            r'expression\s*\(',)
            r'url\s*\(',)
            r'@import',
            r'<svg[^>]*>.*?</svg>',
        ]

        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\b(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(--|#|/\*|\*/)",
            r"(\bUNION\s+SELECT\b)",
            r"(\bINTO\s+OUTFILE\b)",
            r"(\bLOAD_FILE\s*\()",)
            r"(\bCHAR\s*\()",)
            r"(\bCONCAT\s*\()",)
            r"(\bSUBSTRING\s*\()",)
            r"(\bCAST\s*\()",)
            r"(\bCONVERT\s*\()",)
            r"(\bHEX\s*\()",)
            r"(\bUNHEX\s*\()",)
            r"(\bASCII\s*\()",)
            r"(\bBENCHMARK\s*\()",)
            r"(\bSLEEP\s*\()",)
            r"(\bWAITFOR\s+DELAY\b)",
        ]

        self.command_injection_patterns = [
            r"(\||&|;|`|\$\(|\${)",)
            r"(\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp)\b)",
            r"(\.\.\/|\.\.\\)",
            r"(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)",
            r"(\beval\s*\()",)
            r"(\bexec\s*\()",)
            r"(\bsystem\s*\()",)
            r"(\bshell_exec\s*\()",)
            r"(\bpassthru\s*\()",)
            r"(\bpopen\s*\()",)
            r"(\bproc_open\s*\()",)
        ]

        self.path_traversal_patterns = [
            r"(\.\.\/|\.\.\\)",
            r"(%2e%2e%2f|%2e%2e%5c)",
            r"(%252e%252e%252f|%252e%252e%255c)",
            r"(\.\.%2f|\.\.%5c)",
            r"(%2e%2e\/|%2e%2e\\)",
        ]

        # Compile patterns for better performance
        self.compiled_patterns = {
            ThreatType.XSS: [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in self.xss_patterns],
            ThreatType.SQL_INJECTION: [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_injection_patterns],
            ThreatType.COMMAND_INJECTION: [re.compile(pattern, re.IGNORECASE) for pattern in self.command_injection_patterns],
            ThreatType.PATH_TRAVERSAL: [re.compile(pattern, re.IGNORECASE) for pattern in self.path_traversal_patterns],
        }

    def validate_input(self, value: Any, validation_level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
        """Validate and sanitize input with threat detection."""
        if value is None:
            return ValidationResult()
                is_valid=True,
                sanitized_value=None,
                threats_detected=[],
                confidence_score=1.0,
                warnings=[],
                original_value=value
            )

        original_value = value
        threats_detected = []
        warnings = []
        confidence_score = 1.0

        # Convert to string for analysis
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                return ValidationResult()
                    is_valid=False,
                    sanitized_value=None,
                    threats_detected=[],
                    confidence_score=0.0,
                    warnings=["Unable to convert value to string"],
                    original_value=original_value
                )

        # Detect threats
        for threat_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(value):
                    threats_detected.append(threat_type)
                    confidence_score -= 0.2
                    break

        # Sanitize based on validation level
        sanitized_value = self._sanitize_value(value, validation_level, threats_detected)

        # Additional checks based on validation level
        if validation_level in [ValidationLevel.STRICT, ValidationLevel.PARANOID]:
            # Check for encoded attacks
            decoded_value = self._decode_value(value)
            if decoded_value != value:
                warnings.append("Encoded content detected")
                # Re-check decoded value
                for threat_type, patterns in self.compiled_patterns.items():
                    for pattern in patterns:
                        if pattern.search(decoded_value):
                            if threat_type not in threats_detected:
                                threats_detected.append(threat_type)
                                confidence_score -= 0.1

        is_valid = len(threats_detected) == 0 or validation_level == ValidationLevel.BASIC

        return ValidationResult()
            is_valid=is_valid,
            sanitized_value=sanitized_value,
            threats_detected=threats_detected,
            confidence_score=max(0.0, confidence_score),
            warnings=warnings,
            original_value=original_value
        )

    def _sanitize_value(self, value: str, level: ValidationLevel, threats: List[ThreatType]) -> str:
        """Sanitize value based on validation level and detected threats."""
        sanitized = value

        if ThreatType.XSS in threats or level in [ValidationLevel.STRICT, ValidationLevel.PARANOID]:
            # HTML escape
            sanitized = html.escape(sanitized, quote=True)

            # Remove dangerous attributes and tags
            sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'vbscript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'on\w+\s*=', '', sanitized, flags=re.IGNORECASE)

        if ThreatType.SQL_INJECTION in threats:
            # Escape SQL special characters
            sanitized = sanitized.replace("'", "''")
            sanitized = sanitized.replace('"', '""')
            sanitized = sanitized.replace('\\', '\\\\')

        if ThreatType.COMMAND_INJECTION in threats:
            # Remove command injection characters
            dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '{', '}']
            for char in dangerous_chars:
                sanitized = sanitized.replace(char, '')

        if ThreatType.PATH_TRAVERSAL in threats:
            # Remove path traversal sequences
            sanitized = sanitized.replace('../', '')
            sanitized = sanitized.replace('..\\', '')
            sanitized = urllib.parse.quote(sanitized, safe='')

        return sanitized

    def _decode_value(self, value: str) -> str:
        """Decode various encoding schemes to detect hidden attacks."""
        decoded = value

        try:
            # URL decode
            decoded = urllib.parse.unquote(decoded)
            decoded = urllib.parse.unquote_plus(decoded)

            # HTML decode
            decoded = html.unescape(decoded)

            # Base64 decode (if it looks like base64)
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', decoded) and len(decoded) % 4 == 0:
                try:
                    import base64
                    decoded_bytes = base64.b64decode(decoded)
                    decoded = decoded_bytes.decode('utf-8', errors='ignore')
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error decoding value: {e}")

        return decoded

    def validate_json(self, json_str: str) -> ValidationResult:
        """Validate JSON input."""
        try:
            parsed = json.loads(json_str)
            return ValidationResult()
                is_valid=True,
                sanitized_value=parsed,
                threats_detected=[],
                confidence_score=1.0,
                warnings=[],
                original_value=json_str
            )
        except json.JSONDecodeError as e:
            return ValidationResult()
                is_valid=False,
                sanitized_value=None,
                threats_detected=[],
                confidence_score=0.0,
                warnings=[f"Invalid JSON: {str(e)}"],
                original_value=json_str
            )

    def validate_email(self, email: str) -> ValidationResult:
        """Validate email address."""
        email_pattern = re.compile()
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )

        is_valid = bool(email_pattern.match(email))

        return ValidationResult()
            is_valid=is_valid,
            sanitized_value=email.lower().strip() if is_valid else None,
            threats_detected=[],
            confidence_score=1.0 if is_valid else 0.0,
            warnings=[] if is_valid else ["Invalid email format"],
            original_value=email
        )


# Global validator instance
_validator = None


def get_input_validator() -> EnhancedInputValidator:
    """Get the global input validator instance."""
    global _validator
    if _validator is None:
        _validator = EnhancedInputValidator()
    return _validator
