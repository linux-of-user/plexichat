"""
PlexiChat Input Sanitization System

Comprehensive input validation and sanitization with SQL injection prevention,
XSS protection, command injection prevention, and data validation.
"""

import re
import html
import urllib.parse
import json
import logging
from typing import Any, Dict, List, Optional, Union, Set
from dataclasses import dataclass
from enum import Enum
# Optional import for HTML sanitization
try:
    import bleach
    HAS_BLEACH = True
except ImportError:
    HAS_BLEACH = False
from markupsafe import Markup

logger = logging.getLogger(__name__)


class SanitizationType(Enum):
    """Types of sanitization."""
    HTML = "html"
    SQL = "sql"
    COMMAND = "command"
    URL = "url"
    EMAIL = "email"
    FILENAME = "filename"
    JSON = "json"
    XML = "xml"
    LDAP = "ldap"
    REGEX = "regex"


class ValidationLevel(Enum):
    """Validation strictness levels."""
    PERMISSIVE = 1
    STANDARD = 2
    STRICT = 3
    PARANOID = 4


@dataclass
class SanitizationResult:
    """Result of sanitization operation."""
    original_value: Any
    sanitized_value: Any
    is_safe: bool
    threats_detected: List[str]
    sanitization_applied: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "original_value": str(self.original_value),
            "sanitized_value": str(self.sanitized_value),
            "is_safe": self.is_safe,
            "threats_detected": self.threats_detected,
            "sanitization_applied": self.sanitization_applied
        }


class InputSanitizer:
    """Comprehensive input sanitization system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize input sanitizer."""
        self.config = config or {}
        self.validation_level = ValidationLevel(self.config.get("validation_level", ValidationLevel.STANDARD.value))
        
        # SQL injection patterns
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\b(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(UNION\s+SELECT)",
            r"(INSERT\s+INTO)",
            r"(DROP\s+TABLE)",
            r"(EXEC\s*\()",
            r"(SCRIPT\s*>)",
            r"(\bxp_\w+)",
            r"(\bsp_\w+)"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<iframe[^>]*>.*?</iframe>",
            r"<object[^>]*>.*?</object>",
            r"<embed[^>]*>.*?</embed>",
            r"<applet[^>]*>.*?</applet>",
            r"<meta[^>]*>",
            r"<link[^>]*>",
            r"javascript:",
            r"vbscript:",
            r"data:",
            r"on\w+\s*=",
            r"expression\s*\(",
            r"@import",
            r"<\s*\w+[^>]*\s+on\w+\s*="
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"[;&|`$(){}[\]<>]",
            r"\b(cat|ls|dir|type|copy|move|del|rm|mkdir|rmdir|cd|pwd|whoami|id|ps|kill|chmod|chown|sudo|su)\b",
            r"(&&|\|\||;;)",
            r"(\$\(|\`)",
            r"(>|>>|<|<<)",
            r"(\||&)"
        ]
        
        # File path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c"
        ]
        
        # LDAP injection patterns
        self.ldap_patterns = [
            r"[()&|!*]",
            r"\\[0-9a-fA-F]{2}",
            r"\x00"
        ]
        
        # Allowed HTML tags and attributes for HTML sanitization
        self.allowed_html_tags = [
            'p', 'br', 'strong', 'em', 'u', 'i', 'b', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'a', 'img'
        ]
        
        self.allowed_html_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title', 'width', 'height'],
            '*': ['class', 'id']
        }
        
        logger.info(f"Input Sanitizer initialized with {self.validation_level.name} validation level")
    
    def sanitize(self, value: Any, sanitization_type: SanitizationType) -> SanitizationResult:
        """Sanitize input based on type."""
        if value is None:
            return SanitizationResult(
                original_value=value,
                sanitized_value=value,
                is_safe=True,
                threats_detected=[],
                sanitization_applied=[]
            )
        
        str_value = str(value)
        threats_detected = []
        sanitization_applied = []
        
        try:
            if sanitization_type == SanitizationType.HTML:
                sanitized_value, threats, applied = self._sanitize_html(str_value)
            elif sanitization_type == SanitizationType.SQL:
                sanitized_value, threats, applied = self._sanitize_sql(str_value)
            elif sanitization_type == SanitizationType.COMMAND:
                sanitized_value, threats, applied = self._sanitize_command(str_value)
            elif sanitization_type == SanitizationType.URL:
                sanitized_value, threats, applied = self._sanitize_url(str_value)
            elif sanitization_type == SanitizationType.EMAIL:
                sanitized_value, threats, applied = self._sanitize_email(str_value)
            elif sanitization_type == SanitizationType.FILENAME:
                sanitized_value, threats, applied = self._sanitize_filename(str_value)
            elif sanitization_type == SanitizationType.JSON:
                sanitized_value, threats, applied = self._sanitize_json(str_value)
            elif sanitization_type == SanitizationType.XML:
                sanitized_value, threats, applied = self._sanitize_xml(str_value)
            elif sanitization_type == SanitizationType.LDAP:
                sanitized_value, threats, applied = self._sanitize_ldap(str_value)
            else:
                sanitized_value, threats, applied = self._sanitize_generic(str_value)
            
            threats_detected.extend(threats)
            sanitization_applied.extend(applied)
            
            is_safe = len(threats_detected) == 0
            
            return SanitizationResult(
                original_value=value,
                sanitized_value=sanitized_value,
                is_safe=is_safe,
                threats_detected=threats_detected,
                sanitization_applied=sanitization_applied
            )
            
        except Exception as e:
            logger.error(f"Sanitization error for {sanitization_type.value}: {e}")
            return SanitizationResult(
                original_value=value,
                sanitized_value="",
                is_safe=False,
                threats_detected=[f"Sanitization error: {str(e)}"],
                sanitization_applied=["error_fallback"]
            )
    
    def _sanitize_html(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize HTML content."""
        threats = []
        applied = []
        
        # Check for XSS patterns
        for pattern in self.xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                threats.append(f"XSS pattern detected: {pattern}")
        
        # Use bleach for HTML sanitization if available
        if HAS_BLEACH:
            sanitized = bleach.clean(
                value,
                tags=self.allowed_html_tags,
                attributes=self.allowed_html_attributes,
                strip=True
            )

            if sanitized != value:
                applied.append("html_tag_filtering")
        else:
            # Basic HTML tag removal if bleach not available
            import re
            sanitized = re.sub(r'<[^>]+>', '', value)
            if sanitized != value:
                applied.append("basic_html_tag_removal")
        
        # Additional HTML entity encoding
        sanitized = html.escape(sanitized, quote=True)
        
        if sanitized != value:
            applied.append("html_entity_encoding")
        
        return sanitized, threats, applied
    
    def _sanitize_sql(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize SQL input."""
        threats = []
        applied = []
        
        # Check for SQL injection patterns
        for pattern in self.sql_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                threats.append(f"SQL injection pattern detected: {pattern}")
        
        # Escape SQL special characters
        sanitized = value.replace("'", "''")
        sanitized = sanitized.replace('"', '""')
        sanitized = sanitized.replace('\\', '\\\\')
        sanitized = sanitized.replace('\x00', '')
        sanitized = sanitized.replace('\n', '\\n')
        sanitized = sanitized.replace('\r', '\\r')
        sanitized = sanitized.replace('\x1a', '\\Z')
        
        if sanitized != value:
            applied.append("sql_escaping")
        
        return sanitized, threats, applied
    
    def _sanitize_command(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize command input."""
        threats = []
        applied = []
        
        # Check for command injection patterns
        for pattern in self.command_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                threats.append(f"Command injection pattern detected: {pattern}")
        
        # Remove dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']
        sanitized = value
        
        for char in dangerous_chars:
            if char in sanitized:
                sanitized = sanitized.replace(char, '')
                applied.append(f"removed_char_{ord(char)}")
        
        return sanitized, threats, applied
    
    def _sanitize_url(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize URL input."""
        threats = []
        applied = []
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'vbscript:', 'data:', 'file:', 'ftp:']
        
        for protocol in dangerous_protocols:
            if value.lower().startswith(protocol):
                threats.append(f"Dangerous protocol detected: {protocol}")
        
        # URL encode the value
        sanitized = urllib.parse.quote(value, safe=':/?#[]@!$&\'()*+,;=')
        
        if sanitized != value:
            applied.append("url_encoding")
        
        return sanitized, threats, applied
    
    def _sanitize_email(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize email input."""
        threats = []
        applied = []
        
        # Basic email validation pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            threats.append("Invalid email format")
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\'\\\x00-\x1f\x7f-\x9f]', '', value)
        
        if sanitized != value:
            applied.append("email_character_filtering")
        
        return sanitized, threats, applied
    
    def _sanitize_filename(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize filename input."""
        threats = []
        applied = []
        
        # Check for path traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                threats.append(f"Path traversal pattern detected: {pattern}")
        
        # Remove dangerous characters for filenames
        dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\x00']
        sanitized = value
        
        for char in dangerous_chars:
            if char in sanitized:
                sanitized = sanitized.replace(char, '_')
                applied.append(f"replaced_char_{ord(char)}")
        
        # Limit filename length
        if len(sanitized) > 255:
            sanitized = sanitized[:255]
            applied.append("length_truncation")
        
        return sanitized, threats, applied
    
    def _sanitize_json(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize JSON input."""
        threats = []
        applied = []
        
        try:
            # Try to parse JSON to validate structure
            parsed = json.loads(value)
            
            # Re-serialize to ensure clean JSON
            sanitized = json.dumps(parsed, ensure_ascii=True, separators=(',', ':'))
            
            if sanitized != value:
                applied.append("json_normalization")
            
        except json.JSONDecodeError:
            threats.append("Invalid JSON format")
            sanitized = json.dumps({"error": "Invalid JSON"})
            applied.append("json_error_fallback")
        
        return sanitized, threats, applied
    
    def _sanitize_xml(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize XML input."""
        threats = []
        applied = []
        
        # Check for XML injection patterns
        xml_patterns = [
            r'<!ENTITY',
            r'<!DOCTYPE',
            r'<\?xml',
            r'SYSTEM\s+["\']',
            r'PUBLIC\s+["\']'
        ]
        
        for pattern in xml_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                threats.append(f"XML injection pattern detected: {pattern}")
        
        # Escape XML special characters
        sanitized = html.escape(value, quote=True)
        
        if sanitized != value:
            applied.append("xml_escaping")
        
        return sanitized, threats, applied
    
    def _sanitize_ldap(self, value: str) -> tuple[str, List[str], List[str]]:
        """Sanitize LDAP input."""
        threats = []
        applied = []
        
        # Check for LDAP injection patterns
        for pattern in self.ldap_patterns:
            if re.search(pattern, value):
                threats.append(f"LDAP injection pattern detected: {pattern}")
        
        # Escape LDAP special characters
        ldap_escape_map = {
            '\\': '\\5c',
            '*': '\\2a',
            '(': '\\28',
            ')': '\\29',
            '\x00': '\\00'
        }
        
        sanitized = value
        for char, escape in ldap_escape_map.items():
            if char in sanitized:
                sanitized = sanitized.replace(char, escape)
                applied.append(f"ldap_escape_{ord(char)}")
        
        return sanitized, threats, applied
    
    def _sanitize_generic(self, value: str) -> tuple[str, List[str], List[str]]:
        """Generic sanitization for unknown types."""
        threats = []
        applied = []
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        
        if sanitized != value:
            applied.append("control_character_removal")
        
        return sanitized, threats, applied
    
    def validate_and_sanitize_dict(self, data: Dict[str, Any], field_types: Dict[str, SanitizationType]) -> Dict[str, SanitizationResult]:
        """Validate and sanitize dictionary data."""
        results = {}
        
        for field, value in data.items():
            if field in field_types:
                results[field] = self.sanitize(value, field_types[field])
            else:
                results[field] = self.sanitize(value, SanitizationType.HTML)  # Default to HTML sanitization
        
        return results
    
    def is_safe_input(self, value: Any, sanitization_type: SanitizationType) -> bool:
        """Check if input is safe without sanitizing."""
        result = self.sanitize(value, sanitization_type)
        return result.is_safe
    
    def get_threat_report(self, data: Dict[str, Any], field_types: Dict[str, SanitizationType]) -> Dict[str, Any]:
        """Generate comprehensive threat report for data."""
        results = self.validate_and_sanitize_dict(data, field_types)
        
        total_threats = sum(len(result.threats_detected) for result in results.values())
        unsafe_fields = [field for field, result in results.items() if not result.is_safe]
        
        return {
            "total_fields": len(data),
            "total_threats": total_threats,
            "unsafe_fields": unsafe_fields,
            "field_results": {field: result.to_dict() for field, result in results.items()},
            "overall_safe": total_threats == 0
        }


# Global instance
input_sanitizer = InputSanitizer()
