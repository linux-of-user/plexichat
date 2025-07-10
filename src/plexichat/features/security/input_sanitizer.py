"""
Advanced Input Sanitization System for PlexiChat
Comprehensive input validation and sanitization across all endpoints.
"""

import re
import html
import json
import base64
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Callable
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path

class SanitizationLevel(Enum):
    """Sanitization levels."""
    BASIC = "basic"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"

class InputType(Enum):
    """Input data types."""
    TEXT = "text"
    HTML = "html"
    EMAIL = "email"
    URL = "url"
    FILENAME = "filename"
    USERNAME = "username"
    PASSWORD = "password"
    JSON = "json"
    SQL = "sql"
    COMMAND = "command"
    PATH = "path"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"

@dataclass
class SanitizationResult:
    """Result of sanitization operation."""
    original_value: Any
    sanitized_value: Any
    is_valid: bool
    warnings: List[str]
    errors: List[str]
    applied_rules: List[str]

class AdvancedInputSanitizer:
    """Advanced input sanitization with multiple security layers."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Dangerous patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\b(OR|AND)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)",
            r"(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<form[^>]*>",
            r"<input[^>]*>",
            r"eval\s*\(",
            r"expression\s*\("
        ]
        
        self.command_injection_patterns = [
            r"[;&|`$(){}[\]\\]",
            r"\b(rm|del|format|fdisk|kill|shutdown|reboot)\b",
            r"(>|>>|<|\|)",
            r"\$\{.*\}",
            r"`.*`",
            r"\$\(.*\)"
        ]
        
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c"
        ]
        
        # Allowed characters for different input types
        self.allowed_chars = {
            InputType.USERNAME: r"[a-zA-Z0-9_\-\.@]",
            InputType.FILENAME: r"[a-zA-Z0-9_\-\.\s]",
            InputType.DOMAIN: r"[a-zA-Z0-9\-\.]",
            InputType.IP_ADDRESS: r"[0-9\.]"
        }
        
        # Maximum lengths
        self.max_lengths = {
            InputType.TEXT: 10000,
            InputType.USERNAME: 50,
            InputType.EMAIL: 254,
            InputType.URL: 2048,
            InputType.FILENAME: 255,
            InputType.PASSWORD: 128,
            InputType.PHONE: 20,
            InputType.DOMAIN: 253
        }
    
    def sanitize(self, value: Any, input_type: InputType, level: SanitizationLevel = SanitizationLevel.STANDARD) -> SanitizationResult:
        """Main sanitization method."""
        if value is None:
            return SanitizationResult(
                original_value=value,
                sanitized_value=None,
                is_valid=True,
                warnings=[],
                errors=[],
                applied_rules=[]
            )
        
        # Convert to string if needed
        if not isinstance(value, str):
            value = str(value)
        
        original_value = value
        warnings = []
        errors = []
        applied_rules = []
        
        # Apply sanitization based on type and level
        try:
            # Length check
            max_length = self.max_lengths.get(input_type, 10000)
            if len(value) > max_length:
                value = value[:max_length]
                warnings.append(f"Input truncated to {max_length} characters")
                applied_rules.append("length_limit")
            
            # Type-specific sanitization
            if input_type == InputType.TEXT:
                value = self._sanitize_text(value, level)
                applied_rules.append("text_sanitization")
            
            elif input_type == InputType.HTML:
                value = self._sanitize_html(value, level)
                applied_rules.append("html_sanitization")
            
            elif input_type == InputType.EMAIL:
                value, is_valid = self._sanitize_email(value)
                if not is_valid:
                    errors.append("Invalid email format")
                applied_rules.append("email_validation")
            
            elif input_type == InputType.URL:
                value, is_valid = self._sanitize_url(value)
                if not is_valid:
                    errors.append("Invalid URL format")
                applied_rules.append("url_validation")
            
            elif input_type == InputType.USERNAME:
                value, is_valid = self._sanitize_username(value)
                if not is_valid:
                    errors.append("Invalid username format")
                applied_rules.append("username_validation")
            
            elif input_type == InputType.FILENAME:
                value = self._sanitize_filename(value)
                applied_rules.append("filename_sanitization")
            
            elif input_type == InputType.JSON:
                value, is_valid = self._sanitize_json(value)
                if not is_valid:
                    errors.append("Invalid JSON format")
                applied_rules.append("json_validation")
            
            elif input_type == InputType.PATH:
                value, is_valid = self._sanitize_path(value)
                if not is_valid:
                    errors.append("Invalid or dangerous path")
                applied_rules.append("path_validation")
            
            elif input_type == InputType.IP_ADDRESS:
                value, is_valid = self._sanitize_ip_address(value)
                if not is_valid:
                    errors.append("Invalid IP address format")
                applied_rules.append("ip_validation")
            
            # Security checks based on level
            if level in [SanitizationLevel.STRICT, SanitizationLevel.PARANOID]:
                # SQL injection check
                if self._contains_sql_injection(value):
                    errors.append("Potential SQL injection detected")
                    if level == SanitizationLevel.PARANOID:
                        value = self._remove_sql_patterns(value)
                        applied_rules.append("sql_injection_removal")
                
                # XSS check
                if self._contains_xss(value):
                    errors.append("Potential XSS detected")
                    if level == SanitizationLevel.PARANOID:
                        value = self._remove_xss_patterns(value)
                        applied_rules.append("xss_removal")
                
                # Command injection check
                if self._contains_command_injection(value):
                    errors.append("Potential command injection detected")
                    if level == SanitizationLevel.PARANOID:
                        value = self._remove_command_patterns(value)
                        applied_rules.append("command_injection_removal")
            
            # Final validation
            is_valid = len(errors) == 0
            
            return SanitizationResult(
                original_value=original_value,
                sanitized_value=value,
                is_valid=is_valid,
                warnings=warnings,
                errors=errors,
                applied_rules=applied_rules
            )
            
        except Exception as e:
            self.logger.error(f"Sanitization error: {e}")
            return SanitizationResult(
                original_value=original_value,
                sanitized_value=original_value,
                is_valid=False,
                warnings=[],
                errors=[f"Sanitization failed: {e}"],
                applied_rules=[]
            )
    
    def _sanitize_text(self, value: str, level: SanitizationLevel) -> str:
        """Sanitize plain text."""
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize whitespace
        value = re.sub(r'\s+', ' ', value).strip()
        
        if level in [SanitizationLevel.STRICT, SanitizationLevel.PARANOID]:
            # Remove control characters except common ones
            value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        return value
    
    def _sanitize_html(self, value: str, level: SanitizationLevel) -> str:
        """Sanitize HTML content."""
        if level == SanitizationLevel.BASIC:
            # Just escape HTML entities
            return html.escape(value)
        
        # Remove dangerous tags and attributes
        dangerous_tags = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'meta', 'link']
        for tag in dangerous_tags:
            value = re.sub(f'<{tag}[^>]*>.*?</{tag}>', '', value, flags=re.IGNORECASE | re.DOTALL)
            value = re.sub(f'<{tag}[^>]*/?>', '', value, flags=re.IGNORECASE)
        
        # Remove dangerous attributes
        dangerous_attrs = ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur']
        for attr in dangerous_attrs:
            value = re.sub(f'{attr}\s*=\s*["\'][^"\']*["\']', '', value, flags=re.IGNORECASE)
        
        # Remove javascript: and data: URLs
        value = re.sub(r'javascript:[^"\']*', '', value, flags=re.IGNORECASE)
        value = re.sub(r'data:[^"\']*', '', value, flags=re.IGNORECASE)
        
        return value
    
    def _sanitize_email(self, value: str) -> tuple:
        """Sanitize and validate email."""
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        # Remove whitespace
        value = value.strip()
        
        # Convert to lowercase
        value = value.lower()
        
        # Validate format
        is_valid = re.match(email_pattern, value) is not None
        
        return value, is_valid
    
    def _sanitize_url(self, value: str) -> tuple:
        """Sanitize and validate URL."""
        # Remove whitespace
        value = value.strip()
        
        # Check for valid URL format
        url_pattern = r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
        
        # Basic validation
        is_valid = re.match(url_pattern, value) is not None
        
        # Additional security checks
        if 'javascript:' in value.lower() or 'data:' in value.lower():
            is_valid = False
        
        return value, is_valid
    
    def _sanitize_username(self, value: str) -> tuple:
        """Sanitize and validate username."""
        # Remove whitespace
        value = value.strip()
        
        # Check allowed characters
        allowed_pattern = r'^[a-zA-Z0-9_\-\.@]+$'
        is_valid = re.match(allowed_pattern, value) is not None
        
        # Additional checks
        if len(value) < 3 or len(value) > 50:
            is_valid = False
        
        # Cannot start or end with special characters
        if value.startswith(('.', '-', '_')) or value.endswith(('.', '-', '_')):
            is_valid = False
        
        return value, is_valid
    
    def _sanitize_filename(self, value: str) -> str:
        """Sanitize filename."""
        # Remove path separators
        value = value.replace('/', '').replace('\\', '')
        
        # Remove dangerous characters
        dangerous_chars = '<>:"|?*'
        for char in dangerous_chars:
            value = value.replace(char, '_')
        
        # Remove leading/trailing dots and spaces
        value = value.strip('. ')
        
        # Limit length
        if len(value) > 255:
            name, ext = value.rsplit('.', 1) if '.' in value else (value, '')
            max_name_len = 255 - len(ext) - 1 if ext else 255
            value = name[:max_name_len] + ('.' + ext if ext else '')
        
        return value
    
    def _sanitize_json(self, value: str) -> tuple:
        """Sanitize and validate JSON."""
        try:
            # Parse JSON to validate
            parsed = json.loads(value)
            
            # Re-serialize to normalize
            value = json.dumps(parsed, separators=(',', ':'))
            
            return value, True
        except (json.JSONDecodeError, ValueError):
            return value, False
    
    def _sanitize_path(self, value: str) -> tuple:
        """Sanitize and validate file path."""
        # Check for path traversal
        if any(pattern in value for pattern in ['../', '..\\', '%2e%2e']):
            return value, False
        
        # Normalize path
        try:
            path = Path(value)
            # Check if path is within allowed bounds
            resolved = path.resolve()
            return str(resolved), True
        except (OSError, ValueError):
            return value, False
    
    def _sanitize_ip_address(self, value: str) -> tuple:
        """Sanitize and validate IP address."""
        import ipaddress
        
        try:
            # This will raise ValueError if invalid
            ip = ipaddress.ip_address(value.strip())
            return str(ip), True
        except ValueError:
            return value, False
    
    def _contains_sql_injection(self, value: str) -> bool:
        """Check for SQL injection patterns."""
        value_lower = value.lower()
        return any(re.search(pattern, value_lower, re.IGNORECASE) for pattern in self.sql_injection_patterns)
    
    def _contains_xss(self, value: str) -> bool:
        """Check for XSS patterns."""
        value_lower = value.lower()
        return any(re.search(pattern, value_lower, re.IGNORECASE) for pattern in self.xss_patterns)
    
    def _contains_command_injection(self, value: str) -> bool:
        """Check for command injection patterns."""
        return any(re.search(pattern, value, re.IGNORECASE) for pattern in self.command_injection_patterns)
    
    def _remove_sql_patterns(self, value: str) -> str:
        """Remove SQL injection patterns."""
        for pattern in self.sql_injection_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        return value
    
    def _remove_xss_patterns(self, value: str) -> str:
        """Remove XSS patterns."""
        for pattern in self.xss_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        return value
    
    def _remove_command_patterns(self, value: str) -> str:
        """Remove command injection patterns."""
        for pattern in self.command_injection_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        return value
    
    def sanitize_dict(self, data: Dict[str, Any], field_types: Dict[str, InputType], 
                     level: SanitizationLevel = SanitizationLevel.STANDARD) -> Dict[str, Any]:
        """Sanitize all fields in a dictionary."""
        sanitized_data = {}
        
        for key, value in data.items():
            if key in field_types:
                result = self.sanitize(value, field_types[key], level)
                if result.is_valid:
                    sanitized_data[key] = result.sanitized_value
                else:
                    self.logger.warning(f"Invalid input for field {key}: {result.errors}")
                    # You might want to raise an exception here instead
                    sanitized_data[key] = result.sanitized_value
            else:
                # Default to text sanitization for unknown fields
                result = self.sanitize(value, InputType.TEXT, level)
                sanitized_data[key] = result.sanitized_value
        
        return sanitized_data

# Global sanitizer instance
input_sanitizer = AdvancedInputSanitizer()

# Decorator for automatic input sanitization
def sanitize_input(field_types: Dict[str, InputType], level: SanitizationLevel = SanitizationLevel.STANDARD):
    """Decorator to automatically sanitize request data."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would need to be integrated with FastAPI request handling
            # For now, it's a placeholder for the concept
            return func(*args, **kwargs)
        return wrapper
    return decorator
