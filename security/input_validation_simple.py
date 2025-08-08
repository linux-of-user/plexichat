import re
import html
import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class InputType(Enum):
    """Input data types for validation."""
    TEXT = "text"
    EMAIL = "email"
    URL = "url"
    PHONE = "phone"
    PASSWORD = "password"
    USERNAME = "username"
    NUMERIC = "numeric"
    ALPHANUMERIC = "alphanumeric"
    JSON = "json"
    HTML = "html"
    SQL = "sql"


class SecurityLevel(Enum):
    """Security validation levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: Any
    errors: List[str]
    warnings: List[str]
    security_level: SecurityLevel
    metadata: Dict[str, Any]


class InputValidator:
    """Simplified input validation and sanitization."""
    
    def __init__(self):
        self.patterns = {
            InputType.EMAIL: re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            InputType.URL: re.compile(r'^https?://[^\s/$.?#].[^\s]*$'),
            InputType.PHONE: re.compile(r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'),
            InputType.USERNAME: re.compile(r'^[a-zA-Z0-9_]{3,20}$'),
            InputType.ALPHANUMERIC: re.compile(r'^[a-zA-Z0-9]+$'),
            InputType.NUMERIC: re.compile(r'^[0-9]+$')
        }
        
        # Common attack patterns
        self.attack_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'(union|select|insert|update|delete|drop|create|alter)\s+', re.IGNORECASE),
            re.compile(r'(\||&|;|`|\$\(|\${)', re.IGNORECASE)
        ]
    
    def validate_input(self, value: Any, input_type: InputType, 
                      security_level: SecurityLevel = SecurityLevel.MEDIUM,
                      max_length: Optional[int] = None,
                      min_length: Optional[int] = None,
                      custom_pattern: Optional[str] = None) -> ValidationResult:
        """Validate and sanitize input value."""
        errors = []
        warnings = []
        sanitized_value = value
        
        try:
            # Convert to string for validation
            if not isinstance(value, str):
                value = str(value)
            
            # Length validation
            if max_length and len(value) > max_length:
                errors.append(f"Input exceeds maximum length of {max_length}")
            
            if min_length and len(value) < min_length:
                errors.append(f"Input below minimum length of {min_length}")
            
            # Security pattern checks
            for pattern in self.attack_patterns:
                if pattern.search(value):
                    errors.append("Potentially malicious content detected")
                    break
            
            # Type-specific validation
            if input_type in self.patterns:
                if not self.patterns[input_type].match(value):
                    errors.append(f"Invalid format for {input_type.value}")
            
            # Custom pattern validation
            if custom_pattern:
                if not re.match(custom_pattern, value):
                    errors.append("Input does not match required pattern")
            
            # Sanitization
            sanitized_value = self._sanitize_input(value, input_type, security_level)
            
            # Additional security checks based on level
            if security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                additional_warnings = self._advanced_security_checks(value)
                warnings.extend(additional_warnings)
            
            return ValidationResult(
                is_valid=len(errors) == 0,
                sanitized_value=sanitized_value,
                errors=errors,
                warnings=warnings,
                security_level=security_level,
                metadata={"original_length": len(str(value)), "sanitized_length": len(str(sanitized_value))}
            )
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return ValidationResult(
                is_valid=False,
                sanitized_value=value,
                errors=[f"Validation failed: {str(e)}"],
                warnings=[],
                security_level=security_level,
                metadata={}
            )
    
    def _sanitize_input(self, value: str, input_type: InputType, security_level: SecurityLevel) -> str:
        """Sanitize input based on type and security level."""
        sanitized = value
        
        # HTML escaping for web content
        if input_type in [InputType.HTML, InputType.TEXT]:
            sanitized = html.escape(sanitized)
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        # Additional sanitization for high security
        if security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            # Remove control characters
            sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
            
            # Limit special characters
            if input_type == InputType.TEXT:
                sanitized = re.sub(r'[<>"\']', '', sanitized)
        
        return sanitized
    
    def _advanced_security_checks(self, value: str) -> List[str]:
        """Perform advanced security checks."""
        warnings = []
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'\.\./', "Path traversal attempt"),
            (r'%[0-9a-fA-F]{2}', "URL encoding detected"),
            (r'\\x[0-9a-fA-F]{2}', "Hex encoding detected"),
            (r'eval\s*\(', "Code evaluation attempt"),
            (r'exec\s*\(', "Code execution attempt")
        ]
        
        for pattern, message in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                warnings.append(message)
        
        return warnings
    
    def validate_password(self, password: str) -> ValidationResult:
        """Validate password strength."""
        errors = []
        warnings = []
        score = 0
        
        # Length check
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        else:
            score += 1
        
        # Character variety checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            warnings.append("Password should contain lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            warnings.append("Password should contain uppercase letters")
        
        if re.search(r'[0-9]', password):
            score += 1
        else:
            warnings.append("Password should contain numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            warnings.append("Password should contain special characters")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in common_passwords:
            errors.append("Password is too common")
        
        # Determine strength
        if score >= 4:
            strength = "strong"
        elif score >= 3:
            strength = "medium"
        else:
            strength = "weak"
            if not errors:
                errors.append("Password is too weak")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_value=password,  # Don't sanitize passwords
            errors=errors,
            warnings=warnings,
            security_level=SecurityLevel.HIGH,
            metadata={"strength": strength, "score": score}
        )
    
    def validate_email(self, email: str) -> ValidationResult:
        """Validate email address."""
        return self.validate_input(email, InputType.EMAIL, SecurityLevel.MEDIUM)
    
    def validate_url(self, url: str) -> ValidationResult:
        """Validate URL."""
        result = self.validate_input(url, InputType.URL, SecurityLevel.HIGH)
        
        # Additional URL security checks
        if result.is_valid:
            # Check for suspicious domains
            suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl']
            for domain in suspicious_domains:
                if domain in url.lower():
                    result.warnings.append(f"Shortened URL detected: {domain}")
        
        return result
    
    def validate_json(self, json_str: str) -> ValidationResult:
        """Validate JSON string."""
        import json
        
        try:
            parsed = json.loads(json_str)
            return ValidationResult(
                is_valid=True,
                sanitized_value=json.dumps(parsed),  # Re-serialize to normalize
                errors=[],
                warnings=[],
                security_level=SecurityLevel.MEDIUM,
                metadata={"parsed_type": type(parsed).__name__}
            )
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                sanitized_value=json_str,
                errors=[f"Invalid JSON: {str(e)}"],
                warnings=[],
                security_level=SecurityLevel.MEDIUM,
                metadata={}
            )
    
    def sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content by removing dangerous elements."""
        # Remove script tags
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove dangerous attributes
        html_content = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
        
        # Remove javascript: URLs
        html_content = re.sub(r'javascript:[^"\']*', '', html_content, flags=re.IGNORECASE)
        
        return html_content
    
    def validate_batch(self, data: Dict[str, Any], field_types: Dict[str, InputType],
                      security_level: SecurityLevel = SecurityLevel.MEDIUM) -> Dict[str, ValidationResult]:
        """Validate multiple fields at once."""
        results = {}
        
        for field_name, value in data.items():
            if field_name in field_types:
                input_type = field_types[field_name]
                results[field_name] = self.validate_input(value, input_type, security_level)
            else:
                # Default to text validation
                results[field_name] = self.validate_input(value, InputType.TEXT, security_level)
        
        return results


# Global validator instance
_validator: Optional[InputValidator] = None


def get_input_validator() -> InputValidator:
    """Get the global input validator instance."""
    global _validator
    if _validator is None:
        _validator = InputValidator()
    return _validator


def validate_input(value: Any, input_type: InputType, 
                  security_level: SecurityLevel = SecurityLevel.MEDIUM) -> ValidationResult:
    """Convenience function for input validation."""
    return get_input_validator().validate_input(value, input_type, security_level)


def sanitize_html(html_content: str) -> str:
    """Convenience function for HTML sanitization."""
    return get_input_validator().sanitize_html(html_content)
