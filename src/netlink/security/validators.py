"""
NetLink Security Validators

Input validation and security checking utilities.
"""

import re
import logging
from typing import Tuple, List, Optional, Dict, Any

from .exceptions import ValidationError

logger = logging.getLogger(__name__)


class PasswordValidator:
    """Password strength and policy validation."""
    
    def __init__(self):
        self.min_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_symbols = True
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123'
        }
    
    def validate(self, password: str, username: Optional[str] = None) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if self.require_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one symbol")
        
        if password.lower() in self.common_passwords:
            errors.append("Password is too common")
        
        if username and username.lower() in password.lower():
            errors.append("Password cannot contain username")
        
        return len(errors) == 0, errors


class TokenValidator:
    """JWT token validation."""
    
    def __init__(self):
        self.algorithm = "HS256"
        self.secret_key = "your-secret-key"  # Should be loaded from config
    
    def validate(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate JWT token.
        
        Returns:
            Tuple of (is_valid, token_data)
        """
        # JWT validation implementation would go here
        # This is a placeholder
        return True, {"username": "user", "exp": 1234567890}


class BiometricValidator:
    """Biometric data validation."""
    
    def __init__(self):
        self.min_quality_score = 0.8
        self.max_template_size = 1024 * 1024  # 1MB
    
    def validate_fingerprint(self, template_data: bytes) -> Tuple[bool, Optional[str]]:
        """Validate fingerprint template data."""
        if len(template_data) > self.max_template_size:
            return False, "Fingerprint template too large"
        
        # Additional validation would go here
        return True, None
    
    def validate_face(self, image_data: bytes) -> Tuple[bool, Optional[str]]:
        """Validate face recognition data."""
        if len(image_data) > self.max_template_size:
            return False, "Face image too large"
        
        # Additional validation would go here
        return True, None


class InputValidator:
    """General input validation and sanitization."""
    
    def __init__(self):
        self.max_string_length = 10000
        self.allowed_file_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.doc', '.docx'}
    
    def validate_string(self, value: str, field_name: str = "input") -> Tuple[bool, Optional[str]]:
        """Validate string input."""
        if not isinstance(value, str):
            return False, f"{field_name} must be a string"
        
        if len(value) > self.max_string_length:
            return False, f"{field_name} exceeds maximum length of {self.max_string_length}"
        
        return True, None
    
    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """Validate email address format."""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        return True, None
    
    def validate_filename(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Validate uploaded filename."""
        if not filename:
            return False, "Filename cannot be empty"
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, "Invalid filename - path traversal detected"
        
        # Check file extension
        extension = '.' + filename.split('.')[-1].lower() if '.' in filename else ''
        if extension not in self.allowed_file_extensions:
            return False, f"File extension {extension} not allowed"
        
        return True, None
