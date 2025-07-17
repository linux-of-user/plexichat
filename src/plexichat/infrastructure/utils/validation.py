# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Validation Utilities

Enhanced validation utilities with comprehensive checks and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# Pydantic imports
try:
    from pydantic import BaseModel, validator, ValidationError
except ImportError:
    BaseModel = object
    validator = lambda *args, **kwargs: lambda f: f
    ValidationError = Exception

# Use EXISTING performance optimization engine
try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None

logger = logging.getLogger(__name__)

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None

class ValidationUtilities:
    """Enhanced validation utilities using EXISTING systems."""
    
    def __init__(self):
        self.performance_logger = performance_logger
    
    def validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email address."""
        try:
            result = {"valid": True, "errors": []}
            
            if not email or not email.strip():
                result["valid"] = False
                result["errors"].append("Email cannot be empty")
                return result
            
            # Basic email regex
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email.strip()):
                result["valid"] = False
                result["errors"].append("Invalid email format")
            
            # Length check
            if len(email) > 254:
                result["valid"] = False
                result["errors"].append("Email too long")
            
            # Domain check
            if '@' in email:
                local, domain = email.rsplit('@', 1)
                if len(local) > 64:
                    result["valid"] = False
                    result["errors"].append("Local part too long")
                
                if len(domain) > 253:
                    result["valid"] = False
                    result["errors"].append("Domain too long")
            
            return result
        except Exception as e:
            logger.error(f"Email validation error: {e}")
            return {"valid": False, "errors": ["Validation error"]}
    
    def validate_username(self, username: str) -> Dict[str, Any]:
        """Validate username."""
        try:
            result = {"valid": True, "errors": []}
            
            if not username or not username.strip():
                result["valid"] = False
                result["errors"].append("Username cannot be empty")
                return result
            
            username = username.strip()
            
            # Length check
            if len(username) < 3:
                result["valid"] = False
                result["errors"].append("Username must be at least 3 characters")
            
            if len(username) > 50:
                result["valid"] = False
                result["errors"].append("Username cannot exceed 50 characters")
            
            # Character check
            if not re.match(r'^[a-zA-Z0-9_-]+$', username):
                result["valid"] = False
                result["errors"].append("Username can only contain letters, numbers, underscores, and hyphens")
            
            # Reserved usernames
            reserved = ['admin', 'root', 'system', 'api', 'www', 'mail', 'ftp']
            if username.lower() in reserved:
                result["valid"] = False
                result["errors"].append("Username is reserved")
            
            return result
        except Exception as e:
            logger.error(f"Username validation error: {e}")
            return {"valid": False, "errors": ["Validation error"]}
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """Validate password strength."""
        try:
            result = {"valid": True, "errors": [], "score": 0, "strength": "weak"}
            
            if not password:
                result["valid"] = False
                result["errors"].append("Password cannot be empty")
                return result
            
            # Length check
            if len(password) < 6:
                result["valid"] = False
                result["errors"].append("Password must be at least 6 characters")
            else:
                result["score"] += 1
            
            if len(password) >= 8:
                result["score"] += 1
            
            if len(password) >= 12:
                result["score"] += 1
            
            # Character variety
            if re.search(r'[a-z]', password):
                result["score"] += 1
            else:
                result["errors"].append("Include lowercase letters")
            
            if re.search(r'[A-Z]', password):
                result["score"] += 1
            else:
                result["errors"].append("Include uppercase letters")
            
            if re.search(r'\d', password):
                result["score"] += 1
            else:
                result["errors"].append("Include numbers")
            
            if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                result["score"] += 2
            else:
                result["errors"].append("Include special characters")
            
            # Common passwords
            common = ['password', '123456', 'qwerty', 'admin', 'letmein']
            if password.lower() in common:
                result["valid"] = False
                result["errors"].append("Password is too common")
                result["score"] = 0
            
            # Determine strength
            if result["score"] >= 7:
                result["strength"] = "strong"
            elif result["score"] >= 5:
                result["strength"] = "medium"
            else:
                result["strength"] = "weak"
            
            return result
        except Exception as e:
            logger.error(f"Password validation error: {e}")
            return {"valid": False, "errors": ["Validation error"], "score": 0, "strength": "unknown"}
    
    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> Dict[str, Any]:
        """Validate file upload."""
        try:
            result = {"valid": True, "errors": [], "warnings": []}
            
            # Filename validation
            if not filename or not filename.strip():
                result["valid"] = False
                result["errors"].append("Filename cannot be empty")
                return result
            
            # File extension check
            allowed_extensions = {
                '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',  # Images
                '.pdf', '.txt', '.doc', '.docx', '.rtf', '.odt',  # Documents
                '.mp3', '.wav', '.ogg', '.m4a', '.flac',  # Audio
                '.mp4', '.avi', '.mov', '.webm', '.mkv',  # Video
                '.zip', '.tar', '.gz', '.7z', '.rar'  # Archives
            }
            
            import os
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in allowed_extensions:
                result["valid"] = False
                result["errors"].append(f"File extension {file_ext} not allowed")
            
            # File size check (100MB limit)
            max_size = 100 * 1024 * 1024
            if file_size > max_size:
                result["valid"] = False
                result["errors"].append(f"File size exceeds {max_size // (1024*1024)}MB limit")
            
            # Filename security check
            dangerous_patterns = [
                r'\.\./',  # Directory traversal
                r'[<>:"/\\|?*]',  # Invalid characters
                r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$',  # Windows reserved
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, filename, re.IGNORECASE):
                    result["valid"] = False
                    result["errors"].append("Filename contains dangerous patterns")
                    break
            
            # Content type validation
            allowed_content_types = {
                'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
                'application/pdf', 'text/plain', 'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'audio/mpeg', 'audio/wav', 'audio/ogg',
                'video/mp4', 'video/avi', 'video/quicktime', 'video/webm',
                'application/zip', 'application/x-tar', 'application/gzip'
            }
            
            if content_type not in allowed_content_types:
                result["warnings"].append(f"Content type {content_type} may not be safe")
            
            return result
        except Exception as e:
            logger.error(f"File validation error: {e}")
            return {"valid": False, "errors": ["Validation error"], "warnings": []}
    
    def validate_url(self, url: str) -> Dict[str, Any]:
        """Validate URL."""
        try:
            result = {"valid": True, "errors": []}
            
            if not url or not url.strip():
                result["valid"] = False
                result["errors"].append("URL cannot be empty")
                return result
            
            # Basic URL pattern
            url_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
            if not re.match(url_pattern, url.strip()):
                result["valid"] = False
                result["errors"].append("Invalid URL format")
            
            # Length check
            if len(url) > 2048:
                result["valid"] = False
                result["errors"].append("URL too long")
            
            # Security check
            dangerous_patterns = [
                r'javascript:',
                r'vbscript:',
                r'data:',
                r'file:',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    result["valid"] = False
                    result["errors"].append("URL contains dangerous protocol")
                    break
            
            return result
        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return {"valid": False, "errors": ["Validation error"]}
    
    def sanitize_input(self, input_data: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        try:
            if not input_data:
                return ""
            
            # HTML escape
            import html
            sanitized = html.escape(input_data.strip())
            
            # Truncate if too long
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length]
            
            # Remove dangerous patterns
            dangerous_patterns = [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'vbscript:',
                r'onload=',
                r'onerror=',
                r'onclick=',
            ]
            
            for pattern in dangerous_patterns:
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            return sanitized
        except Exception as e:
            logger.error(f"Input sanitization error: {e}")
            return str(input_data)[:max_length] if input_data else ""
    
    def validate_json(self, json_data: str) -> Dict[str, Any]:
        """Validate JSON data."""
        try:
            import json
            
            result = {"valid": True, "errors": [], "data": None}
            
            if not json_data or not json_data.strip():
                result["valid"] = False
                result["errors"].append("JSON data cannot be empty")
                return result
            
            try:
                parsed_data = json.loads(json_data)
                result["data"] = parsed_data
            except json.JSONDecodeError as e:
                result["valid"] = False
                result["errors"].append(f"Invalid JSON: {str(e)}")
            
            return result
        except Exception as e:
            logger.error(f"JSON validation error: {e}")
            return {"valid": False, "errors": ["Validation error"], "data": None}

# Global validation utilities
validation_utils = ValidationUtilities()

# Convenience functions
def validate_email(email: str) -> Dict[str, Any]:
    """Validate email address."""
    return validation_utils.validate_email(email)

def validate_username(username: str) -> Dict[str, Any]:
    """Validate username."""
    return validation_utils.validate_username(username)

def validate_password(password: str) -> Dict[str, Any]:
    """Validate password."""
    return validation_utils.validate_password(password)

def validate_file_upload(filename: str, content_type: str, file_size: int) -> Dict[str, Any]:
    """Validate file upload."""
    return validation_utils.validate_file_upload(filename, content_type, file_size)

def validate_url(url: str) -> Dict[str, Any]:
    """Validate URL."""
    return validation_utils.validate_url(url)

def sanitize_input(input_data: str, max_length: int = 1000) -> str:
    """Sanitize user input."""
    return validation_utils.sanitize_input(input_data, max_length)

def validate_json(json_data: str) -> Dict[str, Any]:
    """Validate JSON data."""
    return validation_utils.validate_json(json_data)

# Validation decorators
def validate_input(validation_func: callable, error_message: str = "Invalid input"):
    """Decorator to validate function input."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Validate first argument
            if args:
                validation_result = validation_func(args[0])
                if not validation_result.get("valid", False):
                    raise ValueError(f"{error_message}: {validation_result.get('errors', [])}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Common validation patterns
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
USERNAME_PATTERN = r'^[a-zA-Z0-9_-]{3,50}$'
URL_PATTERN = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
PHONE_PATTERN = r'^\+?[1-9]\d{1,14}$'

def is_valid_email(email: str) -> bool:
    """Quick email validation."""
    return bool(re.match(EMAIL_PATTERN, email)) if email else False

def is_valid_username(username: str) -> bool:
    """Quick username validation."""
    return bool(re.match(USERNAME_PATTERN, username)) if username else False

def is_valid_url(url: str) -> bool:
    """Quick URL validation."""
    return bool(re.match(URL_PATTERN, url)) if url else False

def is_valid_phone(phone: str) -> bool:
    """Quick phone validation."""
    return bool(re.match(PHONE_PATTERN, phone)) if phone else False
