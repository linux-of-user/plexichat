# app/config/config_manager.py
"""
Comprehensive configuration management system with validation,
environment variable handling, and configuration documentation.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Type
from dataclasses import dataclass, field
from enum import Enum

from app.logger_config import logger


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


class LogLevel(Enum):
    """Valid log levels."""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class ConfigOption:
    """Configuration option definition with validation and documentation."""
    name: str
    default: Any
    description: str
    type_hint: Type = str
    required: bool = False
    choices: Optional[List[Any]] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    env_var: Optional[str] = None
    
    def __post_init__(self):
        if self.env_var is None:
            self.env_var = self.name.upper()
    
    def validate(self, value: Any) -> Any:
        """Validate and convert configuration value."""
        if value is None:
            if self.required:
                raise ConfigValidationError(f"Required configuration option '{self.name}' is missing")
            return self.default
        
        # Type conversion
        try:
            if self.type_hint == bool:
                if isinstance(value, str):
                    value = value.lower() in ("true", "1", "yes", "on")
                else:
                    value = bool(value)
            elif self.type_hint == int:
                value = int(value)
            elif self.type_hint == float:
                value = float(value)
            elif self.type_hint == str:
                value = str(value)
        except (ValueError, TypeError) as e:
            raise ConfigValidationError(f"Invalid type for '{self.name}': {e}")
        
        # Choices validation
        if self.choices and value not in self.choices:
            raise ConfigValidationError(f"Invalid choice for '{self.name}': {value}. Must be one of {self.choices}")
        
        # Range validation
        if self.min_value is not None and value < self.min_value:
            raise ConfigValidationError(f"Value for '{self.name}' ({value}) is below minimum ({self.min_value})")
        
        if self.max_value is not None and value > self.max_value:
            raise ConfigValidationError(f"Value for '{self.name}' ({value}) is above maximum ({self.max_value})")
        
        # Pattern validation (for strings)
        if self.pattern and isinstance(value, str):
            import re
            if not re.match(self.pattern, value):
                raise ConfigValidationError(f"Value for '{self.name}' does not match required pattern: {self.pattern}")
        
        return value


class ConfigurationManager:
    """Comprehensive configuration management system."""
    
    def __init__(self):
        self.config_options: Dict[str, ConfigOption] = {}
        self.config_values: Dict[str, Any] = {}
        self._define_configuration_schema()
        self._load_configuration()
    
    def _define_configuration_schema(self):
        """Define the complete configuration schema."""
        
        # Core Application Settings
        self._add_option("SECRET_KEY", "", "JWT signing secret key", str, required=True)
        self._add_option("WEBHOOK_SECRET", "", "Webhook validation secret", str, required=True)
        self._add_option("HOST", "0.0.0.0", "Server host address", str)
        self._add_option("PORT", 8000, "Server port number", int, min_value=1, max_value=65535)
        self._add_option("API_VERSION", "v1", "API version string", str)
        self._add_option("DEBUG", False, "Enable debug mode", bool)
        
        # Database Configuration
        self._add_option("DATABASE_URL", "", "Complete database connection URL", str, required=True)
        self._add_option("DB_HOST", "", "Database host (optional if DATABASE_URL is complete)", str)
        self._add_option("DB_PORT", 5432, "Database port", int, min_value=1, max_value=65535)
        
        # Authentication & Security
        self._add_option("ACCESS_TOKEN_EXPIRE_MINUTES", 30, "JWT token expiration time in minutes", int, min_value=1)
        self._add_option("RATE_LIMIT_REQUESTS", 100, "Rate limit: requests per window", int, min_value=1)
        self._add_option("RATE_LIMIT_WINDOW", 60, "Rate limit: time window in seconds", int, min_value=1)
        
        # SSL Configuration
        self._add_option("SSL_KEYFILE", None, "Path to SSL private key file", str)
        self._add_option("SSL_CERTFILE", None, "Path to SSL certificate file", str)
        
        # Enhanced Logging Configuration
        self._add_option("LOG_LEVEL", "DEBUG", "Default log level", str, choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._add_option("LOG_TO_CONSOLE", True, "Enable console logging", bool)
        self._add_option("LOG_TO_FILE", True, "Enable file logging", bool)
        self._add_option("LOG_CONSOLE_LEVEL", "INFO", "Console log level", str, choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._add_option("LOG_FILE_LEVEL", "DEBUG", "File log level", str, choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._add_option("LOG_DIR", "logs", "Log directory path", str)
        self._add_option("LOG_MAX_BYTES", 10485760, "Maximum log file size in bytes", int, min_value=1024)
        self._add_option("LOG_BACKUP_COUNT", 30, "Number of backup log files to keep", int, min_value=1)
        self._add_option("LOG_ROTATION_WHEN", "midnight", "Log rotation schedule", str, choices=["midnight", "hourly", "daily", "weekly"])
        self._add_option("LOG_ROTATION_INTERVAL", 1, "Log rotation interval", int, min_value=1)
        self._add_option("LOG_COMPRESS_BACKUPS", True, "Compress rotated log files", bool)
        self._add_option("LOG_CAPTURE_WARNINGS", True, "Capture Python warnings in logs", bool)
        
        # Self-Test Configuration
        self._add_option("SELFTEST_ENABLED", True, "Enable self-test system", bool)
        self._add_option("SELFTEST_INTERVAL_MINUTES", 5, "Self-test execution interval in minutes", int, min_value=1)
        self._add_option("SELFTEST_INITIAL_DELAY_SECONDS", 15, "Initial delay before first self-test", int, min_value=0)
        self._add_option("SELFTEST_TIMEOUT_SECONDS", 30, "Timeout for individual tests", int, min_value=1)
        self._add_option("SELFTEST_RETRY_COUNT", 3, "Number of retries for failed tests", int, min_value=0)
        self._add_option("SELFTEST_RETRY_DELAY_SECONDS", 5, "Delay between test retries", int, min_value=0)
        self._add_option("SELFTEST_LOG_RESULTS", True, "Log detailed test results", bool)
        self._add_option("SELFTEST_LOG_LEVEL", "INFO", "Self-test log level", str, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
        self._add_option("SELFTEST_SAVE_RESULTS", True, "Save test results to files", bool)
        self._add_option("SELFTEST_RESULTS_DIR", "logs/selftest", "Directory for test result files", str)
        self._add_option("SELFTEST_ALERT_ON_FAILURE", True, "Alert on test failures", bool)
        self._add_option("SELFTEST_FAILURE_THRESHOLD", 3, "Number of failures before alerting", int, min_value=1)
        
        # Monitoring Configuration
        self._add_option("MONITORING_ENABLED", True, "Enable monitoring system", bool)
        self._add_option("MONITORING_LOG_PERFORMANCE", True, "Log performance metrics", bool)
        self._add_option("MONITORING_LOG_MEMORY_USAGE", False, "Log memory usage metrics", bool)
        self._add_option("MONITORING_LOG_DISK_USAGE", False, "Log disk usage metrics", bool)
        
        # Connectivity & Network
        self._add_option("CONNECTIVITY_TIMEOUT", 2.0, "Network connectivity timeout in seconds", float, min_value=0.1)
        self._add_option("BASE_URL", "http://0.0.0.0:8000", "Base URL for API endpoints", str)
        
        # Test User Configuration
        self._add_option("TEST_USER", "testuser", "Primary test user username", str)
        self._add_option("TEST_PASS", "TestPass123!", "Primary test user password", str)
        self._add_option("TEST_EMAIL", "testuser@example.com", "Primary test user email", str)
        self._add_option("TEST_DISPLAY", "Test User", "Primary test user display name", str)
        self._add_option("TEST_USER2", "testuser2", "Secondary test user username", str)
        self._add_option("TEST_PASS2", "TestPass123!", "Secondary test user password", str)
        self._add_option("TEST_EMAIL2", "testuser2@example.com", "Secondary test user email", str)
        self._add_option("TEST_DISPLAY2", "Test User 2", "Secondary test user display name", str)
    
    def _add_option(self, name: str, default: Any, description: str, type_hint: Type = str, 
                   required: bool = False, choices: Optional[List[Any]] = None,
                   min_value: Optional[Union[int, float]] = None, 
                   max_value: Optional[Union[int, float]] = None,
                   pattern: Optional[str] = None):
        """Add a configuration option to the schema."""
        option = ConfigOption(
            name=name,
            default=default,
            description=description,
            type_hint=type_hint,
            required=required,
            choices=choices,
            min_value=min_value,
            max_value=max_value,
            pattern=pattern
        )
        self.config_options[name] = option
    
    def _load_configuration(self):
        """Load configuration from environment variables."""
        errors = []
        
        for name, option in self.config_options.items():
            try:
                env_value = os.getenv(option.env_var)
                validated_value = option.validate(env_value)
                self.config_values[name] = validated_value
            except ConfigValidationError as e:
                errors.append(str(e))
        
        if errors:
            error_msg = "Configuration validation errors:\n" + "\n".join(f"  - {error}" for error in errors)
            logger.error(error_msg)
            raise ConfigValidationError(error_msg)
        
        logger.info("Configuration loaded successfully with %d options", len(self.config_values))
    
    def get(self, name: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config_values.get(name, default)
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration values."""
        return self.config_values.copy()
    
    def validate_configuration(self) -> List[str]:
        """Validate current configuration and return any issues."""
        issues = []
        
        # Cross-validation checks
        if self.get("SSL_KEYFILE") and not self.get("SSL_CERTFILE"):
            issues.append("SSL_KEYFILE specified but SSL_CERTFILE is missing")
        
        if self.get("SSL_CERTFILE") and not self.get("SSL_KEYFILE"):
            issues.append("SSL_CERTFILE specified but SSL_KEYFILE is missing")
        
        # File existence checks
        ssl_keyfile = self.get("SSL_KEYFILE")
        if ssl_keyfile and not Path(ssl_keyfile).exists():
            issues.append(f"SSL key file not found: {ssl_keyfile}")
        
        ssl_certfile = self.get("SSL_CERTFILE")
        if ssl_certfile and not Path(ssl_certfile).exists():
            issues.append(f"SSL certificate file not found: {ssl_certfile}")
        
        # Directory checks
        log_dir = Path(self.get("LOG_DIR"))
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create log directory {log_dir}: {e}")
        
        return issues
    
    def generate_documentation(self) -> str:
        """Generate configuration documentation."""
        doc_lines = [
            "# Configuration Options",
            "",
            "This document describes all available configuration options for the Chat API application.",
            "",
        ]
        
        # Group options by category
        categories = {
            "Core Application": ["SECRET_KEY", "WEBHOOK_SECRET", "HOST", "PORT", "API_VERSION", "DEBUG"],
            "Database": ["DATABASE_URL", "DB_HOST", "DB_PORT"],
            "Authentication & Security": ["ACCESS_TOKEN_EXPIRE_MINUTES", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW", "SSL_KEYFILE", "SSL_CERTFILE"],
            "Logging": [name for name in self.config_options.keys() if name.startswith("LOG_")],
            "Self-Tests": [name for name in self.config_options.keys() if name.startswith("SELFTEST_")],
            "Monitoring": [name for name in self.config_options.keys() if name.startswith("MONITORING_")],
            "Network & Connectivity": ["CONNECTIVITY_TIMEOUT", "BASE_URL"],
            "Test Users": [name for name in self.config_options.keys() if name.startswith("TEST_")]
        }
        
        for category, option_names in categories.items():
            doc_lines.extend([f"## {category}", ""])
            
            for name in option_names:
                if name in self.config_options:
                    option = self.config_options[name]
                    doc_lines.extend([
                        f"### {name}",
                        f"- **Description**: {option.description}",
                        f"- **Type**: {option.type_hint.__name__}",
                        f"- **Default**: `{option.default}`",
                        f"- **Environment Variable**: `{option.env_var}`",
                        f"- **Required**: {'Yes' if option.required else 'No'}",
                    ])
                    
                    if option.choices:
                        doc_lines.append(f"- **Valid Choices**: {', '.join(map(str, option.choices))}")
                    
                    if option.min_value is not None or option.max_value is not None:
                        range_info = []
                        if option.min_value is not None:
                            range_info.append(f"min: {option.min_value}")
                        if option.max_value is not None:
                            range_info.append(f"max: {option.max_value}")
                        doc_lines.append(f"- **Range**: {', '.join(range_info)}")
                    
                    doc_lines.append("")
        
        return "\n".join(doc_lines)


# Global configuration manager instance
config_manager = ConfigurationManager()
