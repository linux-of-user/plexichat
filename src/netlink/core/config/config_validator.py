"""
NetLink Configuration Validator

Comprehensive validation system for configuration files with detailed error reporting.
"""

import os
import sys
import re
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
from urllib.parse import urlparse
import logging

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Configuration validation error."""
    pass

class ConfigValidator:
    """
    Configuration validator with comprehensive validation rules.
    
    Features:
    - Type validation
    - Range validation
    - Format validation (URLs, emails, etc.)
    - Cross-field validation
    - Security validation
    - File system validation
    - Network validation
    """
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate(self, config: Dict[str, Any]) -> List[str]:
        """Validate complete configuration and return issues."""
        self.errors = []
        self.warnings = []
        
        # Validate each section
        self._validate_application(config.get("application", {}))
        self._validate_server(config.get("server", {}))
        self._validate_database(config.get("database", {}))
        self._validate_security(config.get("security", {}))
        self._validate_backup(config.get("backup", {}))
        self._validate_cluster(config.get("cluster", {}))
        self._validate_logging(config.get("logging", {}))
        self._validate_ai(config.get("ai", {}))
        self._validate_monitoring(config.get("monitoring", {}))
        self._validate_features(config.get("features", {}))
        self._validate_limits(config.get("limits", {}))
        
        # Cross-section validation
        self._validate_cross_dependencies(config)
        
        return self.errors
    
    def _validate_application(self, config: Dict[str, Any]):
        """Validate application configuration."""
        # Validate name
        name = config.get("name", "")
        if not name or not isinstance(name, str):
            self.errors.append("Application name is required and must be a string")
        elif len(name) > 100:
            self.errors.append("Application name must be less than 100 characters")
        
        # Validate version
        version = config.get("version", "")
        if not version or not isinstance(version, str):
            self.errors.append("Application version is required and must be a string")
        elif not re.match(r'^\d+\.\d+\.\d+', version):
            self.warnings.append("Application version should follow semantic versioning (x.y.z)")
        
        # Validate environment
        environment = config.get("environment", "")
        valid_environments = ["development", "testing", "staging", "production"]
        if environment not in valid_environments:
            self.errors.append(f"Environment must be one of: {', '.join(valid_environments)}")
    
    def _validate_server(self, config: Dict[str, Any]):
        """Validate server configuration."""
        # Validate host
        host = config.get("host", "")
        if not host:
            self.errors.append("Server host is required")
        else:
            if not self._is_valid_host(host):
                self.errors.append(f"Invalid server host: {host}")
        
        # Validate port
        port = config.get("port", 0)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            self.errors.append(f"Server port must be an integer between 1 and 65535, got: {port}")
        elif port < 1024 and os.geteuid() != 0:
            self.warnings.append(f"Port {port} requires root privileges on Unix systems")
        
        # Validate workers
        workers = config.get("workers", 1)
        if not isinstance(workers, int) or workers < 1:
            self.errors.append("Server workers must be a positive integer")
        elif workers > 32:
            self.warnings.append("High worker count may impact performance")
        
        # Validate SSL configuration
        ssl_enabled = config.get("ssl_enabled", False)
        if ssl_enabled:
            ssl_cert = config.get("ssl_cert_file")
            ssl_key = config.get("ssl_key_file")
            
            if not ssl_cert:
                self.errors.append("SSL certificate file is required when SSL is enabled")
            elif not Path(ssl_cert).exists():
                self.errors.append(f"SSL certificate file not found: {ssl_cert}")
            
            if not ssl_key:
                self.errors.append("SSL key file is required when SSL is enabled")
            elif not Path(ssl_key).exists():
                self.errors.append(f"SSL key file not found: {ssl_key}")
        
        # Validate CORS
        cors_origins = config.get("cors_origins", [])
        if not isinstance(cors_origins, list):
            self.errors.append("CORS origins must be a list")
        else:
            for origin in cors_origins:
                if origin != "*" and not self._is_valid_url(origin):
                    self.errors.append(f"Invalid CORS origin: {origin}")
    
    def _validate_database(self, config: Dict[str, Any]):
        """Validate database configuration."""
        # Validate database type
        db_type = config.get("type", "")
        valid_types = ["sqlite", "postgresql", "mysql", "mariadb"]
        if db_type not in valid_types:
            self.errors.append(f"Database type must be one of: {', '.join(valid_types)}")
        
        # Validate database URL or connection parameters
        db_url = config.get("url")
        if db_url:
            if not self._is_valid_database_url(db_url):
                self.errors.append(f"Invalid database URL: {db_url}")
        else:
            # Validate individual connection parameters
            if db_type != "sqlite":
                host = config.get("host")
                if not host or not self._is_valid_host(host):
                    self.errors.append("Valid database host is required for non-SQLite databases")
                
                port = config.get("port", 0)
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    self.errors.append("Valid database port is required for non-SQLite databases")
                
                name = config.get("name")
                if not name or not isinstance(name, str):
                    self.errors.append("Database name is required for non-SQLite databases")
        
        # Validate pool settings
        pool_size = config.get("pool_size", 10)
        if not isinstance(pool_size, int) or pool_size < 1:
            self.errors.append("Database pool size must be a positive integer")
        elif pool_size > 100:
            self.warnings.append("Large database pool size may consume excessive resources")
        
        pool_timeout = config.get("pool_timeout", 30)
        if not isinstance(pool_timeout, int) or pool_timeout < 1:
            self.errors.append("Database pool timeout must be a positive integer")
    
    def _validate_security(self, config: Dict[str, Any]):
        """Validate security configuration."""
        # Validate secret key
        secret_key = config.get("secret_key")
        if not secret_key:
            self.errors.append("Security secret key is required")
        elif len(secret_key) < 32:
            self.errors.append("Security secret key must be at least 32 characters long")
        
        # Validate JWT algorithm
        jwt_algorithm = config.get("jwt_algorithm", "")
        valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        if jwt_algorithm not in valid_algorithms:
            self.errors.append(f"JWT algorithm must be one of: {', '.join(valid_algorithms)}")
        
        # Validate token expiration
        access_expire = config.get("access_token_expire_minutes", 0)
        if not isinstance(access_expire, int) or access_expire < 1:
            self.errors.append("Access token expiration must be a positive integer (minutes)")
        elif access_expire > 1440:  # 24 hours
            self.warnings.append("Long access token expiration may pose security risks")
        
        refresh_expire = config.get("refresh_token_expire_days", 0)
        if not isinstance(refresh_expire, int) or refresh_expire < 1:
            self.errors.append("Refresh token expiration must be a positive integer (days)")
        elif refresh_expire > 90:
            self.warnings.append("Long refresh token expiration may pose security risks")
        
        # Validate password requirements
        min_length = config.get("password_min_length", 0)
        if not isinstance(min_length, int) or min_length < 8:
            self.errors.append("Password minimum length must be at least 8 characters")
        elif min_length > 128:
            self.warnings.append("Very long password requirements may impact usability")
        
        # Validate rate limiting
        rate_limit = config.get("rate_limit_requests", 0)
        if not isinstance(rate_limit, int) or rate_limit < 1:
            self.errors.append("Rate limit requests must be a positive integer")
        
        rate_window = config.get("rate_limit_window", 0)
        if not isinstance(rate_window, int) or rate_window < 1:
            self.errors.append("Rate limit window must be a positive integer (seconds)")
        
        # Validate MFA methods
        mfa_methods = config.get("mfa_methods", [])
        if not isinstance(mfa_methods, list):
            self.errors.append("MFA methods must be a list")
        else:
            valid_methods = ["totp", "sms", "email", "hardware", "biometric"]
            for method in mfa_methods:
                if method not in valid_methods:
                    self.errors.append(f"Invalid MFA method: {method}")
    
    def _validate_backup(self, config: Dict[str, Any]):
        """Validate backup configuration."""
        if not config.get("enabled", True):
            return
        
        # Validate backup directory
        backup_dir = config.get("directory", "")
        if not backup_dir:
            self.errors.append("Backup directory is required when backup is enabled")
        else:
            backup_path = Path(backup_dir)
            try:
                backup_path.mkdir(parents=True, exist_ok=True)
                if not backup_path.is_dir():
                    self.errors.append(f"Backup directory is not a directory: {backup_dir}")
                elif not os.access(backup_path, os.W_OK):
                    self.errors.append(f"Backup directory is not writable: {backup_dir}")
            except Exception as e:
                self.errors.append(f"Cannot access backup directory {backup_dir}: {e}")
        
        # Validate shard size
        shard_size = config.get("shard_size_mb", 0)
        if not isinstance(shard_size, int) or shard_size < 1:
            self.errors.append("Backup shard size must be a positive integer (MB)")
        elif shard_size > 1000:
            self.warnings.append("Large shard size may impact backup performance")
        
        # Validate redundancy level
        redundancy = config.get("redundancy_level", 0)
        if not isinstance(redundancy, int) or redundancy < 1:
            self.errors.append("Backup redundancy level must be a positive integer")
        elif redundancy > 10:
            self.warnings.append("High redundancy level may consume excessive storage")
        
        # Validate retention
        retention = config.get("retention_days", 0)
        if not isinstance(retention, int) or retention < 1:
            self.errors.append("Backup retention must be a positive integer (days)")
        elif retention > 3650:  # 10 years
            self.warnings.append("Very long backup retention may consume excessive storage")
    
    def _validate_cluster(self, config: Dict[str, Any]):
        """Validate cluster configuration."""
        if not config.get("enabled", False):
            return
        
        # Validate node ID
        node_id = config.get("node_id")
        if not node_id:
            self.errors.append("Node ID is required when clustering is enabled")
        elif not isinstance(node_id, str) or len(node_id) < 8:
            self.errors.append("Node ID must be at least 8 characters long")
        
        # Validate discovery method
        discovery = config.get("discovery_method", "")
        valid_methods = ["static", "dns", "consul", "etcd"]
        if discovery not in valid_methods:
            self.errors.append(f"Discovery method must be one of: {', '.join(valid_methods)}")
        
        # Validate nodes list for static discovery
        if discovery == "static":
            nodes = config.get("nodes", [])
            if not isinstance(nodes, list) or len(nodes) == 0:
                self.errors.append("Node list is required for static discovery")
            else:
                for node in nodes:
                    if not self._is_valid_node_address(node):
                        self.errors.append(f"Invalid node address: {node}")
        
        # Validate timing parameters
        heartbeat = config.get("heartbeat_interval", 0)
        if not isinstance(heartbeat, int) or heartbeat < 1:
            self.errors.append("Heartbeat interval must be a positive integer (seconds)")
        
        election_timeout = config.get("election_timeout", 0)
        if not isinstance(election_timeout, int) or election_timeout < 1000:
            self.errors.append("Election timeout must be at least 1000 milliseconds")
    
    def _validate_logging(self, config: Dict[str, Any]):
        """Validate logging configuration."""
        # Validate log level
        level = config.get("level", "")
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if level not in valid_levels:
            self.errors.append(f"Log level must be one of: {', '.join(valid_levels)}")
        
        # Validate log file
        log_file = config.get("file", "")
        if log_file:
            log_path = Path(log_file)
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.errors.append(f"Cannot create log directory: {e}")
        
        # Validate max size
        max_size = config.get("max_size", "")
        if max_size and not re.match(r'^\d+[KMGT]?B?$', max_size.upper()):
            self.errors.append("Log max size must be in format like '10MB', '1GB', etc.")
        
        # Validate backup count
        backup_count = config.get("backup_count", 0)
        if not isinstance(backup_count, int) or backup_count < 0:
            self.errors.append("Log backup count must be a non-negative integer")
    
    def _validate_ai(self, config: Dict[str, Any]):
        """Validate AI configuration."""
        if not config.get("enabled", False):
            return
        
        # Validate providers
        providers = config.get("providers", [])
        if not isinstance(providers, list) or len(providers) == 0:
            self.errors.append("AI providers list is required when AI is enabled")
        
        # Validate default provider
        default_provider = config.get("default_provider")
        if default_provider and default_provider not in providers:
            self.errors.append("Default AI provider must be in the providers list")
        
        # Validate API keys
        api_keys = config.get("api_keys", {})
        if not isinstance(api_keys, dict):
            self.errors.append("AI API keys must be a dictionary")
        else:
            for provider in providers:
                if provider not in api_keys:
                    self.warnings.append(f"No API key configured for AI provider: {provider}")
    
    def _validate_monitoring(self, config: Dict[str, Any]):
        """Validate monitoring configuration."""
        # Validate retention
        retention = config.get("metrics_retention_days", 0)
        if not isinstance(retention, int) or retention < 1:
            self.errors.append("Metrics retention must be a positive integer (days)")
        
        # Validate health check interval
        interval = config.get("health_check_interval", 0)
        if not isinstance(interval, int) or interval < 1:
            self.errors.append("Health check interval must be a positive integer (seconds)")
    
    def _validate_features(self, config: Dict[str, Any]):
        """Validate features configuration."""
        # All feature flags should be boolean
        for key, value in config.items():
            if not isinstance(value, bool):
                self.errors.append(f"Feature flag '{key}' must be a boolean value")
    
    def _validate_limits(self, config: Dict[str, Any]):
        """Validate limits configuration."""
        # Validate all numeric limits
        numeric_limits = [
            "max_message_length", "max_file_size_mb", "max_users",
            "rate_limit_per_minute", "max_concurrent_connections",
            "max_upload_size_mb", "max_backup_size_gb"
        ]
        
        for limit in numeric_limits:
            value = config.get(limit, 0)
            if not isinstance(value, int) or value < 1:
                self.errors.append(f"Limit '{limit}' must be a positive integer")
    
    def _validate_cross_dependencies(self, config: Dict[str, Any]):
        """Validate cross-section dependencies."""
        # SSL and security
        server_config = config.get("server", {})
        security_config = config.get("security", {})
        
        if server_config.get("ssl_enabled") and security_config.get("jwt_algorithm", "").startswith("HS"):
            self.warnings.append("Consider using RS256 JWT algorithm with SSL enabled for better security")
        
        # Backup and clustering
        backup_config = config.get("backup", {})
        cluster_config = config.get("cluster", {})
        
        if cluster_config.get("enabled") and not backup_config.get("distributed_enabled"):
            self.warnings.append("Consider enabling distributed backup when clustering is enabled")
        
        # AI and features
        ai_config = config.get("ai", {})
        features_config = config.get("features", {})
        
        if features_config.get("ai_integration") and not ai_config.get("enabled"):
            self.errors.append("AI must be enabled when AI integration feature is enabled")
    
    def _is_valid_host(self, host: str) -> bool:
        """Validate host address."""
        if host in ["localhost", "0.0.0.0"]:
            return True
        
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid hostname
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
            return True
        
        return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _is_valid_database_url(self, url: str) -> bool:
        """Validate database URL format."""
        try:
            result = urlparse(url)
            valid_schemes = ["sqlite", "postgresql", "mysql", "mariadb"]
            return result.scheme in valid_schemes
        except Exception:
            return False
    
    def _is_valid_node_address(self, address: str) -> bool:
        """Validate cluster node address."""
        if ":" not in address:
            return False
        
        host, port_str = address.rsplit(":", 1)
        
        try:
            port = int(port_str)
            return self._is_valid_host(host) and 1 <= port <= 65535
        except ValueError:
            return False
