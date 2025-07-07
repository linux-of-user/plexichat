"""
NetLink Configuration Templates

Template generation for different environments and deployment scenarios.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml
import json
from datetime import datetime
import logging

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

logger = logging.getLogger(__name__)

class ConfigTemplateGenerator:
    """
    Configuration template generator for different environments and scenarios.
    
    Features:
    - Environment-specific templates (development, staging, production)
    - Deployment scenario templates (standalone, cluster, cloud)
    - Security level templates (basic, enhanced, government)
    - Feature-specific templates
    - Docker and Kubernetes configurations
    """
    
    def __init__(self):
        self.templates = {
            "development": self._get_development_template,
            "testing": self._get_testing_template,
            "staging": self._get_staging_template,
            "production": self._get_production_template,
            "cluster": self._get_cluster_template,
            "backup_node": self._get_backup_node_template,
            "security_enhanced": self._get_security_enhanced_template,
            "minimal": self._get_minimal_template,
        }
    
    def generate_template(self, template_type: str, **kwargs) -> Dict[str, Any]:
        """Generate configuration template by type."""
        if template_type not in self.templates:
            raise ValueError(f"Unknown template type: {template_type}")
        
        generator = self.templates[template_type]
        return generator(**kwargs)
    
    def save_template(self, template_type: str, output_path: Path, **kwargs) -> bool:
        """Generate and save configuration template to file."""
        try:
            config = self.generate_template(template_type, **kwargs)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(
                    config,
                    f,
                    default_flow_style=False,
                    indent=2,
                    sort_keys=False,
                    allow_unicode=True
                )
            
            logger.info(f"Configuration template saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save template: {e}")
            return False
    
    def list_templates(self) -> List[str]:
        """List available template types."""
        return list(self.templates.keys())
    
    def _get_development_template(self, **kwargs) -> Dict[str, Any]:
        """Development environment template."""
        return {
            "version": "3.0.0",
            "environment": "development",
            "application": {
                "name": "NetLink",
                "version": "3.0.0",
                "description": "Government-Level Secure Communication Platform",
                "debug": True,
                "maintenance_mode": False
            },
            "server": {
                "host": "127.0.0.1",
                "port": 8000,
                "workers": 1,
                "debug": True,
                "auto_reload": True,
                "access_log": True,
                "ssl_enabled": False,
                "cors_enabled": True,
                "cors_origins": ["http://localhost:3000", "http://127.0.0.1:3000"]
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./data/netlink_dev.db",
                "echo": True,
                "backup_enabled": True,
                "backup_interval": 1800,  # 30 minutes
                "encryption_enabled": False  # Disabled for easier debugging
            },
            "security": {
                "jwt_algorithm": "HS256",  # Simpler for development
                "access_token_expire_minutes": 60,  # Longer for development
                "refresh_token_expire_days": 7,
                "password_min_length": 8,  # Relaxed for development
                "max_login_attempts": 10,  # More lenient
                "lockout_duration": 60,  # Shorter lockout
                "mfa_enabled": False,  # Disabled for easier testing
                "rate_limiting": False,  # Disabled for development
                "csrf_protection": False  # Disabled for API testing
            },
            "backup": {
                "enabled": True,
                "directory": "backups_dev",
                "encryption_enabled": False,  # Disabled for easier debugging
                "compression_enabled": True,
                "distributed_enabled": False,
                "shard_size_mb": 5,  # Smaller shards for testing
                "redundancy_level": 1,
                "retention_days": 7,  # Shorter retention
                "auto_backup_interval": 1800
            },
            "cluster": {
                "enabled": False
            },
            "logging": {
                "level": "DEBUG",
                "console_enabled": True,
                "file_enabled": True,
                "file": "logs/netlink_dev.log",
                "structured_logging": True,
                "log_requests": True,
                "log_responses": True,
                "log_sql": True
            },
            "ai": {
                "enabled": False,  # Disabled by default in development
                "timeout": 10,
                "max_retries": 2
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
                "health_checks_enabled": True,
                "performance_monitoring": True
            },
            "features": {
                "backup_system": True,
                "clustering": False,
                "ai_integration": False,
                "web_ui": True,
                "api_docs": True,
                "metrics": True,
                "health_checks": True,
                "file_sharing": True,
                "themes": True
            },
            "limits": {
                "max_message_length": 5000,  # Smaller for testing
                "max_file_size_mb": 10,  # Smaller for testing
                "max_users": 100,
                "rate_limit_per_minute": 10000,  # Very high for development
                "max_concurrent_connections": 100
            }
        }
    
    def _get_testing_template(self, **kwargs) -> Dict[str, Any]:
        """Testing environment template."""
        config = self._get_development_template(**kwargs)
        config.update({
            "environment": "testing",
            "database": {
                **config["database"],
                "url": "sqlite:///:memory:",  # In-memory database for tests
                "echo": False,
                "backup_enabled": False
            },
            "logging": {
                **config["logging"],
                "level": "WARNING",  # Reduce log noise in tests
                "console_enabled": False,
                "file_enabled": False
            },
            "backup": {
                **config["backup"],
                "enabled": False  # Disable backup in tests
            }
        })
        return config
    
    def _get_staging_template(self, **kwargs) -> Dict[str, Any]:
        """Staging environment template."""
        return {
            "version": "3.0.0",
            "environment": "staging",
            "application": {
                "name": "NetLink",
                "version": "3.0.0",
                "description": "Government-Level Secure Communication Platform",
                "debug": False,
                "maintenance_mode": False
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 2,
                "debug": False,
                "auto_reload": False,
                "access_log": True,
                "ssl_enabled": True,
                "ssl_cert_file": "/etc/ssl/certs/netlink-staging.crt",
                "ssl_key_file": "/etc/ssl/private/netlink-staging.key",
                "cors_enabled": True,
                "cors_origins": ["https://staging.netlink.example.com"]
            },
            "database": {
                "type": "postgresql",
                "host": "localhost",
                "port": 5432,
                "name": "netlink_staging",
                "username": "netlink_staging",
                "pool_size": 5,
                "echo": False,
                "backup_enabled": True,
                "backup_interval": 3600,
                "encryption_enabled": True
            },
            "security": {
                "jwt_algorithm": "RS256",
                "access_token_expire_minutes": 15,
                "refresh_token_expire_days": 30,
                "password_min_length": 12,
                "max_login_attempts": 5,
                "lockout_duration": 300,
                "mfa_enabled": True,
                "mfa_methods": ["totp", "email"],
                "rate_limiting": True,
                "rate_limit_requests": 1000,
                "rate_limit_window": 60,
                "csrf_protection": True
            },
            "backup": {
                "enabled": True,
                "directory": "/var/backups/netlink",
                "encryption_enabled": True,
                "compression_enabled": True,
                "distributed_enabled": False,
                "shard_size_mb": 10,
                "redundancy_level": 2,
                "retention_days": 30,
                "auto_backup_interval": 3600
            },
            "cluster": {
                "enabled": False
            },
            "logging": {
                "level": "INFO",
                "console_enabled": False,
                "file_enabled": True,
                "file": "/var/log/netlink/netlink.log",
                "structured_logging": True,
                "log_requests": False,
                "log_performance": True,
                "log_security": True
            },
            "ai": {
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
                "health_checks_enabled": True,
                "performance_monitoring": True,
                "error_tracking": True
            },
            "features": {
                "backup_system": True,
                "clustering": False,
                "ai_integration": False,
                "web_ui": True,
                "api_docs": True,
                "metrics": True,
                "health_checks": True,
                "file_sharing": True
            },
            "limits": {
                "max_message_length": 10000,
                "max_file_size_mb": 100,
                "max_users": 1000,
                "rate_limit_per_minute": 1000,
                "max_concurrent_connections": 500
            }
        }
    
    def _get_production_template(self, **kwargs) -> Dict[str, Any]:
        """Production environment template."""
        return {
            "version": "3.0.0",
            "environment": "production",
            "application": {
                "name": "NetLink",
                "version": "3.0.0",
                "description": "Government-Level Secure Communication Platform",
                "debug": False,
                "maintenance_mode": False
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4,
                "debug": False,
                "auto_reload": False,
                "access_log": False,  # Disable for performance
                "ssl_enabled": True,
                "ssl_cert_file": "/etc/ssl/certs/netlink.crt",
                "ssl_key_file": "/etc/ssl/private/netlink.key",
                "cors_enabled": True,
                "cors_origins": []  # Must be configured explicitly
            },
            "database": {
                "type": "postgresql",
                "host": "db.internal",
                "port": 5432,
                "name": "netlink",
                "username": "netlink",
                "pool_size": 20,
                "pool_timeout": 30,
                "echo": False,
                "backup_enabled": True,
                "backup_interval": 3600,
                "encryption_enabled": True,
                "ssl_mode": "require"
            },
            "security": {
                "jwt_algorithm": "RS256",
                "access_token_expire_minutes": 15,
                "refresh_token_expire_days": 30,
                "password_min_length": 12,
                "password_require_uppercase": True,
                "password_require_lowercase": True,
                "password_require_numbers": True,
                "password_require_symbols": True,
                "max_login_attempts": 5,
                "lockout_duration": 300,
                "mfa_enabled": True,
                "mfa_methods": ["totp", "sms", "email", "hardware"],
                "biometric_enabled": True,
                "rate_limiting": True,
                "rate_limit_requests": 1000,
                "rate_limit_window": 60,
                "encryption_algorithm": "AES-256-GCM",
                "hash_algorithm": "SHA-512",
                "csrf_protection": True
            },
            "backup": {
                "enabled": True,
                "directory": "/var/backups/netlink",
                "encryption_enabled": True,
                "compression_enabled": True,
                "compression_algorithm": "zstd",
                "distributed_enabled": True,
                "shard_size_mb": 10,
                "redundancy_level": 3,
                "retention_days": 90,
                "auto_backup_interval": 3600,
                "backup_types": ["database", "files", "config"],
                "verification_enabled": True,
                "quantum_encryption": True
            },
            "cluster": {
                "enabled": False  # Configure separately for cluster deployments
            },
            "logging": {
                "level": "INFO",
                "console_enabled": False,
                "file_enabled": True,
                "file": "/var/log/netlink/netlink.log",
                "max_size": "100MB",
                "backup_count": 10,
                "structured_logging": True,
                "log_requests": False,
                "log_performance": True,
                "log_security": True
            },
            "ai": {
                "enabled": False,  # Configure separately if needed
                "timeout": 30,
                "max_retries": 3,
                "fallback_enabled": True
            },
            "monitoring": {
                "enabled": True,
                "metrics_enabled": True,
                "health_checks_enabled": True,
                "performance_monitoring": True,
                "error_tracking": True,
                "log_aggregation": True,
                "alerting_enabled": True
            },
            "features": {
                "backup_system": True,
                "clustering": False,
                "ai_integration": False,
                "web_ui": True,
                "api_docs": False,  # Disable in production for security
                "metrics": True,
                "health_checks": True,
                "file_sharing": True
            },
            "limits": {
                "max_message_length": 10000,
                "max_file_size_mb": 100,
                "max_users": 10000,
                "rate_limit_per_minute": 1000,
                "max_concurrent_connections": 1000,
                "max_upload_size_mb": 500,
                "max_backup_size_gb": 100
            }
        }
    
    def _get_cluster_template(self, node_id: str = None, **kwargs) -> Dict[str, Any]:
        """Cluster node template."""
        config = self._get_production_template(**kwargs)
        
        config["cluster"] = {
            "enabled": True,
            "node_id": node_id or "node-001",
            "node_name": f"netlink-{node_id or '001'}",
            "discovery_method": "static",
            "nodes": [
                "node-001.cluster.internal:8001",
                "node-002.cluster.internal:8001",
                "node-003.cluster.internal:8001"
            ],
            "heartbeat_interval": 30,
            "election_timeout": 5000,
            "sync_interval": 300,
            "encryption_enabled": True,
            "load_balancing": True,
            "failover_enabled": True,
            "consensus_algorithm": "raft"
        }
        
        config["features"]["clustering"] = True
        config["backup"]["distributed_enabled"] = True
        
        return config
    
    def _get_backup_node_template(self, **kwargs) -> Dict[str, Any]:
        """Dedicated backup node template."""
        config = self._get_minimal_template(**kwargs)
        
        config.update({
            "application": {
                **config["application"],
                "description": "NetLink Dedicated Backup Node"
            },
            "backup": {
                "enabled": True,
                "directory": "/var/backups/netlink",
                "encryption_enabled": True,
                "compression_enabled": True,
                "distributed_enabled": True,
                "shard_size_mb": 50,  # Larger shards for backup nodes
                "redundancy_level": 5,  # Higher redundancy
                "retention_days": 365,  # Longer retention
                "auto_backup_interval": 1800,  # More frequent backups
                "verification_enabled": True,
                "quantum_encryption": True
            },
            "features": {
                **config["features"],
                "backup_system": True,
                "web_ui": False,  # Minimal UI for backup nodes
                "api_docs": False
            }
        })
        
        return config
    
    def _get_security_enhanced_template(self, **kwargs) -> Dict[str, Any]:
        """Security-enhanced template for government/military use."""
        config = self._get_production_template(**kwargs)
        
        config["security"].update({
            "password_min_length": 16,
            "max_login_attempts": 3,
            "lockout_duration": 900,  # 15 minutes
            "mfa_enabled": True,
            "mfa_methods": ["totp", "hardware", "biometric"],
            "biometric_enabled": True,
            "session_timeout": 1800,  # 30 minutes
            "encryption_algorithm": "AES-256-GCM",
            "hash_algorithm": "SHA-512"
        })
        
        config["backup"]["quantum_encryption"] = True
        config["logging"]["log_security"] = True
        config["features"]["api_docs"] = False  # Disable for security
        
        return config
    
    def _get_minimal_template(self, **kwargs) -> Dict[str, Any]:
        """Minimal configuration template."""
        return {
            "version": "3.0.0",
            "environment": "production",
            "application": {
                "name": "NetLink",
                "version": "3.0.0",
                "debug": False
            },
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 2
            },
            "database": {
                "type": "sqlite",
                "url": "sqlite:///./data/netlink.db"
            },
            "security": {
                "jwt_algorithm": "HS256",
                "access_token_expire_minutes": 15
            },
            "backup": {
                "enabled": False
            },
            "cluster": {
                "enabled": False
            },
            "logging": {
                "level": "INFO",
                "console_enabled": True,
                "file_enabled": False
            },
            "ai": {
                "enabled": False
            },
            "monitoring": {
                "enabled": False
            },
            "features": {
                "backup_system": False,
                "clustering": False,
                "ai_integration": False,
                "web_ui": True,
                "api_docs": True
            }
        }
