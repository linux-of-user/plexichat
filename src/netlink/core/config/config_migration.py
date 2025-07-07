"""
NetLink Configuration Migration

Handles configuration version migration and schema updates.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Tuple
import yaml
import json
import logging
from datetime import datetime
import shutil

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

logger = logging.getLogger(__name__)

class ConfigMigrationError(Exception):
    """Configuration migration error."""
    pass

class ConfigMigrator:
    """
    Configuration migration system for NetLink.
    
    Features:
    - Version-based migration system
    - Automatic backup before migration
    - Rollback capabilities
    - Schema validation after migration
    - Migration history tracking
    - Safe migration with validation
    """
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.migration_dir = config_dir / "migrations"
        self.backup_dir = config_dir / "backups"
        
        # Ensure directories exist
        self.migration_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Migration registry
        self.migrations = {
            "1.0.0": self._migrate_to_1_0_0,
            "2.0.0": self._migrate_to_2_0_0,
            "2.1.0": self._migrate_to_2_1_0,
            "3.0.0": self._migrate_to_3_0_0,
        }
        
        # Version order for sequential migration
        self.version_order = ["1.0.0", "2.0.0", "2.1.0", "3.0.0"]
    
    def get_config_version(self, config: Dict[str, Any]) -> str:
        """Get configuration version."""
        return config.get("version", "1.0.0")
    
    def needs_migration(self, config: Dict[str, Any], target_version: str = "3.0.0") -> bool:
        """Check if configuration needs migration."""
        current_version = self.get_config_version(config)
        return self._compare_versions(current_version, target_version) < 0
    
    def migrate_config(self, config: Dict[str, Any], target_version: str = "3.0.0") -> Dict[str, Any]:
        """Migrate configuration to target version."""
        current_version = self.get_config_version(config)
        
        if not self.needs_migration(config, target_version):
            logger.info(f"Configuration already at version {current_version}, no migration needed")
            return config
        
        logger.info(f"Migrating configuration from {current_version} to {target_version}")
        
        # Create backup
        backup_path = self._create_backup(config, current_version)
        logger.info(f"Configuration backup created at {backup_path}")
        
        try:
            # Perform sequential migration
            migrated_config = config.copy()
            
            for version in self.version_order:
                if (self._compare_versions(current_version, version) < 0 and 
                    self._compare_versions(version, target_version) <= 0):
                    
                    logger.info(f"Applying migration to version {version}")
                    migrated_config = self.migrations[version](migrated_config)
                    migrated_config["version"] = version
            
            # Validate migrated configuration
            self._validate_migrated_config(migrated_config)
            
            # Record migration
            self._record_migration(current_version, target_version, backup_path)
            
            logger.info(f"Configuration successfully migrated to {target_version}")
            return migrated_config
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            raise ConfigMigrationError(f"Migration from {current_version} to {target_version} failed: {e}")
    
    def rollback_migration(self, backup_path: Path) -> Dict[str, Any]:
        """Rollback configuration from backup."""
        if not backup_path.exists():
            raise ConfigMigrationError(f"Backup file not found: {backup_path}")
        
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            logger.info(f"Configuration rolled back from {backup_path}")
            return config
            
        except Exception as e:
            raise ConfigMigrationError(f"Rollback failed: {e}")
    
    def list_migrations(self) -> List[Dict[str, Any]]:
        """List migration history."""
        history_file = self.migration_dir / "history.json"
        
        if not history_file.exists():
            return []
        
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read migration history: {e}")
            return []
    
    def _migrate_to_1_0_0(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate to version 1.0.0 (initial version)."""
        # This is the baseline version, no changes needed
        return config
    
    def _migrate_to_2_0_0(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate to version 2.0.0."""
        migrated = config.copy()
        
        # Add new security features
        if "security" not in migrated:
            migrated["security"] = {}
        
        security = migrated["security"]
        
        # Add MFA support
        if "mfa_enabled" not in security:
            security["mfa_enabled"] = False
        if "mfa_methods" not in security:
            security["mfa_methods"] = ["totp"]
        
        # Add rate limiting
        if "rate_limiting" not in security:
            security["rate_limiting"] = True
        if "rate_limit_requests" not in security:
            security["rate_limit_requests"] = 1000
        if "rate_limit_window" not in security:
            security["rate_limit_window"] = 60
        
        # Add backup configuration
        if "backup" not in migrated:
            migrated["backup"] = {
                "enabled": True,
                "directory": "backups",
                "encryption_enabled": True,
                "retention_days": 30
            }
        
        return migrated
    
    def _migrate_to_2_1_0(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate to version 2.1.0."""
        migrated = config.copy()
        
        # Add cluster support
        if "cluster" not in migrated:
            migrated["cluster"] = {
                "enabled": False,
                "node_id": None,
                "discovery_method": "static",
                "nodes": []
            }
        
        # Add AI configuration
        if "ai" not in migrated:
            migrated["ai"] = {
                "enabled": False,
                "providers": [],
                "timeout": 30
            }
        
        # Update backup configuration
        backup = migrated.get("backup", {})
        if "distributed_enabled" not in backup:
            backup["distributed_enabled"] = False
        if "shard_size_mb" not in backup:
            backup["shard_size_mb"] = 10
        if "redundancy_level" not in backup:
            backup["redundancy_level"] = 2
        
        return migrated
    
    def _migrate_to_3_0_0(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate to version 3.0.0."""
        migrated = config.copy()
        
        # Restructure configuration with new sections
        
        # Add application section
        if "application" not in migrated:
            migrated["application"] = {
                "name": "NetLink",
                "version": "3.0.0",
                "description": "Government-Level Secure Communication Platform",
                "debug": migrated.get("server", {}).get("debug", False),
                "environment": migrated.get("environment", "production")
            }
        
        # Update server configuration
        server = migrated.get("server", {})
        if "max_request_size" not in server:
            server["max_request_size"] = 100 * 1024 * 1024  # 100MB
        if "timeout" not in server:
            server["timeout"] = 30
        if "keep_alive" not in server:
            server["keep_alive"] = 2
        
        # Update database configuration
        database = migrated.get("database", {})
        if "ssl_mode" not in database:
            database["ssl_mode"] = "prefer"
        if "connection_timeout" not in database:
            database["connection_timeout"] = 30
        if "query_timeout" not in database:
            database["query_timeout"] = 60
        
        # Update security configuration
        security = migrated.get("security", {})
        if "biometric_enabled" not in security:
            security["biometric_enabled"] = False
        if "session_timeout" not in security:
            security["session_timeout"] = 3600
        if "csrf_protection" not in security:
            security["csrf_protection"] = True
        if "encryption_algorithm" not in security:
            security["encryption_algorithm"] = "AES-256-GCM"
        if "hash_algorithm" not in security:
            security["hash_algorithm"] = "SHA-512"
        
        # Update backup configuration
        backup = migrated.get("backup", {})
        if "compression_algorithm" not in backup:
            backup["compression_algorithm"] = "zstd"
        if "backup_types" not in backup:
            backup["backup_types"] = ["database", "files", "config"]
        if "verification_enabled" not in backup:
            backup["verification_enabled"] = True
        if "quantum_encryption" not in backup:
            backup["quantum_encryption"] = True
        if "max_backup_size_gb" not in backup:
            backup["max_backup_size_gb"] = 100
        
        # Update cluster configuration
        cluster = migrated.get("cluster", {})
        if "load_balancing" not in cluster:
            cluster["load_balancing"] = True
        if "failover_enabled" not in cluster:
            cluster["failover_enabled"] = True
        if "consensus_algorithm" not in cluster:
            cluster["consensus_algorithm"] = "raft"
        
        # Add monitoring section
        if "monitoring" not in migrated:
            migrated["monitoring"] = {
                "enabled": True,
                "metrics_enabled": True,
                "health_checks_enabled": True,
                "performance_monitoring": True,
                "error_tracking": True,
                "log_aggregation": True
            }
        
        # Add features section
        if "features" not in migrated:
            migrated["features"] = {
                "backup_system": True,
                "clustering": cluster.get("enabled", False),
                "ai_integration": migrated.get("ai", {}).get("enabled", False),
                "web_ui": True,
                "api_docs": True,
                "metrics": True,
                "health_checks": True,
                "file_sharing": True,
                "themes": True
            }
        
        # Add limits section
        if "limits" not in migrated:
            migrated["limits"] = {
                "max_message_length": 10000,
                "max_file_size_mb": 100,
                "max_users": 10000,
                "rate_limit_per_minute": 1000,
                "max_concurrent_connections": 1000,
                "max_upload_size_mb": 500,
                "max_backup_size_gb": 100
            }
        
        # Update AI configuration
        ai = migrated.get("ai", {})
        if "features" not in ai:
            ai["features"] = {
                "chat_completion": False,
                "content_moderation": False,
                "translation": False,
                "summarization": False,
                "sentiment_analysis": False
            }
        if "fallback_enabled" not in ai:
            ai["fallback_enabled"] = True
        
        # Update logging configuration
        logging_config = migrated.get("logging", {})
        if "log_performance" not in logging_config:
            logging_config["log_performance"] = True
        if "log_security" not in logging_config:
            logging_config["log_security"] = True
        
        return migrated
    
    def _create_backup(self, config: Dict[str, Any], version: str) -> Path:
        """Create configuration backup."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"config_v{version}_{timestamp}.yaml"
        backup_path = self.backup_dir / backup_filename
        
        with open(backup_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
        
        return backup_path
    
    def _validate_migrated_config(self, config: Dict[str, Any]):
        """Validate migrated configuration."""
        required_sections = [
            "version", "application", "server", "database", 
            "security", "backup", "logging"
        ]
        
        for section in required_sections:
            if section not in config:
                raise ConfigMigrationError(f"Missing required section after migration: {section}")
        
        # Validate version
        version = config.get("version")
        if not version or version not in self.version_order:
            raise ConfigMigrationError(f"Invalid version after migration: {version}")
    
    def _record_migration(self, from_version: str, to_version: str, backup_path: Path):
        """Record migration in history."""
        history_file = self.migration_dir / "history.json"
        
        migration_record = {
            "timestamp": datetime.now().isoformat(),
            "from_version": from_version,
            "to_version": to_version,
            "backup_path": str(backup_path),
            "success": True
        }
        
        # Load existing history
        history = []
        if history_file.exists():
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            except Exception:
                pass
        
        # Add new record
        history.append(migration_record)
        
        # Save updated history
        try:
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to record migration history: {e}")
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        def version_tuple(v):
            return tuple(map(int, v.split('.')))
        
        v1 = version_tuple(version1)
        v2 = version_tuple(version2)
        
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
        else:
            return 0
