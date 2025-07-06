"""
NetLink Configuration YAML Converter

Converts all configuration files from JSON to YAML format for better readability and flexibility.
Handles module configs, system configs, and maintains backward compatibility.
"""

import json
import yaml
import os
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class YAMLConverter:
    """Converts configuration files from JSON to YAML format."""
    
    def __init__(self, root_path: str = "."):
        self.root_path = Path(root_path)
        self.backup_dir = self.root_path / "config_backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        self.converted_files: List[str] = []
        self.failed_files: List[str] = []
        
    def convert_all_configs(self) -> Dict[str, Any]:
        """Convert all configuration files to YAML format."""
        logger.info("🔄 Starting configuration conversion to YAML...")
        
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Find all JSON config files
        config_files = self._find_config_files()
        
        results = {
            "total_files": len(config_files),
            "converted": 0,
            "failed": 0,
            "skipped": 0,
            "backup_location": str(self.backup_dir)
        }
        
        for config_file in config_files:
            try:
                if self._convert_file(config_file):
                    results["converted"] += 1
                    self.converted_files.append(str(config_file))
                else:
                    results["skipped"] += 1
            except Exception as e:
                logger.error(f"Failed to convert {config_file}: {e}")
                results["failed"] += 1
                self.failed_files.append(str(config_file))
        
        # Update import statements and references
        self._update_code_references()
        
        logger.info(f"✅ Conversion complete: {results['converted']} converted, {results['failed']} failed, {results['skipped']} skipped")
        return results
    
    def _find_config_files(self) -> List[Path]:
        """Find all JSON configuration files."""
        config_files = []
        
        # Common config file patterns
        patterns = [
            "config.json",
            "settings.json",
            "*_config.json",
            "*.config.json",
            "config/*.json",
            "configs/*.json",
            "src/**/config*.json",
            "src/**/settings*.json",
            "modules/**/config.json",
            "modules/**/*_config.json"
        ]
        
        for pattern in patterns:
            config_files.extend(self.root_path.glob(pattern))
        
        # Remove duplicates and sort
        config_files = list(set(config_files))
        config_files.sort()
        
        logger.info(f"📁 Found {len(config_files)} configuration files")
        return config_files
    
    def _convert_file(self, json_file: Path) -> bool:
        """Convert a single JSON file to YAML."""
        try:
            # Skip if YAML version already exists
            yaml_file = json_file.with_suffix('.yaml')
            if yaml_file.exists():
                logger.info(f"⏭️ Skipping {json_file} - YAML version already exists")
                return False
            
            # Read JSON file
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Create backup
            backup_file = self.backup_dir / json_file.name
            shutil.copy2(json_file, backup_file)
            
            # Write YAML file
            with open(yaml_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False, indent=2, sort_keys=False)
            
            # Add header comment
            self._add_yaml_header(yaml_file, json_file)
            
            logger.info(f"✅ Converted {json_file} → {yaml_file}")
            
            # Remove original JSON file after successful conversion
            json_file.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to convert {json_file}: {e}")
            return False
    
    def _add_yaml_header(self, yaml_file: Path, original_file: Path):
        """Add header comment to YAML file."""
        try:
            # Read existing content
            with open(yaml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create header
            header = f"""# NetLink Configuration File
# Converted from: {original_file.name}
# Conversion date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Format: YAML
# 
# This file contains configuration settings for NetLink.
# Edit with care and ensure proper YAML syntax.

"""
            
            # Write with header
            with open(yaml_file, 'w', encoding='utf-8') as f:
                f.write(header + content)
                
        except Exception as e:
            logger.error(f"Failed to add header to {yaml_file}: {e}")
    
    def _update_code_references(self):
        """Update code references from JSON to YAML files."""
        try:
            # Find Python files that might reference config files
            python_files = list(self.root_path.glob("src/**/*.py"))
            
            for py_file in python_files:
                self._update_file_references(py_file)
                
        except Exception as e:
            logger.error(f"Failed to update code references: {e}")
    
    def _update_file_references(self, py_file: Path):
        """Update file references in a Python file."""
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Replace common JSON config references
            replacements = [
                ('config.json', 'config.yaml'),
                ('settings.json', 'settings.yaml'),
                ('.json"', '.yaml"'),
                (".json'", ".yaml'"),
                ('json.load', 'yaml.safe_load'),
                ('json.dump', 'yaml.dump'),
                ('import json', 'import yaml'),
            ]
            
            for old, new in replacements:
                content = content.replace(old, new)
            
            # Only write if changes were made
            if content != original_content:
                with open(py_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"📝 Updated references in {py_file}")
                
        except Exception as e:
            logger.error(f"Failed to update references in {py_file}: {e}")
    
    def create_yaml_config_template(self, template_path: str, config_type: str = "general") -> bool:
        """Create a YAML configuration template."""
        try:
            template_file = Path(template_path)
            template_file.parent.mkdir(parents=True, exist_ok=True)
            
            if config_type == "backup_node":
                template = self._get_backup_node_template()
            elif config_type == "module":
                template = self._get_module_template()
            elif config_type == "security":
                template = self._get_security_template()
            else:
                template = self._get_general_template()
            
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(template)
            
            logger.info(f"✅ Created YAML template: {template_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create template {template_path}: {e}")
            return False
    
    def _get_backup_node_template(self) -> str:
        """Get backup node configuration template."""
        return """# NetLink Backup Node Configuration
# This file configures a backup node for distributed storage

# Node Identity
node_id: "backup_node_example"
node_name: "NetLink Backup Node"
node_mode: "standalone"  # builtin, standalone, hybrid

# Network Settings
host: "0.0.0.0"
port: 8001
api_key: "your-secure-api-key-here"

# Storage Configuration
storage_path: "data/backup_node/storage"
max_storage_gb: 100
cleanup_threshold_percent: 85
shard_replication_factor: 2

# Performance Settings
max_concurrent_operations: 10
health_check_interval: 30
sync_interval: 300
compression_enabled: true

# Security Settings
encryption_enabled: true
require_authentication: true
allowed_nodes: []

# Clustering
cluster_enabled: true
auto_discovery: true
cluster_nodes: []
"""
    
    def _get_module_template(self) -> str:
        """Get module configuration template."""
        return """# NetLink Module Configuration
# This file configures a NetLink module

# Module Information
module_name: "example_module"
module_version: "1.0.0"
module_description: "Example NetLink module"

# Module Settings
enabled: true
auto_load: true
priority: 1

# Dependencies
dependencies: []
optional_dependencies: []

# Permissions
required_permissions: []
user_tier_access: ["basic", "premium", "admin"]

# Configuration
settings:
  debug: false
  log_level: "INFO"
  
# Custom module-specific settings go here
custom_settings: {}
"""
    
    def _get_security_template(self) -> str:
        """Get security configuration template."""
        return """# NetLink Security Configuration
# This file configures security settings

# General Security
security_enabled: true
debug_mode: false

# Authentication
require_authentication: true
session_timeout: 3600
max_login_attempts: 5

# Rate Limiting
rate_limiting_enabled: true
requests_per_minute: 60
burst_limit: 100

# DDoS Protection
ddos_protection_enabled: true
auto_block_threshold: 10
block_duration: 300

# Encryption
encryption_enabled: true
encryption_algorithm: "AES-256"

# Logging
security_logging: true
log_failed_attempts: true
log_suspicious_activity: true
"""
    
    def _get_general_template(self) -> str:
        """Get general configuration template."""
        return """# NetLink General Configuration
# This file contains general application settings

# Application Settings
app_name: "NetLink"
app_version: "3.0.0"
debug: false

# Database
database:
  type: "sqlite"
  path: "data/netlink.db"
  
# Logging
logging:
  level: "INFO"
  file: "logs/netlink.log"
  max_size: "10MB"
  backup_count: 5

# Features
features:
  backup_system: true
  clustering: true
  ai_integration: true
  web_ui: true
"""

# Global converter instance
yaml_converter = YAMLConverter()

def convert_all_configs() -> Dict[str, Any]:
    """Convert all configuration files to YAML format."""
    return yaml_converter.convert_all_configs()

def create_config_template(template_path: str, config_type: str = "general") -> bool:
    """Create a YAML configuration template."""
    return yaml_converter.create_yaml_config_template(template_path, config_type)
