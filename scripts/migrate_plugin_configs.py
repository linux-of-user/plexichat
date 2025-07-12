#!/usr/bin/env python3
"""
Plugin Configuration Migration Script

Migrates existing plugin configurations to the unified configuration system:
- Discovers all plugin.json files
- Converts to unified YAML format
- Creates configuration schemas
- Sets up environment-specific overrides
- Validates migrated configurations
"""

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from plexichat.infrastructure.modules.config_manager import (
    get_plugin_config_manager, 
    PluginConfigSchema
)
from plexichat.core_system.logging import get_logger

logger = get_logger(__name__)


class PluginConfigMigrator:
    """Migrates plugin configurations to unified system."""
    
    def __init__(self):
        self.config_manager = get_plugin_config_manager()
        self.source_paths = [
            Path("src/plexichat/features/plugins"),
            Path("plugins"),
            Path("user_plugins")
        ]
        self.migration_report = {
            "discovered": 0,
            "migrated": 0,
            "failed": 0,
            "skipped": 0,
            "errors": []
        }
    
    async def migrate_all_configs(self) -> Dict[str, Any]:
        """Migrate all discovered plugin configurations."""
        logger.info("🔄 Starting plugin configuration migration...")
        
        # Initialize config manager
        await self.config_manager.initialize()
        
        # Discover all plugin configurations
        plugin_configs = self._discover_plugin_configs()
        self.migration_report["discovered"] = len(plugin_configs)
        
        logger.info(f"📋 Discovered {len(plugin_configs)} plugin configurations")
        
        # Migrate each configuration
        for plugin_path, config_data in plugin_configs.items():
            try:
                plugin_name = self._extract_plugin_name(plugin_path, config_data)
                
                logger.info(f"🔄 Migrating plugin: {plugin_name}")
                
                # Convert to unified format
                unified_config = self._convert_to_unified_format(config_data)
                
                # Create schema
                schema = self._create_schema_from_config(plugin_name, config_data)
                
                # Register with config manager
                success = await self.config_manager.register_plugin_config(
                    plugin_name, 
                    unified_config, 
                    schema
                )
                
                if success:
                    self.migration_report["migrated"] += 1
                    logger.info(f"✅ Successfully migrated: {plugin_name}")
                    
                    # Create environment-specific configs if needed
                    await self._create_environment_configs(plugin_name, config_data)
                else:
                    self.migration_report["failed"] += 1
                    logger.error(f"❌ Failed to migrate: {plugin_name}")
                
            except Exception as e:
                self.migration_report["failed"] += 1
                error_msg = f"Migration failed for {plugin_path}: {str(e)}"
                self.migration_report["errors"].append(error_msg)
                logger.error(error_msg)
        
        # Generate migration report
        self._generate_migration_report()
        
        logger.info("🎉 Plugin configuration migration completed!")
        return self.migration_report
    
    def _discover_plugin_configs(self) -> Dict[Path, Dict[str, Any]]:
        """Discover all plugin configuration files."""
        configs = {}
        
        for source_path in self.source_paths:
            if not source_path.exists():
                continue
            
            # Find plugin.json files
            for config_file in source_path.rglob("plugin.json"):
                try:
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                    configs[config_file] = config_data
                    logger.debug(f"Found plugin config: {config_file}")
                except Exception as e:
                    logger.warning(f"Failed to load {config_file}: {e}")
        
        return configs
    
    def _extract_plugin_name(self, plugin_path: Path, config_data: Dict[str, Any]) -> str:
        """Extract plugin name from path or config."""
        # Try to get name from config
        if "name" in config_data:
            # Convert to valid identifier
            name = config_data["name"].lower().replace(" ", "_").replace("-", "_")
            return "".join(c for c in name if c.isalnum() or c == "_")
        
        # Fallback to directory name
        return plugin_path.parent.name
    
    def _convert_to_unified_format(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert plugin.json to unified configuration format."""
        unified_config = {}
        
        # Basic metadata
        unified_config["metadata"] = {
            "name": config_data.get("name", "Unknown Plugin"),
            "version": config_data.get("version", "1.0.0"),
            "description": config_data.get("description", ""),
            "author": config_data.get("author", ""),
            "license": config_data.get("license", "Unknown"),
            "homepage": config_data.get("homepage"),
            "repository": config_data.get("repository")
        }
        
        # Plugin settings
        unified_config["plugin"] = {
            "type": config_data.get("type", "feature"),
            "category": config_data.get("category", "general"),
            "main_file": config_data.get("main", "main.py"),
            "class_name": config_data.get("class"),
            "entry_point": config_data.get("entry_point", "main"),
            "auto_load": config_data.get("auto_load", True),
            "enabled": config_data.get("enabled", True)
        }
        
        # Dependencies
        if "dependencies" in config_data:
            unified_config["dependencies"] = config_data["dependencies"]
        
        # Permissions
        if "permissions" in config_data:
            unified_config["permissions"] = {
                "required": config_data["permissions"],
                "optional": config_data.get("optional_permissions", [])
            }
        
        # Configuration settings
        if "configuration" in config_data:
            unified_config["settings"] = config_data["configuration"]
        
        # Features and capabilities
        if "features" in config_data:
            unified_config["features"] = config_data["features"]
        
        # API information
        if "api" in config_data:
            unified_config["api"] = config_data["api"]
        
        # Database requirements
        if "database_tables" in config_data:
            unified_config["database"] = {
                "tables": config_data["database_tables"],
                "migrations": config_data.get("migrations", [])
            }
        
        # Storage requirements
        if "storage_requirements" in config_data:
            unified_config["storage"] = config_data["storage_requirements"]
        
        # Performance specifications
        if "performance" in config_data:
            unified_config["performance"] = config_data["performance"]
        
        # Security settings
        if "security" in config_data:
            unified_config["security"] = config_data["security"]
        
        # Installation settings
        if "installation" in config_data:
            unified_config["installation"] = config_data["installation"]
        
        return unified_config
    
    def _create_schema_from_config(self, plugin_name: str, config_data: Dict[str, Any]) -> PluginConfigSchema:
        """Create a configuration schema from the plugin config."""
        
        # Base schema structure
        schema = {
            "type": "object",
            "properties": {
                "metadata": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
                        "description": {"type": "string"},
                        "author": {"type": "string"},
                        "license": {"type": "string"}
                    },
                    "required": ["name", "version"]
                },
                "plugin": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["feature", "system", "ui", "integration"]},
                        "category": {"type": "string"},
                        "enabled": {"type": "boolean", "default": True},
                        "auto_load": {"type": "boolean", "default": True}
                    }
                },
                "settings": {
                    "type": "object",
                    "additionalProperties": True
                }
            },
            "required": ["metadata", "plugin"]
        }
        
        # Extract default values
        default_values = {}
        if "configuration" in config_data:
            default_values["settings"] = config_data["configuration"]
        
        # Environment overrides for common scenarios
        environment_overrides = {
            "development": {
                "plugin": {
                    "debug": True,
                    "verbose_logging": True
                }
            },
            "testing": {
                "plugin": {
                    "enabled": False  # Disable by default in tests
                }
            },
            "production": {
                "plugin": {
                    "debug": False,
                    "verbose_logging": False
                }
            }
        }
        
        return PluginConfigSchema(
            name=plugin_name,
            version=config_data.get("version", "1.0.0"),
            schema=schema,
            default_values=default_values,
            required_fields=["metadata", "plugin"],
            environment_overrides=environment_overrides
        )
    
    async def _create_environment_configs(self, plugin_name: str, config_data: Dict[str, Any]):
        """Create environment-specific configuration files."""
        try:
            environments = ["development", "testing", "staging", "production"]
            
            for env in environments:
                env_dir = self.config_manager.environments_dir / env
                env_dir.mkdir(parents=True, exist_ok=True)
                
                env_config_file = env_dir / f"{plugin_name}.yaml"
                
                # Create environment-specific overrides
                env_config = {}
                
                if env == "development":
                    env_config = {
                        "plugin": {
                            "debug": True,
                            "hot_reload": True
                        },
                        "settings": {
                            "log_level": "DEBUG"
                        }
                    }
                elif env == "testing":
                    env_config = {
                        "plugin": {
                            "enabled": False,
                            "mock_mode": True
                        }
                    }
                elif env == "production":
                    env_config = {
                        "plugin": {
                            "debug": False,
                            "hot_reload": False
                        },
                        "settings": {
                            "log_level": "INFO"
                        }
                    }
                
                if env_config:
                    with open(env_config_file, 'w') as f:
                        yaml.dump(env_config, f, default_flow_style=False)
                    
                    logger.debug(f"Created environment config: {env_config_file}")
                    
        except Exception as e:
            logger.error(f"Failed to create environment configs for {plugin_name}: {e}")
    
    def _generate_migration_report(self):
        """Generate and save migration report."""
        try:
            report_file = Path("config/plugins/migration_report.yaml")
            report_file.parent.mkdir(parents=True, exist_ok=True)
            
            report_data = {
                "migration_summary": self.migration_report,
                "timestamp": "2024-01-01T00:00:00Z",  # Would use actual timestamp
                "recommendations": [
                    "Review migrated configurations for accuracy",
                    "Test plugins with new configuration system",
                    "Update plugin documentation to reflect new config format",
                    "Remove old plugin.json files after verification"
                ]
            }
            
            with open(report_file, 'w') as f:
                yaml.dump(report_data, f, default_flow_style=False)
            
            logger.info(f"📄 Migration report saved: {report_file}")
            
        except Exception as e:
            logger.error(f"Failed to generate migration report: {e}")
    
    def print_migration_summary(self):
        """Print migration summary to console."""
        print("\n" + "="*60)
        print("PLUGIN CONFIGURATION MIGRATION SUMMARY")
        print("="*60)
        print(f"📋 Discovered: {self.migration_report['discovered']} configurations")
        print(f"✅ Migrated:   {self.migration_report['migrated']} configurations")
        print(f"❌ Failed:     {self.migration_report['failed']} configurations")
        print(f"⏭️  Skipped:    {self.migration_report['skipped']} configurations")
        
        if self.migration_report["errors"]:
            print(f"\n❌ ERRORS:")
            for error in self.migration_report["errors"]:
                print(f"  - {error}")
        
        success_rate = (self.migration_report['migrated'] / max(1, self.migration_report['discovered'])) * 100
        print(f"\n📊 Success Rate: {success_rate:.1f}%")
        
        if success_rate == 100:
            print("🎉 All configurations migrated successfully!")
        elif success_rate >= 80:
            print("✅ Migration mostly successful - review failed items")
        else:
            print("⚠️  Migration had significant issues - manual review required")


async def main():
    """Main migration entry point."""
    migrator = PluginConfigMigrator()
    
    try:
        # Run migration
        report = await migrator.migrate_all_configs()
        
        # Print summary
        migrator.print_migration_summary()
        
        # Exit with appropriate code
        if report["failed"] == 0:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Migration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
