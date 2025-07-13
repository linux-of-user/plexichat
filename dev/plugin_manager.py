#!/usr/bin/env python3
"""
PlexiChat Enhanced Plugin Manager

Comprehensive plugin management tool with:
- Plugin discovery and loading
- ZIP installation and removal
- Marketplace integration
- Configuration management
- Health monitoring
- UI management
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from plexichat.infrastructure.modules.enhanced_plugin_manager import (
    get_enhanced_plugin_manager, PluginStatus, PluginType
)


class PluginManagerCLI:
    """Command-line interface for plugin management."""
    
    def __init__(self):
        self.plugin_manager = get_enhanced_plugin_manager()
        self.logger = logging.getLogger(__name__)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    async def initialize(self):
        """Initialize the plugin manager."""
        try:
            await self.plugin_manager.initialize()
            self.logger.info("Plugin manager initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin manager: {e}")
            return False
        return True
    
    async def list_plugins(self, show_details: bool = False):
        """List all plugins."""
        try:
            plugins_info = self.plugin_manager.get_all_plugins_info()
            
            if not plugins_info:
                print("No plugins found.")
                return
            
            print(f"\nFound {len(plugins_info)} plugins:\n")
            
            for plugin_name, info in plugins_info.items():
                if not info:
                    continue
                
                metadata = info.get("metadata", {})
                status = info.get("status", "unknown")
                enabled = info.get("enabled", False)
                loaded = info.get("loaded", False)
                
                # Status indicator
                status_icon = {
                    "loaded": "✅",
                    "error": "❌",
                    "disabled": "⏸️",
                    "unknown": "❓"
                }.get(status, "❓")
                
                # Enabled indicator
                enabled_icon = "🟢" if enabled else "🔴"
                
                print(f"{status_icon} {enabled_icon} {plugin_name}")
                print(f"    Version: {metadata.get('version', 'unknown')}")
                print(f"    Author: {metadata.get('author', 'unknown')}")
                print(f"    Type: {metadata.get('plugin_type', 'unknown')}")
                print(f"    Category: {metadata.get('category', 'general')}")
                print(f"    Status: {status}")
                print(f"    Enabled: {enabled}")
                print(f"    Loaded: {loaded}")
                
                if show_details:
                    print(f"    Description: {metadata.get('description', 'No description')}")
                    print(f"    Dependencies: {', '.join(metadata.get('dependencies', []))}")
                    print(f"    UI Pages: {len(info.get('ui_pages', []))}")
                    print(f"    API Endpoints: {len(info.get('api_endpoints', []))}")
                    print(f"    Background Tasks: {len(info.get('background_tasks', []))}")
                
                print()
        
        except Exception as e:
            self.logger.error(f"Error listing plugins: {e}")
            print(f"Error listing plugins: {e}")
    
    async def install_plugin(self, source: str, verify_checksum: bool = True):
        """Install a plugin."""
        try:
            if source.endswith('.zip'):
                # Install from ZIP file
                zip_path = Path(source)
                if not zip_path.exists():
                    print(f"Error: ZIP file not found: {source}")
                    return False
                
                print(f"Installing plugin from ZIP: {source}")
                success = await self.plugin_manager.install_plugin_from_zip(zip_path, verify_checksum)
                
                if success:
                    print("Plugin installed successfully!")
                    return True
                else:
                    print("Failed to install plugin.")
                    return False
            
            elif source.startswith('http'):
                # Install from URL
                print(f"Installing plugin from URL: {source}")
                success = await self.plugin_manager.install_plugin_from_zip(Path(source), verify_checksum)
                
                if success:
                    print("Plugin installed successfully!")
                    return True
                else:
                    print("Failed to install plugin.")
                    return False
            
            else:
                # Try marketplace
                print(f"Installing plugin from marketplace: {source}")
                plugin_file = await self.plugin_manager.marketplace.download_plugin(source)
                
                if not plugin_file:
                    print("Failed to download plugin from marketplace.")
                    return False
                
                success = await self.plugin_manager.install_plugin_from_zip(plugin_file, verify_checksum)
                plugin_file.unlink()  # Clean up
                
                if success:
                    print("Plugin installed successfully!")
                    return True
                else:
                    print("Failed to install plugin.")
                    return False
        
        except Exception as e:
            self.logger.error(f"Error installing plugin: {e}")
            print(f"Error installing plugin: {e}")
            return False
    
    async def remove_plugin(self, plugin_name: str, keep_data: bool = False):
        """Remove a plugin."""
        try:
            print(f"Removing plugin: {plugin_name}")
            success = await self.plugin_manager.remove_plugin(plugin_name, keep_data)
            
            if success:
                print("Plugin removed successfully!")
                return True
            else:
                print("Failed to remove plugin.")
                return False
        
        except Exception as e:
            self.logger.error(f"Error removing plugin: {e}")
            print(f"Error removing plugin: {e}")
            return False
    
    async def enable_plugin(self, plugin_name: str):
        """Enable a plugin."""
        try:
            print(f"Enabling plugin: {plugin_name}")
            success = await self.plugin_manager.load_plugin(plugin_name)
            
            if success:
                print("Plugin enabled successfully!")
                return True
            else:
                print("Failed to enable plugin.")
                return False
        
        except Exception as e:
            self.logger.error(f"Error enabling plugin: {e}")
            print(f"Error enabling plugin: {e}")
            return False
    
    async def disable_plugin(self, plugin_name: str):
        """Disable a plugin."""
        try:
            print(f"Disabling plugin: {plugin_name}")
            success = await self.plugin_manager.unload_plugin(plugin_name)
            
            if success:
                print("Plugin disabled successfully!")
                return True
            else:
                print("Failed to disable plugin.")
                return False
        
        except Exception as e:
            self.logger.error(f"Error disabling plugin: {e}")
            print(f"Error disabling plugin: {e}")
            return False
    
    async def configure_plugin(self, plugin_name: str, config_file: str):
        """Configure a plugin."""
        try:
            # Load configuration from file
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            print(f"Configuring plugin: {plugin_name}")
            
            # Save configuration
            config_path = Path(f"data/plugins/{plugin_name}/config.json")
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print("Plugin configured successfully!")
            return True
        
        except Exception as e:
            self.logger.error(f"Error configuring plugin: {e}")
            print(f"Error configuring plugin: {e}")
            return False
    
    async def get_plugin_info(self, plugin_name: str):
        """Get detailed information about a plugin."""
        try:
            plugin_info = self.plugin_manager.get_plugin_info(plugin_name)
            
            if not plugin_info:
                print(f"Plugin not found: {plugin_name}")
                return False
            
            print(f"\nPlugin Information: {plugin_name}")
            print("=" * 50)
            
            metadata = plugin_info.get("metadata", {})
            print(f"Name: {metadata.get('name', 'N/A')}")
            print(f"Version: {metadata.get('version', 'N/A')}")
            print(f"Author: {metadata.get('author', 'N/A')}")
            print(f"Description: {metadata.get('description', 'N/A')}")
            print(f"Type: {metadata.get('plugin_type', 'N/A')}")
            print(f"Category: {metadata.get('category', 'N/A')}")
            print(f"License: {metadata.get('license', 'N/A')}")
            print(f"Status: {plugin_info.get('status', 'N/A')}")
            print(f"Enabled: {plugin_info.get('enabled', False)}")
            print(f"Loaded: {plugin_info.get('loaded', False)}")
            
            # Dependencies
            deps = metadata.get('dependencies', [])
            if deps:
                print(f"Dependencies: {', '.join(deps)}")
            
            # UI Pages
            ui_pages = plugin_info.get('ui_pages', [])
            if ui_pages:
                print(f"UI Pages: {len(ui_pages)}")
                for page in ui_pages:
                    print(f"  - {page.get('title', 'Unknown')}: {page.get('description', 'No description')}")
            
            # API Endpoints
            api_endpoints = plugin_info.get('api_endpoints', [])
            if api_endpoints:
                print(f"API Endpoints: {len(api_endpoints)}")
                for endpoint in api_endpoints:
                    print(f"  - {endpoint}")
            
            # Background Tasks
            bg_tasks = plugin_info.get('background_tasks', [])
            if bg_tasks:
                print(f"Background Tasks: {len(bg_tasks)}")
                for task in bg_tasks:
                    print(f"  - {task}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error getting plugin info: {e}")
            print(f"Error getting plugin info: {e}")
            return False
    
    async def search_marketplace(self, query: str = "", category: str = ""):
        """Search plugins in marketplace."""
        try:
            print(f"Searching marketplace for: {query or 'all plugins'}")
            results = await self.plugin_manager.marketplace.search_plugins(query, category)
            
            if not results:
                print("No plugins found.")
                return
            
            print(f"\nFound {len(results)} plugins:\n")
            
            for plugin in results:
                print(f"📦 {plugin.get('name', 'Unknown')}")
                print(f"    Version: {plugin.get('version', 'Unknown')}")
                print(f"    Author: {plugin.get('author', 'Unknown')}")
                print(f"    Description: {plugin.get('description', 'No description')}")
                print(f"    Downloads: {plugin.get('download_count', 0)}")
                print(f"    Rating: {plugin.get('rating', 0)}/5")
                print(f"    Category: {plugin.get('category', 'Unknown')}")
                print()
        
        except Exception as e:
            self.logger.error(f"Error searching marketplace: {e}")
            print(f"Error searching marketplace: {e}")
    
    async def get_marketplace_stats(self):
        """Get marketplace statistics."""
        try:
            print("Getting marketplace statistics...")
            
            # Get featured plugins
            featured = await self.plugin_manager.marketplace.search_plugins()
            featured = [p for p in featured if p.get("rating", 0) >= 4.5 and p.get("download_count", 0) >= 100]
            
            # Get categories
            categories = {}
            for plugin in featured:
                category = plugin.get("category", "unknown")
                if category not in categories:
                    categories[category] = 0
                categories[category] += 1
            
            print(f"\nMarketplace Statistics:")
            print(f"Total Featured Plugins: {len(featured)}")
            print(f"Categories: {len(categories)}")
            
            for category, count in categories.items():
                print(f"  - {category}: {count} plugins")
        
        except Exception as e:
            self.logger.error(f"Error getting marketplace stats: {e}")
            print(f"Error getting marketplace stats: {e}")
    
    async def health_check(self):
        """Perform health check on all plugins."""
        try:
            print("Performing plugin health check...")
            
            plugins_info = self.plugin_manager.get_all_plugins_info()
            healthy_count = 0
            total_count = len(plugins_info)
            
            for plugin_name, info in plugins_info.items():
                if not info:
                    continue
                
                plugin = self.plugin_manager.plugins.get(plugin_name)
                if plugin and hasattr(plugin, 'health_check'):
                    try:
                        health = await plugin.health_check()
                        if health.get('healthy', True):
                            print(f"✅ {plugin_name}: Healthy")
                            healthy_count += 1
                        else:
                            print(f"❌ {plugin_name}: Unhealthy - {health.get('message', 'Unknown error')}")
                    except Exception as e:
                        print(f"❌ {plugin_name}: Error - {e}")
                else:
                    status = info.get('status', 'unknown')
                    if status == 'loaded':
                        print(f"✅ {plugin_name}: Loaded (no health check)")
                        healthy_count += 1
                    else:
                        print(f"⚠️  {plugin_name}: {status}")
            
            print(f"\nHealth Check Summary:")
            print(f"Total Plugins: {total_count}")
            print(f"Healthy: {healthy_count}")
            print(f"Unhealthy: {total_count - healthy_count}")
        
        except Exception as e:
            self.logger.error(f"Error performing health check: {e}")
            print(f"Error performing health check: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="PlexiChat Plugin Manager")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List plugins
    list_parser = subparsers.add_parser("list", help="List all plugins")
    list_parser.add_argument("--details", "-d", action="store_true", help="Show detailed information")
    
    # Install plugin
    install_parser = subparsers.add_parser("install", help="Install a plugin")
    install_parser.add_argument("source", help="Plugin source (ZIP file, URL, or marketplace ID)")
    install_parser.add_argument("--no-verify", action="store_true", help="Skip checksum verification")
    
    # Remove plugin
    remove_parser = subparsers.add_parser("remove", help="Remove a plugin")
    remove_parser.add_argument("plugin_name", help="Name of the plugin to remove")
    remove_parser.add_argument("--keep-data", action="store_true", help="Keep plugin data")
    
    # Enable plugin
    enable_parser = subparsers.add_parser("enable", help="Enable a plugin")
    enable_parser.add_argument("plugin_name", help="Name of the plugin to enable")
    
    # Disable plugin
    disable_parser = subparsers.add_parser("disable", help="Disable a plugin")
    disable_parser.add_argument("plugin_name", help="Name of the plugin to disable")
    
    # Configure plugin
    config_parser = subparsers.add_parser("configure", help="Configure a plugin")
    config_parser.add_argument("plugin_name", help="Name of the plugin to configure")
    config_parser.add_argument("config_file", help="Path to configuration JSON file")
    
    # Get plugin info
    info_parser = subparsers.add_parser("info", help="Get plugin information")
    info_parser.add_argument("plugin_name", help="Name of the plugin")
    
    # Search marketplace
    search_parser = subparsers.add_parser("search", help="Search marketplace")
    search_parser.add_argument("query", nargs="?", default="", help="Search query")
    search_parser.add_argument("--category", help="Category filter")
    
    # Marketplace stats
    stats_parser = subparsers.add_parser("stats", help="Get marketplace statistics")
    
    # Health check
    health_parser = subparsers.add_parser("health", help="Perform health check")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create CLI instance
    cli = PluginManagerCLI()
    
    async def run():
        """Run the CLI command."""
        if not await cli.initialize():
            return 1
        
        if args.command == "list":
            await cli.list_plugins(args.details)
        elif args.command == "install":
            success = await cli.install_plugin(args.source, not args.no_verify)
            return 0 if success else 1
        elif args.command == "remove":
            success = await cli.remove_plugin(args.plugin_name, args.keep_data)
            return 0 if success else 1
        elif args.command == "enable":
            success = await cli.enable_plugin(args.plugin_name)
            return 0 if success else 1
        elif args.command == "disable":
            success = await cli.disable_plugin(args.plugin_name)
            return 0 if success else 1
        elif args.command == "configure":
            success = await cli.configure_plugin(args.plugin_name, args.config_file)
            return 0 if success else 1
        elif args.command == "info":
            success = await cli.get_plugin_info(args.plugin_name)
            return 0 if success else 1
        elif args.command == "search":
            await cli.search_marketplace(args.query, args.category)
        elif args.command == "stats":
            await cli.get_marketplace_stats()
        elif args.command == "health":
            await cli.health_check()
        else:
            parser.print_help()
            return 1
        
        return 0
    
    # Run the CLI
    try:
        exit_code = asyncio.run(run())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 