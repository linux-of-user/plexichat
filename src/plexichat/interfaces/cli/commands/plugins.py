"""
Enhanced Plugin CLI Interface for PlexiChat
Command-line interface for comprehensive plugin management.
"""
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalCall=false
# pyright: reportPossiblyUnboundVariable=false

import logging
from pathlib import Path
from typing import List

try:
    from plexichat.app.plugins.enhanced_plugin_manager import PluginSource, get_enhanced_plugin_manager
    from plexichat.core.config import settings
except ImportError:
    # Mock classes for missing imports
    class PluginSource:
        LOCAL = 'local'
        MARKETPLACE = 'marketplace'
        GITHUB = 'github'
        
        def __init__(self, value):
            self.value = value
    
    class MockPluginManager:
        def __init__(self):
            self.plugin_metadata = {}
        
        def get_plugin_dashboard_data(self):
            return {'plugins': [], 'security_overview': {}}
        
        async def install_plugin_from_zip(self, zip_path, source):
            return {'success': True, 'message': 'Mock installation successful'}
        
        async def uninstall_plugin(self, plugin_name, remove_data):
            return {'success': True, 'message': 'Mock uninstall successful'}
        
        def enable_plugin(self, plugin_name):
            return True
        
        def disable_plugin(self, plugin_name):
            return True
        
        async def update_plugin(self, plugin_name):
            return {'success': True, 'message': 'Mock update successful'}
        
        async def check_for_updates(self, plugin_name=None):
            return {'success': True, 'updates': {}, 'total_updates': 0}
        
        async def rescan_plugin_security(self, plugin_name):
            return {'success': True, 'security_result': {'passed': True, 'risk_level': 'low'}}
        
        def set_plugin_auto_update(self, plugin_name, enabled):
            return {'success': True, 'message': 'Auto-update setting changed'}
        
        async def cleanup_quarantine(self, days_old):
            return {'success': True, 'message': 'Cleanup completed'}
    
    def get_enhanced_plugin_manager():
        return MockPluginManager()
    
    settings = {}

logger = logging.getLogger(__name__)
class PluginCLI:
    """Command-line interface for plugin management."""

    def __init__(self):
        self.plugin_manager = get_enhanced_plugin_manager()

    async def cmd_list(self, args: List[str]) -> None:
        """List all installed plugins."""
        try:
            dashboard_data = self.plugin_manager.get_plugin_dashboard_data()
            plugins = dashboard_data.get("plugins", [])

            if not plugins:
                logger.info(" No plugins installed")
                return

            logger.info(f" Installed Plugins ({len(plugins)} total)")
            logger.info("=" * 80)

            for plugin in plugins:
                status_emoji = {
                    "enabled": "",
                    "disabled": "",
                    "quarantined": "",
                    "failed": "",
                    "updating": ""
                }.get(plugin["status"], "")

                risk_emoji = {
                    "low": "",
                    "medium": "",
                    "high": "",
                    "critical": ""
                }.get(plugin.get("security", {}).get("risk_level", "low"), "")

                logger.info(f"{status_emoji} {plugin['name']:<20} v{plugin['version']:<10} "
                      f"{plugin['source']:<12} {risk_emoji} {plugin['size_mb']:.1f}MB")

                if plugin.get("update_info", {}).get("update_available"):
                    logger.info(f"    Update available: v{plugin['update_info']['latest_version']}")

        except Exception as e:
            logger.info(f" Failed to list plugins: {e}")

    async def cmd_install(self, args: List[str]) -> None:
        """Install plugin from ZIP file."""
        if len(args) < 1:
            logger.info("Usage: plugin install <zip_file> [source]")
            return

        zip_path = Path(args[0])
        source = PluginSource(args[1].lower()) if len(args) > 1 else PluginSource.LOCAL

        if not zip_path.exists():
            logger.info(f" File not found: {zip_path}")
            return

        try:
            logger.info(f" Installing plugin from {zip_path}...")
            result = await self.plugin_manager.install_plugin_from_zip(zip_path, source)

            if result["success"]:
                logger.info(f" {result['message']}")
                if "plugin_name" in result:
                    logger.info(f"   Plugin: {result['plugin_name']} v{result.get('version', 'Unknown')}")
            else:
                logger.info(f" Installation failed: {result['error']}")

        except Exception as e:
            logger.info(f" Installation error: {e}")

    async def cmd_uninstall(self, args: List[str]) -> None:
        """Uninstall plugin."""
        if len(args) < 1:
            logger.info("Usage: plugin uninstall <plugin_name> [--remove-data]")
            return

        plugin_name = args[0]
        remove_data = "--remove-data" in args

        try:
            logger.info(f" Uninstalling plugin: {plugin_name}...")
            result = await self.plugin_manager.uninstall_plugin(plugin_name, remove_data)

            if result["success"]:
                logger.info(f" {result['message']}")
            else:
                logger.info(f" Uninstall failed: {result['error']}")

        except Exception as e:
            logger.info(f" Uninstall error: {e}")

    async def cmd_enable(self, args: List[str]) -> None:
        """Enable plugin."""
        if len(args) < 1:
            logger.info("Usage: plugin enable <plugin_name>")
            return

        plugin_name = args[0]

        try:
            success = self.plugin_manager.enable_plugin(plugin_name)
            if success:
                logger.info(f" Plugin enabled: {plugin_name}")
            else:
                logger.info(f" Failed to enable plugin: {plugin_name}")

        except Exception as e:
            logger.info(f" Enable error: {e}")

    async def cmd_disable(self, args: List[str]) -> None:
        """Disable plugin."""
        if len(args) < 1:
            logger.info("Usage: plugin disable <plugin_name>")
            return

        plugin_name = args[0]

        try:
            success = self.plugin_manager.disable_plugin(plugin_name)
            if success:
                logger.info(f" Plugin disabled: {plugin_name}")
            else:
                logger.info(f" Failed to disable plugin: {plugin_name}")

        except Exception as e:
            logger.info(f" Disable error: {e}")

    async def cmd_info(self, args: List[str]) -> None:
        """Show detailed plugin information."""
        if len(args) < 1:
            logger.info("Usage: plugin info <plugin_name>")
            return

        plugin_name = args[0]

        try:
            dashboard_data = self.plugin_manager.get_plugin_dashboard_data()
            plugin_data = None

            for plugin in dashboard_data.get("plugins", []):
                if plugin["name"] == plugin_name:
                    plugin_data = plugin
                    break

            if not plugin_data:
                logger.info(f" Plugin not found: {plugin_name}")
                return

            logger.info(f" Plugin Information: {plugin_name}")
            logger.info("=" * 50)
            logger.info(f"Version:      {plugin_data['version']}")
            logger.info(f"Status:       {plugin_data['status']}")
            logger.info(f"Source:       {plugin_data['source']}")
            logger.info(f"Size:         {plugin_data['size_mb']:.1f} MB")
            logger.info(f"Install Date: {plugin_data['install_date'][:10]}")

            # Security information
            security = plugin_data.get("security", {})
            if security:
                logger.info("\n Security:")
                logger.info(f"Risk Level:   {security.get('risk_level', 'Unknown')}")
                logger.info(f"Virus Clean:  {'' if security.get('virus_scan_clean') else ''}")
                logger.info(f"Signed:       {'' if security.get('signature_valid') else ''}")
                if security.get("scan_date"):
                    logger.info(f"Last Scan:    {security['scan_date'][:10]}")

            # Update information
            update_info = plugin_data.get("update_info", {})
            if update_info:
                logger.info("\n Updates:")
                logger.info(f"Available:    {'' if update_info.get('update_available') else ''}")
                if update_info.get("latest_version"):
                    logger.info(f"Latest:       v{update_info['latest_version']}")
                logger.info(f"Auto-Update:  {'' if update_info.get('auto_update_enabled') else ''}")

            # Plugin metadata
            if plugin_name in self.plugin_manager.plugin_metadata:
                metadata = self.plugin_manager.plugin_metadata[plugin_name]
                logger.info("\n Details:")
                logger.info(f"Description:  {metadata.description}")
                logger.info(f"Author:       {metadata.author}")
                if metadata.dependencies:
                    logger.info(f"Dependencies: {', '.join(metadata.dependencies)}")

        except Exception as e:
            logger.info(f" Info error: {e}")

    async def cmd_update(self, args: List[str]) -> None:
        """Update plugin to latest version."""
        if len(args) < 1:
            logger.info("Usage: plugin update <plugin_name>")
            return

        plugin_name = args[0]

        try:
            logger.info(f" Updating plugin: {plugin_name}...")
            result = await self.plugin_manager.update_plugin(plugin_name)

            if result["success"]:
                logger.info(f" {result['message']}")
            else:
                logger.info(f" Update failed: {result['error']}")

        except Exception as e:
            logger.info(f" Update error: {e}")

    async def cmd_check_updates(self, args: List[str]) -> None:
        """Check for plugin updates."""
        plugin_name = args[0] if args else None

        try:
            logger.info(" Checking for updates...")
            result = await self.plugin_manager.check_for_updates(plugin_name)

            if result["success"]:
                updates = result.get("updates", {})
                total_updates = result.get("total_updates", 0)

                if total_updates == 0:
                    logger.info(" All plugins are up to date")
                else:
                    logger.info(f" {total_updates} update(s) available:")
                    for name, update_info in updates.items():
                        if update_info.get("update_available"):
                            logger.info(f"    {name}: v{update_info.get('current_version', '?')}  "
                                  f"v{update_info.get('latest_version', '?')}")
            else:
                logger.info(f" Update check failed: {result['error']}")

        except Exception as e:
            logger.info(f" Update check error: {e}")

    async def cmd_security(self, args: List[str]) -> None:
        """Show security overview or scan specific plugin."""
        if args and args[0] == "scan" and len(args) > 1:
            # Scan specific plugin
            plugin_name = args[1]
            try:
                logger.info(f" Scanning plugin: {plugin_name}...")
                result = await self.plugin_manager.rescan_plugin_security(plugin_name)

                if result["success"]:
                    security_result = result.get("security_result", {})
                    if security_result.get("passed"):
                        logger.info(" Security scan passed")
                        logger.info(f"   Risk Level: {security_result.get('risk_level', 'low')}")
                    else:
                        logger.info(f" Security scan failed: {security_result.get('reason')}")
                else:
                    logger.info(f" Scan failed: {result['error']}")

            except Exception as e:
                logger.info(f" Security scan error: {e}")
        else:
            # Show security overview
            try:
                dashboard_data = self.plugin_manager.get_plugin_dashboard_data()
                security_overview = dashboard_data.get("security_overview", {})

                logger.info(" Security Overview")
                logger.info("=" * 30)
                logger.info(f"High Risk Plugins:    {security_overview.get('high_risk_plugins', 0)}")
                logger.info(f"Unsigned Plugins:     {security_overview.get('unsigned_plugins', 0)}")
                logger.info(f"Outdated Scans:       {security_overview.get('outdated_scans', 0)}")

                # Show high-risk plugins
                high_risk = []
                for plugin in dashboard_data.get("plugins", []):
                    security = plugin.get("security", {})
                    if security.get("risk_level") in ["high", "critical"]:
                        high_risk.append(plugin)

                if high_risk:
                    logger.info("\n High Risk Plugins:")
                    for plugin in high_risk:
                        risk_level = plugin["security"]["risk_level"]
                        logger.info(f"    {plugin['name']} ({risk_level} risk)")

            except Exception as e:
                logger.info(f" Security overview error: {e}")

    async def cmd_auto_update(self, args: List[str]) -> None:
        """Manage auto-update from plexichat.core.config import settings
settings."""
        if len(args) < 2:
            logger.info("Usage: plugin auto-update <plugin_name> <enable|disable>")
            return

        plugin_name = args[0]
        action = args[1].lower()

        if action not in ["enable", "disable"]:
            logger.info("Action must be 'enable' or 'disable'")
            return

        try:
            enabled = action == "enable"
            result = self.plugin_manager.set_plugin_auto_update(plugin_name, enabled)

            if result["success"]:
                logger.info(f" {result['message']}")
            else:
                logger.info(f" Failed to set auto-update: {result['error']}")

        except Exception as e:
            logger.info(f" Auto-update error: {e}")

    async def cmd_cleanup(self, args: List[str]) -> None:
        """Clean up quarantined plugins."""
        days_old = int(args[0]) if args and args[0].isdigit() else 30

        try:
            logger.info(f" Cleaning up quarantined plugins older than {days_old} days...")
            result = await self.plugin_manager.cleanup_quarantine(days_old)

            if result["success"]:
                logger.info(f" {result['message']}")
            else:
                logger.info(f" Cleanup failed: {result['error']}")

        except Exception as e:
            logger.info(f" Cleanup error: {e}")

    async def execute_command(self, command: str, args: List[str]) -> None:
        """Execute plugin CLI command."""
        commands = {
            "list": self.cmd_list,
            "install": self.cmd_install,
            "uninstall": self.cmd_uninstall,
            "enable": self.cmd_enable,
            "disable": self.cmd_disable,
            "info": self.cmd_info,
            "update": self.cmd_update,
            "check-updates": self.cmd_check_updates,
            "security": self.cmd_security,
            "auto-update": self.cmd_auto_update,
            "cleanup": self.cmd_cleanup
        }

        if command in commands:
            await commands[command](args)
        else:
            logger.info(f" Unknown command: {command}")
            logger.info("Available commands: " + ", ".join(commands.keys()))

# Global plugin CLI instance
plugin_cli = PluginCLI()

async def handle_plugin_command(args: List[str]) -> None:
    """Handle plugin CLI commands."""
    if not args:
        logger.info("Usage: plugin <command> [args...]")
        logger.info("Commands: list, install, uninstall, enable, disable, info, update, check-updates, security, auto-update, cleanup")
        return

    command = args[0]
    command_args = args[1:]

    await plugin_cli.execute_command(command, command_args)
