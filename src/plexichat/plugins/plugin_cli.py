"""
Enhanced Plugin CLI Interface for NetLink
Command-line interface for comprehensive plugin management.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from netlink.app.plugins.enhanced_plugin_manager import get_enhanced_plugin_manager, PluginSource, PluginStatus
from netlink.app.logger_config import logger

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
                print("📦 No plugins installed")
                return
            
            print(f"📦 Installed Plugins ({len(plugins)} total)")
            print("=" * 80)
            
            for plugin in plugins:
                status_emoji = {
                    "enabled": "✅",
                    "disabled": "⏸️",
                    "quarantined": "🚨",
                    "failed": "❌",
                    "updating": "🔄"
                }.get(plugin["status"], "❓")
                
                risk_emoji = {
                    "low": "🟢",
                    "medium": "🟡",
                    "high": "🟠",
                    "critical": "🔴"
                }.get(plugin.get("security", {}).get("risk_level", "low"), "⚪")
                
                print(f"{status_emoji} {plugin['name']:<20} v{plugin['version']:<10} "
                      f"{plugin['source']:<12} {risk_emoji} {plugin['size_mb']:.1f}MB")
                
                if plugin.get("update_info", {}).get("update_available"):
                    print(f"   🔄 Update available: v{plugin['update_info']['latest_version']}")
            
        except Exception as e:
            print(f"❌ Failed to list plugins: {e}")
    
    async def cmd_install(self, args: List[str]) -> None:
        """Install plugin from ZIP file."""
        if len(args) < 1:
            print("Usage: plugin install <zip_file> [source]")
            return
        
        zip_path = Path(args[0])
        source = PluginSource(args[1].lower()) if len(args) > 1 else PluginSource.LOCAL
        
        if not zip_path.exists():
            print(f"❌ File not found: {zip_path}")
            return
        
        try:
            print(f"📦 Installing plugin from {zip_path}...")
            result = await self.plugin_manager.install_plugin_from_zip(zip_path, source)
            
            if result["success"]:
                print(f"✅ {result['message']}")
                if "plugin_name" in result:
                    print(f"   Plugin: {result['plugin_name']} v{result.get('version', 'Unknown')}")
            else:
                print(f"❌ Installation failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Installation error: {e}")
    
    async def cmd_uninstall(self, args: List[str]) -> None:
        """Uninstall plugin."""
        if len(args) < 1:
            print("Usage: plugin uninstall <plugin_name> [--remove-data]")
            return
        
        plugin_name = args[0]
        remove_data = "--remove-data" in args
        
        try:
            print(f"🗑️ Uninstalling plugin: {plugin_name}...")
            result = await self.plugin_manager.uninstall_plugin(plugin_name, remove_data)
            
            if result["success"]:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ Uninstall failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Uninstall error: {e}")
    
    async def cmd_enable(self, args: List[str]) -> None:
        """Enable plugin."""
        if len(args) < 1:
            print("Usage: plugin enable <plugin_name>")
            return
        
        plugin_name = args[0]
        
        try:
            success = self.plugin_manager.enable_plugin(plugin_name)
            if success:
                print(f"✅ Plugin enabled: {plugin_name}")
            else:
                print(f"❌ Failed to enable plugin: {plugin_name}")
                
        except Exception as e:
            print(f"❌ Enable error: {e}")
    
    async def cmd_disable(self, args: List[str]) -> None:
        """Disable plugin."""
        if len(args) < 1:
            print("Usage: plugin disable <plugin_name>")
            return
        
        plugin_name = args[0]
        
        try:
            success = self.plugin_manager.disable_plugin(plugin_name)
            if success:
                print(f"⏸️ Plugin disabled: {plugin_name}")
            else:
                print(f"❌ Failed to disable plugin: {plugin_name}")
                
        except Exception as e:
            print(f"❌ Disable error: {e}")
    
    async def cmd_info(self, args: List[str]) -> None:
        """Show detailed plugin information."""
        if len(args) < 1:
            print("Usage: plugin info <plugin_name>")
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
                print(f"❌ Plugin not found: {plugin_name}")
                return
            
            print(f"📋 Plugin Information: {plugin_name}")
            print("=" * 50)
            print(f"Version:      {plugin_data['version']}")
            print(f"Status:       {plugin_data['status']}")
            print(f"Source:       {plugin_data['source']}")
            print(f"Size:         {plugin_data['size_mb']:.1f} MB")
            print(f"Install Date: {plugin_data['install_date'][:10]}")
            
            # Security information
            security = plugin_data.get("security", {})
            if security:
                print(f"\n🛡️ Security:")
                print(f"Risk Level:   {security.get('risk_level', 'Unknown')}")
                print(f"Virus Clean:  {'✅' if security.get('virus_scan_clean') else '❌'}")
                print(f"Signed:       {'✅' if security.get('signature_valid') else '❌'}")
                if security.get("scan_date"):
                    print(f"Last Scan:    {security['scan_date'][:10]}")
            
            # Update information
            update_info = plugin_data.get("update_info", {})
            if update_info:
                print(f"\n🔄 Updates:")
                print(f"Available:    {'✅' if update_info.get('update_available') else '❌'}")
                if update_info.get("latest_version"):
                    print(f"Latest:       v{update_info['latest_version']}")
                print(f"Auto-Update:  {'✅' if update_info.get('auto_update_enabled') else '❌'}")
            
            # Plugin metadata
            if plugin_name in self.plugin_manager.plugin_metadata:
                metadata = self.plugin_manager.plugin_metadata[plugin_name]
                print(f"\n📝 Details:")
                print(f"Description:  {metadata.description}")
                print(f"Author:       {metadata.author}")
                if metadata.dependencies:
                    print(f"Dependencies: {', '.join(metadata.dependencies)}")
            
        except Exception as e:
            print(f"❌ Info error: {e}")
    
    async def cmd_update(self, args: List[str]) -> None:
        """Update plugin to latest version."""
        if len(args) < 1:
            print("Usage: plugin update <plugin_name>")
            return
        
        plugin_name = args[0]
        
        try:
            print(f"🔄 Updating plugin: {plugin_name}...")
            result = await self.plugin_manager.update_plugin(plugin_name)
            
            if result["success"]:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ Update failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Update error: {e}")
    
    async def cmd_check_updates(self, args: List[str]) -> None:
        """Check for plugin updates."""
        plugin_name = args[0] if args else None
        
        try:
            print("🔄 Checking for updates...")
            result = await self.plugin_manager.check_for_updates(plugin_name)
            
            if result["success"]:
                updates = result.get("updates", {})
                total_updates = result.get("total_updates", 0)
                
                if total_updates == 0:
                    print("✅ All plugins are up to date")
                else:
                    print(f"🔄 {total_updates} update(s) available:")
                    for name, update_info in updates.items():
                        if update_info.get("update_available"):
                            print(f"   • {name}: v{update_info.get('current_version', '?')} → "
                                  f"v{update_info.get('latest_version', '?')}")
            else:
                print(f"❌ Update check failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Update check error: {e}")
    
    async def cmd_security(self, args: List[str]) -> None:
        """Show security overview or scan specific plugin."""
        if args and args[0] == "scan" and len(args) > 1:
            # Scan specific plugin
            plugin_name = args[1]
            try:
                print(f"🛡️ Scanning plugin: {plugin_name}...")
                result = await self.plugin_manager.rescan_plugin_security(plugin_name)
                
                if result["success"]:
                    security_result = result.get("security_result", {})
                    if security_result.get("passed"):
                        print(f"✅ Security scan passed")
                        print(f"   Risk Level: {security_result.get('risk_level', 'low')}")
                    else:
                        print(f"❌ Security scan failed: {security_result.get('reason')}")
                else:
                    print(f"❌ Scan failed: {result['error']}")
                    
            except Exception as e:
                print(f"❌ Security scan error: {e}")
        else:
            # Show security overview
            try:
                dashboard_data = self.plugin_manager.get_plugin_dashboard_data()
                security_overview = dashboard_data.get("security_overview", {})
                
                print("🛡️ Security Overview")
                print("=" * 30)
                print(f"High Risk Plugins:    {security_overview.get('high_risk_plugins', 0)}")
                print(f"Unsigned Plugins:     {security_overview.get('unsigned_plugins', 0)}")
                print(f"Outdated Scans:       {security_overview.get('outdated_scans', 0)}")
                
                # Show high-risk plugins
                high_risk = []
                for plugin in dashboard_data.get("plugins", []):
                    security = plugin.get("security", {})
                    if security.get("risk_level") in ["high", "critical"]:
                        high_risk.append(plugin)
                
                if high_risk:
                    print(f"\n🚨 High Risk Plugins:")
                    for plugin in high_risk:
                        risk_level = plugin["security"]["risk_level"]
                        print(f"   • {plugin['name']} ({risk_level} risk)")
                
            except Exception as e:
                print(f"❌ Security overview error: {e}")
    
    async def cmd_auto_update(self, args: List[str]) -> None:
        """Manage auto-update settings."""
        if len(args) < 2:
            print("Usage: plugin auto-update <plugin_name> <enable|disable>")
            return
        
        plugin_name = args[0]
        action = args[1].lower()
        
        if action not in ["enable", "disable"]:
            print("Action must be 'enable' or 'disable'")
            return
        
        try:
            enabled = action == "enable"
            result = self.plugin_manager.set_plugin_auto_update(plugin_name, enabled)
            
            if result["success"]:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ Failed to set auto-update: {result['error']}")
                
        except Exception as e:
            print(f"❌ Auto-update error: {e}")
    
    async def cmd_cleanup(self, args: List[str]) -> None:
        """Clean up quarantined plugins."""
        days_old = int(args[0]) if args and args[0].isdigit() else 30
        
        try:
            print(f"🧹 Cleaning up quarantined plugins older than {days_old} days...")
            result = await self.plugin_manager.cleanup_quarantine(days_old)
            
            if result["success"]:
                print(f"✅ {result['message']}")
            else:
                print(f"❌ Cleanup failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
    
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
            print(f"❌ Unknown command: {command}")
            print("Available commands: " + ", ".join(commands.keys()))

# Global plugin CLI instance
plugin_cli = PluginCLI()

async def handle_plugin_command(args: List[str]) -> None:
    """Handle plugin CLI commands."""
    if not args:
        print("Usage: plugin <command> [args...]")
        print("Commands: list, install, uninstall, enable, disable, info, update, check-updates, security, auto-update, cleanup")
        return
    
    command = args[0]
    command_args = args[1:]
    
    await plugin_cli.execute_command(command, command_args)
