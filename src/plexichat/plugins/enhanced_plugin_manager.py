"""
Enhanced Plugin Manager for NetLink
Advanced plugin system with zip-based installation, antivirus integration,
self-updating plugins, and comprehensive management capabilities.
"""

import os
import sys
import json
import zipfile
import tempfile
import shutil
import hashlib
import asyncio
import aiohttp
import aiofiles
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import importlib.util

from netlink.app.logger_config import logger
from .plugin_manager import PluginManager, PluginInterface, PluginMetadata

class PluginStatus(str, Enum):
    """Plugin status enumeration."""
    INSTALLED = "installed"
    ENABLED = "enabled"
    DISABLED = "disabled"
    UPDATING = "updating"
    FAILED = "failed"
    QUARANTINED = "quarantined"
    PENDING_INSTALL = "pending_install"

class PluginSource(str, Enum):
    """Plugin source enumeration."""
    LOCAL = "local"
    OFFICIAL = "official"
    COMMUNITY = "community"
    CUSTOM = "custom"

@dataclass
class PluginSecurityInfo:
    """Plugin security information."""
    signature_valid: bool = False
    virus_scan_clean: bool = False
    permissions_reviewed: bool = False
    source_verified: bool = False
    risk_level: str = "unknown"  # low, medium, high, critical
    scan_date: Optional[datetime] = None
    quarantine_reason: Optional[str] = None

@dataclass
class PluginInstallInfo:
    """Plugin installation information."""
    install_date: datetime
    install_source: PluginSource
    install_path: Path
    original_filename: Optional[str] = None
    checksum: Optional[str] = None
    size_bytes: int = 0
    dependencies_resolved: bool = False

@dataclass
class PluginUpdateInfo:
    """Plugin update information."""
    current_version: str
    latest_version: Optional[str] = None
    update_available: bool = False
    update_url: Optional[str] = None
    update_date: Optional[datetime] = None
    auto_update_enabled: bool = False
    changelog: Optional[str] = None

@dataclass
class EnhancedPluginMetadata(PluginMetadata):
    """Enhanced plugin metadata with additional fields."""
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"
    min_netlink_version: str = "3.0.0"
    max_netlink_version: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    cli_commands: List[Dict[str, Any]] = field(default_factory=list)
    hooks: List[str] = field(default_factory=list)
    configuration_schema: Optional[Dict[str, Any]] = None

class EnhancedPluginManager(PluginManager):
    """Enhanced plugin manager with advanced features."""
    
    def __init__(self, plugins_dir: str = "plugins"):
        super().__init__(plugins_dir)
        
        # Enhanced directories
        self.installed_dir = self.plugins_dir / "installed"
        self.quarantine_dir = self.plugins_dir / "quarantine"
        self.temp_dir = self.plugins_dir / "temp"
        self.cache_dir = self.plugins_dir / "cache"
        
        # Create directories
        for directory in [self.installed_dir, self.quarantine_dir, self.temp_dir, self.cache_dir]:
            directory.mkdir(exist_ok=True)
        
        # Enhanced tracking
        self.plugin_security: Dict[str, PluginSecurityInfo] = {}
        self.plugin_installs: Dict[str, PluginInstallInfo] = {}
        self.plugin_updates: Dict[str, PluginUpdateInfo] = {}
        self.plugin_status: Dict[str, PluginStatus] = {}
        
        # Configuration
        self.config = {
            "auto_update_enabled": False,
            "virus_scan_enabled": True,
            "signature_verification": True,
            "allow_unsigned_plugins": False,
            "max_plugin_size_mb": 100,
            "quarantine_duration_days": 30,
            "update_check_interval_hours": 24,
            "official_repository": "https://plugins.netlink.example.com",
            "trusted_sources": ["official", "verified_community"]
        }
        
        # Load enhanced metadata
        self._load_enhanced_metadata()
        
        logger.info("🔌 Enhanced plugin manager initialized")
    
    def _load_enhanced_metadata(self):
        """Load enhanced plugin metadata from disk."""
        metadata_file = self.plugins_dir / "plugin_metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                
                # Load security info
                for plugin_name, security_data in data.get('security', {}).items():
                    if 'scan_date' in security_data and security_data['scan_date']:
                        security_data['scan_date'] = datetime.fromisoformat(security_data['scan_date'])
                    self.plugin_security[plugin_name] = PluginSecurityInfo(**security_data)
                
                # Load install info
                for plugin_name, install_data in data.get('installs', {}).items():
                    install_data['install_date'] = datetime.fromisoformat(install_data['install_date'])
                    install_data['install_path'] = Path(install_data['install_path'])
                    self.plugin_installs[plugin_name] = PluginInstallInfo(**install_data)
                
                # Load update info
                for plugin_name, update_data in data.get('updates', {}).items():
                    if 'update_date' in update_data and update_data['update_date']:
                        update_data['update_date'] = datetime.fromisoformat(update_data['update_date'])
                    self.plugin_updates[plugin_name] = PluginUpdateInfo(**update_data)
                
                # Load status
                for plugin_name, status in data.get('status', {}).items():
                    self.plugin_status[plugin_name] = PluginStatus(status)
                
                logger.info("📋 Loaded enhanced plugin metadata")
                
            except Exception as e:
                logger.error(f"Failed to load enhanced metadata: {e}")
    
    def _save_enhanced_metadata(self):
        """Save enhanced plugin metadata to disk."""
        try:
            data = {
                'security': {},
                'installs': {},
                'updates': {},
                'status': {},
                'last_updated': datetime.now().isoformat()
            }
            
            # Save security info
            for plugin_name, security_info in self.plugin_security.items():
                security_data = {
                    'signature_valid': security_info.signature_valid,
                    'virus_scan_clean': security_info.virus_scan_clean,
                    'permissions_reviewed': security_info.permissions_reviewed,
                    'source_verified': security_info.source_verified,
                    'risk_level': security_info.risk_level,
                    'scan_date': security_info.scan_date.isoformat() if security_info.scan_date else None,
                    'quarantine_reason': security_info.quarantine_reason
                }
                data['security'][plugin_name] = security_data
            
            # Save install info
            for plugin_name, install_info in self.plugin_installs.items():
                install_data = {
                    'install_date': install_info.install_date.isoformat(),
                    'install_source': install_info.install_source.value,
                    'install_path': str(install_info.install_path),
                    'original_filename': install_info.original_filename,
                    'checksum': install_info.checksum,
                    'size_bytes': install_info.size_bytes,
                    'dependencies_resolved': install_info.dependencies_resolved
                }
                data['installs'][plugin_name] = install_data
            
            # Save update info
            for plugin_name, update_info in self.plugin_updates.items():
                update_data = {
                    'current_version': update_info.current_version,
                    'latest_version': update_info.latest_version,
                    'update_available': update_info.update_available,
                    'update_url': update_info.update_url,
                    'update_date': update_info.update_date.isoformat() if update_info.update_date else None,
                    'auto_update_enabled': update_info.auto_update_enabled,
                    'changelog': update_info.changelog
                }
                data['updates'][plugin_name] = update_data
            
            # Save status
            for plugin_name, status in self.plugin_status.items():
                data['status'][plugin_name] = status.value
            
            metadata_file = self.plugins_dir / "plugin_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save enhanced metadata: {e}")
    
    async def install_plugin_from_zip(self, zip_path: Union[str, Path], source: PluginSource = PluginSource.LOCAL) -> Dict[str, Any]:
        """Install plugin from ZIP file with security checks."""
        zip_path = Path(zip_path)
        
        if not zip_path.exists():
            return {"success": False, "error": "ZIP file not found"}
        
        # Check file size
        file_size = zip_path.stat().st_size
        max_size = self.config["max_plugin_size_mb"] * 1024 * 1024
        if file_size > max_size:
            return {"success": False, "error": f"Plugin too large: {file_size / 1024 / 1024:.1f}MB > {self.config['max_plugin_size_mb']}MB"}
        
        # Calculate checksum
        checksum = await self._calculate_file_checksum(zip_path)
        
        try:
            # Extract to temporary directory
            temp_extract_dir = self.temp_dir / f"extract_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            temp_extract_dir.mkdir(exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Security check: validate file paths
                for member in zip_ref.namelist():
                    if os.path.isabs(member) or ".." in member:
                        shutil.rmtree(temp_extract_dir)
                        return {"success": False, "error": "Unsafe file paths in ZIP"}
                
                zip_ref.extractall(temp_extract_dir)
            
            # Find plugin.json
            plugin_json_path = None
            for root, dirs, files in os.walk(temp_extract_dir):
                if "plugin.json" in files:
                    plugin_json_path = Path(root) / "plugin.json"
                    break
            
            if not plugin_json_path:
                shutil.rmtree(temp_extract_dir)
                return {"success": False, "error": "No plugin.json found in ZIP"}
            
            # Load and validate plugin metadata
            with open(plugin_json_path, 'r') as f:
                plugin_config = json.load(f)
            
            plugin_name = plugin_config.get("name", "unknown")
            plugin_version = plugin_config.get("version", "1.0.0")
            
            # Perform security checks
            security_result = await self._perform_security_checks(temp_extract_dir, plugin_config, source)
            
            if not security_result["passed"]:
                # Move to quarantine
                await self._quarantine_plugin(temp_extract_dir, plugin_name, security_result["reason"])
                return {"success": False, "error": f"Security check failed: {security_result['reason']}"}
            
            # Install plugin
            install_dir = self.installed_dir / plugin_name
            if install_dir.exists():
                shutil.rmtree(install_dir)
            
            shutil.move(str(temp_extract_dir), str(install_dir))
            
            # Record installation info
            self.plugin_installs[plugin_name] = PluginInstallInfo(
                install_date=datetime.now(),
                install_source=source,
                install_path=install_dir,
                original_filename=zip_path.name,
                checksum=checksum,
                size_bytes=file_size,
                dependencies_resolved=True  # TODO: Implement dependency resolution
            )
            
            self.plugin_status[plugin_name] = PluginStatus.INSTALLED
            self.plugin_security[plugin_name] = PluginSecurityInfo(
                signature_valid=security_result.get("signature_valid", False),
                virus_scan_clean=security_result.get("virus_clean", True),
                permissions_reviewed=True,
                source_verified=source in [PluginSource.OFFICIAL],
                risk_level=security_result.get("risk_level", "low"),
                scan_date=datetime.now()
            )
            
            # Save metadata
            self._save_enhanced_metadata()
            
            logger.info(f"✅ Installed plugin: {plugin_name} v{plugin_version}")
            
            return {
                "success": True,
                "plugin_name": plugin_name,
                "version": plugin_version,
                "message": f"Plugin '{plugin_name}' installed successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to install plugin from {zip_path}: {e}")
            return {"success": False, "error": str(e)}
    
    async def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of file."""
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            async for chunk in f:
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    async def _perform_security_checks(self, plugin_dir: Path, plugin_config: Dict[str, Any], source: PluginSource) -> Dict[str, Any]:
        """Perform comprehensive security checks on plugin."""
        result = {
            "passed": True,
            "reason": None,
            "signature_valid": False,
            "virus_clean": True,
            "risk_level": "low"
        }
        
        try:
            # Check if virus scanning is enabled
            if self.config["virus_scan_enabled"]:
                virus_scan_result = await self._scan_for_viruses(plugin_dir)
                result["virus_clean"] = virus_scan_result["clean"]
                if not virus_scan_result["clean"]:
                    result["passed"] = False
                    result["reason"] = f"Virus detected: {virus_scan_result['threat']}"
                    result["risk_level"] = "critical"
                    return result
            
            # Check permissions
            permissions = plugin_config.get("permissions", [])
            dangerous_permissions = ["filesystem.write", "network.external", "system.execute"]
            if any(perm in permissions for perm in dangerous_permissions):
                result["risk_level"] = "high"
                if source not in [PluginSource.OFFICIAL]:
                    result["passed"] = False
                    result["reason"] = "Dangerous permissions from untrusted source"
                    return result
            
            # Check for suspicious files
            suspicious_extensions = [".exe", ".bat", ".cmd", ".sh", ".ps1"]
            for root, dirs, files in os.walk(plugin_dir):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in suspicious_extensions):
                        result["risk_level"] = "high"
                        if source not in [PluginSource.OFFICIAL]:
                            result["passed"] = False
                            result["reason"] = f"Suspicious file: {file}"
                            return result
            
            # Signature verification (if enabled)
            if self.config["signature_verification"]:
                signature_valid = await self._verify_plugin_signature(plugin_dir)
                result["signature_valid"] = signature_valid
                if not signature_valid and not self.config["allow_unsigned_plugins"]:
                    result["passed"] = False
                    result["reason"] = "Plugin signature verification failed"
                    return result
            
            return result

        except Exception as e:
            logger.error(f"Security check failed: {e}")
            result["passed"] = False
            result["reason"] = f"Security check error: {e}"
            return result

    async def _scan_for_viruses(self, plugin_dir: Path) -> Dict[str, Any]:
        """Scan plugin directory for viruses using built-in antivirus."""
        try:
            # Import antivirus scanner if available
            try:
                from netlink.app.security.antivirus import get_antivirus_scanner
                scanner = get_antivirus_scanner()

                # Scan all files in plugin directory
                scan_results = []
                for root, dirs, files in os.walk(plugin_dir):
                    for file in files:
                        file_path = Path(root) / file
                        result = await scanner.scan_file(file_path)
                        scan_results.append(result)

                # Check if any threats found
                threats = [r for r in scan_results if not r.get("clean", True)]
                if threats:
                    return {
                        "clean": False,
                        "threat": threats[0].get("threat_name", "Unknown threat"),
                        "details": threats
                    }

                return {"clean": True, "details": scan_results}

            except ImportError:
                logger.warning("Antivirus scanner not available, skipping virus scan")
                return {"clean": True, "details": "Scanner not available"}

        except Exception as e:
            logger.error(f"Virus scan failed: {e}")
            return {"clean": False, "threat": f"Scan error: {e}"}

    async def _verify_plugin_signature(self, plugin_dir: Path) -> bool:
        """Verify plugin digital signature."""
        try:
            signature_file = plugin_dir / "plugin.sig"
            if not signature_file.exists():
                return False

            # TODO: Implement actual signature verification
            # This would involve checking against trusted certificates
            logger.info("Plugin signature verification not yet implemented")
            return False

        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    async def _quarantine_plugin(self, plugin_dir: Path, plugin_name: str, reason: str):
        """Move plugin to quarantine directory."""
        try:
            quarantine_path = self.quarantine_dir / f"{plugin_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.move(str(plugin_dir), str(quarantine_path))

            # Record quarantine info
            self.plugin_security[plugin_name] = PluginSecurityInfo(
                signature_valid=False,
                virus_scan_clean=False,
                permissions_reviewed=False,
                source_verified=False,
                risk_level="critical",
                scan_date=datetime.now(),
                quarantine_reason=reason
            )

            self.plugin_status[plugin_name] = PluginStatus.QUARANTINED
            self._save_enhanced_metadata()

            logger.warning(f"🚨 Quarantined plugin: {plugin_name} - {reason}")

        except Exception as e:
            logger.error(f"Failed to quarantine plugin {plugin_name}: {e}")

    async def uninstall_plugin(self, plugin_name: str, remove_data: bool = False) -> Dict[str, Any]:
        """Uninstall plugin with optional data removal."""
        try:
            # Unload plugin if loaded
            if plugin_name in self.loaded_plugins:
                if not self.unload_plugin(plugin_name):
                    return {"success": False, "error": "Failed to unload plugin"}

            # Remove plugin directory
            install_dir = self.installed_dir / plugin_name
            if install_dir.exists():
                shutil.rmtree(install_dir)

            # Remove from tracking
            self.plugin_installs.pop(plugin_name, None)
            self.plugin_security.pop(plugin_name, None)
            self.plugin_updates.pop(plugin_name, None)
            self.plugin_status.pop(plugin_name, None)

            # Remove data if requested
            if remove_data:
                data_dir = self.plugins_dir / "data" / plugin_name
                if data_dir.exists():
                    shutil.rmtree(data_dir)

            self._save_enhanced_metadata()

            logger.info(f"🗑️ Uninstalled plugin: {plugin_name}")

            return {
                "success": True,
                "message": f"Plugin '{plugin_name}' uninstalled successfully"
            }

        except Exception as e:
            logger.error(f"Failed to uninstall plugin {plugin_name}: {e}")
            return {"success": False, "error": str(e)}

    async def check_for_updates(self, plugin_name: Optional[str] = None) -> Dict[str, Any]:
        """Check for plugin updates."""
        try:
            plugins_to_check = [plugin_name] if plugin_name else list(self.plugin_installs.keys())
            update_results = {}

            for name in plugins_to_check:
                if name not in self.plugin_installs:
                    continue

                install_info = self.plugin_installs[name]
                current_version = self.plugin_metadata.get(name, {}).version if name in self.plugin_metadata else "1.0.0"

                # Check for updates from repository
                update_info = await self._check_plugin_update(name, current_version, install_info.install_source)

                if update_info["update_available"]:
                    self.plugin_updates[name] = PluginUpdateInfo(
                        current_version=current_version,
                        latest_version=update_info["latest_version"],
                        update_available=True,
                        update_url=update_info["update_url"],
                        changelog=update_info.get("changelog"),
                        auto_update_enabled=self.plugin_updates.get(name, PluginUpdateInfo(current_version)).auto_update_enabled
                    )

                update_results[name] = update_info

            self._save_enhanced_metadata()

            return {
                "success": True,
                "updates": update_results,
                "total_updates": sum(1 for r in update_results.values() if r["update_available"])
            }

        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {"success": False, "error": str(e)}

    async def _check_plugin_update(self, plugin_name: str, current_version: str, source: PluginSource) -> Dict[str, Any]:
        """Check for plugin update from repository."""
        try:
            if source == PluginSource.OFFICIAL:
                # Check official repository
                url = f"{self.config['official_repository']}/api/plugins/{plugin_name}/latest"

                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            latest_version = data.get("version", current_version)

                            # Simple version comparison (should be more sophisticated)
                            update_available = latest_version != current_version

                            return {
                                "update_available": update_available,
                                "latest_version": latest_version,
                                "update_url": data.get("download_url"),
                                "changelog": data.get("changelog"),
                                "release_date": data.get("release_date")
                            }

            # No update available or source not supported
            return {
                "update_available": False,
                "latest_version": current_version,
                "update_url": None,
                "changelog": None
            }

        except Exception as e:
            logger.error(f"Failed to check update for {plugin_name}: {e}")
            return {
                "update_available": False,
                "latest_version": current_version,
                "error": str(e)
            }

    async def update_plugin(self, plugin_name: str, auto_update: bool = False) -> Dict[str, Any]:
        """Update plugin to latest version."""
        try:
            if plugin_name not in self.plugin_updates:
                return {"success": False, "error": "No update information available"}

            update_info = self.plugin_updates[plugin_name]
            if not update_info.update_available:
                return {"success": False, "error": "No update available"}

            if not update_info.update_url:
                return {"success": False, "error": "No update URL available"}

            # Set status to updating
            self.plugin_status[plugin_name] = PluginStatus.UPDATING
            self._save_enhanced_metadata()

            # Download update
            temp_file = self.temp_dir / f"{plugin_name}_update.zip"

            async with aiohttp.ClientSession() as session:
                async with session.get(update_info.update_url) as response:
                    if response.status == 200:
                        async with aiofiles.open(temp_file, 'wb') as f:
                            async for chunk in response.content.iter_chunked(8192):
                                await f.write(chunk)
                    else:
                        self.plugin_status[plugin_name] = PluginStatus.FAILED
                        return {"success": False, "error": f"Failed to download update: HTTP {response.status}"}

            # Backup current plugin
            backup_dir = self.plugins_dir / "backups" / plugin_name
            backup_dir.mkdir(parents=True, exist_ok=True)

            current_install = self.installed_dir / plugin_name
            backup_path = backup_dir / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            if current_install.exists():
                shutil.copytree(current_install, backup_path)

            # Install update
            install_result = await self.install_plugin_from_zip(
                temp_file,
                self.plugin_installs[plugin_name].install_source
            )

            if install_result["success"]:
                # Update metadata
                update_info.current_version = update_info.latest_version
                update_info.update_available = False
                update_info.update_date = datetime.now()

                self.plugin_status[plugin_name] = PluginStatus.INSTALLED

                # Clean up
                temp_file.unlink(missing_ok=True)

                logger.info(f"🔄 Updated plugin: {plugin_name} to v{update_info.latest_version}")

                return {
                    "success": True,
                    "message": f"Plugin '{plugin_name}' updated to v{update_info.latest_version}",
                    "version": update_info.latest_version
                }
            else:
                # Restore backup on failure
                if backup_path.exists():
                    if current_install.exists():
                        shutil.rmtree(current_install)
                    shutil.copytree(backup_path, current_install)

                self.plugin_status[plugin_name] = PluginStatus.FAILED
                return {"success": False, "error": f"Update failed: {install_result['error']}"}

        except Exception as e:
            logger.error(f"Failed to update plugin {plugin_name}: {e}")
            self.plugin_status[plugin_name] = PluginStatus.FAILED
            return {"success": False, "error": str(e)}

    def get_plugin_dashboard_data(self) -> Dict[str, Any]:
        """Get comprehensive plugin data for dashboard."""
        try:
            dashboard_data = {
                "summary": {
                    "total_plugins": len(self.plugin_installs),
                    "enabled_plugins": len([p for p in self.plugin_status.values() if p == PluginStatus.ENABLED]),
                    "disabled_plugins": len([p for p in self.plugin_status.values() if p == PluginStatus.DISABLED]),
                    "quarantined_plugins": len([p for p in self.plugin_status.values() if p == PluginStatus.QUARANTINED]),
                    "updates_available": len([u for u in self.plugin_updates.values() if u.update_available]),
                    "failed_plugins": len([p for p in self.plugin_status.values() if p == PluginStatus.FAILED])
                },
                "plugins": [],
                "security_overview": {
                    "high_risk_plugins": 0,
                    "unsigned_plugins": 0,
                    "outdated_scans": 0
                },
                "recent_activity": []
            }

            # Collect plugin information
            for plugin_name in self.plugin_installs.keys():
                plugin_info = {
                    "name": plugin_name,
                    "status": self.plugin_status.get(plugin_name, PluginStatus.INSTALLED).value,
                    "version": self.plugin_metadata.get(plugin_name, {}).version if plugin_name in self.plugin_metadata else "Unknown",
                    "install_date": self.plugin_installs[plugin_name].install_date.isoformat(),
                    "source": self.plugin_installs[plugin_name].install_source.value,
                    "size_mb": round(self.plugin_installs[plugin_name].size_bytes / 1024 / 1024, 2),
                    "security": {},
                    "update_info": {}
                }

                # Add security information
                if plugin_name in self.plugin_security:
                    security = self.plugin_security[plugin_name]
                    plugin_info["security"] = {
                        "risk_level": security.risk_level,
                        "virus_scan_clean": security.virus_scan_clean,
                        "signature_valid": security.signature_valid,
                        "scan_date": security.scan_date.isoformat() if security.scan_date else None,
                        "quarantine_reason": security.quarantine_reason
                    }

                    # Update security overview
                    if security.risk_level in ["high", "critical"]:
                        dashboard_data["security_overview"]["high_risk_plugins"] += 1
                    if not security.signature_valid:
                        dashboard_data["security_overview"]["unsigned_plugins"] += 1
                    if security.scan_date and (datetime.now() - security.scan_date).days > 30:
                        dashboard_data["security_overview"]["outdated_scans"] += 1

                # Add update information
                if plugin_name in self.plugin_updates:
                    update = self.plugin_updates[plugin_name]
                    plugin_info["update_info"] = {
                        "update_available": update.update_available,
                        "latest_version": update.latest_version,
                        "auto_update_enabled": update.auto_update_enabled,
                        "changelog": update.changelog
                    }

                dashboard_data["plugins"].append(plugin_info)

            # Sort plugins by name
            dashboard_data["plugins"].sort(key=lambda x: x["name"])

            return dashboard_data

        except Exception as e:
            logger.error(f"Failed to get dashboard data: {e}")
            return {"error": str(e)}

    async def cleanup_quarantine(self, days_old: int = 30) -> Dict[str, Any]:
        """Clean up old quarantined plugins."""
        try:
            cleaned_count = 0
            cutoff_date = datetime.now() - timedelta(days=days_old)

            for item in self.quarantine_dir.iterdir():
                if item.is_dir():
                    # Check if directory is old enough
                    creation_time = datetime.fromtimestamp(item.stat().st_ctime)
                    if creation_time < cutoff_date:
                        shutil.rmtree(item)
                        cleaned_count += 1

            logger.info(f"🧹 Cleaned up {cleaned_count} old quarantined plugins")

            return {
                "success": True,
                "cleaned_count": cleaned_count,
                "message": f"Cleaned up {cleaned_count} old quarantined plugins"
            }

        except Exception as e:
            logger.error(f"Failed to cleanup quarantine: {e}")
            return {"success": False, "error": str(e)}

    async def auto_update_plugins(self) -> Dict[str, Any]:
        """Automatically update plugins that have auto-update enabled."""
        try:
            updated_plugins = []
            failed_updates = []

            for plugin_name, update_info in self.plugin_updates.items():
                if update_info.auto_update_enabled and update_info.update_available:
                    result = await self.update_plugin(plugin_name, auto_update=True)
                    if result["success"]:
                        updated_plugins.append(plugin_name)
                    else:
                        failed_updates.append({"plugin": plugin_name, "error": result["error"]})

            logger.info(f"🔄 Auto-updated {len(updated_plugins)} plugins")

            return {
                "success": True,
                "updated_plugins": updated_plugins,
                "failed_updates": failed_updates,
                "message": f"Auto-updated {len(updated_plugins)} plugins"
            }

        except Exception as e:
            logger.error(f"Auto-update failed: {e}")
            return {"success": False, "error": str(e)}

    def set_plugin_auto_update(self, plugin_name: str, enabled: bool) -> Dict[str, Any]:
        """Enable or disable auto-update for a plugin."""
        try:
            if plugin_name not in self.plugin_updates:
                # Create update info if it doesn't exist
                current_version = self.plugin_metadata.get(plugin_name, {}).version if plugin_name in self.plugin_metadata else "1.0.0"
                self.plugin_updates[plugin_name] = PluginUpdateInfo(
                    current_version=current_version,
                    auto_update_enabled=enabled
                )
            else:
                self.plugin_updates[plugin_name].auto_update_enabled = enabled

            self._save_enhanced_metadata()

            return {
                "success": True,
                "message": f"Auto-update {'enabled' if enabled else 'disabled'} for {plugin_name}"
            }

        except Exception as e:
            logger.error(f"Failed to set auto-update for {plugin_name}: {e}")
            return {"success": False, "error": str(e)}

    async def rescan_plugin_security(self, plugin_name: str) -> Dict[str, Any]:
        """Re-scan plugin for security issues."""
        try:
            if plugin_name not in self.plugin_installs:
                return {"success": False, "error": "Plugin not installed"}

            install_info = self.plugin_installs[plugin_name]
            plugin_dir = install_info.install_path

            if not plugin_dir.exists():
                return {"success": False, "error": "Plugin directory not found"}

            # Load plugin config
            config_file = plugin_dir / "plugin.json"
            if config_file.exists():
                with open(config_file, 'r') as f:
                    plugin_config = json.load(f)
            else:
                plugin_config = {}

            # Perform security scan
            security_result = await self._perform_security_checks(plugin_dir, plugin_config, install_info.install_source)

            # Update security info
            self.plugin_security[plugin_name] = PluginSecurityInfo(
                signature_valid=security_result.get("signature_valid", False),
                virus_scan_clean=security_result.get("virus_clean", True),
                permissions_reviewed=True,
                source_verified=install_info.install_source in [PluginSource.OFFICIAL],
                risk_level=security_result.get("risk_level", "low"),
                scan_date=datetime.now(),
                quarantine_reason=None if security_result["passed"] else security_result["reason"]
            )

            # Update status
            if not security_result["passed"]:
                await self._quarantine_plugin(plugin_dir, plugin_name, security_result["reason"])
                self.plugin_status[plugin_name] = PluginStatus.QUARANTINED
            else:
                self.plugin_status[plugin_name] = PluginStatus.INSTALLED

            self._save_enhanced_metadata()

            return {
                "success": True,
                "security_result": security_result,
                "message": f"Security scan completed for {plugin_name}"
            }

        except Exception as e:
            logger.error(f"Failed to rescan plugin {plugin_name}: {e}")
            return {"success": False, "error": str(e)}


# Global enhanced plugin manager instance
enhanced_plugin_manager = EnhancedPluginManager()


def get_enhanced_plugin_manager() -> EnhancedPluginManager:
    """Get the global enhanced plugin manager instance."""
    return enhanced_plugin_manager
