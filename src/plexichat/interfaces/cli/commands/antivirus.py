# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
from pathlib import Path
from typing import List, Optional

from plexichat.core.logging import logger


"""
Enhanced Antivirus CLI
Command-line interface for the enhanced antivirus system.
"""

logger = logging.getLogger(__name__)
class AntivirusCLI:
    """CLI for enhanced antivirus management."""

    def __init__(self):
        self.manager: Optional[EnhancedAntivirusManager] = None

    def print_colored(self, text: str, color: str = "white") -> None:
        """Print colored text."""
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "reset": "\033[0m"
        }
        logger.info(f"{colors.get(color, colors['white'])}{text}{colors['reset']}")

    async def _ensure_manager(self) -> EnhancedAntivirusManager:
        """Ensure antivirus manager is initialized."""
        if not self.manager:
            self.manager = EnhancedAntivirusManager()
            if hasattr(self.manager, "initialize"):
                await self.manager.initialize()
        return self.manager

    async def show_status(self) -> None:
        """Show antivirus system status."""
        try:
            manager = await self._ensure_manager()

            self.print_colored(" Enhanced Antivirus System Status", "cyan")
            self.print_colored("=" * 50, "cyan")

            status = " Running" if manager._running else " Stopped"
            enabled = " Enabled" if manager.config["enabled"] else " Disabled"

            logger.info(f"Status: {status}")
            logger.info(f"Enabled: {enabled}")
            logger.info(f"Initialized: {' Yes' if manager._initialized else ' No'}")
            logger.info(f"Real-time Scanning: {' On' if manager.config['real_time_scanning'] else ' Off'}")
            logger.info(f"Scan Workers: {manager.config['scan_workers']}")
            logger.info(f"Max File Size: {manager.config['max_file_size'] / (1024*1024):.1f} MB")

            # Show component status
            self.print_colored("\n Components:", "yellow")
            components = {
                "Hash Scanning": manager.config["hash_scanning"],
                "Behavioral Analysis": manager.config["behavioral_analysis"],
                "Filename Analysis": manager.config["filename_analysis"],
                "Threat Intelligence": manager.config["threat_intelligence"],
                "Link Scanning": manager.config["link_scanning"],
                "Plugin Scanning": manager.config["plugin_scanning"]
            }

            for component, enabled in components.items():
                status_icon = "" if enabled else ""
                logger.info(f"  {status_icon} {component}")

        except Exception as e:
            self.print_colored(f" Failed to get status: {e}", "red")

    async def show_statistics(self) -> None:
        """Show scan statistics."""
        try:
            manager = await self._ensure_manager()
            stats = await manager.get_scan_statistics()

            self.print_colored(" Scan Statistics", "cyan")
            self.print_colored("=" * 50, "cyan")

            logger.info(f"Total Scans: {stats['total_scans']:,}")
            logger.info(f"Threats Detected: {stats['threats_detected']:,}")
            logger.info(f"Files Quarantined: {stats['files_quarantined']:,}")
            logger.info(f"Clean Files: {stats['clean_files']:,}")
            logger.info(f"Scan Errors: {stats['scan_errors']:,}")
            logger.info(f"Plugin Scans: {stats['plugin_scans']:,}")
            logger.info(f"Real-time Scans: {stats['real_time_scans']:,}")

            if stats['last_scan_time']:
                logger.info(f"Last Scan: {stats['last_scan_time']}")

            logger.info(f"Average Scan Time: {stats['average_scan_time']:.2f}s")

            self.print_colored("\n Current Activity:", "yellow")
            logger.info(f"Active Scans: {stats['active_scans']}")
            logger.info(f"Queue Size: {stats['queue_size']}")
            logger.info(f"Quarantine Count: {stats['quarantine_count']}")
            logger.info(f"Monitored Directories: {stats['monitored_directories']}")

        except Exception as e:
            self.print_colored(f" Failed to get statistics: {e}", "red")

    async def scan_file(self, file_path: str, scan_types: Optional[List[str]] = None) -> None:
        """Scan a file for threats."""
        try:
            manager = await self._ensure_manager()

            if not Path(file_path).exists():
                self.print_colored(f" File not found: {file_path}", "red")
                return

            # Convert scan type strings to enums
            if scan_types is None:
                scan_types = ["hash", "behavioral", "filename", "threat_intelligence"]

            type_mapping = {
                "hash": ScanType.HASH_SCAN,
                "behavioral": ScanType.BEHAVIORAL_SCAN,
                "filename": ScanType.FILENAME_ANALYSIS,
                "threat_intelligence": ScanType.THREAT_INTELLIGENCE
            }

            scan_type_enums = []
            for scan_type in scan_types:
                if scan_type in type_mapping:
                    scan_type_enums.append(type_mapping[scan_type])

            if not scan_type_enums:
                self.print_colored(" No valid scan types specified", "red")
                return

            self.print_colored(f" Scanning file: {file_path}", "cyan")
            self.print_colored(f"Scan types: {', '.join(scan_types)}", "cyan")

            # Perform scan
            results = await manager.scan_file(file_path, scan_type_enums, priority=2, requester="cli")

            if not results:
                self.print_colored(" No scan results returned", "red")
                return

            # Display results
            self.print_colored(f"\n Scan Results ({len(results)} scans performed):", "yellow")

            overall_threat_level = ThreatLevel.CLEAN
            for result in results:
                if result.threat_level.value > overall_threat_level.value:
                    overall_threat_level = result.threat_level

                # Color code based on threat level
                if result.threat_level == ThreatLevel.CLEAN:
                    color = "green"
                    icon = ""
                elif result.threat_level == ThreatLevel.SUSPICIOUS:
                    color = "yellow"
                    icon = ""
                else:
                    color = "red"
                    icon = ""

                self.print_colored(f"\n{icon} {result.scan_type.value}:", color)
                logger.info(f"   Threat Level: {result.threat_level.value}")
                if result.threat_name:
                    logger.info(f"   Threat Name: {result.threat_name}")
                if result.threat_type:
                    logger.info(f"   Threat Type: {result.threat_type.value}")
                logger.info(f"   Confidence: {result.confidence_score:.2f}")
                logger.info(f"   Scan Duration: {result.scan_duration:.2f}s")

                if result.details:
                    logger.info(f"   Details: {json.dumps(result.details, indent=6)}")

            # Overall assessment
            if overall_threat_level == ThreatLevel.CLEAN:
                self.print_colored("\n Overall Assessment: CLEAN", "green")
            elif overall_threat_level == ThreatLevel.SUSPICIOUS:
                self.print_colored("\n Overall Assessment: SUSPICIOUS", "yellow")
            else:
                self.print_colored("\n Overall Assessment: THREAT DETECTED", "red")

        except Exception as e:
            self.print_colored(f" Scan failed: {e}", "red")

    async def scan_plugin(self, plugin_path: str) -> None:
        """Scan a plugin file."""
        try:
            manager = await self._ensure_manager()

            if not Path(plugin_path).exists():
                self.print_colored(f" Plugin file not found: {plugin_path}", "red")
                return

            self.print_colored(f" Scanning plugin: {plugin_path}", "cyan")

            # Perform plugin scan
            results = await manager.scan_plugin(plugin_path)

            if not results:
                self.print_colored(" No scan results returned", "red")
                return

            # Display results (similar to scan_file but with plugin context)
            self.print_colored(f"\n Plugin Scan Results ({len(results)} scans performed):", "yellow")

            threat_count = 0
            for result in results:
                if result.threat_level.value > ThreatLevel.CLEAN.value:
                    threat_count += 1

                # Color code based on threat level
                if result.threat_level == ThreatLevel.CLEAN:
                    color = "green"
                    icon = ""
                elif result.threat_level == ThreatLevel.SUSPICIOUS:
                    color = "yellow"
                    icon = ""
                else:
                    color = "red"
                    icon = ""

                self.print_colored(f"\n{icon} {result.scan_type.value}:", color)
                logger.info(f"   Threat Level: {result.threat_level.value}")
                if result.threat_name:
                    logger.info(f"   Threat Name: {result.threat_name}")
                logger.info(f"   Confidence: {result.confidence_score:.2f}")

            # Plugin assessment
            if threat_count == 0:
                self.print_colored("\n Plugin Assessment: SAFE TO INSTALL", "green")
            elif threat_count <= 2:
                self.print_colored(f"\n Plugin Assessment: REVIEW REQUIRED ({threat_count} issues)", "yellow")
            else:
                self.print_colored(f"\n Plugin Assessment: NOT RECOMMENDED ({threat_count} threats)", "red")

        except Exception as e:
            self.print_colored(f" Plugin scan failed: {e}", "red")

    async def scan_url(self, url: str) -> None:
        """Scan a URL for safety."""
        try:
            manager = await self._ensure_manager()

            self.print_colored(f" Scanning URL: {url}", "cyan")

            # Perform URL scan
            result = await manager.scan_url(url)

            # Display result
            if result.threat_level == ThreatLevel.CLEAN:
                color = "green"
                icon = ""
                assessment = "SAFE"
            elif result.threat_level == ThreatLevel.SUSPICIOUS:
                color = "yellow"
                icon = ""
                assessment = "SUSPICIOUS"
            else:
                color = "red"
                icon = ""
                assessment = "DANGEROUS"

            self.print_colored(f"\n{icon} URL Assessment: {assessment}", color)
            logger.info(f"Threat Level: {result.threat_level.value}")
            if result.threat_name:
                logger.info(f"Threat Name: {result.threat_name}")
            if result.threat_type:
                logger.info(f"Threat Type: {result.threat_type.value}")
            logger.info(f"Confidence: {result.confidence_score:.2f}")
            logger.info(f"Scan Duration: {result.scan_duration:.2f}s")

            if result.details:
                logger.info(f"Details: {json.dumps(result.details, indent=2)}")

        except Exception as e:
            self.print_colored(f" URL scan failed: {e}", "red")

    async def show_quarantine(self) -> None:
        """Show quarantined files."""
        try:
            manager = await self._ensure_manager()
            quarantine_list = await manager.get_quarantine_list()

            self.print_colored(" Quarantined Files", "cyan")
            self.print_colored("=" * 50, "cyan")

            if not quarantine_list:
                self.print_colored("No files in quarantine.", "green")
                return

            for entry in quarantine_list:
                threat_color = "red" if entry["threat_level"] in ["HIGH_RISK", "CRITICAL"] else "yellow"

                self.print_colored(f"\n {entry['threat_name']}", threat_color)
                logger.info(f"   Original Path: {entry['original_path']}")
                logger.info(f"   File Hash: {entry['file_hash'][:16]}...")
                logger.info(f"   Threat Level: {entry['threat_level']}")
                logger.info(f"   Quarantined: {entry['quarantine_time']}")
                logger.info(f"   File Size: {entry['file_size']:,} bytes")
                if entry['auto_delete_after']:
                    logger.info(f"   Auto-delete: {entry['auto_delete_after']}")

            self.print_colored(f"\nTotal quarantined files: {len(quarantine_list)}", "yellow")

        except Exception as e:
            self.print_colored(f" Failed to get quarantine list: {e}", "red")

    async def restore_quarantine(self, file_hash: str, restore_path: Optional[str] = None) -> None:
        """Restore a file from quarantine."""
        try:
            manager = await self._ensure_manager()

            success = await manager.restore_from_quarantine(file_hash, restore_path)

            if success:
                self.print_colored(f" File restored from quarantine: {file_hash[:16]}...", "green")
            else:
                self.print_colored(" Failed to restore file from quarantine", "red")

        except Exception as e:
            self.print_colored(f" Restore failed: {e}", "red")

    async def delete_quarantine(self, file_hash: str) -> None:
        """Delete a quarantined file permanently."""
        try:
            manager = await self._ensure_manager()

            success = await manager.delete_quarantined_file(file_hash)

            if success:
                self.print_colored(f" Quarantined file deleted permanently: {file_hash[:16]}...", "green")
            else:
                self.print_colored(" Failed to delete quarantined file", "red")

        except Exception as e:
            self.print_colored(f" Delete failed: {e}", "red")

    async def update_database(self) -> None:
        """Update threat intelligence database."""
        try:
            manager = await self._ensure_manager()

            self.print_colored(" Updating threat intelligence database...", "cyan")

            success = await manager.update_threat_database()

            if success:
                self.print_colored(" Threat database updated successfully", "green")
            else:
                self.print_colored(" Failed to update threat database", "red")

        except Exception as e:
            self.print_colored(f" Database update failed: {e}", "red")

async def handle_antivirus_command(args: List[str]) -> None:
    """Handle antivirus management commands."""
    if not args:
        logger.info(" Enhanced Antivirus Commands:")
        logger.info("  status                        - Show system status")
        logger.info("  stats                         - Show scan statistics")
        logger.info("  scan <file_path> [types]      - Scan file")
        logger.info("  scan-plugin <plugin_path>     - Scan plugin")
        logger.info("  scan-url <url>                - Scan URL")
        logger.info("  quarantine                    - Show quarantined files")
        logger.info("  restore <hash> [path]         - Restore from quarantine")
        logger.info("  delete <hash>                 - Delete quarantined file")
        logger.info("  update-db                     - Update threat database")
        logger.info("")
        logger.info("Scan types: hash, behavioral, filename, threat_intelligence")
        return

    cli = AntivirusCLI()
    command = args[0]
    command_args = args[1:]

    try:
        if command == "status":
            await cli.show_status()
        elif command == "stats":
            await cli.show_statistics()
        elif command == "scan" and command_args:
            scan_types = command_args[1].split(",") if len(command_args) > 1 else None
            await cli.scan_file(command_args[0], scan_types)
        elif command == "scan-plugin" and command_args:
            await cli.scan_plugin(command_args[0])
        elif command == "scan-url" and command_args:
            await cli.scan_url(command_args[0])
        elif command == "quarantine":
            await cli.show_quarantine()
        elif command == "restore" and command_args:
            restore_path = command_args[1] if len(command_args) > 1 else None
            await cli.restore_quarantine(command_args[0], restore_path)
        elif command == "delete" and command_args:
            await cli.delete_quarantine(command_args[0])
        elif command == "update-db":
            await cli.update_database()
        else:
            logger.info(f" Unknown command or missing arguments: {command}")

    except Exception as e:
        logger.info(f" Command failed: {e}")
        logger.error(f"Antivirus CLI command failed: {e}")
