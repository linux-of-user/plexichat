# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


from .core import ScanResult, ScanType, ThreatLevel, ThreatType
from .core.antivirus_engine import AdvancedAntivirusEngine

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path


from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

from plexichat.app.logger_config import logger

"""
import time
Enhanced Antivirus Manager
Integrates the existing antivirus system with plugin scanning, real-time monitoring,
and advanced threat detection capabilities.
"""

@dataclass
class ScanRequest:
    """Scan request with metadata."""
    file_path: str
    scan_types: List[ScanType]
    priority: int = 1  # 1=low, 2=medium, 3=high, 4=critical
    requester: str = "system"
    metadata: Dict[str, Any] = None
    callback: Optional[Callable] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class QuarantineEntry:
    """Quarantined file entry."""
    original_path: str
    quarantine_path: str
    threat_name: str
    threat_level: ThreatLevel
    quarantine_time: datetime
    file_hash: str
    file_size: int
    scan_results: List[ScanResult]
    auto_delete_after: Optional[datetime] = None

class EnhancedAntivirusManager:
    """Enhanced antivirus manager with plugin integration and real-time monitoring."""

    def __init__(self, data_dir: str = "data"):
        from pathlib import Path
self.data_dir = Path(data_dir)
        self.antivirus_dir = self.data_dir / "antivirus"
        self.quarantine_dir = self.antivirus_dir / "quarantine"
        self.config_path = self.antivirus_dir / "enhanced_config.json"

        # Create directories
        self.antivirus_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        # Initialize core antivirus engine
        self.antivirus_engine = AdvancedAntivirusEngine(self.data_dir)

        # Scan queue and processing
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.active_scans: Dict[str, ScanRequest] = {}
        self.scan_workers: List[asyncio.Task] = []

        # Quarantine management
        self.quarantine_entries: Dict[str, QuarantineEntry] = {}

        # Real-time monitoring
        self.monitored_directories: Set[str] = set()
        self.file_watchers: Dict[str, Any] = {}

        # Configuration
        self.config = {
            "enabled": True,
            "real_time_scanning": True,
            "scan_workers": 3,
            "max_file_size": 100 * 1024 * 1024,  # 100MB
            "quarantine_auto_delete_days": 30,
            "scan_timeout": 300,  # 5 minutes
            "plugin_scanning": True,
            "link_scanning": True,
            "behavioral_analysis": True,
            "hash_scanning": True,
            "filename_analysis": True,
            "threat_intelligence": True,
            "scan_archives": True,
            "scan_compressed": True,
            "whitelist_extensions": [".txt", ".md", ".json", ".xml", ".csv"],
            "blacklist_extensions": [".exe", ".scr", ".bat", ".cmd", ".com", ".pif"],
            "notification_callbacks": []
        }

        # Statistics
        self.stats = {
            "total_scans": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "clean_files": 0,
            "scan_errors": 0,
            "last_scan_time": None,
            "average_scan_time": 0.0,
            "plugin_scans": 0,
            "real_time_scans": 0
        }

        self._initialized = False
        self._running = False

    async def initialize(self) -> None:
        """Initialize the enhanced antivirus manager."""
        if self._initialized:
            return

        logger.info("Initializing Enhanced Antivirus Manager")

        # Load configuration
        await self._load_config()

        # Initialize core antivirus engine
        await self.if antivirus_engine and hasattr(antivirus_engine, "initialize"): antivirus_engine.initialize()

        # Load quarantine entries
        await self._load_quarantine_entries()

        # Start scan workers
        await self._start_scan_workers()

        # Start real-time monitoring if enabled
        if self.config["real_time_scanning"]:
            await self._start_real_time_monitoring()

        # Start background tasks
        asyncio.create_task(self._background_maintenance_task())

        self._initialized = True
        self._running = True
        logger.info("Enhanced Antivirus Manager initialized successfully")

    async def shutdown(self) -> None:
        """Shutdown the antivirus manager."""
        if not self._running:
            return

        logger.info("Shutting down Enhanced Antivirus Manager")
        self._running = False

        # Stop scan workers
        for worker in self.scan_workers:
            worker.cancel()

        # Stop file watchers
        for watcher in self.file_watchers.values():
            if hasattr(watcher, 'stop'):
                if watcher and hasattr(watcher, "stop"): watcher.stop()

        # Save configuration and quarantine data
        await self._save_config()
        await self._save_quarantine_entries()

        logger.info("Enhanced Antivirus Manager shutdown complete")

    async def scan_file(self, file_path: str, scan_types: Optional[List[ScanType]] = None, )
                       priority: int = 1, requester: str = "manual") -> List[ScanResult]:
        """
        Scan a file with specified scan types.

        Args:
            file_path: Path to file to scan
            scan_types: List of scan types to perform (default: all)
            priority: Scan priority (1-4)
            requester: Who requested the scan

        Returns:
            List of scan results from different scan types
        """
        if not self._running:
            raise RuntimeError("Antivirus manager not running")

        if scan_types is None:
            scan_types = [
                ScanType.HASH_SCAN,
                ScanType.BEHAVIORAL_SCAN,
                ScanType.FILENAME_ANALYSIS,
                ScanType.THREAT_INTELLIGENCE
            ]

        # Create scan request
        scan_request = ScanRequest()
            file_path=file_path,
            scan_types=scan_types,
            priority=priority,
            requester=requester,
            metadata={"scan_time": datetime.now(timezone.utc).isoformat()}
        )

        # Add to queue
        await self.scan_queue.put(scan_request)

        # Wait for scan completion (simplified - in real implementation would use callbacks)
        # For now, perform scan directly
        return await self._perform_scan(scan_request)

    async def scan_plugin(self, plugin_path: str) -> List[ScanResult]:
        """
        Scan a plugin file with comprehensive security checks.

        Args:
            plugin_path: Path to plugin file

        Returns:
            List of scan results
        """
        logger.info(f"Scanning plugin: {plugin_path}")

        # Use all scan types for plugins
        scan_types = [
            ScanType.HASH_SCAN,
            ScanType.BEHAVIORAL_SCAN,
            ScanType.FILENAME_ANALYSIS,
            ScanType.THREAT_INTELLIGENCE
        ]

        results = await self.scan_file(plugin_path, scan_types, priority=3, requester="plugin_system")

        # Additional plugin-specific checks
        plugin_specific_result = await self._scan_plugin_specific(plugin_path)
        if plugin_specific_result:
            results.append(plugin_specific_result)

        self.stats["plugin_scans"] += 1
        return results

    async def scan_url(self, url: str) -> ScanResult:
        """
        Scan a URL for safety.

        Args:
            url: URL to scan

        Returns:
            Scan result for the URL
        """
        logger.debug(f"Scanning URL: {url}")
        return await self.antivirus_engine.link_scanner.scan_url(url)

    async def quarantine_file(self, file_path: str, scan_results: List[ScanResult], )
                             threat_name: Optional[str] = None) -> bool:
        """
        Quarantine a file that was detected as a threat.

        Args:
            file_path: Path to file to quarantine
            scan_results: Scan results that triggered quarantine
            threat_name: Name of the threat (optional)

        Returns:
            True if quarantine successful, False otherwise
        """
        try:
            from pathlib import Path

            self.path = Path(file_path)
            if not path.exists():
                logger.warning(f"Cannot quarantine non-existent file: {file_path}")
                return False

            # Calculate file hash
            file_hash = await self._calculate_file_hash(path)

            # Create quarantine filename
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{file_hash[:16]}_{path.name}"
            quarantine_path = self.quarantine_dir / quarantine_filename

            # Move file to quarantine
            path.rename(quarantine_path)

            # Determine threat level and name
            max_threat_level = max((r.threat_level for r in scan_results), default=ThreatLevel.CLEAN)
            if not threat_name:
                threat_names = [r.threat_name for r in scan_results if r.threat_name]
                threat_name = threat_names[0] if threat_names else "Unknown Threat"

            # Create quarantine entry
            entry = QuarantineEntry()
                original_path=str(path),
                quarantine_path=str(quarantine_path),
                threat_name=threat_name,
                threat_level=max_threat_level,
                quarantine_time=datetime.now(timezone.utc),
                file_hash=file_hash,
                file_size=quarantine_path.stat().st_size,
                scan_results=scan_results,
                auto_delete_after=datetime.now(timezone.utc) + timedelta(days=self.config["quarantine_auto_delete_days"])
            )

            self.quarantine_entries[file_hash] = entry
            await self._save_quarantine_entries()

            self.stats["files_quarantined"] += 1
            logger.warning(f"File quarantined: {file_path} -> {quarantine_path}")

            # Notify callbacks
            await self._notify_threat_detected(file_path, threat_name, max_threat_level)

            return True

        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False

    async def restore_from_quarantine(self, file_hash: str, restore_path: Optional[str] = None) -> bool:
        """
        Restore a file from quarantine.

        Args:
            file_hash: Hash of the quarantined file
            restore_path: Path to restore to (optional, uses original path)

        Returns:
            True if restore successful, False otherwise
        """
        try:
            if file_hash not in self.quarantine_entries:
                logger.warning(f"Quarantine entry not found: {file_hash}")
                return False

            entry = self.quarantine_entries[file_hash]
            from pathlib import Path

            self.quarantine_path = Path(entry.quarantine_path)

            if not quarantine_path.exists():
                logger.error(f"Quarantined file not found: {entry.quarantine_path}")
                return False

            # Determine restore path
            if not restore_path:
                restore_path = entry.original_path

            from pathlib import Path


            self.restore_path = Path(restore_path)
            restore_path.parent.mkdir(parents=True, exist_ok=True)

            # Move file back
            quarantine_path.rename(restore_path)

            # Remove from quarantine
            del self.quarantine_entries[file_hash]
            await self._save_quarantine_entries()

            logger.info(f"File restored from quarantine: {restore_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore file from quarantine: {e}")
            return False

    async def delete_quarantined_file(self, file_hash: str) -> bool:
        """
        Permanently delete a quarantined file.

        Args:
            file_hash: Hash of the quarantined file

        Returns:
            True if deletion successful, False otherwise
        """
        try:
            if file_hash not in self.quarantine_entries:
                logger.warning(f"Quarantine entry not found: {file_hash}")
                return False

            entry = self.quarantine_entries[file_hash]
            from pathlib import Path

            self.quarantine_path = Path(entry.quarantine_path)

            if quarantine_path.exists():
                quarantine_path.unlink()

            # Remove from quarantine
            del self.quarantine_entries[file_hash]
            await self._save_quarantine_entries()

            logger.info(f"Quarantined file permanently deleted: {entry.original_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete quarantined file: {e}")
            return False

    async def get_quarantine_list(self) -> List[Dict[str, Any]]:
        """Get list of all quarantined files."""
        return [
            {
                "file_hash": file_hash,
                "original_path": entry.original_path,
                "threat_name": entry.threat_name,
                "threat_level": entry.threat_level.value,
                "quarantine_time": entry.quarantine_time.isoformat(),
                "file_size": entry.file_size,
                "auto_delete_after": entry.auto_delete_after.isoformat() if entry.auto_delete_after else None
            }
            for file_hash, entry in self.quarantine_entries.items()
        ]

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics."""
        # Combine with core engine stats
        core_stats = await self.antivirus_engine.get_scan_statistics()

        return {
            **self.stats,
            "core_engine_stats": core_stats,
            "quarantine_count": len(self.quarantine_entries),
            "active_scans": len(self.active_scans),
            "queue_size": self.scan_queue.qsize(),
            "monitored_directories": len(self.monitored_directories),
            "config": self.config
        }

    async def update_threat_database(self) -> bool:
        """Update threat intelligence database."""
        try:
            logger.info("Updating threat database")
            await self.antivirus_engine.threat_intelligence.update_threat_signatures()
            logger.info("Threat database updated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to update threat database: {e}")
            return False

    # Private methods
    async def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            if self.config_path.exists() if self.config_path else False:
                with open(self.config_path, 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
                logger.debug("Configuration loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load config, using defaults: {e}")

    async def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.debug("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    async def _load_quarantine_entries(self) -> None:
        """Load quarantine entries from file."""
        try:
            quarantine_db_path = self.antivirus_dir / "quarantine.json"
            if quarantine_db_path.exists():
                with open(quarantine_db_path, 'r') as f:
                    data = json.load(f)
                    for file_hash, entry_data in data.items():
                        # Convert datetime strings back to datetime objects
                        entry_data['quarantine_time'] = datetime.fromisoformat(entry_data['quarantine_time'])
                        if entry_data.get('auto_delete_after'):
                            entry_data['auto_delete_after'] = datetime.fromisoformat(entry_data['auto_delete_after'])

                        # Convert scan results back to ScanResult objects
                        scan_results = []
                        for result_data in entry_data.get('scan_results', []):
                            # Simplified reconstruction - in real implementation would need proper deserialization
                            scan_results.append(ScanResult(**result_data))
                        entry_data['scan_results'] = scan_results

                        self.quarantine_entries[file_hash] = QuarantineEntry(**entry_data)
                logger.debug(f"Loaded {len(self.quarantine_entries)} quarantine entries")
        except Exception as e:
            logger.warning(f"Failed to load quarantine entries: {e}")

    async def _save_quarantine_entries(self) -> None:
        """Save quarantine entries to file."""
        try:
            quarantine_db_path = self.antivirus_dir / "quarantine.json"
            data = {}
            for file_hash, entry in self.quarantine_entries.items():
                entry_dict = asdict(entry)
                # Convert datetime objects to strings
                entry_dict['quarantine_time'] = entry.quarantine_time.isoformat()
                if entry.auto_delete_after:
                    entry_dict['auto_delete_after'] = entry.auto_delete_after.isoformat()

                # Convert scan results to dictionaries
                entry_dict['scan_results'] = [asdict(result) for result in entry.scan_results]
                data[file_hash] = entry_dict

            with open(quarantine_db_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug("Quarantine entries saved successfully")
        except Exception as e:
            logger.error(f"Failed to save quarantine entries: {e}")

    async def _start_scan_workers(self) -> None:
        """Start background scan worker tasks."""
        num_workers = self.config["scan_workers"]
        for i in range(num_workers):
            worker = asyncio.create_task(self._scan_worker(f"worker-{i}"))
            self.scan_workers.append(worker)
        logger.info(f"Started {num_workers} scan workers")

    async def _scan_worker(self, worker_name: str) -> None:
        """Background scan worker that processes scan queue."""
        logger.debug(f"Scan worker {worker_name} started")

        while self._running:
            try:
                # Get scan request from queue with timeout
                scan_request = await asyncio.wait_for(self.scan_queue.get(), timeout=1.0)

                # Track active scan
                self.active_scans[scan_request.file_path] = scan_request

                try:
                    # Perform the scan
                    results = await self._perform_scan(scan_request)

                    # Handle scan results
                    await self._handle_scan_results(scan_request, results)

                except Exception as e:
                    logger.error(f"Scan failed for {scan_request.file_path}: {e}")
                    self.stats["scan_errors"] += 1

                finally:
                    # Remove from active scans
                    self.active_scans.pop(scan_request.file_path, None)
                    self.scan_queue.task_done()

            except asyncio.TimeoutError:
                # No scan requests in queue, continue
                continue
            except Exception as e:
                logger.error(f"Scan worker {worker_name} error: {e}")
                await asyncio.sleep(1)

        logger.debug(f"Scan worker {worker_name} stopped")

    async def _perform_scan(self, scan_request: ScanRequest) -> List[ScanResult]:
        """Perform the actual scan based on scan request."""
        start_time = datetime.now(timezone.utc)
        results = []

        try:
            file_path = scan_request.file_path

            # Check if file exists
            if not from pathlib import Path
Path(file_path).exists():
                logger.warning(f"File not found for scanning: {file_path}")
                return []

            # Check file size limit
            from pathlib import Path

            self.file_size = Path(file_path).stat().st_size
            if file_size > self.config["max_file_size"]:
                logger.warning(f"File too large for scanning: {file_path} ({file_size} bytes)")
                return []

            # Perform requested scan types
            for scan_type in scan_request.scan_types:
                try:
                    if scan_type == ScanType.HASH_SCAN and self.config["hash_scanning"]:
                        file_hash = await self._calculate_file_hash(from pathlib import Path)
Path(file_path))
                        result = await self.antivirus_engine.hash_scanner.scan_hash(file_hash, file_path)
                        results.append(result)

                    elif scan_type == ScanType.BEHAVIORAL_SCAN and self.config["behavioral_analysis"]:
                        result = await self.antivirus_engine.behavioral_analyzer.analyze_file(file_path)
                        results.append(result)

                    elif scan_type == ScanType.FILENAME_ANALYSIS and self.config["filename_analysis"]:
                        result = await self.antivirus_engine.filename_analyzer.analyze_filename(file_path)
                        results.append(result)

                    elif scan_type == ScanType.THREAT_INTELLIGENCE and self.config["threat_intelligence"]:
                        file_hash = await self._calculate_file_hash(from pathlib import Path)
Path(file_path))
                        threat_sig = await self.antivirus_engine.threat_intelligence.check_hash_threat(file_hash)
                        if threat_sig:
                            # Convert threat signature to scan result
                            result = ScanResult()
                                file_path=file_path,
                                file_hash=file_hash,
                                threat_level=threat_sig.threat_level,
                                threat_type=threat_sig.threat_type,
                                threat_name=threat_sig.threat_name,
                                scan_type=ScanType.THREAT_INTELLIGENCE,
                                scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
                                detected_at=datetime.now(timezone.utc),
                                confidence_score=threat_sig.confidence_score,
                                details={"source": threat_sig.source, "description": threat_sig.description}
                            )
                            results.append(result)

                except Exception as e:
                    logger.error(f"Scan type {scan_type} failed for {file_path}: {e}")

            # Update statistics
            self.stats["total_scans"] += 1
            scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.stats["average_scan_time"] = ()
                (self.stats["average_scan_time"] * (self.stats["total_scans"] - 1) + scan_duration) /
                self.stats["total_scans"]
            )
            self.stats["last_scan_time"] = datetime.now(timezone.utc).isoformat()

            return results

        except Exception as e:
            logger.error(f"Scan failed for {scan_request.file_path}: {e}")
            self.stats["scan_errors"] += 1
            return []

    async def _handle_scan_results(self, scan_request: ScanRequest, results: List[ScanResult]) -> None:
        """Handle scan results and take appropriate actions."""
        if not results:
            return

        # Determine overall threat level
        max((r.threat_level for r in results), default=ThreatLevel.CLEAN)

        # Count clean vs threat results
        threat_results = [r for r in results if r.threat_level.value > ThreatLevel.CLEAN.value]

        if threat_results:
            self.stats["threats_detected"] += 1

            # Determine if file should be quarantined
            should_quarantine = any()
                r.threat_level.value >= ThreatLevel.MEDIUM_RISK.value
                for r in threat_results
            )

            if should_quarantine:
                threat_names = [r.threat_name for r in threat_results if r.threat_name]
                threat_name = ", ".join(threat_names) if threat_names else "Multiple Threats"

                await self.quarantine_file(scan_request.file_path, results, threat_name)

            # Log threat detection
            logger.warning(f"Threats detected in {scan_request.file_path}: {len(threat_results)} threats")
            for result in threat_results:
                logger.warning(f"  - {result.threat_name} ({result.threat_level.value}) - {result.confidence_score:.2f}")

        else:
            self.stats["clean_files"] += 1

        # Call callback if provided
        if scan_request.callback:
            try:
                await scan_request.callback(scan_request, results)
            except Exception as e:
                logger.error(f"Scan callback failed: {e}")

    async def _scan_plugin_specific(self, plugin_path: str) -> Optional[ScanResult]:
        """Perform plugin-specific security checks."""
        start_time = datetime.now(timezone.utc)
        from pathlib import Path

        self.path = Path(plugin_path)

        try:
            # Check if it's a ZIP file (plugin format)
            if not path.suffix.lower() == '.zip':
                return ScanResult()
                    file_path=plugin_path,
                    file_hash="",
                    threat_level=ThreatLevel.SUSPICIOUS,
                    threat_type=ThreatType.SUSPICIOUS_BEHAVIOR,
                    threat_name="Invalid Plugin Format",
                    scan_type=ScanType.BEHAVIORAL_SCAN,
                    scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
                    detected_at=datetime.now(timezone.utc),
                    confidence_score=0.8,
                    details={"reason": "Plugin must be a ZIP file"}
                )

            # Additional plugin-specific checks would go here
            # For now, return clean result
            return ScanResult(
                file_path=plugin_path,
                file_hash="",
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.BEHAVIORAL_SCAN,
                scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
                detected_at=datetime.now(timezone.utc),
                confidence_score=0.1,
                details={"plugin_format_check": "passed"}
            )

        except Exception as e:
            logger.error(f"Plugin-specific scan failed: {e}")
            return None

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-512 hash of a file."""
        try:
            hash_sha512 = hashlib.sha512()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha512.update(chunk)
            return hash_sha512.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""

    async def _start_real_time_monitoring(self) -> None:
        """Start real-time file system monitoring."""
        try:
            # Add common directories to monitor
            common_dirs = [
                "uploads",
                "plugins",
                "temp",
                "downloads"
            ]

            for dir_name in common_dirs:
                dir_path = self.data_dir / dir_name
                if dir_path.exists():
                    await self._add_directory_monitor(str(dir_path))

            logger.info("Real-time monitoring started")
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")

    async def _add_directory_monitor(self, directory: str) -> None:
        """Add a directory to real-time monitoring."""
        try:
            # Simplified monitoring - in real implementation would use watchdog or similar
            self.monitored_directories.add(directory)
            logger.debug(f"Added directory to monitoring: {directory}")
        except Exception as e:
            logger.error(f"Failed to add directory monitor: {e}")

    async def _notify_threat_detected(self, file_path: str, threat_name: str, threat_level: ThreatLevel) -> None:
        """Notify registered callbacks about threat detection."""
        for callback in self.config.get("notification_callbacks", []):
            try:
                if callable(callback):
                    await callback(file_path, threat_name, threat_level)
            except Exception as e:
                logger.error(f"Notification callback failed: {e}")

    async def _background_maintenance_task(self) -> None:
        """Background task for maintenance operations."""
        while self._running:
            try:
                # Clean up expired quarantine entries
                await self._cleanup_expired_quarantine()

                # Update threat intelligence periodically
                if datetime.now(timezone.utc).hour == 2:  # Update at 2 AM
                    await self.update_threat_database()

                # Sleep for 1 hour
                await asyncio.sleep(3600)

            except Exception as e:
                logger.error(f"Background maintenance task error: {e}")
                await asyncio.sleep(300)  # Sleep 5 minutes on error

    async def _cleanup_expired_quarantine(self) -> None:
        """Clean up expired quarantine entries."""
        try:
            now = datetime.now(timezone.utc)
            expired_entries = []

            for file_hash, entry in self.quarantine_entries.items():
                if entry.auto_delete_after and now > entry.auto_delete_after:
                    expired_entries.append(file_hash)

            for file_hash in expired_entries:
                await self.delete_quarantined_file(file_hash)
                logger.info(f"Auto-deleted expired quarantine entry: {file_hash}")

            if expired_entries:
                logger.info(f"Cleaned up {len(expired_entries)} expired quarantine entries")

        except Exception as e:
            logger.error(f"Failed to cleanup expired quarantine entries: {e}")
