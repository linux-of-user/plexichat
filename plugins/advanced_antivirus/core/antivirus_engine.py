import asyncio
import hashlib
from plexichat.core.logging import get_logger
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
from dataclasses import asdict, is_dataclass

# plugins_internal was relocated into the plexichat package as part of the SDK generator.
# Try to import the EnhancedPluginAPI that the engine expects; fall back to the generic
# PluginAPI if EnhancedPluginAPI is not available.
try:
    from plexichat.plugins_internal import EnhancedPluginAPI  # type: ignore
except Exception:
    try:
        from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI  # type: ignore
    except Exception:  # pragma: no cover - extremely defensive fallback
        EnhancedPluginAPI = Any  # type: ignore

from . import (
    MAX_FILE_SIZE_SCAN,
    SUSPICIOUS_EXTENSIONS,
    ScanResult,
    ScanType,
    ThreatLevel,
)
from plugins.advanced_antivirus.core.behavioral_analyzer import BehavioralAnalyzer
from plugins.advanced_antivirus.core.filename_analyzer import FilenameAnalyzer
from plugins.advanced_antivirus.core.hash_scanner import HashBasedScanner
from plugins.advanced_antivirus.core.link_scanner import LinkSafetyScanner
from plugins.advanced_antivirus.core.threat_intelligence import ThreatIntelligenceManager

logger = get_logger(__name__)


class AdvancedAntivirusEngine:
    """
    Advanced antivirus engine that coordinates scanning components and uses the Plugin SDK.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        # The SDK API exposes a logger for the plugin; prefer that for contextual logs.
        self.logger = getattr(api, "logger", logger)

        # Initialize scanning components, passing the SDK's api object to each
        self.hash_scanner = HashBasedScanner(api=self.api)
        self.behavioral_analyzer = BehavioralAnalyzer(api=self.api)
        self.link_scanner = LinkSafetyScanner(api=self.api)
        self.filename_analyzer = FilenameAnalyzer()
        self.threat_intelligence = ThreatIntelligenceManager({})  # self-contained

        # Scan statistics
        self.scan_stats = {
            "total_scans": 0,
            "threats_detected": 0,
            "files_quarantined": 0,
            "false_positives": 0,
            "last_update": None,
        }

        self._initialized = False

    async def initialize(self):
        """Initialize the antivirus engine and all components."""
        if self._initialized:
            return

        self.logger.info("Initializing Advanced Antivirus Engine")

        # Initialize all scanning components if they provide initialize()
        try:
            if self.hash_scanner and hasattr(self.hash_scanner, "initialize"):
                await self.hash_scanner.initialize()
            if self.behavioral_analyzer and hasattr(self.behavioral_analyzer, "initialize"):
                await self.behavioral_analyzer.initialize()
            if self.link_scanner and hasattr(self.link_scanner, "initialize"):
                await self.link_scanner.initialize()
            if self.threat_intelligence and hasattr(self.threat_intelligence, "initialize"):
                await self.threat_intelligence.initialize()
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")

        # Load scan statistics
        try:
            await self._load_scan_statistics()
        except Exception as e:
            self.logger.warning(f"Unable to load scan statistics: {e}")

        # Start background tasks
        try:
            asyncio.create_task(self._background_update_task())
        except Exception:
            # In a testing environment create_task might not be available; ignore failure.
            pass

        self._initialized = True
        self.logger.info("Advanced Antivirus Engine initialized successfully")

    async def scan_file(
        self, file_path: str, scan_type: ScanType = ScanType.FULL_SCAN
    ) -> ScanResult:
        """
        Perform comprehensive scan of a file.

        Args:
            file_path: Path to file to scan
            scan_type: Type of scan to perform

        Returns:
            ScanResult with detection details
        """
        start_time = time.time()
        self.file_path = Path(file_path)

        self.logger.debug(f"Scanning file: {file_path} with {getattr(scan_type, 'value', str(scan_type))} scan")

        # Basic file checks
        if not self.file_path.exists():
            return self._create_error_result(
                str(self.file_path), "File not found", start_time
            )

        try:
            file_size = self.file_path.stat().st_size
        except Exception as e:
            self.logger.error(f"Failed to stat file {self.file_path}: {e}")
            return self._create_error_result(str(self.file_path), "Unable to access file", start_time)

        if file_size > MAX_FILE_SIZE_SCAN:
            return self._create_warning_result(
                str(self.file_path),
                f"File too large for scanning ({file_size} bytes)",
                start_time,
            )

        # Calculate file hash
        try:
            file_hash = await self._calculate_file_hash(self.file_path)
        except Exception as e:
            self.logger.error(f"Failed to calculate file hash for {self.file_path}: {e}")
            return self._create_error_result(str(self.file_path), "Hashing failure", start_time)

        # Perform different types of scans based on scan_type
        scan_results: List[ScanResult] = []

        if scan_type in [ScanType.FULL_SCAN, ScanType.HASH_SCAN]:
            # Hash-based scanning
            try:
                hash_result = await self.hash_scanner.scan_hash(
                    file_hash, str(self.file_path)
                )
                scan_results.append(hash_result)
            except Exception as e:
                self.logger.warning(f"Hash scanner failed for {self.file_path}: {e}")

        if scan_type in [ScanType.FULL_SCAN, ScanType.FILENAME_SCAN]:
            # Filename analysis
            try:
                filename_result = await self.filename_analyzer.analyze_filename(
                    str(self.file_path)
                )
                scan_results.append(filename_result)
            except Exception as e:
                self.logger.warning(f"Filename analyzer failed for {self.file_path}: {e}")

        if scan_type in [ScanType.FULL_SCAN, ScanType.BEHAVIORAL_SCAN]:
            # Behavioral analysis (for executable files)
            if self.file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                try:
                    behavioral_result = await self.behavioral_analyzer.analyze_file(
                        str(self.file_path)
                    )
                    scan_results.append(behavioral_result)
                except Exception as e:
                    self.logger.warning(f"Behavioral analyzer failed for {self.file_path}: {e}")

        # Combine results and determine final threat level
        final_result = self._combine_scan_results(scan_results, file_hash, start_time)

        # Handle threats
        try:
            if getattr(final_result, "threat_level", ThreatLevel.CLEAN).value >= ThreatLevel.MEDIUM_RISK.value:
                await self._handle_threat(final_result)
        except Exception as e:
            self.logger.error(f"Error handling threat: {e}")

        # Update statistics
        try:
            await self._update_scan_statistics(final_result)
        except Exception as e:
            self.logger.warning(f"Failed to update scan statistics: {e}")

        # Log scan to database
        try:
            await self._log_scan_result(final_result)
        except Exception as e:
            self.logger.warning(f"Failed to log scan result: {e}")

        scan_duration = time.time() - start_time
        # Some ScanResult implementations may allow setting attributes directly
        try:
            setattr(final_result, "scan_duration", scan_duration)
        except Exception:
            pass

        self.logger.info(
            f"Scan completed: {self.file_path} - {getattr(final_result, 'threat_level', 'unknown').name if getattr(final_result, 'threat_level', None) is not None else 'unknown'} in {scan_duration:.2f}s"
        )
        return final_result

    async def scan_link(self, url: str) -> ScanResult:
        """Scan a URL for safety."""
        start_time = time.time()
        self.logger.debug(f"Scanning link: {url}")

        result = await self.link_scanner.scan_url(url)
        try:
            setattr(result, "scan_duration", time.time() - start_time)
        except Exception:
            pass

        try:
            await self._update_scan_statistics(result)
        except Exception as e:
            self.logger.warning(f"Failed to update stats for URL scan: {e}")

        try:
            await self._log_scan_result(result)
        except Exception as e:
            self.logger.warning(f"Failed to log URL scan result: {e}")

        return result

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics."""
        try:
            return {
                **self.scan_stats,
                "hash_scanner_stats": self.hash_scanner.get_statistics(),
                "behavioral_stats": self.behavioral_analyzer.get_statistics(),
                "link_scanner_stats": self.link_scanner.get_statistics(),
                "threat_intel_stats": self.threat_intelligence.get_threat_statistics(),
            }
        except Exception as e:
            self.logger.warning(f"Failed to collect scanner statistics: {e}")
            return {**self.scan_stats}

    async def update_threat_databases(self) -> bool:
        """Update all threat databases."""
        self.logger.info("Updating threat databases")

        try:
            # Update hash database
            hash_updated = await self.hash_scanner.update_database()

            # Update threat intelligence
            intel_updated = await self.threat_intelligence.update_intelligence_feeds()

            # Update behavioral patterns
            behavioral_updated = await self.behavioral_analyzer.update_patterns({})

            self.scan_stats["last_update"] = datetime.now(timezone.utc).isoformat()

            self.logger.info(
                f"Database update completed - Hash: {hash_updated}, Intel: {intel_updated}, Behavioral: {behavioral_updated}"
            )
            return bool(hash_updated or intel_updated or behavioral_updated)

        except Exception as e:
            self.logger.error(f"Failed to update threat databases: {e}")
            return False

    async def _log_scan_result(self, scan_result: ScanResult):
        """Logs a scan result to the database via the SDK."""
        # This provides an example of how the engine could log its own data
        # if it needed to, separate from the sub-scanners.

        # Determine file_hash in a robust way
        file_hash = None
        try:
            file_hash = getattr(scan_result, "file_hash", None)
            if not file_hash and hasattr(scan_result, "file_path"):
                # Try to compute a simple hash from path if not present
                file_hash = hashlib.sha256(str(getattr(scan_result, "file_path")).encode()).hexdigest()
        except Exception:
            file_hash = ""

        log_key = f"scan_log:{file_hash or ''}:{int(time.time())}"

        # Serialize scan_result to a dict in a defensive manner
        log_data: Dict[str, Any]
        try:
            if hasattr(scan_result, "to_dict") and callable(getattr(scan_result, "to_dict")):
                log_data = scan_result.to_dict()
            elif is_dataclass(scan_result):
                log_data = asdict(scan_result)
            elif hasattr(scan_result, "__dict__"):
                log_data = dict(vars(scan_result))
            else:
                # Last resort: try to stringify
                log_data = {"result": str(scan_result)}
        except Exception as e:
            self.logger.warning(f"Failed to convert scan result to dict: {e}")
            log_data = {"result": str(scan_result)}

        # Normalize common fields (enum -> value, datetime -> isoformat)
        try:
            # threat_level normalization
            tl = log_data.get("threat_level", getattr(scan_result, "threat_level", None))
            if hasattr(tl, "value"):
                log_data["threat_level"] = tl.value
            else:
                log_data["threat_level"] = tl

            # threat_type normalization (may be enum)
            tt = log_data.get("threat_type", getattr(scan_result, "threat_type", None))
            if hasattr(tt, "value"):
                log_data["threat_type"] = tt.value
            else:
                log_data["threat_type"] = tt

            # scan_type normalization
            st = log_data.get("scan_type", getattr(scan_result, "scan_type", None))
            if hasattr(st, "value"):
                log_data["scan_type"] = st.value
            else:
                log_data["scan_type"] = st

            # detected_at normalization
            da = log_data.get("detected_at", getattr(scan_result, "detected_at", None))
            if isinstance(da, datetime):
                log_data["detected_at"] = da.isoformat()
            elif da is None:
                log_data["detected_at"] = datetime.now(timezone.utc).isoformat()
            else:
                # keep as-is (likely already a string)
                log_data["detected_at"] = da
        except Exception as e:
            self.logger.debug(f"Partial normalization of scan result failed: {e}")

        # Persist log via SDK API - many SDKs expose db_set_value or similar
        try:
            await self.api.db_set_value(log_key, log_data)
        except Exception as e:
            # Try alternative method name if available
            try:
                await self.api.database.db_set_value(log_key, log_data)  # type: ignore
            except Exception:
                self.logger.warning(f"Failed to store scan log in persistent storage: {e}")

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-512 hash of file."""
        hash_sha512 = hashlib.sha512()

        async with aiofiles.open(file_path, "rb") as f:
            while True:
                chunk = await f.read(8192)
                if not chunk:
                    break
                hash_sha512.update(chunk)

        return hash_sha512.hexdigest()

    def _create_error_result(
        self, file_path: str, error_msg: str, start_time: float
    ) -> ScanResult:
        """Create error scan result."""
        return ScanResult(
            file_path=file_path,
            file_hash="",
            threat_level=ThreatLevel.CLEAN,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.QUICK_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=0.0,
            details={"error": error_msg},
        )

    def _create_warning_result(
        self, file_path: str, warning_msg: str, start_time: float
    ) -> ScanResult:
        """Create warning scan result."""
        return ScanResult(
            file_path=file_path,
            file_hash="",
            threat_level=ThreatLevel.SUSPICIOUS,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.QUICK_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=0.3,
            details={"warning": warning_msg},
        )

    def _combine_scan_results(
        self, results: List[ScanResult], file_hash: str, start_time: float
    ) -> ScanResult:
        """Combine multiple scan results into final result."""
        if not results:
            return ScanResult(
                file_path="unknown",
                file_hash=file_hash,
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.FULL_SCAN,
                scan_duration=time.time() - start_time,
                detected_at=datetime.now(timezone.utc),
                confidence_score=1.0,
                details={"status": "clean"},
            )

        # Find highest threat level (defensive: handle either enum or comparable values)
        try:
            max_threat_level = max(result.threat_level for result in results)
        except Exception:
            # fall back to comparing numeric .value attributes
            try:
                max_threat_level = max(getattr(result.threat_level, "value", 0) for result in results)
                # convert back to a ThreatLevel-like holder if possible
            except Exception:
                max_threat_level = ThreatLevel.CLEAN

        # Select the result that has the highest threat_level (best-effort)
        highest_threat_result = results[0]
        try:
            for result in results:
                # compare using .value when available
                a = getattr(result.threat_level, "value", result.threat_level)
                b = getattr(highest_threat_result.threat_level, "value", highest_threat_result.threat_level)
                if a > b:
                    highest_threat_result = result
        except Exception:
            pass

        # Combine confidence scores defensively
        try:
            avg_confidence = sum(getattr(result, "confidence_score", 0.0) for result in results) / max(1, len(results))
        except Exception:
            avg_confidence = 0.0

        # Combine details
        combined_details: Dict[str, Any] = {}
        for result in results:
            try:
                if isinstance(result.details, dict):
                    combined_details.update(result.details)
                else:
                    combined_details.update({"detail": str(result.details)})
            except Exception:
                combined_details.update({"detail_error": "unable to extract details"})

        return ScanResult(
            file_path=getattr(highest_threat_result, "file_path", "unknown"),
            file_hash=file_hash,
            threat_level=getattr(highest_threat_result, "threat_level", ThreatLevel.CLEAN),
            threat_type=getattr(highest_threat_result, "threat_type", None),
            threat_name=getattr(highest_threat_result, "threat_name", None),
            scan_type=ScanType.FULL_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=avg_confidence,
            details=combined_details,
        )

    async def _handle_threat(self, scan_result: ScanResult):
        """Handle detected threat by logging it. Quarantine is handled by the manager."""
        try:
            if getattr(scan_result, "threat_level", ThreatLevel.CLEAN).value >= ThreatLevel.MEDIUM_RISK.value:
                self.logger.warning(
                    f"Threat detected: {getattr(scan_result, 'threat_name', 'unknown')} in {getattr(scan_result, 'file_path', 'unknown')} (Level: {getattr(scan_result, 'threat_level', ThreatLevel.CLEAN).name})"
                )
        except Exception as e:
            self.logger.error(f"Error while handling threat: {e}")

    async def _update_scan_statistics(self, scan_result: ScanResult):
        """Update scan statistics."""
        self.scan_stats["total_scans"] += 1

        try:
            if getattr(scan_result, "threat_level", ThreatLevel.CLEAN).value >= ThreatLevel.MEDIUM_RISK.value:
                self.scan_stats["threats_detected"] += 1
        except Exception:
            # If threat_level is not comparable, attempt to infer from details
            if isinstance(getattr(scan_result, "details", None), dict) and scan_result.details.get("status") != "clean":
                self.scan_stats["threats_detected"] += 1

        # Persist updated statistics (best-effort)
        try:
            await self.api.db_set_value("scan_statistics", self.scan_stats)
        except Exception:
            try:
                await self.api.database.db_set_value("scan_statistics", self.scan_stats)  # type: ignore
            except Exception:
                self.logger.debug("Unable to persist scan statistics")

    async def _load_scan_statistics(self):
        """Load scan statistics from database via SDK."""
        try:
            stats = await self.api.db_get_value("scan_statistics")
            if stats and isinstance(stats, dict):
                self.scan_stats.update(stats)
        except Exception as e:
            self.logger.debug(f"Unable to load scan statistics from storage: {e}")

    async def _background_update_task(self):
        """Background task for updating threat databases."""
        while True:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self.update_threat_databases()
            except Exception as e:
                logger.error(f"Background update task failed: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
