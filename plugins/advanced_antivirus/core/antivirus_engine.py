import asyncio
import hashlib
from plexichat.core.logging import get_logger
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import aiofiles

from plugins_internal import EnhancedPluginAPI
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
        self.logger = api.logger

        # Initialize scanning components, passing the SDK's api object to each
        self.hash_scanner = HashBasedScanner(api=self.api)
        self.behavioral_analyzer = BehavioralAnalyzer(api=self.api)
        self.link_scanner = LinkSafetyScanner(api=self.api)
        self.filename_analyzer = FilenameAnalyzer()
        self.threat_intelligence = ThreatIntelligenceManager({}) # This one seems self-contained

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

        # Database is no longer initialized here; components handle their own persistence via SDK.

        # Initialize all scanning components
        if self.hash_scanner and hasattr(self.hash_scanner, "initialize"):
            await self.hash_scanner.initialize()
        if self.behavioral_analyzer and hasattr(self.behavioral_analyzer, "initialize"):
            await self.behavioral_analyzer.initialize()
        if self.link_scanner and hasattr(self.link_scanner, "initialize"):
            await self.link_scanner.initialize()
        if self.threat_intelligence and hasattr(self.threat_intelligence, "initialize"):
            await self.threat_intelligence.initialize()

        # Load scan statistics
        await self._load_scan_statistics()

        # Start background tasks
        asyncio.create_task(self._background_update_task())

        self._initialized = True
        logger.info("Advanced Antivirus Engine initialized successfully")

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

        logger.debug(f"Scanning file: {file_path} with {scan_type.value} scan")

        # Basic file checks
        if not self.file_path.exists():
            return self._create_error_result(
                str(self.file_path), "File not found", start_time
            )

        if self.file_path.stat().st_size > MAX_FILE_SIZE_SCAN:
            return self._create_warning_result(
                str(self.file_path),
                f"File too large for scanning ({self.file_path.stat().st_size} bytes)",
                start_time,
            )

        # Calculate file hash
        file_hash = await self._calculate_file_hash(self.file_path)

        # Perform different types of scans based on scan_type
        scan_results = []

        if scan_type in [ScanType.FULL_SCAN, ScanType.HASH_SCAN]:
            # Hash-based scanning
            hash_result = await self.hash_scanner.scan_hash(
                file_hash, str(self.file_path)
            )
            scan_results.append(hash_result)

        if scan_type in [ScanType.FULL_SCAN, ScanType.FILENAME_SCAN]:
            # Filename analysis
            filename_result = await self.filename_analyzer.analyze_filename(
                str(self.file_path)
            )
            scan_results.append(filename_result)

        if scan_type in [ScanType.FULL_SCAN, ScanType.BEHAVIORAL_SCAN]:
            # Behavioral analysis (for executable files)
            if self.file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                behavioral_result = await self.behavioral_analyzer.analyze_file(
                    str(self.file_path)
                )
                scan_results.append(behavioral_result)

        # Combine results and determine final threat level
        final_result = self._combine_scan_results(scan_results, file_hash, start_time)

        # Handle threats
        if final_result.threat_level.value >= ThreatLevel.MEDIUM_RISK.value:
            await self._handle_threat(final_result)

        # Update statistics
        await self._update_scan_statistics(final_result)

        # Log scan to database
        await self._log_scan_result(final_result)

        scan_duration = time.time() - start_time
        final_result.scan_duration = scan_duration

        logger.info(
            f"Scan completed: {self.file_path} - {final_result.threat_level.name} in {scan_duration:.2f}s"
        )
        return final_result

    async def scan_link(self, url: str) -> ScanResult:
        """Scan a URL for safety."""
        start_time = time.time()
        logger.debug(f"Scanning link: {url}")

        result = await self.link_scanner.scan_url(url)
        result.scan_duration = time.time() - start_time

        await self._update_scan_statistics(result)
        await self._log_scan_result(result)

        return result

    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics."""
        return {
            **self.scan_stats,
            "hash_scanner_stats": self.hash_scanner.get_statistics(),
            "behavioral_stats": self.behavioral_analyzer.get_statistics(),
            "link_scanner_stats": self.link_scanner.get_statistics(),
            "threat_intel_stats": self.threat_intelligence.get_threat_statistics(),
        }

    async def update_threat_databases(self) -> bool:
        """Update all threat databases."""
        logger.info("Updating threat databases")

        try:
            # Update hash database
            hash_updated = await self.hash_scanner.update_database()

            # Update threat intelligence
            intel_updated = await self.threat_intelligence.update_intelligence_feeds()

            # Update behavioral patterns
            behavioral_updated = await self.behavioral_analyzer.update_patterns({})

            self.scan_stats["last_update"] = datetime.now(timezone.utc).isoformat()

            logger.info(
                f"Database update completed - Hash: {hash_updated}, Intel: {intel_updated}, Behavioral: {behavioral_updated}"
            )
            return bool(hash_updated or intel_updated or behavioral_updated)

        except Exception as e:
            logger.error(f"Failed to update threat databases: {e}")
            return False

    async def _log_scan_result(self, scan_result: ScanResult):
        """Logs a scan result to the database via the SDK."""
        # This provides an example of how the engine could log its own data
        # if it needed to, separate from the sub-scanners.
        log_key = f"scan_log:{scan_result.file_hash}:{int(time.time())}"
        log_data = asdict(scan_result)
        # Ensure enums/datetimes are serializable
        log_data['threat_level'] = log_data['threat_level'].value
        log_data['threat_type'] = log_data['threat_type'].value if log_data['threat_type'] else None
        log_data['scan_type'] = log_data['scan_type'].value
        log_data['detected_at'] = log_data['detected_at'].isoformat()

        await self.api.db_set_value(log_key, log_data)

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-512 hash of file."""
        hash_sha512 = hashlib.sha512()

        async with aiofiles.open(file_path, "rb") as f:
            while chunk := await f.read(8192):
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

        # Find highest threat level
        max_threat_level = max(result.threat_level for result in results)
        highest_threat_result = next(
            result for result in results if result.threat_level == max_threat_level
        )

        # Combine confidence scores
        avg_confidence = sum(result.confidence_score for result in results) / len(
            results
        )

        # Combine details
        combined_details = {}
        for result in results:
            combined_details.update(result.details)

        return ScanResult(
            file_path=highest_threat_result.file_path,
            file_hash=file_hash,
            threat_level=max_threat_level,
            threat_type=highest_threat_result.threat_type,
            threat_name=highest_threat_result.threat_name,
            scan_type=ScanType.FULL_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=avg_confidence,
            details=combined_details,
        )

    async def _handle_threat(self, scan_result: ScanResult):
        """Handle detected threat by logging it. Quarantine is handled by the manager."""
        if scan_result.threat_level.value >= ThreatLevel.MEDIUM_RISK.value:
            self.logger.warning(
                f"Threat detected: {scan_result.threat_name} in {scan_result.file_path} (Level: {scan_result.threat_level.name})"
            )

    async def _update_scan_statistics(self, scan_result: ScanResult):
        """Update scan statistics."""
        self.scan_stats["total_scans"] += 1

        if scan_result.threat_level.value >= ThreatLevel.MEDIUM_RISK.value:
            self.scan_stats["threats_detected"] += 1


    async def _load_scan_statistics(self):
        """Load scan statistics from database via SDK."""
        stats = await self.api.db_get_value("scan_statistics")
        if stats and isinstance(stats, dict):
            self.scan_stats.update(stats)

    async def _background_update_task(self):
        """Background task for updating threat databases."""
        while True:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self.update_threat_databases()
            except Exception as e:
                logger.error(f"Background update task failed: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
