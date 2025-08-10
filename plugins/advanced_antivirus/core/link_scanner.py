from plugins_internal import EnhancedPluginAPI
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

from . import ScanResult, ScanType, ThreatLevel, ThreatType

class LinkSafetyScanner:
    """
    Scans URLs for safety using the Plugin SDK for persistence.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        self.logger = api.logger
        self.scan_stats = {
            "total_urls_scanned": 0,
            "malicious_urls_found": 0,
            "db_hits": 0,
        }
        self._initialized = False

    async def initialize(self):
        """Initializes the link scanner."""
        if self._initialized:
            return
        self.logger.info("Initializing Link Safety Scanner (SDK-based).")
        self._initialized = True

    async def scan_url(self, url: str) -> ScanResult:
        """Scans a URL for safety against a database of malicious domains."""
        start_time = datetime.now(timezone.utc)
        self.scan_stats["total_urls_scanned"] += 1

        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if not domain:
                return self._create_scan_result(url, None, start_time, error="Invalid URL")
        except Exception as e:
            return self._create_scan_result(url, None, start_time, error=f"URL parsing failed: {e}")

        # Check domain against our unified database via SDK
        db_key = f"domain:{domain}"
        db_result = await self.api.db_get_value(db_key)

        if db_result and db_result.get("status") == "malicious":
            self.scan_stats["db_hits"] += 1
            self.scan_stats["malicious_urls_found"] += 1
            self.logger.warning(f"Malicious domain detected: {domain}")
            return self._create_scan_result(url, ThreatLevel.CRITICAL, start_time, threat_name=f"Malicious Domain: {domain}")

        # If not found, assume clean for now
        return self._create_scan_result(url, ThreatLevel.CLEAN, start_time)

    async def report_malicious_domain(self, domain: str, source: str = "community") -> bool:
        """Reports a new malicious domain, storing it via the SDK."""
        self.logger.info(f"Reporting new malicious domain: {domain}")
        db_key = f"domain:{domain}"
        db_value = {
            "status": "malicious",
            "source": source,
            "reported_at": datetime.now(timezone.utc).isoformat()
        }
        return await self.api.db_set_value(db_key, db_value)

    def _create_scan_result(self, url: str, threat_level: Optional[ThreatLevel], start_time: datetime, threat_name: Optional[str] = None, error: Optional[str] = None) -> ScanResult:
        """Creates a ScanResult object."""
        end_time = datetime.now(timezone.utc)
        scan_duration = (end_time - start_time).total_seconds()

        if error:
            return ScanResult(
                file_path=url, threat_level=ThreatLevel.UNKNOWN, scan_type=ScanType.LINK_SCAN,
                scan_duration=scan_duration, detected_at=end_time, details={"error": error}
            )

        if threat_level and threat_level.value > ThreatLevel.CLEAN.value:
            return ScanResult(
                file_path=url, threat_level=threat_level, threat_type=ThreatType.MALICIOUS_LINK,
                threat_name=threat_name, scan_type=ScanType.LINK_SCAN, scan_duration=scan_duration,
                detected_at=end_time, confidence_score=0.99, details={"source": "Internal DB"}
            )
        else:
            return ScanResult(
                file_path=url, threat_level=ThreatLevel.CLEAN, scan_type=ScanType.LINK_SCAN,
                scan_duration=scan_duration, detected_at=end_time, confidence_score=0.9,
                details={"status": "clean"}
            )

    async def get_statistics(self) -> Dict[str, Any]:
        """Gets link scanner statistics."""
        return self.scan_stats
