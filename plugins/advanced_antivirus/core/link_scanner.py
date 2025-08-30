from datetime import datetime, timezone
from typing import Any, Dict, Optional, TYPE_CHECKING
from urllib.parse import urlparse
from enum import Enum, IntEnum

# Try to import the plugin SDK API type for static type checking / runtime if available.
# If not available at runtime, fall back to a permissive Any type so the module still works.
if TYPE_CHECKING:
    from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI  # type: ignore
else:
    try:
        from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI  # type: ignore
    except Exception:
        EnhancedPluginAPI = Any  # type: ignore

# Attempt to import ScanResult and related enums from the local package.
# Provide safe fallbacks if the imports are not available to avoid runtime ImportErrors.
try:
    from . import ScanResult, ScanType, ThreatLevel, ThreatType  # type: ignore
except Exception:
    # Fallback implementations that satisfy the usage within this module.
    class ScanType(Enum):
        LINK_SCAN = "link_scan"

    class ThreatLevel(IntEnum):
        CLEAN = 0
        UNKNOWN = 1
        LOW = 2
        MEDIUM = 3
        HIGH = 4
        CRITICAL = 5

    class ThreatType(Enum):
        MALICIOUS_LINK = "malicious_link"
        SUSPICIOUS = "suspicious"
        UNKNOWN = "unknown"

    class ScanResult:
        """
        Lightweight fallback ScanResult used when the real ScanResult class is not importable.
        This mirrors the fields used by this module and provides a to_dict() helper.
        """

        def __init__(
            self,
            file_path: str,
            threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
            threat_type: Optional[ThreatType] = None,
            threat_name: Optional[str] = None,
            scan_type: ScanType = ScanType.LINK_SCAN,
            scan_duration: float = 0.0,
            detected_at: Optional[datetime] = None,
            confidence_score: Optional[float] = None,
            details: Optional[Dict[str, Any]] = None,
        ):
            self.file_path = file_path
            self.threat_level = threat_level
            self.threat_type = threat_type
            self.threat_name = threat_name
            self.scan_type = scan_type
            self.scan_duration = scan_duration
            self.detected_at = detected_at or datetime.now(timezone.utc)
            self.confidence_score = confidence_score
            self.details = details or {}

        def to_dict(self) -> Dict[str, Any]:
            return {
                "file_path": self.file_path,
                "threat_level": int(self.threat_level) if isinstance(self.threat_level, IntEnum) else str(self.threat_level),
                "threat_type": self.threat_type.value if isinstance(self.threat_type, Enum) else self.threat_type,
                "threat_name": self.threat_name,
                "scan_type": self.scan_type.value if isinstance(self.scan_type, Enum) else self.scan_type,
                "scan_duration": self.scan_duration,
                "detected_at": self.detected_at.isoformat() if isinstance(self.detected_at, datetime) else self.detected_at,
                "confidence_score": self.confidence_score,
                "details": self.details,
            }


class LinkSafetyScanner:
    """
    Scans URLs for safety using the Plugin SDK for persistence.
    """

    def __init__(self, api: EnhancedPluginAPI):
        # api may be a PluginAPI instance from the SDK, or any object providing
        # db_get_value / db_set_value and logger attributes when the SDK isn't present.
        self.api = api
        # If the provided API doesn't have a logger, provide a minimal shim to avoid attribute errors.
        self.logger = getattr(api, "logger", type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None, "error": lambda *a, **k: None, "debug": lambda *a, **k: None})())
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
        try:
            self.logger.info("Initializing Link Safety Scanner (SDK-based).")
        except Exception:
            # Logger may be a simple object; ignore failures in logging during init.
            pass
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

        # Normalize domain: strip credentials and ports (e.g., user:pass@host:port -> host)
        if "@" in domain:
            domain = domain.split("@")[-1]
        if ":" in domain:
            domain = domain.split(":")[0]

        # Check domain against our unified database via SDK.
        # Support both async db_get_value (from SDK) and a sync fallback if present.
        db_key = f"domain:{domain}"
        db_result = None
        try:
            db_get = getattr(self.api, "db_get_value", None)
            if callable(db_get):
                # Call it and await if it's a coroutine
                maybe = db_get(db_key)
                if hasattr(maybe, "__await__"):
                    db_result = await maybe
                else:
                    db_result = maybe
            else:
                # No db interface available; treat as not found
                db_result = None
        except Exception as e:
            # Logging the error and continue treating as not found
            try:
                self.logger.debug(f"Error querying DB for {db_key}: {e}")
            except Exception:
                pass
            db_result = None

        if db_result and isinstance(db_result, dict) and db_result.get("status") == "malicious":
            self.scan_stats["db_hits"] += 1
            self.scan_stats["malicious_urls_found"] += 1
            try:
                self.logger.warning(f"Malicious domain detected: {domain}")
            except Exception:
                pass
            return self._create_scan_result(
                url,
                ThreatLevel.CRITICAL,
                start_time,
                threat_name=f"Malicious Domain: {domain}"
            )

        # If not found, assume clean for now
        return self._create_scan_result(url, ThreatLevel.CLEAN, start_time)

    async def report_malicious_domain(self, domain: str, source: str = "community") -> bool:
        """Reports a new malicious domain, storing it via the SDK."""
        try:
            self.logger.info(f"Reporting new malicious domain: {domain}")
        except Exception:
            pass

        db_key = f"domain:{domain}"
        db_value = {
            "status": "malicious",
            "source": source,
            "reported_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            db_set = getattr(self.api, "db_set_value", None)
            if callable(db_set):
                maybe = db_set(db_key, db_value)
                if hasattr(maybe, "__await__"):
                    return bool(await maybe)
                return bool(maybe)
        except Exception as e:
            try:
                self.logger.error(f"Failed to report malicious domain {domain}: {e}")
            except Exception:
                pass
            return False

        # If no db API present, cannot persist; return False
        return False

    def _create_scan_result(
        self,
        url: str,
        threat_level: Optional[ThreatLevel],
        start_time: datetime,
        threat_name: Optional[str] = None,
        error: Optional[str] = None,
    ) -> ScanResult:
        """Creates a ScanResult object."""
        end_time = datetime.now(timezone.utc)
        scan_duration = (end_time - start_time).total_seconds()

        # If there's an error, return an 'unknown' result with error details.
        if error:
            return ScanResult(
                file_path=url,
                threat_level=ThreatLevel.UNKNOWN if 'ThreatLevel' in globals() else None,
                scan_type=ScanType.LINK_SCAN if 'ScanType' in globals() else None,
                scan_duration=scan_duration,
                detected_at=end_time,
                details={"error": error},
            )

        # Treat threat_level as an enum/int that is comparable to CLEAN
        try:
            is_malicious = threat_level is not None and getattr(threat_level, "value", threat_level) > getattr(ThreatLevel.CLEAN, "value", 0)
        except Exception:
            is_malicious = bool(threat_level)

        if is_malicious:
            return ScanResult(
                file_path=url,
                threat_level=threat_level,
                threat_type=ThreatType.MALICIOUS_LINK if 'ThreatType' in globals() else None,
                threat_name=threat_name,
                scan_type=ScanType.LINK_SCAN if 'ScanType' in globals() else None,
                scan_duration=scan_duration,
                detected_at=end_time,
                confidence_score=0.99,
                details={"source": "Internal DB"},
            )
        else:
            return ScanResult(
                file_path=url,
                threat_level=ThreatLevel.CLEAN if 'ThreatLevel' in globals() else None,
                scan_type=ScanType.LINK_SCAN if 'ScanType' in globals() else None,
                scan_duration=scan_duration,
                detected_at=end_time,
                confidence_score=0.9,
                details={"status": "clean"},
            )

    async def get_statistics(self) -> Dict[str, Any]:
        """Gets link scanner statistics."""
        return self.scan_stats
