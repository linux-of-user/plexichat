from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
import asyncio

# Robust import for the plugin SDK - prefer the package location, fallback to local, and finally a safe shim.
try:
    # Preferred import path for generated SDK inside the package
    from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI, create_plugin_api
    from plexichat.plugins_internal import ScanResult as SDK_ScanResult, ScanType as SDK_ScanType, ThreatLevel as SDK_ThreatLevel
except Exception:
    try:
        # Local import fallback (when running from project root)
        from plugins_internal import PluginAPI as EnhancedPluginAPI, create_plugin_api
        from plugins_internal import ScanResult as SDK_ScanResult, ScanType as SDK_ScanType, ThreatLevel as SDK_ThreatLevel
    except Exception:
        # Last-resort shim to avoid import failures during development/testing.
        # Provides minimal compatibility surface used by this module.
        import logging as _logging

        def _get_fallback_logger():
            logger = _logging.getLogger("comprehensive_antivirus_manager")
            if not logger.handlers:
                handler = _logging.StreamHandler()
                formatter = _logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
                handler.setFormatter(formatter)
                logger.addHandler(handler)
            return logger

        class EnhancedPluginAPI:
            """Fallback minimal plugin API for environments where plugins_internal is not available."""
            def __init__(self):
                self.logger = _get_fallback_logger()

            async def get_config(self, key: str, default: Any = None) -> Any:
                return default

            async def db_set_value(self, key: str, value: Any) -> bool:
                # Simulate failure for writes in fallback scenario.
                self.logger.debug(f"[Fallback API] db_set_value called for key={key}")
                return False

        # Minimal ScanResult / enums used only to keep types stable; real implementations come from SDK.
        class SDK_ThreatLevel:
            CLEAN = 0
            LOW_RISK = 1
            MEDIUM_RISK = 2
            HIGH_RISK = 3
            CRITICAL = 4

        class SDK_ScanType:
            FULL_SCAN = "full"

        class SDK_ScanResult:
            def __init__(self, is_safe: bool = True, threat_level: Any = SDK_ThreatLevel.CLEAN, details: str = "", timestamp: datetime = None):
                self.is_safe = is_safe
                self.threat_level = threat_level
                self.details = details
                self.timestamp = timestamp or datetime.now(timezone.utc)

            def to_dict(self) -> Dict[str, Any]:
                return {
                    "is_safe": self.is_safe,
                    "threat_level": getattr(self.threat_level, "value", self.threat_level),
                    "details": self.details,
                    "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
                }

# Try to import the plugin's advanced antivirus core types (preferred). Fall back to SDK definitions above.
try:
    from plugins.advanced_antivirus.core import ScanResult, ScanType, ThreatLevel
except Exception:
    # Use SDK types if plugin core cannot be imported
    ScanResult = SDK_ScanResult  # type: ignore
    ScanType = SDK_ScanType  # type: ignore
    ThreatLevel = SDK_ThreatLevel  # type: ignore

# Ensure a get_logger helper that uses the core logging system if available.
try:
    from plexichat.core.logging import get_logger
except Exception:
    import logging

    def get_logger(name: str = "comprehensive_antivirus_manager"):
        return logging.getLogger(name)

@dataclass
class ScanRequest:
    file_path: str
    scan_types: List[ScanType]
    priority: int = 1
    requester: str = "system"
    metadata: Dict[str, Any] = None
    callback: Optional[Callable] = None

@dataclass
class QuarantineEntry:
    original_path: str
    quarantine_path: str  # logical path/ID or DB key
    threat_name: str
    threat_level: Any
    quarantine_time: datetime
    file_hash: str
    file_size: int
    scan_results: List[ScanResult]
    auto_delete_after: Optional[datetime] = None

class EnhancedAntivirusManager:
    """
    Enhanced antivirus manager that uses the Plugin SDK for all external interactions,
    including configuration, data storage, and logging.

    This implementation is defensive about the shapes of ScanResult objects it receives:
    it prefers to call `to_dict()` when available, and otherwise attempts to convert
    dataclasses or simple objects to dictionaries. It also tolerates enums or raw values
    for threat levels and scan types.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        # If the API provides a logger, use it; otherwise request core logger
        self.logger = getattr(api, "logger", get_logger("comprehensive_antivirus_manager"))
        # Lazy import of the engine; keep as attribute to allow testing without engine present
        try:
            from plugins.advanced_antivirus.core.antivirus_engine import AdvancedAntivirusEngine
            self.antivirus_engine = AdvancedAntivirusEngine(api=self.api)
        except Exception:
            # Provide a minimal stub engine so functions can still be called in degraded mode.
            class _StubEngine:
                def __init__(self, api=None):
                    self.api = api

                async def initialize(self):
                    return

                async def scan_file(self, file_path, scan_types):
                    # Return an empty clean scan result
                    return [ScanResult(is_safe=True, threat_level=getattr(ThreatLevel, "CLEAN", 0), details="stub")]

                async def _calculate_file_hash(self, file_path):
                    return None

            self.antivirus_engine = _StubEngine(api=self.api)

        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.active_scans: Dict[str, ScanRequest] = {}
        self.scan_workers: List[asyncio.Task] = []
        self._initialized = False
        self._running = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        self.logger.info("Initializing Enhanced Antivirus Manager...")
        try:
            await self.antivirus_engine.initialize()
        except Exception as e:
            self.logger.error(f"Antivirus engine failed to initialize: {e}", exc_info=True)
            raise

        await self._start_scan_workers()
        self._initialized = True
        self._running = True
        self.logger.info("Enhanced Antivirus Manager initialized successfully.")

    async def shutdown(self) -> None:
        if not self._running:
            return
        self.logger.info("Shutting down Enhanced Antivirus Manager...")
        self._running = False
        for worker in self.scan_workers:
            worker.cancel()
        # Additional cleanup if needed

    async def scan_file(self, file_path: str, scan_types: Optional[List[ScanType]] = None) -> List[ScanResult]:
        # Simplified scan for now, directly calling the engine
        results = await self.antivirus_engine.scan_file(file_path, scan_types or [getattr(ScanType, "FULL_SCAN", ScanType)])
        # Normalize threat level comparison using helper
        if any(self._threat_level_value(r) >= self._threat_level_value(getattr(ThreatLevel, "MEDIUM_RISK", 2)) for r in results):
            await self.quarantine_file(file_path, results)
        return results

    async def quarantine_file(self, file_path: str, scan_results: List[ScanResult]) -> bool:
        """Quarantines a file by storing its info in the database via the SDK."""
        try:
            # Attempt to calculate file hash via engine wrapper if available
            file_hash = None
            try:
                # Some engines expose a protected method; attempt to call it when present
                calc = getattr(self.antivirus_engine, "_calculate_file_hash", None)
                if callable(calc):
                    file_hash = await calc(file_path)
            except Exception:
                file_hash = None

            if not file_hash:
                self.logger.warning(f"Could not calculate file hash for {file_path}; aborting quarantine entry creation.")
                return False

            # Determine maximum threat level among results
            max_threat_obj = max((self._threat_level_obj_from_result(r) for r in scan_results), key=lambda x: self._threat_level_value(x), default=getattr(ThreatLevel, "CLEAN", 0))
            # Determine threat name from available fields
            threat_names = []
            for r in scan_results:
                # Best-effort extraction of a threat name from known keys
                name = None
                if hasattr(r, "threat_name"):
                    name = getattr(r, "threat_name")
                elif hasattr(r, "virus_name"):
                    name = getattr(r, "virus_name")
                else:
                    # If result can be dictified, look inside
                    try:
                        d = r.to_dict() if hasattr(r, "to_dict") else asdict(r) if hasattr(r, "__dataclass_fields__") else dict(r)
                        for k in ("threat_name", "virus_name", "name"):
                            if k in d and d[k]:
                                name = d[k]
                                break
                    except Exception:
                        name = None
                if name:
                    threat_names.append(name)
            threat_name = threat_names[0] if threat_names else "Unknown Threat"

            # The "quarantine path" is now just a key in the DB.
            quarantine_key = f"quarantine:{file_hash}"

            entry = QuarantineEntry(
                original_path=str(file_path),
                quarantine_path=quarantine_key,
                threat_name=threat_name,
                threat_level=max_threat_obj,
                quarantine_time=datetime.now(timezone.utc),
                file_hash=file_hash,
                file_size=0,  # Stat size would be needed here if available
                scan_results=scan_results,
                auto_delete_after=datetime.now(timezone.utc) + timedelta(days=30)
            )

            # Use asdict for dataclasses, otherwise attempt to call to_dict on results.
            entry_dict = asdict(entry)

            # Normalize the threat level
            entry_dict['threat_level'] = self._threat_level_value(entry.threat_level)

            # Serialize datetimes
            entry_dict['quarantine_time'] = entry.quarantine_time.isoformat()
            if entry.auto_delete_after:
                entry_dict['auto_delete_after'] = entry.auto_delete_after.isoformat()

            # Normalize scan_results into serializable dicts
            serialized_results = []
            for r in entry.scan_results:
                try:
                    if hasattr(r, "to_dict"):
                        rd = r.to_dict()
                    elif hasattr(r, "__dataclass_fields__"):
                        rd = asdict(r)
                    else:
                        rd = dict(r)
                except Exception:
                    # Last resort: create a simple representation
                    rd = {"details": getattr(r, "details", str(r))}

                # Normalize common fields
                # threat_level
                rd_threat = rd.get("threat_level", getattr(r, "threat_level", None))
                rd["threat_level"] = self._threat_level_value(rd_threat)

                # threat_type (optional)
                if "threat_type" in rd:
                    tt = rd.get("threat_type")
                    rd["threat_type"] = getattr(tt, "value", tt) if tt is not None else None

                # scan_type (optional)
                if "scan_type" in rd:
                    st = rd.get("scan_type")
                    rd["scan_type"] = getattr(st, "value", st) if st is not None else st

                # detected_at / timestamp normalization
                detected = rd.get("detected_at") or rd.get("timestamp") or getattr(r, "timestamp", None)
                if isinstance(detected, datetime):
                    rd["detected_at"] = detected.isoformat()
                elif detected is None:
                    rd["detected_at"] = datetime.now(timezone.utc).isoformat()
                else:
                    rd["detected_at"] = str(detected)

                serialized_results.append(rd)

            entry_dict['scan_results'] = serialized_results

            # Persist via plugin API
            success = await self.api.db_set_value(quarantine_key, entry_dict)

            if success:
                self.logger.warning(f"File quarantined (logged): {file_path}")
            else:
                self.logger.error(f"Failed to persist quarantine entry for {file_path}")

            return success
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}", exc_info=True)
            return False

    async def _start_scan_workers(self) -> None:
        num_workers = await self.api.get_config("scan_workers", 3)
        try:
            num_workers = int(num_workers)
        except Exception:
            num_workers = 3
        for i in range(num_workers):
            worker = asyncio.create_task(self._scan_worker(f"worker-{i}"))
            self.scan_workers.append(worker)
        self.logger.info(f"Started {num_workers} scan workers.")

    async def _scan_worker(self, worker_name: str) -> None:
        while self._running:
            try:
                scan_request: ScanRequest = await self.scan_queue.get()
                self.active_scans[scan_request.file_path] = scan_request
                try:
                    await self.scan_file(scan_request.file_path, scan_request.scan_types)
                finally:
                    self.active_scans.pop(scan_request.file_path, None)
                    self.scan_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in scan worker {worker_name}: {e}", exc_info=True)
                await asyncio.sleep(1)
        self.logger.info(f"Scan worker {worker_name} stopped.")

    def _threat_level_value(self, result_or_level: Any) -> int:
        """
        Normalize a threat level or a ScanResult to an integer value for comparison.
        Supports enums with `.value`, direct integers, strings matching enum names,
        or ScanResult objects exposing a `threat_level` attribute.
        """
        # If passed a ScanResult object, extract its threat level
        if hasattr(result_or_level, "threat_level") and not isinstance(result_or_level, (int, str)):
            val = getattr(result_or_level, "threat_level")
            return self._threat_level_value(val)

        val = result_or_level
        # Enum-like objects with value
        if hasattr(val, "value"):
            try:
                return int(val.value)
            except Exception:
                try:
                    return int(getattr(val, "value", 0))
                except Exception:
                    return 0
        # Direct integer
        if isinstance(val, int):
            return val
        # String mapping to enum name
        if isinstance(val, str):
            try:
                enum_val = getattr(ThreatLevel, val.upper())
                return self._threat_level_value(enum_val)
            except Exception:
                # Attempt to parse numeric string
                try:
                    return int(val)
                except Exception:
                    return 0
        return 0

    def _threat_level_obj_from_result(self, r: Any) -> Any:
        """
        Return a canonical threat-level-like object (preferably an enum or numeric)
        extracted from a ScanResult or provided directly.
        """
        if hasattr(r, "threat_level"):
            return getattr(r, "threat_level")
        try:
            d = r.to_dict() if hasattr(r, "to_dict") else asdict(r) if hasattr(r, "__dataclass_fields__") else dict(r)
            return d.get("threat_level", getattr(ThreatLevel, "CLEAN", 0))
        except Exception:
            return getattr(ThreatLevel, "CLEAN", 0)
