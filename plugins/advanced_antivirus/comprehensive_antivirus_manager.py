from plugins_internal import EnhancedPluginAPI
from plugins.advanced_antivirus.core import ScanResult, ScanType, ThreatLevel
from plugins.advanced_antivirus.core.antivirus_engine import AdvancedAntivirusEngine
import asyncio
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict

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
    quarantine_path: str # This will now be a logical path/ID
    threat_name: str
    threat_level: ThreatLevel
    quarantine_time: datetime
    file_hash: str
    file_size: int
    scan_results: List[ScanResult]
    auto_delete_after: Optional[datetime] = None

class EnhancedAntivirusManager:
    """
    Enhanced antivirus manager that uses the Plugin SDK for all external interactions,
    including configuration, data storage, and logging.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        self.logger = api.logger
        self.antivirus_engine = AdvancedAntivirusEngine(api=self.api)
        self.scan_queue: asyncio.Queue = asyncio.Queue()
        self.active_scans: Dict[str, ScanRequest] = {}
        self.scan_workers: List[asyncio.Task] = []
        self._initialized = False
        self._running = False

    async def initialize(self) -> None:
        if self._initialized:
            return
        self.logger.info("Initializing Enhanced Antivirus Manager...")
        await self.antivirus_engine.initialize()
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
        # Any other cleanup...

    async def scan_file(self, file_path: str, scan_types: Optional[List[ScanType]] = None) -> List[ScanResult]:
        # Simplified scan for now, directly calling the engine
        results = await self.antivirus_engine.scan_file(file_path, scan_types or [ScanType.FULL_SCAN])
        if any(r.threat_level.value >= ThreatLevel.MEDIUM_RISK.value for r in results):
            await self.quarantine_file(file_path, results)
        return results

    async def quarantine_file(self, file_path: str, scan_results: List[ScanResult]) -> bool:
        """Quarantines a file by storing its info in the database via the SDK."""
        try:
            file_hash = await self.antivirus_engine._calculate_file_hash(file_path)
            if not file_hash:
                return False

            max_threat_level = max((r.threat_level for r in scan_results), default=ThreatLevel.CLEAN)
            threat_names = [r.threat_name for r in scan_results if r.threat_name]
            threat_name = threat_names[0] if threat_names else "Unknown Threat"

            # The "quarantine path" is now just a key in the DB.
            # The file content would need to be stored if we want to restore it.
            # For now, we'll just log the quarantine event.
            quarantine_key = f"quarantine:{file_hash}"

            entry = QuarantineEntry(
                original_path=str(file_path),
                quarantine_path=quarantine_key,
                threat_name=threat_name,
                threat_level=max_threat_level,
                quarantine_time=datetime.now(timezone.utc),
                file_hash=file_hash,
                file_size=0, # Stat size would be needed here
                scan_results=scan_results,
                auto_delete_after=datetime.now(timezone.utc) + timedelta(days=30)
            )

            # Use asdict to convert dataclasses to dicts for JSON serialization
            entry_dict = asdict(entry)

            # Convert enums and datetimes to serializable types
            entry_dict['threat_level'] = entry.threat_level.value
            entry_dict['quarantine_time'] = entry.quarantine_time.isoformat()
            if entry.auto_delete_after:
                entry_dict['auto_delete_after'] = entry.auto_delete_after.isoformat()
            entry_dict['scan_results'] = [asdict(r) for r in entry.scan_results]
            for r in entry_dict['scan_results']:
                r['threat_level'] = r['threat_level'].value
                r['threat_type'] = r['threat_type'].value if r['threat_type'] else None
                r['scan_type'] = r['scan_type'].value
                r['detected_at'] = r['detected_at'].isoformat()

            success = await self.api.db_set_value(quarantine_key, entry_dict)

            if success:
                self.logger.warning(f"File quarantined (logged): {file_path}")
            return success
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {e}", exc_info=True)
            return False

    async def _start_scan_workers(self) -> None:
        num_workers = await self.api.get_config("scan_workers", 3)
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
