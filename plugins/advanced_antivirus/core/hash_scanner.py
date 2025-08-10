from plugins_internal import EnhancedPluginAPI
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dataclasses import asdict

from . import ScanResult, ScanType, ThreatLevel, ThreatSignature, ThreatType

class HashBasedScanner:
    """
    Hash-based virus scanner that uses the PlexiChat Plugin SDK for all data persistence,
    removing the need for a local database file.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        self.logger = api.logger
        self.public_apis = {
            "virustotal": {
                "url": "https://www.virustotal.com/vtapi/v2/file/report",
                "api_key": "your_virustotal_api_key",
                "enabled": False,
            }
        }
        self.scan_stats = {
            "total_hash_scans": 0,
            "threats_found": 0,
            "api_queries": 0,
            "db_hits": 0,
        }
        self._initialized = False

    async def initialize(self):
        """Initializes the scanner by loading configuration from the SDK."""
        if self._initialized:
            return
        self.logger.info("Initializing Hash-Based Scanner (SDK-based).")
        self.public_apis["virustotal"]["enabled"] = await self.api.get_config("virustotal_enabled", False)
        self._initialized = True
        self.logger.info("Hash-Based Scanner initialized.")

    async def scan_hash(self, file_hash: str, file_path: str) -> ScanResult:
        """Scans a file hash for threats using the SDK's key-value store."""
        start_time = datetime.now(timezone.utc)
        self.scan_stats["total_hash_scans"] += 1

        # 1. Check unified database via SDK
        db_key = f"hash:{file_hash}"
        db_result = await self.api.db_get_value(db_key)

        if db_result and isinstance(db_result, dict):
            self.scan_stats["db_hits"] += 1
            signature_data = db_result.get("signature")
            if signature_data:
                # Re-create a ThreatSignature object from the stored dict
                signature = self._dict_to_signature(signature_data)
                self.logger.info(f"Threat found in DB for hash {file_hash[:16]}...")
                return self._create_scan_result(file_path, file_hash, signature, start_time)
            elif db_result.get("status") == "clean":
                self.logger.debug(f"Clean hash found in DB for {file_hash[:16]}...")
                return self._create_scan_result(file_path, file_hash, None, start_time)

        # 2. If not in DB, mark as clean for now and store it.
        # In a real scenario, this is where you might check external APIs before marking.
        await self.api.db_set_value(db_key, {"status": "clean", "checked_at": datetime.now(timezone.utc).isoformat()})
        return self._create_scan_result(file_path, file_hash, None, start_time)

    async def report_threat(self, file_hash: str, threat_name: str, threat_type: ThreatType, confidence: float = 0.8) -> bool:
        """Reports a new threat, storing it in the unified database via the SDK."""
        self.logger.info(f"Reporting new threat '{threat_name}' for hash {file_hash[:16]}...")
        signature = ThreatSignature(
            signature_id=f"community_{file_hash[:16]}",
            signature_type="hash",
            threat_name=threat_name,
            threat_type=threat_type,
            threat_level=ThreatLevel.MEDIUM_RISK,
            hash_sha512=file_hash,
            description=f"Community reported threat: {threat_name}",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

        # Convert to dict for JSON serialization, handling enums and datetimes
        signature_dict = self._signature_to_dict(signature)
        return await self.api.db_set_value(f"hash:{file_hash}", {"signature": signature_dict})

    def _signature_to_dict(self, signature: ThreatSignature) -> dict:
        """Converts a ThreatSignature object to a JSON-serializable dictionary."""
        sig_dict = asdict(signature)
        for key, value in sig_dict.items():
            if isinstance(value, Enum):
                sig_dict[key] = value.value
            elif isinstance(value, datetime):
                sig_dict[key] = value.isoformat()
        return sig_dict

    def _dict_to_signature(self, data: dict) -> ThreatSignature:
        """Converts a dictionary back to a ThreatSignature object."""
        data['threat_type'] = ThreatType(data['threat_type'])
        data['threat_level'] = ThreatLevel(data['threat_level'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        # Remove fields that are not in the dataclass definition
        valid_fields = {f.name for f in ThreatSignature.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return ThreatSignature(**filtered_data)

    def _create_scan_result(self, file_path: str, file_hash: str, signature: Optional[ThreatSignature], start_time: datetime) -> ScanResult:
        """Creates a ScanResult object from a signature."""
        end_time = datetime.now(timezone.utc)
        scan_duration = (end_time - start_time).total_seconds()

        if signature:
            self.scan_stats["threats_found"] += 1
            return ScanResult(
                file_path=file_path, file_hash=file_hash, threat_level=signature.threat_level,
                threat_type=signature.threat_type, threat_name=signature.threat_name,
                scan_type=ScanType.HASH_SCAN, scan_duration=scan_duration, detected_at=end_time,
                confidence_score=0.95, details={"signature_id": signature.signature_id, "source": "Internal DB"}
            )
        else:
            return ScanResult(
                file_path=file_path, file_hash=file_hash, threat_level=ThreatLevel.CLEAN,
                threat_type=None, threat_name=None, scan_type=ScanType.HASH_SCAN,
                scan_duration=scan_duration, detected_at=end_time, confidence_score=0.9,
                details={"status": "clean", "source": "Internal DB"}
            )

    async def get_statistics(self) -> Dict[str, Any]:
        """Gets hash scanner statistics."""
        # In a real implementation, we might pull some of these stats from the DB.
        return self.scan_stats
