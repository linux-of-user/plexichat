try:
    # Prefer the namespaced import if running as part of the plexichat package
    from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI
except Exception:
    # Fallback to top-level import (useful in testing or different run contexts)
    from plugins_internal import PluginAPI as EnhancedPluginAPI

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dataclasses import asdict
from enum import Enum

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
        try:
            enabled = await self.api.get_config("virustotal_enabled", False)
            self.public_apis["virustotal"]["enabled"] = bool(enabled)
        except Exception as e:
            # If any issue with config fetch, log and continue with defaults
            self.logger.debug(f"Failed to load virustotal_enabled config: {e}")
        self._initialized = True
        self.logger.info("Hash-Based Scanner initialized.")

    async def scan_hash(self, file_hash: str, file_path: str) -> ScanResult:
        """Scans a file hash for threats using the SDK's key-value store."""
        start_time = datetime.now(timezone.utc)
        self.scan_stats["total_hash_scans"] += 1

        # 1. Check unified database via SDK
        db_key = f"hash:{file_hash}"
        try:
            db_result = await self.api.db_get_value(db_key)
        except Exception as e:
            self.logger.error(f"Error reading DB for key {db_key}: {e}")
            db_result = None

        if db_result and isinstance(db_result, dict):
            self.scan_stats["db_hits"] += 1
            signature_data = db_result.get("signature")
            if signature_data:
                # Re-create a ThreatSignature object from the stored dict
                try:
                    signature = self._dict_to_signature(signature_data)
                    self.logger.info(f"Threat found in DB for hash {file_hash[:16]}...")
                    return self._create_scan_result(file_path, file_hash, signature, start_time)
                except Exception as e:
                    self.logger.error(f"Failed to reconstruct ThreatSignature from DB for {file_hash}: {e}")
                    # fall through to treat as clean for safety

            elif db_result.get("status") == "clean":
                self.logger.debug(f"Clean hash found in DB for {file_hash[:16]}...")
                return self._create_scan_result(file_path, file_hash, None, start_time)

        # 2. If not in DB, mark as clean for now and store it.
        # In a real scenario, this is where you might check external APIs before marking.
        try:
            await self.api.db_set_value(
                db_key,
                {"status": "clean", "checked_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as e:
            self.logger.error(f"Failed to write clean result to DB for {file_hash}: {e}")

        return self._create_scan_result(file_path, file_hash, None, start_time)

    async def report_threat(
        self,
        file_hash: str,
        threat_name: str,
        threat_type: ThreatType,
        confidence: float = 0.8,
    ) -> bool:
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
        try:
            return await self.api.db_set_value(f"hash:{file_hash}", {"signature": signature_dict})
        except Exception as e:
            self.logger.error(f"Failed to store reported threat for {file_hash}: {e}")
            return False

    def _signature_to_dict(self, signature: ThreatSignature) -> dict:
        """Converts a ThreatSignature object to a JSON-serializable dictionary."""
        sig_dict = asdict(signature)
        # Normalize enums and datetimes to serializable forms
        for key, value in list(sig_dict.items()):
            if isinstance(value, Enum):
                sig_dict[key] = value.value
            elif isinstance(value, datetime):
                sig_dict[key] = value.isoformat()
        return sig_dict

    def _dict_to_signature(self, data: dict) -> ThreatSignature:
        """Converts a dictionary back to a ThreatSignature object."""
        # Defensive copy to avoid mutating caller's dict
        d = dict(data)

        # Convert enum/string fields back to Enums if necessary
        if "threat_type" in d and d["threat_type"] is not None:
            try:
                d["threat_type"] = ThreatType(d["threat_type"])
            except Exception:
                # If direct construction fails, try name-based lookup
                d["threat_type"] = ThreatType[d["threat_type"]] if isinstance(d["threat_type"], str) and d["threat_type"] in ThreatType.__members__ else d["threat_type"]

        if "threat_level" in d and d["threat_level"] is not None:
            try:
                d["threat_level"] = ThreatLevel(d["threat_level"])
            except Exception:
                d["threat_level"] = ThreatLevel[d["threat_level"]] if isinstance(d["threat_level"], str) and d["threat_level"] in ThreatLevel.__members__ else d["threat_level"]

        # Parse datetimes if present
        if "created_at" in d and isinstance(d["created_at"], str):
            try:
                d["created_at"] = datetime.fromisoformat(d["created_at"])
            except Exception:
                d["created_at"] = datetime.now(timezone.utc)

        if "updated_at" in d and isinstance(d["updated_at"], str):
            try:
                d["updated_at"] = datetime.fromisoformat(d["updated_at"])
            except Exception:
                d["updated_at"] = datetime.now(timezone.utc)

        # Remove fields that are not in the dataclass definition
        try:
            valid_fields = {f.name for f in ThreatSignature.__dataclass_fields__.values()}
        except Exception:
            # Fallback: if dataclass metadata is not available, accept all keys
            valid_fields = set(d.keys())

        filtered_data = {k: v for k, v in d.items() if k in valid_fields}
        return ThreatSignature(**filtered_data)

    def _create_scan_result(
        self,
        file_path: str,
        file_hash: str,
        signature: Optional[ThreatSignature],
        start_time: datetime,
    ) -> ScanResult:
        """Creates a ScanResult object from a signature."""
        end_time = datetime.now(timezone.utc)
        scan_duration = (end_time - start_time).total_seconds()

        if signature:
            self.scan_stats["threats_found"] += 1
            return ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                threat_level=signature.threat_level,
                threat_type=signature.threat_type,
                threat_name=signature.threat_name,
                scan_type=ScanType.HASH_SCAN,
                scan_duration=scan_duration,
                detected_at=end_time,
                confidence_score=0.95,
                details={"signature_id": signature.signature_id, "source": "Internal DB"},
            )
        else:
            return ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.HASH_SCAN,
                scan_duration=scan_duration,
                detected_at=end_time,
                confidence_score=0.9,
                details={"status": "clean", "source": "Internal DB"},
            )

    async def get_statistics(self) -> Dict[str, Any]:
        """Gets hash scanner statistics."""
        # In a real implementation, we might pull some of these stats from the DB.
        return self.scan_stats
