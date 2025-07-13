from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from plexichat.antivirus.core import ScanType
from plexichat.antivirus.enhanced_antivirus_manager import EnhancedAntivirusManager
from plexichat.app.logger_config import logger

"""
Enhanced Antivirus API Endpoints
REST API for managing the enhanced antivirus system.
"""

# Initialize router
router = APIRouter(prefix="/antivirus", tags=["Enhanced Antivirus"])

# Global antivirus manager instance
antivirus_manager: Optional[EnhancedAntivirusManager] = None

# Pydantic models
class ScanRequest(BaseModel):
    file_path: str = Field(..., description="Path to file to scan")
    scan_types: List[str] = Field(default=["hash", "behavioral", "filename", "threat_intelligence"], 
                                 description="Types of scans to perform")
    priority: int = Field(default=1, ge=1, le=4, description="Scan priority (1-4)")
    requester: str = Field(default="api", description="Who requested the scan")

class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan for safety")

class QuarantineAction(BaseModel):
    file_hash: str = Field(..., description="Hash of quarantined file")
    action: str = Field(..., description="Action to perform: restore, delete")
    restore_path: Optional[str] = Field(None, description="Path to restore file to (optional)")

class ScanResult(BaseModel):
    file_path: str
    file_hash: str
    threat_level: str
    threat_type: Optional[str]
    threat_name: Optional[str]
    scan_type: str
    scan_duration: float
    detected_at: str
    confidence_score: float
    details: Dict[str, Any]

class AntivirusStatus(BaseModel):
    enabled: bool
    initialized: bool
    running: bool
    version: str = "2.0.0"
    last_update: Optional[str]

class ScanStatistics(BaseModel):
    total_scans: int
    threats_detected: int
    files_quarantined: int
    clean_files: int
    scan_errors: int
    last_scan_time: Optional[str]
    average_scan_time: float
    plugin_scans: int
    real_time_scans: int
    quarantine_count: int
    active_scans: int
    queue_size: int
    monitored_directories: int

class QuarantineEntry(BaseModel):
    file_hash: str
    original_path: str
    threat_name: str
    threat_level: str
    quarantine_time: str
    file_size: int
    auto_delete_after: Optional[str]

# Dependency to get antivirus manager
async def get_antivirus_manager() -> EnhancedAntivirusManager:
    """Get the antivirus manager instance."""
    global antivirus_manager
    if not antivirus_manager:
        antivirus_manager = EnhancedAntivirusManager()
        await antivirus_manager.initialize()
    return antivirus_manager

# Authentication dependency (placeholder)
async def verify_admin_access():
    """Verify admin access for antivirus operations."""
    # TODO: Implement proper authentication
    return True

@router.get("/status", response_model=AntivirusStatus)
async def get_antivirus_status(
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager)
):
    """Get antivirus system status."""
    try:
        return AntivirusStatus(
            enabled=manager.config["enabled"],
            initialized=manager._initialized,
            running=manager._running,
            last_update=manager.stats.get("last_scan_time")
        )
    except Exception as e:
        logger.error(f"Failed to get antivirus status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/statistics", response_model=ScanStatistics)
async def get_scan_statistics(
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager)
):
    """Get comprehensive scan statistics."""
    try:
        stats = await manager.get_scan_statistics()
        return ScanStatistics(**stats)
    except Exception as e:
        logger.error(f"Failed to get scan statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/file", response_model=List[ScanResult])
async def scan_file(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Scan a file for threats."""
    try:
        # Validate file exists
        if not from pathlib import Path
Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        # Convert scan type strings to enums
        scan_types = []
        type_mapping = {
            "hash": ScanType.HASH_SCAN,
            "behavioral": ScanType.BEHAVIORAL_SCAN,
            "filename": ScanType.FILENAME_ANALYSIS,
            "threat_intelligence": ScanType.THREAT_INTELLIGENCE
        }
        
        for scan_type_str in request.scan_types:
            if scan_type_str in type_mapping:
                scan_types.append(type_mapping[scan_type_str])
        
        if not scan_types:
            raise HTTPException(status_code=400, detail="No valid scan types specified")
        
        # Perform scan
        results = await manager.scan_file(
            request.file_path,
            scan_types,
            request.priority,
            request.requester
        )
        
        # Convert results to response format
        response_results = []
        for result in results:
            response_results.append(ScanResult(
                file_path=result.file_path,
                file_hash=result.file_hash,
                threat_level=result.threat_level.value,
                threat_type=result.threat_type.value if result.threat_type else None,
                threat_name=result.threat_name,
                scan_type=result.scan_type.value,
                scan_duration=result.scan_duration,
                detected_at=result.detected_at.isoformat(),
                confidence_score=result.confidence_score,
                details=result.details
            ))
        
        return response_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/upload", response_model=List[ScanResult])
async def scan_uploaded_file(
    file: UploadFile = File(...),
    scan_types: str = "hash,behavioral,filename,threat_intelligence",
    priority: int = 2,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Scan an uploaded file for threats."""
    try:
        # Save uploaded file temporarily
        temp_dir = from pathlib import Path
Path("temp/antivirus_scans")
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        temp_file_path = temp_dir / f"upload_{from datetime import datetime
datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        
        with open(temp_file_path, "wb") as temp_file:
            content = await file.read()
            temp_file.write(content)
        
        try:
            # Create scan request
            scan_request = ScanRequest(
                file_path=str(temp_file_path),
                scan_types=scan_types.split(","),
                priority=priority,
                requester="upload_api"
            )
            
            # Perform scan
            results = await scan_file(scan_request, None, manager, True)
            
            return results
            
        finally:
            # Clean up temporary file
            if temp_file_path.exists():
                temp_file_path.unlink()
        
    except Exception as e:
        logger.error(f"Upload scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/plugin", response_model=List[ScanResult])
async def scan_plugin(
    request: ScanRequest,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Scan a plugin file with comprehensive security checks."""
    try:
        # Validate file exists
        if not from pathlib import Path
Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail="Plugin file not found")
        
        # Perform plugin scan
        results = await manager.scan_plugin(request.file_path)
        
        # Convert results to response format
        response_results = []
        for result in results:
            response_results.append(ScanResult(
                file_path=result.file_path,
                file_hash=result.file_hash,
                threat_level=result.threat_level.value,
                threat_type=result.threat_type.value if result.threat_type else None,
                threat_name=result.threat_name,
                scan_type=result.scan_type.value,
                scan_duration=result.scan_duration,
                detected_at=result.detected_at.isoformat(),
                confidence_score=result.confidence_score,
                details=result.details
            ))
        
        return response_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/url", response_model=ScanResult)
async def scan_url(
    request: URLScanRequest,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Scan a URL for safety."""
    try:
        result = await manager.scan_url(request.url)
        
        return ScanResult(
            file_path=request.url,
            file_hash="",
            threat_level=result.threat_level.value,
            threat_type=result.threat_type.value if result.threat_type else None,
            threat_name=result.threat_name,
            scan_type=result.scan_type.value,
            scan_duration=result.scan_duration,
            detected_at=result.detected_at.isoformat(),
            confidence_score=result.confidence_score,
            details=result.details
        )
        
    except Exception as e:
        logger.error(f"URL scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/quarantine", response_model=List[QuarantineEntry])
async def get_quarantine_list(
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Get list of all quarantined files."""
    try:
        quarantine_list = await manager.get_quarantine_list()
        
        return [
            QuarantineEntry(
                file_hash=entry["file_hash"],
                original_path=entry["original_path"],
                threat_name=entry["threat_name"],
                threat_level=entry["threat_level"],
                quarantine_time=entry["quarantine_time"],
                file_size=entry["file_size"],
                auto_delete_after=entry["auto_delete_after"]
            )
            for entry in quarantine_list
        ]
        
    except Exception as e:
        logger.error(f"Failed to get quarantine list: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/quarantine/action")
async def quarantine_action(
    request: QuarantineAction,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Perform action on quarantined file (restore or delete)."""
    try:
        if request.action == "restore":
            success = await manager.restore_from_quarantine(request.file_hash, request.restore_path)
            if success:
                return {"message": "File restored from quarantine successfully"}
            else:
                raise HTTPException(status_code=400, detail="Failed to restore file from quarantine")
        
        elif request.action == "delete":
            success = await manager.delete_quarantined_file(request.file_hash)
            if success:
                return {"message": "Quarantined file deleted successfully"}
            else:
                raise HTTPException(status_code=400, detail="Failed to delete quarantined file")
        
        else:
            raise HTTPException(status_code=400, detail="Invalid action. Use 'restore' or 'delete'")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Quarantine action failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update-database")
async def update_threat_database(
    background_tasks: BackgroundTasks,
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Update threat intelligence database."""
    try:
        # Run update in background
        background_tasks.add_task(manager.update_threat_database)
        return {"message": "Threat database update started"}
        
    except Exception as e:
        logger.error(f"Failed to start database update: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/enable")
async def enable_antivirus(
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Enable antivirus system."""
    try:
        manager.config["enabled"] = True
        await manager._save_config()
        return {"message": "Antivirus system enabled"}
        
    except Exception as e:
        logger.error(f"Failed to enable antivirus: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/disable")
async def disable_antivirus(
    manager: EnhancedAntivirusManager = Depends(get_antivirus_manager),
    _: bool = Depends(verify_admin_access)
):
    """Disable antivirus system."""
    try:
        manager.config["enabled"] = False
        await manager._save_config()
        return {"message": "Antivirus system disabled"}
        
    except Exception as e:
        logger.error(f"Failed to disable antivirus: {e}")
        raise HTTPException(status_code=500, detail=str(e))
