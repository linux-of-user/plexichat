"""
Enhanced Antivirus Dashboard
Web interface for managing the enhanced antivirus system.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from netlink.antivirus.enhanced_antivirus_manager import EnhancedAntivirusManager
from netlink.antivirus.core import ScanType, ThreatLevel
from netlink.app.logger_config import logger

# Initialize router and templates
router = APIRouter(prefix="/ui/antivirus", tags=["Antivirus Dashboard"])
templates = Jinja2Templates(directory="src/netlink/app/webui/templates")

# Global antivirus manager instance
antivirus_manager: Optional[EnhancedAntivirusManager] = None

async def get_antivirus_manager() -> EnhancedAntivirusManager:
    """Get the antivirus manager instance."""
    global antivirus_manager
    if not antivirus_manager:
        antivirus_manager = EnhancedAntivirusManager()
        await antivirus_manager.initialize()
    return antivirus_manager

@router.get("/", response_class=HTMLResponse)
async def antivirus_dashboard(request: Request):
    """Main antivirus dashboard."""
    try:
        manager = await get_antivirus_manager()
        stats = await manager.get_scan_statistics()
        quarantine_list = await manager.get_quarantine_list()
        
        # Prepare dashboard data
        dashboard_data = {
            "status": {
                "enabled": manager.config["enabled"],
                "running": manager._running,
                "initialized": manager._initialized,
                "real_time_scanning": manager.config["real_time_scanning"]
            },
            "stats": stats,
            "quarantine_count": len(quarantine_list),
            "recent_quarantine": quarantine_list[:5] if quarantine_list else [],
            "components": {
                "Hash Scanning": manager.config["hash_scanning"],
                "Behavioral Analysis": manager.config["behavioral_analysis"],
                "Filename Analysis": manager.config["filename_analysis"],
                "Threat Intelligence": manager.config["threat_intelligence"],
                "Link Scanning": manager.config["link_scanning"],
                "Plugin Scanning": manager.config["plugin_scanning"]
            }
        }
        
        return templates.TemplateResponse("antivirus_dashboard.html", {
            "request": request,
            "data": dashboard_data,
            "page_title": "Enhanced Antivirus Dashboard"
        })
        
    except Exception as e:
        logger.error(f"Antivirus dashboard error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Antivirus Dashboard Error"
        })

@router.get("/scan", response_class=HTMLResponse)
async def scan_interface(request: Request):
    """File scanning interface."""
    return templates.TemplateResponse("antivirus_scan.html", {
        "request": request,
        "page_title": "File Scanner",
        "scan_types": [
            {"id": "hash", "name": "Hash Scanning", "description": "Check file hashes against threat databases"},
            {"id": "behavioral", "name": "Behavioral Analysis", "description": "Analyze file behavior and structure"},
            {"id": "filename", "name": "Filename Analysis", "description": "Check filename for suspicious patterns"},
            {"id": "threat_intelligence", "name": "Threat Intelligence", "description": "Check against threat intelligence feeds"}
        ]
    })

@router.post("/scan/file")
async def scan_file_upload(
    request: Request,
    file: UploadFile = File(...),
    scan_types: str = Form("hash,behavioral,filename,threat_intelligence"),
    priority: int = Form(2)
):
    """Handle file upload and scanning."""
    try:
        manager = await get_antivirus_manager()
        
        # Save uploaded file temporarily
        temp_dir = Path("temp/antivirus_scans")
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_file_path = temp_dir / f"upload_{timestamp}_{file.filename}"
        
        with open(temp_file_path, "wb") as temp_file:
            content = await file.read()
            temp_file.write(content)
        
        try:
            # Convert scan type strings to enums
            type_mapping = {
                "hash": ScanType.HASH_SCAN,
                "behavioral": ScanType.BEHAVIORAL_SCAN,
                "filename": ScanType.FILENAME_ANALYSIS,
                "threat_intelligence": ScanType.THREAT_INTELLIGENCE
            }
            
            scan_type_list = scan_types.split(",")
            scan_type_enums = [type_mapping[t] for t in scan_type_list if t in type_mapping]
            
            # Perform scan
            results = await manager.scan_file(str(temp_file_path), scan_type_enums, priority, "web_upload")
            
            # Prepare results for display
            scan_results = []
            overall_threat_level = ThreatLevel.CLEAN
            
            for result in results:
                if result.threat_level.value > overall_threat_level.value:
                    overall_threat_level = result.threat_level
                
                scan_results.append({
                    "scan_type": result.scan_type.value,
                    "threat_level": result.threat_level.value,
                    "threat_name": result.threat_name,
                    "threat_type": result.threat_type.value if result.threat_type else None,
                    "confidence_score": result.confidence_score,
                    "scan_duration": result.scan_duration,
                    "details": result.details
                })
            
            return templates.TemplateResponse("antivirus_scan_results.html", {
                "request": request,
                "page_title": "Scan Results",
                "filename": file.filename,
                "file_size": len(content),
                "scan_results": scan_results,
                "overall_threat_level": overall_threat_level.value,
                "threat_count": len([r for r in results if r.threat_level.value > ThreatLevel.CLEAN.value])
            })
            
        finally:
            # Clean up temporary file
            if temp_file_path.exists():
                temp_file_path.unlink()
        
    except Exception as e:
        logger.error(f"File scan upload error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Scan Error"
        })

@router.post("/scan/url")
async def scan_url_submit(
    request: Request,
    url: str = Form(...)
):
    """Handle URL scanning."""
    try:
        manager = await get_antivirus_manager()
        
        # Perform URL scan
        result = await manager.scan_url(url)
        
        # Prepare result for display
        scan_result = {
            "url": url,
            "threat_level": result.threat_level.value,
            "threat_name": result.threat_name,
            "threat_type": result.threat_type.value if result.threat_type else None,
            "confidence_score": result.confidence_score,
            "scan_duration": result.scan_duration,
            "details": result.details
        }
        
        return templates.TemplateResponse("antivirus_url_results.html", {
            "request": request,
            "page_title": "URL Scan Results",
            "result": scan_result
        })
        
    except Exception as e:
        logger.error(f"URL scan error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "URL Scan Error"
        })

@router.get("/quarantine", response_class=HTMLResponse)
async def quarantine_management(request: Request):
    """Quarantine management interface."""
    try:
        manager = await get_antivirus_manager()
        quarantine_list = await manager.get_quarantine_list()
        
        # Sort by quarantine time (newest first)
        quarantine_list.sort(key=lambda x: x["quarantine_time"], reverse=True)
        
        return templates.TemplateResponse("antivirus_quarantine.html", {
            "request": request,
            "page_title": "Quarantine Management",
            "quarantine_list": quarantine_list,
            "total_count": len(quarantine_list)
        })
        
    except Exception as e:
        logger.error(f"Quarantine management error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Quarantine Error"
        })

@router.post("/quarantine/action")
async def quarantine_action(
    request: Request,
    file_hash: str = Form(...),
    action: str = Form(...),
    restore_path: str = Form(None)
):
    """Handle quarantine actions (restore/delete)."""
    try:
        manager = await get_antivirus_manager()
        
        if action == "restore":
            success = await manager.restore_from_quarantine(file_hash, restore_path)
            message = "File restored from quarantine successfully" if success else "Failed to restore file"
        elif action == "delete":
            success = await manager.delete_quarantined_file(file_hash)
            message = "File deleted permanently" if success else "Failed to delete file"
        else:
            raise ValueError("Invalid action")
        
        return templates.TemplateResponse("antivirus_action_result.html", {
            "request": request,
            "page_title": "Quarantine Action",
            "success": success,
            "message": message,
            "action": action,
            "file_hash": file_hash[:16] + "..."
        })
        
    except Exception as e:
        logger.error(f"Quarantine action error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Quarantine Action Error"
        })

@router.get("/settings", response_class=HTMLResponse)
async def antivirus_settings(request: Request):
    """Antivirus settings interface."""
    try:
        manager = await get_antivirus_manager()
        
        return templates.TemplateResponse("antivirus_settings.html", {
            "request": request,
            "page_title": "Antivirus Settings",
            "config": manager.config
        })
        
    except Exception as e:
        logger.error(f"Antivirus settings error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Settings Error"
        })

@router.post("/settings/update")
async def update_antivirus_settings(
    request: Request,
    enabled: bool = Form(False),
    real_time_scanning: bool = Form(False),
    scan_workers: int = Form(3),
    max_file_size: int = Form(100),
    quarantine_auto_delete_days: int = Form(30),
    hash_scanning: bool = Form(False),
    behavioral_analysis: bool = Form(False),
    filename_analysis: bool = Form(False),
    threat_intelligence: bool = Form(False),
    link_scanning: bool = Form(False),
    plugin_scanning: bool = Form(False)
):
    """Update antivirus settings."""
    try:
        manager = await get_antivirus_manager()
        
        # Update configuration
        manager.config.update({
            "enabled": enabled,
            "real_time_scanning": real_time_scanning,
            "scan_workers": scan_workers,
            "max_file_size": max_file_size * 1024 * 1024,  # Convert MB to bytes
            "quarantine_auto_delete_days": quarantine_auto_delete_days,
            "hash_scanning": hash_scanning,
            "behavioral_analysis": behavioral_analysis,
            "filename_analysis": filename_analysis,
            "threat_intelligence": threat_intelligence,
            "link_scanning": link_scanning,
            "plugin_scanning": plugin_scanning
        })
        
        # Save configuration
        await manager._save_config()
        
        return RedirectResponse(url="/ui/antivirus/settings?updated=true", status_code=303)
        
    except Exception as e:
        logger.error(f"Settings update error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Settings Update Error"
        })

@router.post("/update-database")
async def update_threat_database(request: Request):
    """Update threat intelligence database."""
    try:
        manager = await get_antivirus_manager()
        
        # Start database update in background
        asyncio.create_task(manager.update_threat_database())
        
        return templates.TemplateResponse("antivirus_action_result.html", {
            "request": request,
            "page_title": "Database Update",
            "success": True,
            "message": "Threat database update started in background",
            "action": "update_database"
        })
        
    except Exception as e:
        logger.error(f"Database update error: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e),
            "page_title": "Database Update Error"
        })
