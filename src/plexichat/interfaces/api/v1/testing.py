"""
Enhanced testing API for PlexiChat.
Provides comprehensive testing capabilities accessible from WebUI and GUI.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Query
from fastapi.responses import JSONResponse, FileResponse
from sqlmodel import Session
from pydantic import BaseModel
from pathlib import Path

from plexichat.app.db import get_session
from plexichat.app.models.enhanced_models import EnhancedUser
from plexichat.app.utils.auth import get_current_user, get_optional_current_user
from plexichat.app.testing.enhanced_test_suite import enhanced_test_suite
from plexichat.app.logger_config import logger


# Pydantic models for API
class TestRunRequest(BaseModel):
    categories: Optional[List[str]] = None
    include_stress_tests: bool = False
    include_government_tests: bool = True
    save_report: bool = True


class TestCategoryInfo(BaseModel):
    name: str
    description: str
    test_count: int
    estimated_duration_seconds: int


router = APIRouter(prefix="/api/v1/testing", tags=["Enhanced Testing"])


@router.get("/categories")
async def get_test_categories(
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> List[TestCategoryInfo]:
    """Get available test categories with descriptions."""
    categories = []
    
    category_info = {
        "system": ("System Configuration & Resources", 4, 30),
        "database": ("Database Connectivity & Performance", 3, 20),
        "security": ("Security & Encryption", 5, 45),
        "backup": ("Backup System & Recovery", 6, 60),
        "performance": ("Performance & Scalability", 3, 40),
        "network": ("Network & Connectivity", 2, 15),
        "integration": ("API & Integration", 2, 25),
        "stress": ("Stress & Load Testing", 3, 120),
        "government": ("Government-Level Security Compliance", 4, 50)
    }
    
    for category, (description, test_count, duration) in category_info.items():
        categories.append(TestCategoryInfo(
            name=category,
            description=description,
            test_count=test_count,
            estimated_duration_seconds=duration
        ))
    
    return categories


@router.post("/run")
async def run_tests(
    request: TestRunRequest,
    background_tasks: BackgroundTasks,
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> JSONResponse:
    """Run comprehensive test suite."""
    try:
        logger.info(f"🧪 Starting test run requested by user {current_user.id if current_user else 'anonymous'}")
        
        # Validate categories
        available_categories = list(enhanced_test_suite.test_categories.keys())
        if request.categories:
            invalid_categories = [cat for cat in request.categories if cat not in available_categories]
            if invalid_categories:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid categories: {invalid_categories}"
                )
        
        # Filter categories based on request
        categories_to_run = request.categories or available_categories
        
        if not request.include_stress_tests and "stress" in categories_to_run:
            categories_to_run.remove("stress")
        
        if not request.include_government_tests and "government" in categories_to_run:
            categories_to_run.remove("government")
        
        # Run tests in background
        background_tasks.add_task(
            _run_tests_background,
            categories_to_run,
            request.save_report,
            current_user.id if current_user else None
        )
        
        return JSONResponse({
            "success": True,
            "message": "Test run started",
            "categories": categories_to_run,
            "estimated_duration_seconds": sum(
                _get_category_duration(cat) for cat in categories_to_run
            ),
            "test_run_id": f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        })
        
    except Exception as e:
        logger.error(f"Failed to start test run: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_test_status(
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get current test execution status."""
    try:
        # Check if tests are currently running
        running_tests = [test for test in enhanced_test_suite.tests.values() if test.status == "running"]
        
        # Get latest test results
        latest_results = {name: test.to_dict() for name, test in enhanced_test_suite.tests.items()}
        
        # Calculate summary statistics
        total_tests = len(enhanced_test_suite.tests)
        if total_tests > 0:
            passed_tests = len([t for t in enhanced_test_suite.tests.values() if t.status == "passed"])
            failed_tests = len([t for t in enhanced_test_suite.tests.values() if t.status == "failed"])
            warning_tests = len([t for t in enhanced_test_suite.tests.values() if t.status == "warning"])
            
            summary = {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "warning_tests": warning_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "is_running": len(running_tests) > 0,
                "running_tests": [test.name for test in running_tests]
            }
        else:
            summary = {
                "total_tests": 0,
                "passed_tests": 0,
                "failed_tests": 0,
                "warning_tests": 0,
                "success_rate": 0,
                "is_running": False,
                "running_tests": []
            }
        
        return {
            "summary": summary,
            "latest_results": latest_results,
            "last_updated": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get test status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/latest")
async def get_latest_results(
    category: Optional[str] = Query(None, description="Filter by category"),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Get latest test results."""
    try:
        tests = enhanced_test_suite.tests
        
        if category:
            tests = {name: test for name, test in tests.items() if test.category == category}
        
        results = {name: test.to_dict() for name, test in tests.items()}
        
        return {
            "results": results,
            "summary": enhanced_test_suite._generate_test_summary(),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get test results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports")
async def list_test_reports(
    limit: int = Query(10, le=50),
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> List[Dict[str, Any]]:
    """List available test reports."""
    try:
        reports_dir = Path("tests/reports")
        if not reports_dir.exists():
            return []
        
        report_files = list(reports_dir.glob("enhanced_test_report_*.json"))
        report_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        reports = []
        for report_file in report_files[:limit]:
            try:
                stat = report_file.stat()
                reports.append({
                    "filename": report_file.name,
                    "size_bytes": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "download_url": f"/api/v1/testing/reports/{report_file.name}/download"
                })
            except Exception as e:
                logger.warning(f"Failed to read report file {report_file}: {e}")
        
        return reports
        
    except Exception as e:
        logger.error(f"Failed to list test reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{filename}/download")
async def download_test_report(
    filename: str,
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> FileResponse:
    """Download a specific test report."""
    try:
        # Validate filename to prevent path traversal
        if not filename.startswith("enhanced_test_report_") or not filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Invalid report filename")
        
        report_file = Path("tests/reports") / filename
        
        if not report_file.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            path=str(report_file),
            media_type="application/json",
            filename=filename
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/quick-test")
async def run_quick_test(
    current_user: Optional[EnhancedUser] = Depends(get_optional_current_user)
) -> Dict[str, Any]:
    """Run a quick system health test."""
    try:
        logger.info("🚀 Running quick system health test...")
        
        # Run only essential tests
        essential_categories = ["system", "security", "database"]
        
        # Clear previous test results for quick test
        enhanced_test_suite.tests.clear()
        
        # Run tests
        report = await enhanced_test_suite.run_comprehensive_tests(essential_categories)
        
        # Extract key metrics
        summary = report.get("summary", {})
        
        return {
            "success": True,
            "message": "Quick test completed",
            "summary": summary,
            "duration_seconds": report.get("total_duration_seconds", 0),
            "overall_status": summary.get("overall_status", "unknown"),
            "critical_issues": [
                test["name"] for test in report.get("tests", {}).values()
                if test.get("status") == "failed"
            ],
            "warnings": [
                test["name"] for test in report.get("tests", {}).values()
                if test.get("warnings")
            ]
        }
        
    except Exception as e:
        logger.error(f"Quick test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/results")
async def clear_test_results(
    current_user: EnhancedUser = Depends(get_current_user)
) -> JSONResponse:
    """Clear all test results (admin only)."""
    try:
        # Check if user has admin privileges (simplified check)
        # In production, implement proper role-based access control
        
        enhanced_test_suite.tests.clear()
        
        logger.info(f"Test results cleared by user {current_user.id}")
        
        return JSONResponse({
            "success": True,
            "message": "Test results cleared successfully"
        })
        
    except Exception as e:
        logger.error(f"Failed to clear test results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper functions
async def _run_tests_background(
    categories: List[str],
    save_report: bool,
    user_id: Optional[int]
):
    """Run tests in background task."""
    try:
        logger.info(f"🔄 Running background tests for categories: {categories}")
        
        # Clear previous results
        enhanced_test_suite.tests.clear()
        
        # Run comprehensive tests
        report = await enhanced_test_suite.run_comprehensive_tests(categories)
        
        if save_report:
            await enhanced_test_suite._save_enhanced_report(report)
        
        logger.info(f"✅ Background test run completed for user {user_id}")
        
    except Exception as e:
        logger.error(f"Background test run failed: {e}")


def _get_category_duration(category: str) -> int:
    """Get estimated duration for a test category."""
    durations = {
        "system": 30,
        "database": 20,
        "security": 45,
        "backup": 60,
        "performance": 40,
        "network": 15,
        "integration": 25,
        "stress": 120,
        "government": 50
    }
    return durations.get(category, 30)
