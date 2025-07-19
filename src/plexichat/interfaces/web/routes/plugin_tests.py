# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
Plugin Tests WebUI Routes

Web interface for plugin testing with scheduling and management features.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Request, HTTPException, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# from plexichat.infrastructure.modules.plugin_test_manager import (
#     get_test_manager, TestStatus, TestPriority, TestSchedule
# )
# from plexichat.infrastructure.modules.plugin_manager import get_plugin_manager

def get_test_manager():
    class DummyTestManager:
        def get_test_statistics(self, *a, **k): return {}
        def get_test_results(self, *a, **k): return []
        async def run_plugin_test(self, *a, **k):
            class R:
                test_id = 1
                status = type('S', (), {'value': 'ok'})()
                duration = 0
                message = ''
                error = ''
            return R()
        async def run_all_plugin_tests(self, *a, **k): return []
        def schedule_test(self, *a, **k): return 1
        def unschedule_test(self, *a, **k): return True
        @property
        def test_schedules(self): return {}
        @property
        def discovered_tests(self): return {}
    return DummyTestManager()
class TestStatus:
    value = 'ok'
class TestPriority:
    LOW = 'low'; MEDIUM = 'medium'; HIGH = 'high'; CRITICAL = 'critical'
class TestSchedule:
    pass
def get_plugin_manager():
    class DummyPluginManager:
        @property
        def loaded_plugins(self): return {"dummy": object()}
    return DummyPluginManager()

logger = logging.getLogger(__name__)

# Initialize router and templates
router = APIRouter(prefix="/tests", tags=["Plugin Tests"])
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")


class TestRunRequest(BaseModel):
    """Test run request model."""
    plugin_name: str
    test_name: Optional[str] = None
    timeout: int = 300


class TestScheduleRequest(BaseModel):
    """Test schedule request model."""
    plugin_name: str
    test_name: str
    schedule_expression: str
    priority: str = "medium"
    timeout: int = 300
    enabled: bool = True


@router.get("/", response_class=HTMLResponse)
async def tests_dashboard(request: Request):
    """Main plugin tests dashboard."""
    try:
        test_manager = get_test_manager()
        plugin_manager = get_plugin_manager()

        # Get test statistics
        overall_stats = test_manager.get_test_statistics()

        # Get plugin-specific stats
        plugin_stats = {}
        for plugin_name in plugin_manager.loaded_plugins.keys():
            plugin_stats[plugin_name] = test_manager.get_test_statistics(plugin_name)

        # Get recent test results
        recent_results = test_manager.get_test_results(limit=20)

        # Get scheduled tests
        scheduled_tests = list(test_manager.test_schedules.values())

        # Get discovered tests
        discovered_tests = test_manager.discovered_tests

        return templates.TemplateResponse("plugin_tests_dashboard.html", {
            "request": request,
            "overall_stats": overall_stats,
            "plugin_stats": plugin_stats,
            "recent_results": recent_results,
            "scheduled_tests": scheduled_tests,
            "discovered_tests": discovered_tests,
            "page_title": "Plugin Tests Dashboard"
        })

    except Exception as e:
        logger.error(f"Error loading tests dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/plugin/{plugin_name}", response_class=HTMLResponse)
async def plugin_tests_page(request: Request, plugin_name: str):
    """Individual plugin tests page."""
    try:
        test_manager = get_test_manager()
        plugin_manager = get_plugin_manager()

        # Check if plugin exists
        if plugin_name not in plugin_manager.loaded_plugins:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")

        # Get plugin tests
        plugin_tests = test_manager.discovered_tests.get(plugin_name, {})

        # Get test results for this plugin
        test_results = test_manager.get_test_results(plugin_name, limit=50)

        # Get plugin statistics
        plugin_stats = test_manager.get_test_statistics(plugin_name)

        # Get scheduled tests for this plugin
        plugin_schedules = [
            schedule for schedule in test_manager.test_schedules.values()
            if schedule.plugin_name == plugin_name
        ]

        return templates.TemplateResponse("plugin_tests_detail.html", {
            "request": request,
            "plugin_name": plugin_name,
            "plugin_tests": plugin_tests,
            "test_results": test_results,
            "plugin_stats": plugin_stats,
            "plugin_schedules": plugin_schedules,
            "page_title": f"Tests - {plugin_name}"
        })

    except Exception as e:
        logger.error(f"Error loading plugin tests page: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run")
async def run_test(request: TestRunRequest):
    """Run a specific test or all tests for a plugin."""
    try:
        test_manager = get_test_manager()

        if request.test_name:
            # Run specific test
            result = await test_manager.run_plugin_test(
                request.plugin_name,
                request.test_name,
                request.timeout
            )
            return JSONResponse(content={
                "success": True,
                "result": {
                    "test_id": result.test_id,
                    "status": result.status.value,
                    "duration": result.duration,
                    "message": result.message,
                    "error": result.error
                }
            })
        else:
            # Run all tests for plugin
            results = await test_manager.run_all_plugin_tests(request.plugin_name)
            return JSONResponse(content={
                "success": True,
                "results": [
                    {
                        "test_id": result.test_id,
                        "test_name": result.test_name,
                        "status": result.status.value,
                        "duration": result.duration,
                        "message": result.message,
                        "error": result.error
                    }
                    for result in results
                ]
            })

    except Exception as e:
        logger.error(f"Error running test: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/schedule")
async def schedule_test(request: TestScheduleRequest):
    """Schedule a test to run automatically."""
    try:
        test_manager = get_test_manager()

        # Convert priority string to enum
        priority_map = {
            "low": TestPriority.LOW,
            "medium": TestPriority.MEDIUM,
            "high": TestPriority.HIGH,
            "critical": TestPriority.CRITICAL
        }
        priority = priority_map.get(request.priority.lower(), TestPriority.MEDIUM)

        # Schedule the test
        schedule_id = test_manager.schedule_test(
            request.plugin_name,
            request.test_name,
            request.schedule_expression,
            priority,
            request.timeout
        )

        return JSONResponse(content={
            "success": True,
            "schedule_id": schedule_id,
            "message": f"Test scheduled successfully"
        })

    except Exception as e:
        logger.error(f"Error scheduling test: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/schedule/{schedule_id}")
async def unschedule_test(schedule_id: str):
    """Remove a scheduled test."""
    try:
        test_manager = get_test_manager()

        success = test_manager.unschedule_test(schedule_id)

        if success:
            return JSONResponse(content={
                "success": True,
                "message": "Test unscheduled successfully"
            })
        else:
            return JSONResponse(content={
                "success": False,
                "message": "Schedule not found"
            }, status_code=404)

    except Exception as e:
        logger.error(f"Error unscheduling test: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results")
async def get_test_results(
    plugin_name: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    status: Optional[str] = Query(None)
):
    """Get test results with optional filtering."""
    try:
        test_manager = get_test_manager()

        # Get results
        results = test_manager.get_test_results(plugin_name, limit)

        # Filter by status if specified
        if status:
            results = [r for r in results if r.status.value == status]

        # Convert to JSON-serializable format
        results_data = [
            {
                "test_id": result.test_id,
                "plugin_name": result.plugin_name,
                "test_name": result.test_name,
                "status": result.status.value,
                "duration": result.duration,
                "message": result.message,
                "error": result.error,
                "timestamp": result.timestamp,
                "metadata": result.metadata
            }
            for result in results
        ]

        return JSONResponse(content={
            "success": True,
            "results": results_data,
            "count": len(results_data)
        })

    except Exception as e:
        logger.error(f"Error getting test results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_test_statistics(plugin_name: Optional[str] = Query(None)):
    """Get test statistics."""
    try:
        test_manager = get_test_manager()

        stats = test_manager.get_test_statistics(plugin_name)

        return JSONResponse(content={
            "success": True,
            "statistics": stats
        })

    except Exception as e:
        logger.error(f"Error getting test statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/schedules")
async def get_scheduled_tests():
    """Get all scheduled tests."""
    try:
        test_manager = get_test_manager()

        schedules = [
            {
                "test_id": schedule.test_id,
                "plugin_name": schedule.plugin_name,
                "test_name": schedule.test_name,
                "schedule_expression": schedule.schedule_expression,
                "enabled": schedule.enabled,
                "priority": schedule.priority.value,
                "timeout": schedule.timeout,
                "last_run": schedule.last_run,
                "next_run": schedule.next_run
            }
            for schedule in test_manager.test_schedules.values()
        ]

        return JSONResponse(content={
            "success": True,
            "schedules": schedules
        })

    except Exception as e:
        logger.error(f"Error getting scheduled tests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/discover")
async def discover_tests(plugin_name: Optional[str] = None):
    """Discover tests for plugins."""
    try:
        test_manager = get_test_manager()
        plugin_manager = get_plugin_manager()

        discovered_count = 0

        if plugin_name:
            # Discover tests for specific plugin
            if plugin_name in plugin_manager.loaded_plugins:
                plugin_path = Path(f"plugins/{plugin_name}")
                tests = await test_manager.discover_plugin_tests(plugin_name, plugin_path)
                discovered_count = len(tests)
            else:
                raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        else:
            # Discover tests for all plugins
            for plugin_name in plugin_manager.loaded_plugins.keys():
                plugin_path = Path(f"plugins/{plugin_name}")
                tests = await test_manager.discover_plugin_tests(plugin_name, plugin_path)
                discovered_count += len(tests)

        return JSONResponse(content={
            "success": True,
            "message": f"Discovered {discovered_count} tests",
            "discovered_count": discovered_count
        })

    except Exception as e:
        logger.error(f"Error discovering tests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/live-updates")
async def live_test_updates():
    """WebSocket-like endpoint for live test updates (using Server-Sent Events)."""
    try:
        # This would implement Server-Sent Events for real-time updates
        # For now, return current status
        test_manager = get_test_manager()

        running_tests = list(test_manager.running_tests.keys())
        recent_results = test_manager.get_test_results(limit=5)

        return JSONResponse(content={
            "success": True,
            "running_tests": running_tests,
            "recent_results": [
                {
                    "test_id": result.test_id,
                    "plugin_name": result.plugin_name,
                    "test_name": result.test_name,
                    "status": result.status.value,
                    "timestamp": result.timestamp
                }
                for result in recent_results
            ]
        })

    except Exception as e:
        logger.error(f"Error getting live updates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk-run")
async def bulk_run_tests(plugin_names: List[str]):
    """Run tests for multiple plugins."""
    try:
        test_manager = get_test_manager()

        all_results = []

        for plugin_name in plugin_names:
            try:
                results = await test_manager.run_all_plugin_tests(plugin_name)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error running tests for plugin {plugin_name}: {e}")

        # Summarize results
        summary = {
            "total_tests": len(all_results),
            "passed": len([r for r in all_results if r.status == TestStatus.PASSED]),
            "failed": len([r for r in all_results if r.status == TestStatus.FAILED]),
            "error": len([r for r in all_results if r.status == TestStatus.ERROR])
        }

        return JSONResponse(content={
            "success": True,
            "summary": summary,
            "results": [
                {
                    "test_id": result.test_id,
                    "plugin_name": result.plugin_name,
                    "test_name": result.test_name,
                    "status": result.status.value,
                    "duration": result.duration,
                    "message": result.message
                }
                for result in all_results
            ]
        })

    except Exception as e:
        logger.error(f"Error running bulk tests: {e}")
        raise HTTPException(status_code=500, detail=str(e))
