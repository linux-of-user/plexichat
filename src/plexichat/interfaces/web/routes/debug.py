# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
import time
Debug WebUI Routes

Web interface for debugging and monitoring PlexiChat components.
"""

# import asyncio  # Unused import
import json
import logging
from datetime import datetime  # , timedelta  # Unused import
from typing import Optional  # Dict, List  # Unused imports

from fastapi import APIRouter, Request, HTTPException, Query, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from plexichat.infrastructure.debugging.debug_manager import get_debug_manager, DebugLevel
from plexichat.infrastructure.debugging.debug_utils import create_debug_dump, analyze_performance_bottlenecks

logger = logging.getLogger(__name__)

# Initialize router and templates
router = APIRouter(prefix="/debug", tags=["Debug"])
templates = Jinja2Templates(directory="src/plexichat/interfaces/web/templates")


class DebugQuery(BaseModel):
    """Debug query parameters."""
    level: Optional[str] = None
    source: Optional[str] = None
    limit: int = 100
    start_time: Optional[str] = None
    end_time: Optional[str] = None


@router.get("/", response_class=HTMLResponse)
async def debug_dashboard(request: Request):
    """Main debug dashboard."""
    try:
        debug_manager = get_debug_manager()

        # Get recent events
        recent_events = debug_manager.get_debug_events(limit=50)

        # Get error summary
        error_summary = debug_manager.get_error_summary()

        # Get performance summary
        performance_summary = debug_manager.get_performance_summary()

        # Get active sessions
        active_sessions = [
            {
                "session_id": session_id,
                "name": session.name,
                "start_time": session.start_time,
                "event_count": len(session.events),
                "active": session.active
            }
            for session_id, session in debug_manager.debug_sessions.items()
        ]

        return templates.TemplateResponse("debug_dashboard.html", {)
            "request": request,
            "recent_events": recent_events,
            "error_summary": error_summary,
            "performance_summary": performance_summary,
            "active_sessions": active_sessions,
            "page_title": "Debug Dashboard"
        })

    except Exception as e:
        logger.error(f"Error loading debug dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/events")
async def get_debug_events()
    level: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=10000),
    format: str = Query("json")
):
    """Get debug events with filtering."""
    try:
        debug_manager = get_debug_manager()

        # Convert level string to enum
        debug_level = None
        if level:
            try:
                debug_level = DebugLevel(level.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid debug level: {level}")

        # Get events
        events = debug_manager.get_debug_events(debug_level, source, limit)

        # Convert to JSON-serializable format
        events_data = [
            {
                "timestamp": event.timestamp,
                "level": event.level.value,
                "source": event.source,
                "message": event.message,
                "context": event.context,
                "stack_trace": event.stack_trace,
                "performance_data": event.performance_data
            }
            for event in events
        ]

        if format.lower() == "csv":
            # Return CSV format
            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["timestamp", "level", "source", "message"])
            writer.writeheader()

            for event_data in events_data:
                writer.writerow({)
                    "timestamp": event_data["timestamp"],
                    "level": event_data["level"],
                    "source": event_data["source"],
                    "message": event_data["message"]
                })

            return JSONResponse(content=output.getvalue(), media_type="text/csv")

        return JSONResponse(content={)
            "success": True,
            "events": events_data,
            "count": len(events_data),
            "filters": {
                "level": level,
                "source": source,
                "limit": limit
            }
        })

    except Exception as e:
        logger.error(f"Error getting debug events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/errors")
async def get_error_summary():
    """Get error summary and statistics."""
    try:
        debug_manager = get_debug_manager()
        error_summary = debug_manager.get_error_summary()

        return JSONResponse(content={)
            "success": True,
            "error_summary": error_summary
        })

    except Exception as e:
        logger.error(f"Error getting error summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance")
async def get_performance_data():
    """Get performance data and statistics."""
    try:
        debug_manager = get_debug_manager()
        performance_summary = debug_manager.get_performance_summary()

        # Analyze bottlenecks
        bottlenecks = analyze_performance_bottlenecks()

        return JSONResponse(content={)
            "success": True,
            "performance_summary": performance_summary,
            "bottlenecks": bottlenecks
        })

    except Exception as e:
        logger.error(f"Error getting performance data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/memory")
async def get_memory_data():
    """Get memory usage data and snapshots."""
    try:
        debug_manager = get_debug_manager()

        # Get recent memory snapshots
        recent_snapshots = debug_manager.memory_snapshots[-50:]  # Last 50 snapshots

        # Calculate memory trends
        if len(recent_snapshots) > 1:
            memory_trend = []
            for i, snapshot in enumerate(recent_snapshots):
                if i > 0:
                    prev_memory = recent_snapshots[i-1]["memory_usage"]
                    curr_memory = snapshot["memory_usage"]
                    change = curr_memory - prev_memory

                    memory_trend.append({)
                        "timestamp": snapshot["timestamp"],
                        "memory_usage": curr_memory,
                        "change": change,
                        "label": snapshot["label"]
                    })
        else:
            memory_trend = []

        return JSONResponse(content={)
            "success": True,
            "memory_snapshots": recent_snapshots,
            "memory_trend": memory_trend,
            "snapshot_count": len(debug_manager.memory_snapshots)
        })

    except Exception as e:
        logger.error(f"Error getting memory data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def get_debug_sessions():
    """Get all debug sessions."""
    try:
        debug_manager = get_debug_manager()

        sessions_data = []
        for session_id, session in debug_manager.debug_sessions.items():
            sessions_data.append({)
                "session_id": session_id,
                "name": session.name,
                "start_time": session.start_time,
                "end_time": getattr(session, 'end_time', None),
                "duration": getattr(session, 'duration', None),
                "active": session.active,
                "event_count": len(session.events),
                "profiling_data_count": len(session.profiling_data),
                "metadata": session.metadata
            })

        return JSONResponse(content={)
            "success": True,
            "sessions": sessions_data
        })

    except Exception as e:
        logger.error(f"Error getting debug sessions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions/{session_id}")
async def get_debug_session(session_id: str):
    """Get detailed information about a specific debug session."""
    try:
        debug_manager = get_debug_manager()

        if session_id not in debug_manager.debug_sessions:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

        session_data = debug_manager.export_debug_data(session_id)

        return JSONResponse(content={)
            "success": True,
            "session_data": session_data
        })

    except Exception as e:
        logger.error(f"Error getting debug session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sessions")
async def create_debug_session(name: str = Form(...), metadata: str = Form("{}")):
    """Create a new debug session."""
    try:
        debug_manager = get_debug_manager()

        # Parse metadata
        try:
            metadata_dict = json.loads(metadata) if metadata else {}
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid metadata JSON")

        session_id = debug_manager.create_debug_session(name, metadata_dict)

        return JSONResponse(content={)
            "success": True,
            "session_id": session_id,
            "message": f"Debug session '{name}' created successfully"
        })

    except Exception as e:
        logger.error(f"Error creating debug session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/sessions/{session_id}")
async def delete_debug_session(session_id: str):
    """Delete a debug session."""
    try:
        debug_manager = get_debug_manager()

        if session_id not in debug_manager.debug_sessions:
            raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

        debug_manager.clear_debug_data(session_id)

        return JSONResponse(content={)
            "success": True,
            "message": f"Debug session {session_id} deleted successfully"
        })

    except Exception as e:
        logger.error(f"Error deleting debug session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/memory/snapshot")
async def take_memory_snapshot(label: str = Form("")):
    """Take a memory snapshot."""
    try:
        debug_manager = get_debug_manager()
        debug_manager.take_memory_snapshot(label)

        return JSONResponse(content={)
            "success": True,
            "message": "Memory snapshot taken successfully"
        })

    except Exception as e:
        logger.error(f"Error taking memory snapshot: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export")
async def export_debug_data()
    session_id: Optional[str] = Form(None),
    format: str = Form("json")
):
    """Export debug data."""
    try:
        debug_manager = get_debug_manager()

        if format.lower() == "json":
            # Create debug dump
            dump_path = create_debug_dump()

            if dump_path:
                return FileResponse()
                    path=dump_path,
                    filename=f"debug_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    media_type="application/json"
                )
            else:
                raise HTTPException(status_code=500, detail="Failed to create debug dump")

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    except Exception as e:
        logger.error(f"Error exporting debug data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/clear")
async def clear_debug_data(session_id: Optional[str] = Form(None)):
    """Clear debug data."""
    try:
        debug_manager = get_debug_manager()
        debug_manager.clear_debug_data(session_id)

        message = f"Debug data cleared for session {session_id}" if session_id else "All debug data cleared"

        return JSONResponse(content={)
            "success": True,
            "message": message
        })

    except Exception as e:
        logger.error(f"Error clearing debug data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/live-events")
async def get_live_events():
    """Get live debug events (for real-time updates)."""
    try:
        debug_manager = get_debug_manager()

        # Get most recent events
        recent_events = debug_manager.get_debug_events(limit=10)

        # Get current performance data
        current_performance = debug_manager._get_current_performance_data()

        # Get error counts
        error_summary = debug_manager.get_error_summary()

        return JSONResponse(content={)
            "success": True,
            "recent_events": [
                {
                    "timestamp": event.timestamp,
                    "level": event.level.value,
                    "source": event.source,
                    "message": event.message
                }
                for event in recent_events
            ],
            "current_performance": current_performance,
            "error_count": error_summary.get("total_errors", 0),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting live events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_debug_events()
    query: str = Query(...),
    level: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Search debug events by message content."""
    try:
        debug_manager = get_debug_manager()

        # Get all events
        all_events = debug_manager.get_debug_events(limit=10000)  # Get more for searching

        # Filter by search query
        matching_events = []
        query_lower = query.lower()

        for event in all_events:
            if (query_lower in event.message.lower() or )
                query_lower in event.source.lower() or
                any(query_lower in str(v).lower() for v in event.context.values())):

                # Apply additional filters
                if level and event.level.value != level.lower():
                    continue

                if source and source.lower() not in event.source.lower():
                    continue

                matching_events.append(event)

        # Limit results
        matching_events = matching_events[-limit:]

        # Convert to JSON format
        events_data = [
            {
                "timestamp": event.timestamp,
                "level": event.level.value,
                "source": event.source,
                "message": event.message,
                "context": event.context
            }
            for event in matching_events
        ]

        return JSONResponse(content={)
            "success": True,
            "events": events_data,
            "count": len(events_data),
            "query": query,
            "filters": {
                "level": level,
                "source": source
            }
        })

    except Exception as e:
        logger.error(f"Error searching debug events: {e}")
        raise HTTPException(status_code=500, detail=str(e))
