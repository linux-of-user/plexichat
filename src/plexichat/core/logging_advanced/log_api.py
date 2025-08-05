# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import csv
import io
import json
from datetime import datetime
from typing import Dict, List, Optional

from starlette.websockets import WebSocketState

# # from . import LogCategory, LogEntry, LogLevel, get_logging_manager
from .performance_logger import get_performance_logger
from .security_logger import SecurityEventType, SecuritySeverity, get_security_logger


from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from plexichat.infrastructure.utils.auth import require_admin

"""
import socket
PlexiChat Centralized Log Management API

REST API endpoints for log management, monitoring, and analysis.
Provides real-time log streaming, filtering, search, and analytics.

Features:
- Real-time log streaming via WebSocket
- Advanced log filtering and search
- Performance metrics API
- Security event monitoring
- Log export and archival
- Dashboard data endpoints
- Alert management
- Log integrity verification
"""

# Pydantic models for API
class LogFilterRequest(BaseModel):
    """Log filter request model."""
    level: Optional[str] = None
    category: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    search_query: Optional[str] = None
    limit: Optional[int] = Field(default=100, le=1000)

class LogExportRequest(BaseModel):
    """Log export request model."""
    format: str = Field(default="json", pattern="^(json|csv|txt)$")
    level: Optional[str] = None
    category: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    include_context: bool = True

class SecurityEventRequest(BaseModel):
    """Security event request model."""
    event_types: Optional[List[str]] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: Optional[int] = Field(default=100, le=1000)

class PerformanceMetricsRequest(BaseModel):
    """Performance metrics request model."""
    metric_names: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    aggregation: str = Field(default="avg", pattern="^(avg|min|max|sum|count)$")
    interval: str = Field(default="1h", pattern="^(1m|5m|15m|1h|6h|24h)$")

# WebSocket connection manager
class LogWebSocketManager:
    """Manage WebSocket connections for real-time log streaming."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_filters: Dict[WebSocket, LogFilterRequest] = {}

    async def connect(self, websocket: WebSocket, log_filter: Optional[LogFilterRequest] = None):
        """Accept WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        if log_filter:
            self.connection_filters[websocket] = log_filter

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_filters:
            del self.connection_filters[websocket]

    async def broadcast_log_entry(self, log_entry: LogEntry):
        """Broadcast log entry to all connected clients."""
        if not self.active_connections:
            return

        message = {
            "type": "log_entry",
            "data": log_entry.to_dict()
        }

        disconnected = []
        for connection in self.active_connections:
            try:
                # Check if entry matches connection filter
                if self._matches_filter(log_entry, self.connection_filters.get(connection)):
                    if connection.client_state == WebSocketState.CONNECTED:
                        await connection.send_text(json.dumps(message, default=str))
                    else:
                        disconnected.append(connection)
            except Exception:
                disconnected.append(connection)

        # Clean up disconnected connections
        for connection in disconnected:
            self.disconnect(connection)

    def _matches_filter(self, log_entry: LogEntry, log_filter: Optional[LogFilterRequest]) -> bool:
        """Check if log entry matches filter criteria."""
        if not log_filter:
            return True

        # Level filter
        if log_filter.level:
            try:
                filter_level = LogLevel[log_filter.level.upper()]
                if log_entry.level.value < filter_level.value:
                    return False
            except KeyError:
                pass

        # Category filter
        if log_filter.category:
            try:
                filter_category = LogCategory(log_filter.category.lower())
                if log_entry.category != filter_category:
                    return False
            except ValueError:
                pass

        # Time filters
        if log_filter.start_time and log_entry.timestamp < log_filter.start_time:
            return False
        if log_filter.end_time and log_entry.timestamp > log_filter.end_time:
            return False

        # Search query filter
        if log_filter.search_query:
            search_text = log_filter.search_query.lower()
            if search_text not in log_entry.message.lower():
                return False

        return True

# Global WebSocket manager
websocket_manager = LogWebSocketManager()

# Setup log streaming callback
def setup_log_streaming():
    """Setup log streaming to WebSocket clients."""
    logging_manager = get_logging_manager()
    logging_manager.subscribe_to_logs()
        lambda entry: asyncio.create_task(websocket_manager.broadcast_log_entry(entry))
    )

# API Router
router = APIRouter(prefix="/api/v2/logs", tags=["logging"])

@router.get("/entries")
async def get_log_entries()
    level: Optional[str] = Query(None, description="Minimum log level"),
    category: Optional[str] = Query(None, description="Log category"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    search_query: Optional[str] = Query(None, description="Search in log messages"),
    limit: int = Query(100, le=1000, description="Maximum number of entries"),
    current_user = Depends(require_admin)
):
    """Get log entries with filtering."""
    logging_manager = get_logging_manager()

    # Parse filters
    level_filter = None
    if level:
        try:
            level_filter = LogLevel[level.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid log level: {level}")

    category_filter = None
    if category:
        try:
            category_filter = LogCategory(category.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid log category: {category}")

    # Get entries
    entries = logging_manager.get_log_entries()
        count=limit,
        level_filter=level_filter,
        category_filter=category_filter
    )

    # Apply additional filters
    filtered_entries = []
    for entry in entries:
        # Time filters
        if start_time and entry.timestamp < start_time:
            continue
        if end_time and entry.timestamp > end_time:
            continue

        # Search filter
        if search_query and search_query.lower() not in entry.message.lower():
            continue

        filtered_entries.append(entry.to_dict())

    return {}
        "entries": filtered_entries,
        "total": len(filtered_entries),
        "filters": {
            "level": level,
            "category": category,
            "start_time": start_time,
            "end_time": end_time,
            "search_query": search_query,
            "limit": limit
        }
    }

@router.websocket("/stream")
async def log_stream_websocket()
    websocket: WebSocket,
    level: Optional[str] = Query(None),
    category: Optional[str] = Query(None)
):
    """WebSocket endpoint for real-time log streaming."""
    # Create filter from query parameters
    log_filter = None
    if level or category:
        log_filter = LogFilterRequest(level=level, category=category)

    await websocket_manager.connect(websocket, log_filter)

    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get("type") == "update_filter":
                    # Update filter for this connection
                    filter_data = message.get("filter", {})
                    websocket_manager.connection_filters[websocket] = LogFilterRequest(**filter_data)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@router.get("/performance/summary")
async def get_performance_summary()
    hours: int = Query(1, ge=1, le=168, description="Hours to include in summary"),
    current_user = Depends(require_admin)
):
    """Get performance summary."""
    performance_logger = get_performance_logger()
    return performance_logger.get_performance_summary(hours=hours)

@router.get("/performance/metrics")
async def get_performance_metrics()
    metric_names: Optional[List[str]] = Query(None, description="Specific metric names"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    limit: int = Query(1000, le=10000, description="Maximum number of data points"),
    current_user = Depends(require_admin)
):
    """Get performance metrics."""
    performance_logger = get_performance_logger()

    if not metric_names:
        metric_names = performance_logger.metric_buffer.get_all_metric_names()

    metrics_data = {}
    for metric_name in metric_names:
        metrics = performance_logger.metric_buffer.get_metrics()
            metric_name, start_time, end_time, limit
        )
        metrics_data[metric_name] = [m.to_dict() for m in metrics]

    return {}
        "metrics": metrics_data,
        "filters": {
            "metric_names": metric_names,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit
        }
    }

@router.get("/security/events")
async def get_security_events()
    event_types: Optional[List[str]] = Query(None, description="Security event types"),
    severity: Optional[str] = Query(None, description="Minimum severity level"),
    start_time: Optional[datetime] = Query(None, description="Start time filter"),
    end_time: Optional[datetime] = Query(None, description="End time filter"),
    limit: int = Query(100, le=1000, description="Maximum number of events"),
    current_user = Depends(require_admin)
):
    """Get security events."""
    security_logger = get_security_logger()

    # Parse filters
    event_type_filters = None
    if event_types:
        try:
            event_type_filters = [SecurityEventType(et) for et in event_types]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid event type: {e}")

    severity_filter = None
    if severity:
        try:
            severity_filter = SecuritySeverity[severity.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    events = security_logger.get_security_events()
        start_time=start_time,
        end_time=end_time,
        event_types=event_type_filters,
        severity=severity_filter
    )

    # Apply limit
    if limit:
        events = events[-limit:]

    return {}
        "events": events,
        "total": len(events),
        "filters": {
            "event_types": event_types,
            "severity": severity,
            "start_time": start_time,
            "end_time": end_time,
            "limit": limit
        }
    }

@router.get("/security/integrity")
async def verify_log_integrity(current_user = Depends(require_admin)):
    """Verify security log integrity."""
    security_logger = get_security_logger()
    return security_logger.verify_log_integrity()

@router.post("/export")
async def export_logs()
    export_request: LogExportRequest,
    current_user = Depends(require_admin)
):
    """Export logs in various formats."""
    logging_manager = get_logging_manager()

    # Parse filters
    level_filter = None
    if export_request.level:
        try:
            level_filter = LogLevel[export_request.level.upper()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid log level: {export_request.level}")

    category_filter = None
    if export_request.category:
        try:
            category_filter = LogCategory(export_request.category.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid log category: {export_request.category}")

    # Get entries
    entries = logging_manager.get_log_entries()
        level_filter=level_filter,
        category_filter=category_filter
    )

    # Apply time filters
    filtered_entries = []
    for entry in entries:
        if export_request.start_time and entry.timestamp < export_request.start_time:
            continue
        if export_request.end_time and entry.timestamp > export_request.end_time:
            continue
        filtered_entries.append(entry)

    # Generate export data
    if export_request.format == "json":
        def generate_json():
            yield "[\n"
            for i, entry in enumerate(filtered_entries):
                if i > 0:
                    yield ",\n"
                yield json.dumps(entry.to_dict(), default=str, indent=2)
            yield "\n]"

        return StreamingResponse()
            generate_json(),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=logs.json"}
        )

    elif export_request.format == "csv":
        def generate_csv():
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow([)
                "timestamp", "level", "category", "message", "module", "function", "line"
            ])

            for entry in filtered_entries:
                writer.writerow([)
                    entry.timestamp.isoformat(),
                    entry.level.name,
                    entry.category.value,
                    entry.message,
                    entry.module,
                    entry.function,
                    entry.line
                ])

            output.seek(0)
            return output.getvalue()

        return StreamingResponse()
            iter([generate_csv()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=logs.csv"}
        )

    else:  # txt format
        def generate_txt():
            for entry in filtered_entries:
                yield f"[{entry.timestamp.isoformat()}] [{entry.level.name}] [{entry.category.value}] {entry.module}: {entry.message}\n"

        return StreamingResponse()
            generate_txt(),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=logs.txt"}
        )

@router.get("/stats")
async def get_log_stats(current_user = Depends(require_admin)):
    """Get logging system statistics."""
    logging_manager = get_logging_manager()

    # Get recent entries for stats
    recent_entries = logging_manager.get_log_entries(count=1000)

    # Calculate statistics
    level_counts = {}
    category_counts = {}
    hourly_counts = {}

    for entry in recent_entries:
        # Level counts
        level_name = entry.level.name
        level_counts[level_name] = level_counts.get(level_name, 0) + 1

        # Category counts
        category_name = entry.category.value
        category_counts[category_name] = category_counts.get(category_name, 0) + 1

        # Hourly counts
        hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
        hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1

    return {}
        "total_entries": len(recent_entries),
        "level_distribution": level_counts,
        "category_distribution": category_counts,
        "hourly_distribution": hourly_counts,
        "performance_summary": logging_manager.get_performance_summary()
    }

# Initialize log streaming when module is imported
setup_log_streaming()

# Export router
__all__ = ["router", "websocket_manager"]
