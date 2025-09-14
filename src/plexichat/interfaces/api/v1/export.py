"""
Chat Export API Router

Provides endpoints for exporting chat messages in various formats.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from plexichat.core.services.chat_export_service import (
    ExportOptions,
    get_chat_export_service,
)


# Mock user dependency - replace with actual auth
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}


router = APIRouter(prefix="/export", tags=["Export"])


@router.get("/channel/{channel_id}")
async def export_channel_messages(
    channel_id: str,
    format: str = Query(..., description="Export format: json, csv, txt, html"),
    start_date: str | None = Query(
        None, description="Start date in ISO format (YYYY-MM-DDTHH:MM:SS)"
    ),
    end_date: str | None = Query(
        None, description="End date in ISO format (YYYY-MM-DDTHH:MM:SS)"
    ),
    include_attachments: bool = Query(
        False, description="Include attachment information"
    ),
    include_reactions: bool = Query(True, description="Include reaction information"),
    include_threads: bool = Query(False, description="Include thread information"),
    current_user: dict = Depends(get_current_user),
):
    """
    Export messages from a channel.

    Supports multiple formats: JSON, CSV, TXT, HTML
    """
    try:
        # Parse dates
        start_datetime = None
        end_datetime = None

        if start_date:
            try:
                start_datetime = datetime.fromisoformat(
                    start_date.replace("Z", "+00:00")
                )
                if start_datetime.tzinfo is None:
                    start_datetime = start_datetime.replace(tzinfo=UTC)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid start_date format. Use ISO format: YYYY-MM-DDTHH:MM:SS",
                )

        if end_date:
            try:
                end_datetime = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                if end_datetime.tzinfo is None:
                    end_datetime = end_datetime.replace(tzinfo=UTC)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid end_date format. Use ISO format: YYYY-MM-DDTHH:MM:SS",
                )

        # Validate format
        supported_formats = ["json", "csv", "txt", "html"]
        if format not in supported_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {format}. Supported formats: {', '.join(supported_formats)}",
            )

        # Create export options
        options = ExportOptions(
            format=format,
            start_date=start_datetime,
            end_date=end_datetime,
            include_attachments=include_attachments,
            include_reactions=include_reactions,
            include_threads=include_threads,
        )

        # Get export service
        export_service = get_chat_export_service()

        # Export messages
        success, error_message, export_data = export_service.export_messages(
            channel_id=channel_id, user_id=current_user["id"], options=options
        )

        if not success:
            raise HTTPException(
                status_code=403 if "Access denied" in error_message else 404,
                detail=error_message,
            )

        # Determine content type and filename
        content_type = "application/json"
        filename = (
            f"chat_export_{channel_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        if format == "json":
            content_type = "application/json"
            filename += ".json"
        elif format == "csv":
            content_type = "text/csv"
            filename += ".csv"
        elif format == "txt":
            content_type = "text/plain"
            filename += ".txt"
        elif format == "html":
            content_type = "text/html"
            filename += ".html"

        # Create streaming response
        def generate():
            yield export_data

        return StreamingResponse(
            generate(),
            media_type=content_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "X-Export-Format": format,
                "X-Message-Count": str(
                    len(export_data.split("\n")) if format == "txt" else "1"
                ),
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {e!s}")


@router.get("/formats")
async def get_supported_formats():
    """
    Get list of supported export formats.
    """
    return {
        "formats": [
            {
                "format": "json",
                "description": "JSON format with full message metadata",
                "content_type": "application/json",
            },
            {
                "format": "csv",
                "description": "CSV format for spreadsheet applications",
                "content_type": "text/csv",
            },
            {
                "format": "txt",
                "description": "Plain text format for simple viewing",
                "content_type": "text/plain",
            },
            {
                "format": "html",
                "description": "HTML format with styled output",
                "content_type": "text/html",
            },
        ]
    }


@router.get("/channel/{channel_id}/preview")
async def preview_channel_export(
    channel_id: str,
    format: str = Query("json", description="Export format: json, csv, txt, html"),
    limit: int = Query(10, description="Number of messages to preview", ge=1, le=50),
    current_user: dict = Depends(get_current_user),
):
    """
    Preview export data without downloading the full export.
    """
    try:
        # Validate format
        supported_formats = ["json", "csv", "txt", "html"]
        if format not in supported_formats:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported format: {format}. Supported formats: {', '.join(supported_formats)}",
            )

        # Create export options with limit
        options = ExportOptions(
            format=format,
            include_attachments=False,
            include_reactions=True,
            include_threads=False,
        )

        # Get export service
        export_service = get_chat_export_service()

        # Get messages
        messages = export_service.get_channel_messages(channel_id, options)

        # Limit messages for preview
        preview_messages = messages[:limit]

        if not preview_messages:
            return {"preview": "No messages found", "count": 0}

        # Generate preview based on format
        if format == "json":
            preview_data = export_service.export_json(preview_messages, options)
        elif format == "csv":
            preview_data = export_service.export_csv(preview_messages, options)
        elif format == "txt":
            preview_data = export_service.export_txt(preview_messages, options)
        elif format == "html":
            preview_data = export_service.export_html(preview_messages, options)

        return {
            "preview": (
                preview_data[:2000] + "..."
                if len(preview_data) > 2000
                else preview_data
            ),
            "count": len(preview_messages),
            "total_available": len(messages),
            "format": format,
            "truncated": len(preview_data) > 2000,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Preview failed: {e!s}")


if __name__ == "__main__":
    # Example of how to run this API with uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
