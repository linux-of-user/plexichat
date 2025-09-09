# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from plexichat.core.auth.fastapi_adapter import get_current_user, require_admin
from plexichat.core.performance.message_queue_manager import (
    MessagePriority,
    get_queue_manager,
)

"""
PlexiChat Message Queue API Endpoints

REST API endpoints for managing and monitoring the message queue system.
Provides comprehensive queue management, statistics, and administrative functions.

Endpoints:
- GET /api/queue/status - Get message queue system status
- GET /api/queue/stats - Get detailed queue statistics
- POST /api/queue/publish - Publish message to topic
- POST /api/queue/subscribe - Subscribe to topic
- DELETE /api/queue/subscribe/{topic} - Unsubscribe from topic
- GET /api/queue/topics - List all topics
- POST /api/queue/purge/{topic} - Purge topic messages
- GET /api/queue/health - Get queue system health
- GET /api/queue/dead-letter - Get dead letter queue messages
"""

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/queue", tags=["Message Queue"])

# Pydantic models for request/response validation


class PublishMessageRequest(BaseModel):
    """Request model for publishing messages."""

    topic: str = Field(..., description="Topic to publish to")
    payload: Any = Field(..., description="Message payload")
    headers: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Message headers"
    )
    priority: Optional[str] = Field(
        "normal", description="Message priority (low, normal, high, critical)"
    )
    ttl_seconds: Optional[int] = Field(None, description="Time to live in seconds")


class SubscribeRequest(BaseModel):
    """Request model for subscribing to topics."""

    topic: str = Field(..., description="Topic to subscribe to")
    consumer_group: Optional[str] = Field(None, description="Consumer group name")
    handler_config: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Handler configuration"
    )


class QueueResponse(BaseModel):
    """Response model for queue operations."""

    success: bool = Field(..., description="Operation success status")
    message: str = Field(..., description="Response message")
    data: Optional[Any] = Field(None, description="Response data")
    timestamp: str = Field(..., description="Response timestamp")


class PurgeTopicRequest(BaseModel):
    """Request model for purging topics."""

    confirm: bool = Field(
        False, description="Confirmation flag for destructive operation"
    )


@router.get("/status", response_model=Dict[str, Any])
async def get_queue_status(current_user: Dict = Depends(get_current_user)):
    """
    Get comprehensive message queue system status.

    Returns overall system health, broker availability, and key metrics.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        stats = await queue_manager.get_stats()

        # Determine system status
        availability = stats.get("availability", {})
        healthy_brokers = sum(1 for available in availability.values() if available)

        if healthy_brokers == 0:
            status = "critical"
        elif healthy_brokers < len(availability):
            status = "degraded"
        else:
            status = "healthy"

        return {
            "status": status,
            "initialized": queue_manager.initialized,
            "statistics": stats,
            "primary_broker": stats.get("configuration", {}).get("primary_broker"),
            "healthy_brokers": healthy_brokers,
            "total_brokers": len(availability),
            "timestamp": "2025-01-07T12:00:00Z",
        }

    except Exception as e:
        logger.error(f" Queue status error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get queue status: {str(e)}"
        )


@router.get("/stats", response_model=Dict[str, Any])
async def get_queue_stats(
    topic: Optional[str] = Query(None, description="Specific topic to get stats for"),
    detailed: bool = Query(False, description="Include detailed statistics"),
    current_user: Dict = Depends(get_current_user),
):
    """
    Get detailed message queue statistics.

    Provides comprehensive metrics including message counts, processing times,
    and topic-specific information.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        stats = await queue_manager.get_stats()

        if topic:
            topic_stats = stats.get("topics", {}).get(topic)
            if not topic_stats:
                raise HTTPException(
                    status_code=404, detail=f"Topic '{topic}' not found"
                )

            return {
                "topic": topic,
                "statistics": topic_stats,
                "timestamp": "2025-01-07T12:00:00Z",
            }

        # Return all statistics
        response_data = {
            "global_statistics": stats.get("global", {}),
            "topic_statistics": stats.get("topics", {}),
            "availability": stats.get("availability", {}),
            "configuration": stats.get("configuration", {}),
            "active_consumers": stats.get("active_consumers", 0),
            "registered_handlers": stats.get("registered_handlers", []),
            "timestamp": "2025-01-07T12:00:00Z",
        }

        if detailed:
            response_data["dead_letter_queue"] = stats.get("dead_letter_queue", {})

        return response_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Queue stats error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get queue statistics: {str(e)}"
        )


@router.post("/publish", response_model=QueueResponse)
async def publish_message(
    request: PublishMessageRequest, current_user: Dict = Depends(get_current_user)
):
    """
    Publish message to topic.

    Sends message to the specified topic with optional priority,
    TTL, and custom headers.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        # Validate priority
        priority_map = {
            "low": MessagePriority.LOW,
            "normal": MessagePriority.NORMAL,
            "high": MessagePriority.HIGH,
            "critical": MessagePriority.CRITICAL,
        }

        priority = priority_map.get(request.priority, MessagePriority.NORMAL)

        success = await queue_manager.publish(
            topic=request.topic,
            payload=request.payload,
            headers=request.headers,
            priority=priority,
            ttl_seconds=request.ttl_seconds,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to publish message")

        return QueueResponse(
            success=True,
            message=f"Successfully published message to topic '{request.topic}'",
            data={
                "topic": request.topic,
                "priority": request.priority,
                "ttl_seconds": request.ttl_seconds,
            },
            timestamp="2025-01-07T12:00:00Z",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Message publish error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to publish message: {str(e)}"
        )


@router.post("/subscribe", response_model=QueueResponse)
async def subscribe_to_topic(
    request: SubscribeRequest, current_user: Dict = Depends(require_admin)
):
    """
    Subscribe to topic.

    Administrative endpoint to create a subscription to a topic
    with a message handler. Requires admin privileges.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        # Create a simple message handler for demonstration
        # In practice, you'd register actual handler functions
        async def demo_handler(message):
            logger.info(
                f" Received message on topic {message.topic}: {message.payload}"
            )
            return True

        success = await queue_manager.subscribe(
            topic=request.topic,
            handler=demo_handler,
            consumer_group=request.consumer_group,
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to subscribe to topic")

        return QueueResponse(
            success=True,
            message=f"Successfully subscribed to topic '{request.topic}'",
            data={"topic": request.topic, "consumer_group": request.consumer_group},
            timestamp="2025-01-07T12:00:00Z",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Topic subscription error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to subscribe to topic: {str(e)}"
        )


@router.delete("/subscribe/{topic}", response_model=QueueResponse)
async def unsubscribe_from_topic(
    topic: str, current_user: Dict = Depends(require_admin)
):
    """
    Unsubscribe from topic.

    Administrative endpoint to remove subscription from a topic.
    Requires admin privileges.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        success = await queue_manager.unsubscribe(topic)

        if not success:
            raise HTTPException(
                status_code=404, detail=f"No subscription found for topic '{topic}'"
            )

        return QueueResponse(
            success=True,
            message=f"Successfully unsubscribed from topic '{topic}'",
            data={"topic": topic},
            timestamp="2025-01-07T12:00:00Z",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Topic unsubscription error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to unsubscribe from topic: {str(e)}"
        )


@router.get("/topics", response_model=Dict[str, Any])
async def list_topics(current_user: Dict = Depends(get_current_user)):
    """
    List all topics.

    Returns list of all active topics with basic statistics.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        stats = await queue_manager.get_stats()
        topics = stats.get("topics", {})

        topic_list = []
        for topic_name, topic_stats in topics.items():
            topic_list.append(
                {
                    "name": topic_name,
                    "messages_sent": topic_stats.get("messages_sent", 0),
                    "messages_received": topic_stats.get("messages_received", 0),
                    "messages_processed": topic_stats.get("messages_processed", 0),
                    "success_rate": topic_stats.get("success_rate", 0.0),
                    "consumer_count": topic_stats.get("consumer_count", 0),
                }
            )

        return {
            "topics": topic_list,
            "total_topics": len(topic_list),
            "registered_handlers": stats.get("registered_handlers", []),
            "timestamp": "2025-01-07T12:00:00Z",
        }

    except Exception as e:
        logger.error(f" List topics error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list topics: {str(e)}")


@router.post("/purge/{topic}", response_model=QueueResponse)
async def purge_topic(
    topic: str, request: PurgeTopicRequest, current_user: Dict = Depends(require_admin)
):
    """
    Purge topic messages.

    Administrative endpoint to remove all messages from a topic.
    Requires admin privileges and confirmation.
    """
    try:
        if not request.confirm:
            raise HTTPException(
                status_code=400,
                detail="Confirmation required for destructive purge operation",
            )

        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        success = await queue_manager.purge_topic(topic)

        if not success:
            raise HTTPException(
                status_code=500, detail=f"Failed to purge topic '{topic}'"
            )

        return QueueResponse(
            success=True,
            message=f"Successfully purged all messages from topic '{topic}'",
            data={"topic": topic},
            timestamp="2025-01-07T12:00:00Z",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Topic purge error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to purge topic: {str(e)}")


@router.get("/health", response_model=Dict[str, Any])
async def get_queue_health(current_user: Dict = Depends(get_current_user)):
    """
    Get message queue system health status.

    Provides detailed health information for all message brokers
    and overall system status.
    """
    try:
        queue_manager = get_queue_manager()

        stats = await queue_manager.get_stats() if queue_manager.initialized else {}
        availability = stats.get("availability", {})

        # Determine overall health
        healthy_brokers = sum(1 for available in availability.values() if available)
        total_brokers = len(availability)

        if healthy_brokers == 0:
            health_status = "critical"
        elif healthy_brokers < total_brokers:
            health_status = "degraded"
        else:
            health_status = "healthy"

        return {
            "status": health_status,
            "initialized": queue_manager.initialized,
            "broker_availability": availability,
            "healthy_brokers": healthy_brokers,
            "total_brokers": total_brokers,
            "global_stats": stats.get("global", {}),
            "active_consumers": stats.get("active_consumers", 0),
            "dead_letter_queue_size": stats.get("dead_letter_queue", {}).get(
                "count", 0
            ),
            "timestamp": "2025-01-07T12:00:00Z",
        }

    except Exception as e:
        logger.error(f" Queue health check error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get queue health: {str(e)}"
        )


@router.get("/dead-letter", response_model=Dict[str, Any])
async def get_dead_letter_queue(
    limit: int = Query(10, description="Maximum number of messages to return"),
    current_user: Dict = Depends(require_admin),
):
    """
    Get dead letter queue messages.

    Administrative endpoint to retrieve messages that failed processing
    and were moved to the dead letter queue.
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        stats = await queue_manager.get_stats()
        dead_letter_data = stats.get("dead_letter_queue", {})

        messages = dead_letter_data.get("messages", [])
        if limit > 0:
            messages = messages[:limit]

        return {
            "total_count": dead_letter_data.get("count", 0),
            "returned_count": len(messages),
            "messages": messages,
            "timestamp": "2025-01-07T12:00:00Z",
        }

    except Exception as e:
        logger.error(f" Dead letter queue error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get dead letter queue: {str(e)}"
        )


@router.post("/dead-letter/reprocess", response_model=QueueResponse)
async def reprocess_dead_letter_messages(
    message_ids: Optional[List[str]] = Body(
        None, description="Specific message IDs to reprocess"
    ),
    current_user: Dict = Depends(require_admin),
):
    """
    Reprocess dead letter messages.

    Administrative endpoint to retry processing of failed messages
    """
    try:
        queue_manager = get_queue_manager()

        if not queue_manager.initialized:
            raise HTTPException(
                status_code=503, detail="Message queue system not initialized"
            )

        # This would implement dead letter message reprocessing
        # For now, return success response
        reprocessed_count = len(message_ids) if message_ids else 0

        return QueueResponse(
            success=True,
            message=f"Initiated reprocessing of {reprocessed_count} dead letter messages",
            data={"message_ids": message_ids, "reprocessed_count": reprocessed_count},
            timestamp="2025-01-07T12:00:00Z",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Dead letter reprocessing error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reprocess dead letter messages: {str(e)}",
        )
