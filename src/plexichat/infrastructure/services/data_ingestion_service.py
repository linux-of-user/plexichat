import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

            from ..database.enhanced_abstraction import enhanced_db_manager
            

"""
PlexiChat Data Ingestion Service

Comprehensive data ingestion system for streaming application data to the lakehouse:
- Real-time event streaming
- Database change data capture (CDC)
- Application log ingestion
- User activity tracking
- File upload metadata
- System metrics collection
- Batch and streaming processing
- Data quality validation
- Schema evolution handling

Data Sources:
- Application logs (structured JSON)
- User events (login, logout, message_send, etc.)
- Database changes (messages, users, files)
- System metrics (performance, errors)
- WebSocket events
- API access logs
- File operations
- Security events
"""

logger = logging.getLogger(__name__)


class DataSourceType(Enum):
    """Types of data sources."""
    APPLICATION_LOGS = "application_logs"
    USER_EVENTS = "user_events"
    DATABASE_CHANGES = "database_changes"
    SYSTEM_METRICS = "system_metrics"
    API_LOGS = "api_logs"
    WEBSOCKET_EVENTS = "websocket_events"
    FILE_OPERATIONS = "file_operations"
    SECURITY_EVENTS = "security_events"
    PERFORMANCE_METRICS = "performance_metrics"


class IngestionMode(Enum):
    """Data ingestion modes."""
    REAL_TIME = "real_time"
    BATCH = "batch"
    MICRO_BATCH = "micro_batch"


@dataclass
class DataEvent:
    """Standardized data event structure."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    source_type: DataSourceType = DataSourceType.USER_EVENTS
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source_type": self.source_type.value,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "data": self.data,
            "metadata": self.metadata
        }


@dataclass
class IngestionConfig:
    """Data ingestion configuration."""
    # Lakehouse settings
    lakehouse_enabled: bool = True
    lakehouse_table_prefix: str = "raw_"
    
    # Batch settings
    batch_size: int = 1000
    batch_timeout_seconds: int = 30
    max_batch_memory_mb: int = 100
    
    # Real-time settings
    buffer_size: int = 10000
    flush_interval_seconds: int = 5
    
    # Data quality
    validation_enabled: bool = True
    schema_enforcement: bool = True
    duplicate_detection: bool = True
    
    # Partitioning
    partition_by_date: bool = True
    partition_by_source: bool = True
    
    # Retention
    raw_data_retention_days: int = 90
    processed_data_retention_days: int = 365
    
    # Performance
    compression_enabled: bool = True
    compression_format: str = "snappy"
    
    # Monitoring
    metrics_enabled: bool = True
    alert_on_failures: bool = True


class DataIngestionService:
    """Main data ingestion service."""
    
    def __init__(self, config: IngestionConfig = None):
        self.config = config or IngestionConfig()
        self.is_running = False
        
        # Data buffers
        self.event_buffer: List[DataEvent] = []
        self.batch_buffer: Dict[str, List[DataEvent]] = {}
        
        # Processors
        self.processors: Dict[DataSourceType, Callable] = {}
        self.validators: Dict[DataSourceType, Callable] = {}
        
        # Metrics
        self.metrics = {
            "events_ingested": 0,
            "events_processed": 0,
            "events_failed": 0,
            "batches_written": 0,
            "total_processing_time": 0.0,
            "last_batch_time": None
        }
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        
        # Initialize default processors
        self._init_default_processors()
    
    def _init_default_processors(self):
        """Initialize default data processors."""
        self.processors[DataSourceType.APPLICATION_LOGS] = self._process_application_logs
        self.processors[DataSourceType.USER_EVENTS] = self._process_user_events
        self.processors[DataSourceType.DATABASE_CHANGES] = self._process_database_changes
        self.processors[DataSourceType.SYSTEM_METRICS] = self._process_system_metrics
        self.processors[DataSourceType.API_LOGS] = self._process_api_logs
        self.processors[DataSourceType.WEBSOCKET_EVENTS] = self._process_websocket_events
        self.processors[DataSourceType.FILE_OPERATIONS] = self._process_file_operations
        self.processors[DataSourceType.SECURITY_EVENTS] = self._process_security_events
    
    async def start(self):
        """Start the ingestion service."""
        if self.is_running:
            return
        
        self.is_running = True
        logger.info(" Starting data ingestion service...")
        
        # Start background tasks
        if self.config.lakehouse_enabled:
            self.background_tasks.append(
                asyncio.create_task(self._batch_processor())
            )
        
        self.background_tasks.append(
            asyncio.create_task(self._metrics_collector())
        )
        
        logger.info(" Data ingestion service started")
    
    async def stop(self):
        """Stop the ingestion service."""
        if not self.is_running:
            return
        
        self.is_running = False
        logger.info(" Stopping data ingestion service...")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Flush remaining data
        await self._flush_buffers()
        
        logger.info(" Data ingestion service stopped")
    
    async def ingest_event(self, event: DataEvent) -> bool:
        """Ingest a single data event."""
        try:
            # Validate event
            if self.config.validation_enabled:
                if not await self._validate_event(event):
                    self.metrics["events_failed"] += 1
                    return False
            
            # Process event
            processor = self.processors.get(event.source_type)
            if processor:
                event = await processor(event)
            
            # Add to buffer
            self.event_buffer.append(event)
            self.metrics["events_ingested"] += 1
            
            # Check if buffer needs flushing
            if len(self.event_buffer) >= self.config.batch_size:
                await self._flush_event_buffer()
            
            return True
            
        except Exception as e:
            logger.error(f" Event ingestion failed: {e}")
            self.metrics["events_failed"] += 1
            return False
    
    async def ingest_batch(self, events: List[DataEvent]) -> int:
        """Ingest a batch of events."""
        successful = 0
        
        for event in events:
            if await self.ingest_event(event):
                successful += 1
        
        return successful
    
    async def ingest_log_entry(self, level: str, module: str, message: str, 
                             extra_data: Dict[str, Any] = None) -> bool:
        """Ingest application log entry."""
        event = DataEvent(
            event_type="log_entry",
            source_type=DataSourceType.APPLICATION_LOGS,
            data={
                "level": level,
                "module": module,
                "message": message,
                "extra": extra_data or {}
            }
        )
        
        return await self.ingest_event(event)
    
    async def ingest_user_event(self, user_id: str, event_type: str, 
                              session_id: str = None, data: Dict[str, Any] = None) -> bool:
        """Ingest user activity event."""
        event = DataEvent(
            event_type=event_type,
            source_type=DataSourceType.USER_EVENTS,
            user_id=user_id,
            session_id=session_id,
            data=data or {}
        )
        
        return await self.ingest_event(event)
    
    async def ingest_database_change(self, table: str, operation: str, 
                                   record_id: str, changes: Dict[str, Any]) -> bool:
        """Ingest database change event."""
        event = DataEvent(
            event_type="database_change",
            source_type=DataSourceType.DATABASE_CHANGES,
            data={
                "table": table,
                "operation": operation,
                "record_id": record_id,
                "changes": changes
            }
        )
        
        return await self.ingest_event(event)
    
    async def ingest_api_request(self, method: str, endpoint: str, user_id: str = None,
                               response_code: int = None, response_time: float = None,
                               request_data: Dict[str, Any] = None) -> bool:
        """Ingest API request log."""
        event = DataEvent(
            event_type="api_request",
            source_type=DataSourceType.API_LOGS,
            user_id=user_id,
            data={
                "method": method,
                "endpoint": endpoint,
                "response_code": response_code,
                "response_time": response_time,
                "request_data": request_data or {}
            }
        )
        
        return await self.ingest_event(event)
    
    async def ingest_system_metric(self, metric_name: str, value: float, 
                                 tags: Dict[str, str] = None) -> bool:
        """Ingest system performance metric."""
        event = DataEvent(
            event_type="system_metric",
            source_type=DataSourceType.SYSTEM_METRICS,
            data={
                "metric_name": metric_name,
                "value": value,
                "tags": tags or {}
            }
        )
        
        return await self.ingest_event(event)
    
    async def _validate_event(self, event: DataEvent) -> bool:
        """Validate data event."""
        try:
            # Basic validation
            if not event.event_type:
                logger.warning("Event missing event_type")
                return False
            
            if not event.timestamp:
                logger.warning("Event missing timestamp")
                return False
            
            # Source-specific validation
            validator = self.validators.get(event.source_type)
            if validator:
                return await validator(event)
            
            return True
            
        except Exception as e:
            logger.error(f"Event validation failed: {e}")
            return False
    
    async def _flush_event_buffer(self):
        """Flush event buffer to storage."""
        if not self.event_buffer:
            return
        
        try:
            # Group events by source type for efficient storage
            grouped_events = {}
            for event in self.event_buffer:
                source_key = event.source_type.value
                if source_key not in grouped_events:
                    grouped_events[source_key] = []
                grouped_events[source_key].append(event)
            
            # Write to lakehouse
            if self.config.lakehouse_enabled:
                await self._write_to_lakehouse(grouped_events)
            
            # Update metrics
            self.metrics["events_processed"] += len(self.event_buffer)
            self.metrics["batches_written"] += 1
            self.metrics["last_batch_time"] = datetime.now(timezone.utc)
            
            # Clear buffer
            self.event_buffer.clear()
            
        except Exception as e:
            logger.error(f" Failed to flush event buffer: {e}")
    
    async def _write_to_lakehouse(self, grouped_events: Dict[str, List[DataEvent]]):
        """Write events to lakehouse."""
        try:
            for source_type, events in grouped_events.items():
                table_name = f"{self.config.lakehouse_table_prefix}{source_type}"
                
                # Convert events to dictionaries
                data = [event.to_dict() for event in events]
                
                # Add partitioning columns
                if self.config.partition_by_date:
                    for record in data:
                        timestamp = datetime.fromisoformat(record["timestamp"].replace('Z', '+00:00'))
                        record["year"] = timestamp.year
                        record["month"] = timestamp.month
                        record["day"] = timestamp.day
                        record["hour"] = timestamp.hour
                
                # Write to lakehouse
                lakehouse_client = enhanced_db_manager.clients.get("lakehouse")
                if lakehouse_client:
                    await lakehouse_client.ingest_data(table_name, data, mode="append")
                
        except Exception as e:
            logger.error(f" Lakehouse write failed: {e}")
            raise
    
    async def _batch_processor(self):
        """Background batch processor."""
        while self.is_running:
            try:
                await asyncio.sleep(self.config.flush_interval_seconds)
                
                if self.event_buffer:
                    await self._flush_event_buffer()
                    
            except Exception as e:
                logger.error(f" Batch processor error: {e}")
    
    async def _metrics_collector(self):
        """Background metrics collector."""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Collect metrics every minute
                
                # Collect system metrics
                await self.ingest_system_metric("ingestion_events_per_minute", 
                                               self.metrics["events_ingested"])
                await self.ingest_system_metric("ingestion_buffer_size", 
                                               len(self.event_buffer))
                
            except Exception as e:
                logger.error(f" Metrics collector error: {e}")
    
    async def _flush_buffers(self):
        """Flush all remaining buffers."""
        if self.event_buffer:
            await self._flush_event_buffer()
    
    # Default processors
    async def _process_application_logs(self, event: DataEvent) -> DataEvent:
        """Process application log events."""
        # Add standard fields
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "application_logs"
        return event
    
    async def _process_user_events(self, event: DataEvent) -> DataEvent:
        """Process user activity events."""
        # Add user context
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "user_events"
        return event
    
    async def _process_database_changes(self, event: DataEvent) -> DataEvent:
        """Process database change events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "database_changes"
        return event
    
    async def _process_system_metrics(self, event: DataEvent) -> DataEvent:
        """Process system metric events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "system_metrics"
        return event
    
    async def _process_api_logs(self, event: DataEvent) -> DataEvent:
        """Process API log events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "api_logs"
        return event
    
    async def _process_websocket_events(self, event: DataEvent) -> DataEvent:
        """Process WebSocket events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "websocket_events"
        return event
    
    async def _process_file_operations(self, event: DataEvent) -> DataEvent:
        """Process file operation events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "file_operations"
        return event
    
    async def _process_security_events(self, event: DataEvent) -> DataEvent:
        """Process security events."""
        event.metadata["processed_at"] = datetime.now(timezone.utc).isoformat()
        event.metadata["processor"] = "security_events"
        event.metadata["security_level"] = "high"
        return event
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get ingestion metrics."""
        return {
            **self.metrics,
            "buffer_size": len(self.event_buffer),
            "is_running": self.is_running,
            "config": {
                "batch_size": self.config.batch_size,
                "flush_interval": self.config.flush_interval_seconds,
                "lakehouse_enabled": self.config.lakehouse_enabled
            }
        }


# Global instance
data_ingestion_service = DataIngestionService()
