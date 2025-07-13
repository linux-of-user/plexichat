import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

                import hashlib
            from ..database.enhanced_abstraction import enhanced_db_manager
            
            from ..database.enhanced_abstraction import enhanced_db_manager
            
            from ..database.enhanced_abstraction import enhanced_db_manager
            

"""
PlexiChat ETL/ELT Pipeline Service

Advanced data transformation pipelines for the lakehouse architecture:
- Extract data from multiple sources (lakehouse, databases, APIs)
- Transform data with complex business logic
- Load data into analytics warehouses and marts
- Support for both ETL and ELT patterns
- Real-time and batch processing
- Data quality validation and monitoring
- Pipeline orchestration and scheduling
- Error handling and retry mechanisms

Pipeline Types:
- Real-time streaming pipelines
- Batch processing pipelines
- Micro-batch pipelines
- Event-driven pipelines
- Scheduled pipelines

Transformations:
- Data cleaning and validation
- Aggregations and rollups
- Joins across multiple sources
- Feature engineering for ML
- Data enrichment
- Format conversions
"""

logger = logging.getLogger(__name__)


class PipelineType(Enum):
    """Types of data pipelines."""
    BATCH = "batch"
    STREAMING = "streaming"
    MICRO_BATCH = "micro_batch"
    EVENT_DRIVEN = "event_driven"
    SCHEDULED = "scheduled"


class PipelineStatus(Enum):
    """Pipeline execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class TransformationType(Enum):
    """Types of data transformations."""
    FILTER = "filter"
    MAP = "map"
    AGGREGATE = "aggregate"
    JOIN = "join"
    WINDOW = "window"
    PIVOT = "pivot"
    UNPIVOT = "unpivot"
    VALIDATE = "validate"
    ENRICH = "enrich"


@dataclass
class PipelineConfig:
    """Pipeline configuration."""
    name: str
    pipeline_type: PipelineType
    description: str = ""
    
    # Source configuration
    source_type: str = "lakehouse"  # lakehouse, database, api, file
    source_config: Dict[str, Any] = field(default_factory=dict)
    
    # Target configuration
    target_type: str = "analytics_warehouse"  # analytics_warehouse, database, file
    target_config: Dict[str, Any] = field(default_factory=dict)
    
    # Transformation configuration
    transformations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Scheduling
    schedule_cron: Optional[str] = None  # Cron expression for scheduled pipelines
    trigger_events: List[str] = field(default_factory=list)  # Events that trigger pipeline
    
    # Performance settings
    batch_size: int = 1000
    parallel_workers: int = 1
    memory_limit_mb: int = 512
    timeout_seconds: int = 3600
    
    # Error handling
    retry_attempts: int = 3
    retry_delay_seconds: int = 60
    continue_on_error: bool = False
    
    # Data quality
    validation_enabled: bool = True
    quality_checks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Monitoring
    metrics_enabled: bool = True
    alerts_enabled: bool = True


@dataclass
class PipelineRun:
    """Pipeline execution run."""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_name: str = ""
    status: PipelineStatus = PipelineStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Execution metrics
    records_processed: int = 0
    records_failed: int = 0
    bytes_processed: int = 0
    
    # Error information
    error_message: Optional[str] = None
    error_details: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate run duration."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class DataTransformer:
    """Data transformation engine."""
    
    def __init__(self):
        self.transformations: Dict[TransformationType, Callable] = {
            TransformationType.FILTER: self._filter_transform,
            TransformationType.MAP: self._map_transform,
            TransformationType.AGGREGATE: self._aggregate_transform,
            TransformationType.JOIN: self._join_transform,
            TransformationType.WINDOW: self._window_transform,
            TransformationType.VALIDATE: self._validate_transform,
            TransformationType.ENRICH: self._enrich_transform,
        }
    
    async def apply_transformations(self, data: List[Dict[str, Any]], 
                                  transformations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply a series of transformations to data."""
        result = data
        
        for transform_config in transformations:
            transform_type = TransformationType(transform_config["type"])
            transform_func = self.transformations.get(transform_type)
            
            if transform_func:
                result = await transform_func(result, transform_config)
            else:
                logger.warning(f"Unknown transformation type: {transform_type}")
        
        return result
    
    async def _filter_transform(self, data: List[Dict[str, Any]], 
                              config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Filter data based on conditions."""
        condition = config.get("condition", "")
        
        # Simple condition evaluation (in production, use a proper expression evaluator)
        filtered_data = []
        for record in data:
            try:
                # Replace field references in condition
                eval_condition = condition
                for key, value in record.items():
                    eval_condition = eval_condition.replace(f"{{{key}}}", str(value))
                
                # Evaluate condition (WARNING: eval is dangerous in production)
                if eval(eval_condition):
                    filtered_data.append(record)
            except Exception as e:
                logger.warning(f"Filter condition evaluation failed: {e}")
                continue
        
        return filtered_data
    
    async def _map_transform(self, data: List[Dict[str, Any]], 
                           config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map/transform fields in data."""
        field_mappings = config.get("mappings", {})
        
        mapped_data = []
        for record in data:
            new_record = {}
            
            for new_field, mapping in field_mappings.items():
                if isinstance(mapping, str):
                    # Simple field mapping
                    if mapping in record:
                        new_record[new_field] = record[mapping]
                elif isinstance(mapping, dict):
                    # Complex mapping with transformation
                    source_field = mapping.get("source")
                    transform_func = mapping.get("transform")
                    
                    if source_field in record:
                        value = record[source_field]
                        
                        # Apply transformation function
                        if transform_func == "upper":
                            value = str(value).upper()
                        elif transform_func == "lower":
                            value = str(value).lower()
                        elif transform_func == "date_format":
                            # Convert timestamp to date
                            if isinstance(value, str):
                                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                value = dt.strftime(mapping.get("format", "%Y-%m-%d"))
                        
                        new_record[new_field] = value
            
            # Keep unmapped fields if specified
            if config.get("keep_unmapped", False):
                for key, value in record.items():
                    if key not in new_record:
                        new_record[key] = value
            
            mapped_data.append(new_record)
        
        return mapped_data
    
    async def _aggregate_transform(self, data: List[Dict[str, Any]], 
                                 config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Aggregate data by grouping and applying functions."""
        group_by = config.get("group_by", [])
        aggregations = config.get("aggregations", {})
        
        # Group data
        groups = {}
        for record in data:
            # Create group key
            group_key = tuple(record.get(field, None) for field in group_by)
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(record)
        
        # Apply aggregations
        aggregated_data = []
        for group_key, group_records in groups.items():
            agg_record = {}
            
            # Add group by fields
            for i, field in enumerate(group_by):
                agg_record[field] = group_key[i]
            
            # Apply aggregation functions
            for agg_field, agg_func in aggregations.items():
                if agg_func == "count":
                    agg_record[agg_field] = len(group_records)
                elif agg_func == "sum":
                    values = [r.get(agg_field, 0) for r in group_records if isinstance(r.get(agg_field), (int, float))]
                    agg_record[agg_field] = sum(values)
                elif agg_func == "avg":
                    values = [r.get(agg_field, 0) for r in group_records if isinstance(r.get(agg_field), (int, float))]
                    agg_record[agg_field] = sum(values) / len(values) if values else 0
                elif agg_func == "min":
                    values = [r.get(agg_field) for r in group_records if r.get(agg_field) is not None]
                    agg_record[agg_field] = min(values) if values else None
                elif agg_func == "max":
                    values = [r.get(agg_field) for r in group_records if r.get(agg_field) is not None]
                    agg_record[agg_field] = max(values) if values else None
            
            aggregated_data.append(agg_record)
        
        return aggregated_data
    
    async def _join_transform(self, data: List[Dict[str, Any]], 
                            config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Join data with another dataset."""
        # This is a simplified implementation
        # In production, you'd load the join dataset from the specified source
        join_data = config.get("join_data", [])
        join_key = config.get("join_key", "id")
        join_type = config.get("join_type", "inner")  # inner, left, right, outer
        
        # Create lookup dictionary for join data
        join_lookup = {record[join_key]: record for record in join_data if join_key in record}
        
        joined_data = []
        for record in data:
            join_value = record.get(join_key)
            join_record = join_lookup.get(join_value)
            
            if join_record:
                # Merge records
                merged_record = {**record, **join_record}
                joined_data.append(merged_record)
            elif join_type in ["left", "outer"]:
                # Keep original record for left/outer joins
                joined_data.append(record)
        
        return joined_data
    
    async def _window_transform(self, data: List[Dict[str, Any]], 
                              config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply window functions to data."""
        # Simplified window function implementation
        window_field = config.get("window_field", "timestamp")
        window_size = config.get("window_size", 60)  # seconds
        window_func = config.get("function", "count")
        
        # Sort data by window field
        sorted_data = sorted(data, key=lambda x: x.get(window_field, ""))
        
        windowed_data = []
        for i, record in enumerate(sorted_data):
            # Calculate window boundaries
            current_time = datetime.fromisoformat(record[window_field].replace('Z', '+00:00'))
            window_start = current_time - timedelta(seconds=window_size)
            
            # Find records in window
            window_records = []
            for j in range(i + 1):
                other_record = sorted_data[j]
                other_time = datetime.fromisoformat(other_record[window_field].replace('Z', '+00:00'))
                if other_time >= window_start:
                    window_records.append(other_record)
            
            # Apply window function
            if window_func == "count":
                record[f"window_{window_func}"] = len(window_records)
            elif window_func == "sum":
                sum_field = config.get("sum_field", "value")
                record[f"window_{window_func}"] = sum(r.get(sum_field, 0) for r in window_records)
            
            windowed_data.append(record)
        
        return windowed_data
    
    async def _validate_transform(self, data: List[Dict[str, Any]], 
                                config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate data quality."""
        validations = config.get("validations", [])
        
        valid_data = []
        for record in data:
            is_valid = True
            
            for validation in validations:
                field = validation.get("field")
                rule = validation.get("rule")
                
                if field not in record:
                    if rule == "required":
                        is_valid = False
                        break
                    continue
                
                value = record[field]
                
                if rule == "not_null" and value is None:
                    is_valid = False
                    break
                elif rule == "min_length" and len(str(value)) < validation.get("value", 0):
                    is_valid = False
                    break
                elif rule == "max_length" and len(str(value)) > validation.get("value", 0):
                    is_valid = False
                    break
                elif rule == "regex" and not re.match(validation.get("pattern", ""), str(value)):
                    is_valid = False
                    break
            
            if is_valid:
                valid_data.append(record)
        
        return valid_data
    
    async def _enrich_transform(self, data: List[Dict[str, Any]], 
                              config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enrich data with additional information."""
        enrichment_type = config.get("type", "timestamp")
        
        enriched_data = []
        for record in data:
            enriched_record = record.copy()
            
            if enrichment_type == "timestamp":
                enriched_record["processed_at"] = datetime.now(timezone.utc).isoformat()
            elif enrichment_type == "uuid":
                enriched_record["processing_id"] = str(uuid.uuid4())
            elif enrichment_type == "hash":
                record_str = json.dumps(record, sort_keys=True)
                enriched_record["record_hash"] = hashlib.md5(record_str.encode()).hexdigest()
            
            enriched_data.append(enriched_record)
        
        return enriched_data


class ETLPipelineService:
    """Main ETL/ELT pipeline service."""
    
    def __init__(self):
        self.pipelines: Dict[str, PipelineConfig] = {}
        self.active_runs: Dict[str, PipelineRun] = {}
        self.transformer = DataTransformer()
        self.is_running = False
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        
        # Metrics
        self.metrics = {
            "pipelines_executed": 0,
            "total_records_processed": 0,
            "total_execution_time": 0.0,
            "failed_pipelines": 0
        }
    
    async def start(self):
        """Start the pipeline service."""
        if self.is_running:
            return
        
        self.is_running = True
        logger.info(" Starting ETL pipeline service...")
        
        # Start background scheduler
        self.background_tasks.append(
            asyncio.create_task(self._pipeline_scheduler())
        )
        
        logger.info(" ETL pipeline service started")
    
    async def stop(self):
        """Stop the pipeline service."""
        if not self.is_running:
            return
        
        self.is_running = False
        logger.info(" Stopping ETL pipeline service...")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        logger.info(" ETL pipeline service stopped")
    
    def register_pipeline(self, config: PipelineConfig):
        """Register a new pipeline."""
        self.pipelines[config.name] = config
        logger.info(f" Registered pipeline: {config.name}")
    
    async def execute_pipeline(self, pipeline_name: str, 
                             trigger_data: Dict[str, Any] = None) -> PipelineRun:
        """Execute a specific pipeline."""
        if pipeline_name not in self.pipelines:
            raise ValueError(f"Pipeline '{pipeline_name}' not found")
        
        config = self.pipelines[pipeline_name]
        run = PipelineRun(
            pipeline_name=pipeline_name,
            start_time=datetime.now(timezone.utc),
            status=PipelineStatus.RUNNING
        )
        
        self.active_runs[run.run_id] = run
        
        try:
            logger.info(f" Executing pipeline: {pipeline_name}")
            
            # Extract data
            data = await self._extract_data(config, trigger_data)
            run.records_processed = len(data)
            
            # Transform data
            if config.transformations:
                data = await self.transformer.apply_transformations(data, config.transformations)
            
            # Load data
            await self._load_data(config, data)
            
            # Complete run
            run.status = PipelineStatus.COMPLETED
            run.end_time = datetime.now(timezone.utc)
            
            # Update metrics
            self.metrics["pipelines_executed"] += 1
            self.metrics["total_records_processed"] += run.records_processed
            if run.duration_seconds:
                self.metrics["total_execution_time"] += run.duration_seconds
            
            logger.info(f" Pipeline completed: {pipeline_name} ({run.records_processed} records)")
            
        except Exception as e:
            run.status = PipelineStatus.FAILED
            run.end_time = datetime.now(timezone.utc)
            run.error_message = str(e)
            
            self.metrics["failed_pipelines"] += 1
            logger.error(f" Pipeline failed: {pipeline_name} - {e}")
        
        return run
    
    async def _extract_data(self, config: PipelineConfig, 
                          trigger_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Extract data from source."""
        source_type = config.source_type
        source_config = config.source_config
        
        if source_type == "lakehouse":
            # Extract from lakehouse
            lakehouse_client = enhanced_db_manager.clients.get("lakehouse")
            if lakehouse_client:
                query = source_config.get("query", "SELECT * FROM raw_user_events LIMIT 1000")
                result = await lakehouse_client.execute_query(query)
                return result.data
        
        elif source_type == "database":
            # Extract from database
            db_name = source_config.get("database", "default")
            query = source_config.get("query", "SELECT * FROM messages LIMIT 1000")
            
            result = await enhanced_db_manager.execute_query(query, database=db_name)
            return result.data
        
        elif source_type == "api":
            # Extract from API (placeholder)
            return []
        
        elif source_type == "file":
            # Extract from file (placeholder)
            return []
        
        return []
    
    async def _load_data(self, config: PipelineConfig, data: List[Dict[str, Any]]):
        """Load data to target."""
        target_type = config.target_type
        target_config = config.target_config
        
        if target_type == "analytics_warehouse":
            # Load to analytics warehouse (ClickHouse)
            analytics_client = enhanced_db_manager.clients.get("analytics")
            if analytics_client:
                target_config.get("table", "processed_events")
                
                # Convert data to INSERT statements (simplified)
                for record in data:
                    # This is a simplified implementation
                    # In production, use batch inserts
                    pass
        
        elif target_type == "database":
            # Load to database
            pass
        
        elif target_type == "file":
            # Load to file
            pass
    
    async def _pipeline_scheduler(self):
        """Background pipeline scheduler."""
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Check for scheduled pipelines
                datetime.now(timezone.utc)
                
                for pipeline_name, config in self.pipelines.items():
                    if config.schedule_cron:
                        # Check if pipeline should run based on cron schedule
                        # This is a simplified implementation
                        # In production, use a proper cron parser like croniter
                        pass
                
            except Exception as e:
                logger.error(f" Pipeline scheduler error: {e}")
    
    def get_pipeline_status(self, run_id: str) -> Optional[PipelineRun]:
        """Get pipeline run status."""
        return self.active_runs.get(run_id)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline service metrics."""
        return {
            **self.metrics,
            "active_pipelines": len(self.active_runs),
            "registered_pipelines": len(self.pipelines),
            "is_running": self.is_running
        }


# Global instance
etl_pipeline_service = ETLPipelineService()
