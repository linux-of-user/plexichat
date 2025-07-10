"""
PlexiChat Zero-Downtime Database Migration System

Advanced migration system with:
- Zero-downtime schema changes
- Dual-write strategies for seamless transitions
- Incremental schema evolution
- Automatic rollback on failure
- Multi-database coordination
- Real-time validation and monitoring
"""

import asyncio
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class MigrationPhase(Enum):
    """Phases of zero-downtime migration."""
    PREPARING = "preparing"
    DUAL_WRITE_SETUP = "dual_write_setup"
    SCHEMA_CHANGE = "schema_change"
    DATA_MIGRATION = "data_migration"
    VALIDATION = "validation"
    CUTOVER = "cutover"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"


class MigrationStrategy(Enum):
    """Migration strategies for different scenarios."""
    EXPAND_CONTRACT = "expand_contract"  # Add new, migrate data, remove old
    DUAL_WRITE = "dual_write"  # Write to both old and new schemas
    SHADOW_TABLE = "shadow_table"  # Create shadow table, sync, swap
    ONLINE_DDL = "online_ddl"  # Use database-specific online DDL
    BLUE_GREEN = "blue_green"  # Complete database switch


class ConsistencyLevel(Enum):
    """Data consistency levels during migration."""
    EVENTUAL = "eventual"
    STRONG = "strong"
    CAUSAL = "causal"
    MONOTONIC = "monotonic"


@dataclass
class MigrationStep:
    """Individual migration step."""
    step_id: str
    phase: MigrationPhase
    description: str
    sql_commands: List[str] = field(default_factory=list)
    validation_queries: List[str] = field(default_factory=list)
    rollback_commands: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 3
    requires_dual_write: bool = False
    
    def __post_init__(self):
        """Validate migration step."""
        if not self.sql_commands and self.phase != MigrationPhase.VALIDATION:
            raise ValueError(f"Migration step {self.step_id} requires SQL commands")


@dataclass
class ZeroDowntimeMigration:
    """Zero-downtime migration configuration."""
    migration_id: str
    name: str
    description: str
    strategy: MigrationStrategy
    consistency_level: ConsistencyLevel
    steps: List[MigrationStep] = field(default_factory=list)
    affected_tables: Set[str] = field(default_factory=set)
    dual_write_duration_minutes: int = 30
    validation_timeout_minutes: int = 10
    rollback_timeout_minutes: int = 15
    
    # Migration metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    target_databases: List[str] = field(default_factory=list)
    
    def add_step(self, step: MigrationStep):
        """Add migration step."""
        self.steps.append(step)
        
        # Extract affected tables from SQL commands
        for command in step.sql_commands:
            self._extract_table_names(command)
    
    def _extract_table_names(self, sql: str):
        """Extract table names from SQL command."""
        # Simplified table name extraction
        sql_upper = sql.upper()
        keywords = ["CREATE TABLE", "ALTER TABLE", "DROP TABLE", "INSERT INTO", "UPDATE", "DELETE FROM"]
        
        for keyword in keywords:
            if keyword in sql_upper:
                # Extract table name after keyword
                parts = sql_upper.split(keyword)
                if len(parts) > 1:
                    table_part = parts[1].strip().split()[0]
                    table_name = table_part.replace("IF NOT EXISTS", "").replace("IF EXISTS", "").strip()
                    if table_name:
                        self.affected_tables.add(table_name.lower())


@dataclass
class MigrationExecution:
    """Migration execution state and results."""
    migration_id: str
    current_phase: MigrationPhase
    current_step: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    success: bool = False
    error: Optional[str] = None
    
    # Execution tracking
    completed_steps: List[str] = field(default_factory=list)
    failed_steps: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)
    
    # Performance metrics
    total_duration_seconds: float = 0.0
    step_durations: Dict[str, float] = field(default_factory=dict)
    data_migrated_rows: int = 0
    validation_results: Dict[str, bool] = field(default_factory=dict)
    
    # Dual-write tracking
    dual_write_active: bool = False
    dual_write_errors: int = 0
    dual_write_lag_ms: float = 0.0


class DualWriteManager:
    """Manages dual-write operations during migration."""
    
    def __init__(self):
        self.active_dual_writes: Dict[str, Dict[str, Any]] = {}
        self.write_interceptors: Dict[str, Callable] = {}
        self.error_counts: Dict[str, int] = {}
        
    async def setup_dual_write(self, table_name: str, old_schema: Dict[str, Any], 
                             new_schema: Dict[str, Any]) -> bool:
        """Setup dual-write for table migration."""
        try:
            dual_write_config = {
                "table_name": table_name,
                "old_schema": old_schema,
                "new_schema": new_schema,
                "field_mapping": self._create_field_mapping(old_schema, new_schema),
                "started_at": datetime.now(timezone.utc),
                "write_count": 0,
                "error_count": 0
            }
            
            self.active_dual_writes[table_name] = dual_write_config
            
            # Setup write interceptor
            self.write_interceptors[table_name] = self._create_write_interceptor(table_name)
            
            logger.info(f"Dual-write setup completed for table: {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup dual-write for {table_name}: {e}")
            return False
    
    def _create_field_mapping(self, old_schema: Dict[str, Any], new_schema: Dict[str, Any]) -> Dict[str, str]:
        """Create field mapping between old and new schemas."""
        mapping = {}
        
        # Direct field mappings
        for old_field, old_type in old_schema.items():
            if old_field in new_schema:
                mapping[old_field] = old_field
        
        # Custom mappings would be configured here
        # For example: mapping["old_name"] = "new_name"
        
        return mapping
    
    def _create_write_interceptor(self, table_name: str) -> Callable:
        """Create write interceptor for dual-write operations."""
        async def interceptor(operation: str, data: Dict[str, Any]) -> bool:
            try:
                config = self.active_dual_writes[table_name]
                
                # Transform data for new schema
                transformed_data = self._transform_data(data, config["field_mapping"])
                
                # Write to both old and new schemas
                old_success = await self._write_to_old_schema(table_name, operation, data)
                new_success = await self._write_to_new_schema(table_name, operation, transformed_data)
                
                config["write_count"] += 1
                
                if not (old_success and new_success):
                    config["error_count"] += 1
                    self.error_counts[table_name] = self.error_counts.get(table_name, 0) + 1
                
                return old_success and new_success
                
            except Exception as e:
                logger.error(f"Dual-write interceptor error for {table_name}: {e}")
                self.error_counts[table_name] = self.error_counts.get(table_name, 0) + 1
                return False
        
        return interceptor
    
    def _transform_data(self, data: Dict[str, Any], field_mapping: Dict[str, str]) -> Dict[str, Any]:
        """Transform data according to field mapping."""
        transformed = {}
        
        for old_field, new_field in field_mapping.items():
            if old_field in data:
                transformed[new_field] = data[old_field]
        
        return transformed
    
    async def _write_to_old_schema(self, table_name: str, operation: str, data: Dict[str, Any]) -> bool:
        """Write to old schema."""
        # Placeholder for actual database write
        # In production, this would execute the SQL operation
        return True
    
    async def _write_to_new_schema(self, table_name: str, operation: str, data: Dict[str, Any]) -> bool:
        """Write to new schema."""
        # Placeholder for actual database write
        # In production, this would execute the SQL operation
        return True
    
    async def cleanup_dual_write(self, table_name: str):
        """Cleanup dual-write configuration."""
        if table_name in self.active_dual_writes:
            del self.active_dual_writes[table_name]
        
        if table_name in self.write_interceptors:
            del self.write_interceptors[table_name]
        
        logger.info(f"Dual-write cleanup completed for table: {table_name}")


class ZeroDowntimeMigrationManager:
    """Manages zero-downtime database migrations."""
    
    def __init__(self):
        self.active_migrations: Dict[str, MigrationExecution] = {}
        self.migration_history: List[MigrationExecution] = []
        self.dual_write_manager = DualWriteManager()
        
        # Migration configuration
        self.max_concurrent_migrations = 1
        self.validation_enabled = True
        self.automatic_rollback = True
        self.monitoring_enabled = True
        
    async def initialize(self):
        """Initialize zero-downtime migration manager."""
        await self._create_migration_tables()
        await self._load_migration_history()
        logger.info("Zero-downtime migration manager initialized")
    
    async def _create_migration_tables(self):
        """Create migration tracking tables."""
        # In production, this would create actual database tables
        logger.info("Migration tracking tables created")
    
    async def _load_migration_history(self):
        """Load migration history from database."""
        # In production, this would load from actual database
        logger.info("Migration history loaded")
    
    async def execute_migration(self, migration: ZeroDowntimeMigration) -> MigrationExecution:
        """Execute zero-downtime migration."""
        execution = MigrationExecution(
            migration_id=migration.migration_id,
            current_phase=MigrationPhase.PREPARING,
            current_step=0,
            started_at=datetime.now(timezone.utc)
        )
        
        self.active_migrations[migration.migration_id] = execution
        
        try:
            logger.info(f"Starting zero-downtime migration: {migration.name}")
            
            # Execute migration phases
            for phase in MigrationPhase:
                if phase in [MigrationPhase.FAILED, MigrationPhase.ROLLING_BACK, MigrationPhase.COMPLETED]:
                    continue
                
                execution.current_phase = phase
                success = await self._execute_phase(migration, execution, phase)
                
                if not success:
                    execution.current_phase = MigrationPhase.FAILED
                    execution.error = f"Failed in phase: {phase.value}"
                    
                    if self.automatic_rollback:
                        await self._rollback_migration(migration, execution)
                    
                    break
            
            if execution.current_phase != MigrationPhase.FAILED:
                execution.current_phase = MigrationPhase.COMPLETED
                execution.success = True
                execution.completed_at = datetime.now(timezone.utc)
                execution.total_duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
                
                logger.info(f"Migration completed successfully: {migration.name}")
            
        except Exception as e:
            execution.current_phase = MigrationPhase.FAILED
            execution.error = str(e)
            execution.completed_at = datetime.now(timezone.utc)
            
            logger.error(f"Migration failed: {migration.name} - {e}")
            
            if self.automatic_rollback:
                await self._rollback_migration(migration, execution)
        
        # Cleanup and store results
        self.migration_history.append(execution)
        if migration.migration_id in self.active_migrations:
            del self.active_migrations[migration.migration_id]
        
        return execution

    async def _execute_phase(self, migration: ZeroDowntimeMigration,
                           execution: MigrationExecution, phase: MigrationPhase) -> bool:
        """Execute specific migration phase."""
        try:
            logger.info(f"Executing phase: {phase.value}")

            if phase == MigrationPhase.PREPARING:
                return await self._prepare_migration(migration, execution)
            elif phase == MigrationPhase.DUAL_WRITE_SETUP:
                return await self._setup_dual_write_phase(migration, execution)
            elif phase == MigrationPhase.SCHEMA_CHANGE:
                return await self._execute_schema_changes(migration, execution)
            elif phase == MigrationPhase.DATA_MIGRATION:
                return await self._migrate_data(migration, execution)
            elif phase == MigrationPhase.VALIDATION:
                return await self._validate_migration(migration, execution)
            elif phase == MigrationPhase.CUTOVER:
                return await self._execute_cutover(migration, execution)
            elif phase == MigrationPhase.CLEANUP:
                return await self._cleanup_migration(migration, execution)

            return True

        except Exception as e:
            logger.error(f"Phase {phase.value} failed: {e}")
            return False

    async def _prepare_migration(self, migration: ZeroDowntimeMigration,
                               execution: MigrationExecution) -> bool:
        """Prepare migration environment."""
        try:
            # Validate migration configuration
            if not migration.steps:
                raise ValueError("Migration has no steps defined")

            # Check database connectivity
            for db_name in migration.target_databases:
                if not await self._check_database_connection(db_name):
                    raise Exception(f"Cannot connect to database: {db_name}")

            # Create backup if required
            if migration.strategy in [MigrationStrategy.EXPAND_CONTRACT, MigrationStrategy.SHADOW_TABLE]:
                await self._create_migration_backup(migration.migration_id)

            logger.info("Migration preparation completed")
            return True

        except Exception as e:
            logger.error(f"Migration preparation failed: {e}")
            return False

    async def _setup_dual_write_phase(self, migration: ZeroDowntimeMigration,
                                    execution: MigrationExecution) -> bool:
        """Setup dual-write for affected tables."""
        try:
            if migration.strategy not in [MigrationStrategy.DUAL_WRITE, MigrationStrategy.EXPAND_CONTRACT]:
                return True  # Skip if not needed

            for table_name in migration.affected_tables:
                # Get current and target schemas
                old_schema = await self._get_table_schema(table_name)
                new_schema = await self._get_target_schema(table_name, migration)

                # Setup dual-write
                success = await self.dual_write_manager.setup_dual_write(
                    table_name, old_schema, new_schema
                )

                if not success:
                    raise Exception(f"Failed to setup dual-write for table: {table_name}")

                execution.dual_write_active = True

            # Wait for dual-write to stabilize
            await asyncio.sleep(5)

            logger.info("Dual-write setup completed")
            return True

        except Exception as e:
            logger.error(f"Dual-write setup failed: {e}")
            return False

    async def _execute_schema_changes(self, migration: ZeroDowntimeMigration,
                                    execution: MigrationExecution) -> bool:
        """Execute schema changes."""
        try:
            schema_steps = [step for step in migration.steps if step.phase == MigrationPhase.SCHEMA_CHANGE]

            for step in schema_steps:
                step_start = datetime.now()

                # Execute SQL commands
                for sql_command in step.sql_commands:
                    await self._execute_sql_with_retry(sql_command, step.retry_count)

                # Validate step
                if step.validation_queries:
                    for validation_query in step.validation_queries:
                        result = await self._execute_validation_query(validation_query)
                        if not result:
                            raise Exception(f"Validation failed for step: {step.step_id}")

                # Track timing
                step_duration = (datetime.now() - step_start).total_seconds()
                execution.step_durations[step.step_id] = step_duration
                execution.completed_steps.append(step.step_id)

                logger.info(f"Schema change step completed: {step.step_id}")

            return True

        except Exception as e:
            logger.error(f"Schema changes failed: {e}")
            return False

    async def _migrate_data(self, migration: ZeroDowntimeMigration,
                          execution: MigrationExecution) -> bool:
        """Migrate data between schemas."""
        try:
            data_steps = [step for step in migration.steps if step.phase == MigrationPhase.DATA_MIGRATION]

            for step in data_steps:
                step_start = datetime.now()

                # Execute data migration commands
                for sql_command in step.sql_commands:
                    rows_affected = await self._execute_data_migration_sql(sql_command)
                    execution.data_migrated_rows += rows_affected

                # Track timing
                step_duration = (datetime.now() - step_start).total_seconds()
                execution.step_durations[step.step_id] = step_duration
                execution.completed_steps.append(step.step_id)

                logger.info(f"Data migration step completed: {step.step_id}")

            return True

        except Exception as e:
            logger.error(f"Data migration failed: {e}")
            return False

    async def _validate_migration(self, migration: ZeroDowntimeMigration,
                                execution: MigrationExecution) -> bool:
        """Validate migration results."""
        try:
            validation_steps = [step for step in migration.steps if step.phase == MigrationPhase.VALIDATION]

            for step in validation_steps:
                for validation_query in step.validation_queries:
                    result = await self._execute_validation_query(validation_query)
                    execution.validation_results[validation_query] = result

                    if not result:
                        logger.error(f"Validation failed: {validation_query}")
                        return False

            # Additional consistency checks
            if migration.consistency_level == ConsistencyLevel.STRONG:
                if not await self._verify_strong_consistency(migration):
                    return False

            logger.info("Migration validation completed successfully")
            return True

        except Exception as e:
            logger.error(f"Migration validation failed: {e}")
            return False

    async def _execute_cutover(self, migration: ZeroDowntimeMigration,
                             execution: MigrationExecution) -> bool:
        """Execute cutover to new schema."""
        try:
            # Stop dual-write
            for table_name in migration.affected_tables:
                await self.dual_write_manager.cleanup_dual_write(table_name)

            execution.dual_write_active = False

            # Execute cutover steps
            cutover_steps = [step for step in migration.steps if step.phase == MigrationPhase.CUTOVER]

            for step in cutover_steps:
                for sql_command in step.sql_commands:
                    await self._execute_sql_with_retry(sql_command, step.retry_count)

                execution.completed_steps.append(step.step_id)

            logger.info("Cutover completed successfully")
            return True

        except Exception as e:
            logger.error(f"Cutover failed: {e}")
            return False

    async def _cleanup_migration(self, migration: ZeroDowntimeMigration,
                               execution: MigrationExecution) -> bool:
        """Cleanup migration artifacts."""
        try:
            cleanup_steps = [step for step in migration.steps if step.phase == MigrationPhase.CLEANUP]

            for step in cleanup_steps:
                for sql_command in step.sql_commands:
                    await self._execute_sql_with_retry(sql_command, step.retry_count)

                execution.completed_steps.append(step.step_id)

            logger.info("Migration cleanup completed")
            return True

        except Exception as e:
            logger.error(f"Migration cleanup failed: {e}")
            return False

    async def _rollback_migration(self, migration: ZeroDowntimeMigration,
                                execution: MigrationExecution):
        """Rollback failed migration."""
        try:
            execution.current_phase = MigrationPhase.ROLLING_BACK
            logger.info(f"Rolling back migration: {migration.name}")

            # Stop dual-write if active
            if execution.dual_write_active:
                for table_name in migration.affected_tables:
                    await self.dual_write_manager.cleanup_dual_write(table_name)

            # Execute rollback commands in reverse order
            for step in reversed(migration.steps):
                if step.step_id in execution.completed_steps:
                    for rollback_command in step.rollback_commands:
                        await self._execute_sql_with_retry(rollback_command, step.retry_count)

                    execution.rollback_steps.append(step.step_id)

            logger.info("Migration rollback completed")

        except Exception as e:
            logger.error(f"Migration rollback failed: {e}")

    async def _check_database_connection(self, db_name: str) -> bool:
        """Check database connectivity."""
        # Placeholder for actual database connection check
        return True

    async def _create_migration_backup(self, migration_id: str):
        """Create backup before migration."""
        # Placeholder for backup creation
        logger.info(f"Backup created for migration: {migration_id}")

    async def _get_table_schema(self, table_name: str) -> Dict[str, Any]:
        """Get current table schema."""
        # Placeholder for schema retrieval
        return {"id": "INTEGER", "name": "VARCHAR(255)"}

    async def _get_target_schema(self, table_name: str, migration: ZeroDowntimeMigration) -> Dict[str, Any]:
        """Get target schema for table."""
        # Placeholder for target schema retrieval
        return {"id": "INTEGER", "name": "VARCHAR(255)", "email": "VARCHAR(255)"}

    async def _execute_sql_with_retry(self, sql: str, retry_count: int) -> bool:
        """Execute SQL with retry logic."""
        for attempt in range(retry_count):
            try:
                # Placeholder for actual SQL execution
                await asyncio.sleep(0.1)  # Simulate execution time
                return True
            except Exception as e:
                if attempt == retry_count - 1:
                    raise e
                await asyncio.sleep(1)  # Wait before retry
        return False

    async def _execute_validation_query(self, query: str) -> bool:
        """Execute validation query."""
        # Placeholder for validation query execution
        return True

    async def _execute_data_migration_sql(self, sql: str) -> int:
        """Execute data migration SQL and return affected rows."""
        # Placeholder for data migration execution
        return 100  # Simulate 100 rows affected

    async def _verify_strong_consistency(self, migration: ZeroDowntimeMigration) -> bool:
        """Verify strong consistency requirements."""
        # Placeholder for consistency verification
        return True

    def get_migration_status(self, migration_id: str) -> Optional[MigrationExecution]:
        """Get migration status."""
        return self.active_migrations.get(migration_id)

    def get_migration_history(self) -> List[MigrationExecution]:
        """Get migration history."""
        return self.migration_history.copy()


# Global zero-downtime migration manager instance
zero_downtime_migration_manager = ZeroDowntimeMigrationManager()
