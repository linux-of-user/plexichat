import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any, Optional
import database_manager
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

class Migration(ABC):
    """
    Base class for database migrations. Subclasses should override abstract methods
    to define specific schema elements.
    """
    
    MIGRATION_VERSION: str = ""
    MIGRATION_DESCRIPTION: str = ""
    
    MIGRATION_TABLE = "schema_migrations"
    
    def __init__(self):
        self.session = None
        self.rollback_sql = []
        self.engine = None
        self.db_type = None
    
    @abstractmethod
    def _get_tables(self) -> Dict[str, Dict[str, Any]]:
        """
        Return dict of table_name: schema definition.
        Schema is dict with keys: columns (list of (name, type, nullable, default, primary_key)),
        unique_constraints (list of column lists).
        """
        pass
    
    @abstractmethod
    def _get_indexes(self) -> Dict[str, List[Tuple[str, List[str], bool]]]:
        """
        Return dict of table_name: list of (index_name, columns, unique).
        """
        pass
    
    @abstractmethod
    def _get_foreign_keys(self) -> Dict[str, List[Tuple[str, str, str, str, str, str]]]:
        """
        Return dict of table_name: list of (fk_name, local_col, ref_table, ref_col, on_delete, on_update).
        """
        pass
    
    @abstractmethod
    def _get_check_constraints(self) -> Dict[str, List[Tuple[str, str]]]:
        """
        Return dict of table_name: list of (constraint_name, condition).
        """
        pass
    
    async def up(self):
        """Execute the migration up."""
        await self._setup_session()
        try:
            await self._ensure_migration_table()
            if await self._is_applied():
                logger.info(f"Migration {self.MIGRATION_VERSION} already applied.")
                return
            await self._create_tables()
            await self._create_indexes()
            await self._add_foreign_keys()
            await self._add_check_constraints()
            await self._record_migration()
            logger.info(f"Migration {self.MIGRATION_VERSION} applied successfully.")
        except Exception as e:
            logger.error(f"Error applying migration {self.MIGRATION_VERSION}: {e}")
            await self._rollback()
            raise
        finally:
            await self._cleanup_session()
    
    async def down(self):
        """Execute the migration down."""
        await self._setup_session()
        try:
            if not await self._is_applied():
                logger.info(f"Migration {self.MIGRATION_VERSION} not applied.")
                return
            rollback_sql = await self._get_rollback_sql()
            for sql in rollback_sql:
                await self.session.execute(text(sql))
            await self._remove_migration_record()
            logger.info(f"Migration {self.MIGRATION_VERSION} rolled back successfully.")
        except Exception as e:
            logger.error(f"Error rolling back migration {self.MIGRATION_VERSION}: {e}")
            raise
        finally:
            await self._cleanup_session()
    
    async def _setup_session(self):
        """Setup database session and detect dialect."""
        self.engine = database_manager.get_engine()
        self.db_type = self.engine.dialect.name
        self.session = database_manager.get_session()
    
    async def _cleanup_session(self):
        """Cleanup database session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def _ensure_migration_table(self):
        """Ensure the migration tracking table exists."""
        create_table_sql = self._get_dialect_sql(f"""
            CREATE TABLE IF NOT EXISTS {self.MIGRATION_TABLE} (
                id SERIAL PRIMARY KEY,
                version VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                rollback_sql TEXT
            )
        """)
        await self.session.execute(text(create_table_sql))
        await self.session.commit()
    
    async def _is_applied(self) -> bool:
        """Check if migration is already applied."""
        check_sql = self._get_dialect_sql(f"""
            SELECT 1 FROM {self.MIGRATION_TABLE} WHERE version = :version
        """)
        result = await self.session.execute(text(check_sql), {"version": self.MIGRATION_VERSION})
        return result.scalar() is not None
    
    async def _record_migration(self):
        """Record the migration as applied with rollback SQL."""
        rollback_str = "; ".join(self.rollback_sql)
        insert_sql = self._get_dialect_sql(f"""
            INSERT INTO {self.MIGRATION_TABLE} (version, description, rollback_sql)
            VALUES (:version, :description, :rollback_sql)
        """)
        await self.session.execute(text(insert_sql), {
            "version": self.MIGRATION_VERSION,
            "description": self.MIGRATION_DESCRIPTION,
            "rollback_sql": rollback_str
        })
        await self.session.commit()
    
    async def _remove_migration_record(self):
        """Remove the migration record."""
        delete_sql = self._get_dialect_sql(f"""
            DELETE FROM {self.MIGRATION_TABLE} WHERE version = :version
        """)
        await self.session.execute(text(delete_sql), {"version": self.MIGRATION_VERSION})
        await self.session.commit()
    
    async def _get_rollback_sql(self) -> List[str]:
        """Retrieve rollback SQL from tracking table."""
        select_sql = self._get_dialect_sql(f"""
            SELECT rollback_sql FROM {self.MIGRATION_TABLE} WHERE version = :version
        """)
        result = await self.session.execute(text(select_sql), {"version": self.MIGRATION_VERSION})
        row = result.fetchone()
        if row and row[0]:
            return [sql.strip() for sql in row[0].split(";") if sql.strip()]
        # Generate default rollback if not recorded
        return await self._generate_rollback_sql()
    
    async def _generate_rollback_sql(self) -> List[str]:
        """Generate rollback SQL for drops."""
        rollback = []
        # Drop constraints first
        for table, constraints in self._get_check_constraints().items():
            for name, _ in constraints:
                rollback.append(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
        for table, fks in self._get_foreign_keys().items():
            for name, _, _, _, _, _ in fks:
                rollback.append(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")
        # Drop indexes
        for table, indexes in self._get_indexes().items():
            for name, _, _ in indexes:
                rollback.append(f"DROP INDEX IF EXISTS {name}")
        # Drop tables
        for table in self._get_tables().keys():
            rollback.append(f"DROP TABLE IF EXISTS {table}")
        return [self._get_dialect_sql(sql) for sql in rollback]
    
    async def _create_tables(self):
        """Create tables with constraints."""
        tables = self._get_tables()
        for table_name, schema in tables.items():
            await self._create_table_with_constraints(table_name, schema)
    
    async def _create_table_with_constraints(self, table_name: str, schema: Dict[str, Any]):
        """Create a single table with unique constraints."""
        columns_def = []
        for col_name, col_type, nullable, default, primary_key in schema.get("columns", []):
            col_def = f"{col_name} {col_type}"
            if primary_key:
                col_def += " PRIMARY KEY"
            elif not nullable:
                col_def += " NOT NULL"
            if default is not None:
                default_val = self._get_dialect_default(default)
                col_def += f" DEFAULT {default_val}"
            columns_def.append(col_def)
        
        # Add unique constraints
        unique_defs = []
        for unique_cols in schema.get("unique_constraints", []):
            if len(unique_cols) == 1:
                col = unique_cols[0]
                unique_defs.append(f"UNIQUE ({col})")
            else:
                cols_str = ", ".join(unique_cols)
                unique_defs.append(f"UNIQUE ({cols_str})")
        
        constraints_str = ", ".join(unique_defs)
        if constraints_str:
            constraints_str = f", {constraints_str}"
        
        create_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(columns_def)}{constraints_str})"
        dialect_sql = self._get_dialect_sql(create_sql)
        await self.session.execute(text(dialect_sql))
        self.rollback_sql.append(f"DROP TABLE IF EXISTS {table_name}")
        await self.session.commit()
    
    async def _create_indexes(self):
        """Create indexes."""
        indexes = self._get_indexes()
        for table_name, idx_list in indexes.items():
            for idx_name, columns, unique in idx_list:
                unique_str = "UNIQUE " if unique else ""
                cols_str = ", ".join(columns)
                create_sql = f"CREATE {unique_str}INDEX IF NOT EXISTS {idx_name} ON {table_name} ({cols_str})"
                dialect_sql = self._get_dialect_sql(create_sql)
                await self.session.execute(text(dialect_sql))
                self.rollback_sql.append(f"DROP INDEX IF EXISTS {idx_name}")
                await self.session.commit()
    
    async def _add_foreign_keys(self):
        """Add foreign keys."""
        fks = self._get_foreign_keys()
        for table_name, fk_list in fks.items():
            for fk_name, local_col, ref_table, ref_col, on_delete, on_update in fk_list:
                add_sql = f"""
                    ALTER TABLE {table_name} ADD CONSTRAINT {fk_name} 
                    FOREIGN KEY ({local_col}) REFERENCES {ref_table} ({ref_col})
                    ON DELETE {on_delete} ON UPDATE {on_update}
                """
                # Skip for SQLite if not enabled
                if self.db_type == "sqlite" and not self._sqlite_fks_enabled():
                    logger.warning(f"Skipping FK {fk_name} in SQLite")
                    continue
                dialect_sql = self._get_dialect_sql(add_sql)
                await self.session.execute(text(dialect_sql))
                self.rollback_sql.append(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {fk_name}")
                await self.session.commit()
    
    async def _add_check_constraints(self):
        """Add check constraints."""
        checks = self._get_check_constraints()
        for table_name, check_list in checks.items():
            for check_name, condition in check_list:
                add_sql = f"ALTER TABLE {table_name} ADD CONSTRAINT {check_name} CHECK ({condition})"
                # Skip for SQLite
                if self.db_type == "sqlite":
                    logger.warning(f"Skipping check {check_name} in SQLite")
                    continue
                dialect_sql = self._get_dialect_sql(add_sql)
                await self.session.execute(text(dialect_sql))
                self.rollback_sql.append(f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {check_name}")
                await self.session.commit()
    
    def _get_dialect_sql(self, sql: str) -> str:
        """Adjust SQL for dialect."""
        if self.db_type == "postgresql":
            # PostgreSQL specific: SERIAL, etc.
            sql = sql.replace("AUTOINCREMENT", "SERIAL")
        elif self.db_type == "mysql":
            # MySQL specific: AUTO_INCREMENT, etc.
            sql = sql.replace("SERIAL", "AUTO_INCREMENT")
            sql = sql.replace("AUTOINCREMENT", "AUTO_INCREMENT")
        elif self.db_type == "sqlite":
            # SQLite specific
            sql = sql.replace("SERIAL", "INTEGER PRIMARY KEY AUTOINCREMENT")
        return sql
    
    def _get_dialect_default(self, default: Any) -> str:
        """Get dialect-specific default value."""
        if self.db_type == "sqlite" and isinstance(default, bool):
            return str(int(default)).lower()
        return str(default)
    
    def _sqlite_fks_enabled(self) -> bool:
        """Check if foreign keys are enabled in SQLite."""
        # Assume enabled or check via PRAGMA
        return True  # Placeholder; implement actual check if needed
    
    async def verify(self):
        """Verify migration state."""
        await self._setup_session()
        try:
            applied = await self._is_applied()
            logger.info(f"Migration {self.MIGRATION_VERSION} applied: {applied}")
            # Additional verification logic can be overridden
        finally:
            await self._cleanup_session()
    
    async def _rollback(self):
        """Rollback the current migration."""
        for sql in reversed(self.rollback_sql):
            try:
                await self.session.execute(text(sql))
            except SQLAlchemyError as e:
                logger.error(f"Rollback error: {e}")
        await self.session.commit()

async def main():
    """CLI entry point for the migration."""
    import sys
    if len(sys.argv) < 2:
        print("Usage: python base.py [up|down|verify]")
        sys.exit(1)
    
    action = sys.argv[1]
    # Note: This base doesn't instantiate specific migration; subclasses should have their own main
    # For base, perhaps raise error or provide example
    print(f"Base migration class. Use specific migration files for execution.")
    sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())