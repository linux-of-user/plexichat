import logging
import time
from typing import Any, AsyncGenerator, Dict, List

"""
PlexiChat Analytics Database Clients

Specialized database clients for analytics workloads:
- ClickHouse (Column-oriented OLAP, Optional)
- Apache Druid (Real-time analytics)
- TimescaleDB (Time-series analytics)
- Apache Pinot (Real-time OLAP)

Features:
- Optimized for analytical workloads
- Real-time data ingestion
- Complex aggregations and analytics
- Time-series analysis
- Materialized views

try:
    from .enhanced_abstraction import (
        AbstractDatabaseClient,
        DatabaseConfig,
        DatabaseType,
        QueryResult,
        QueryType,
    )
except ImportError:
    # Fallback implementations
    class AbstractDatabaseClient:
        def __init__(self, config):
            self.config = config

    class DatabaseConfig:
        pass

    class DatabaseType:
        CLICKHOUSE = "clickhouse"
        TIMESCALEDB = "timescaledb"

    class QueryResult:
        def __init__(self, data=None):
            self.data = data or []

    class QueryType:
        SELECT = "select"
        INSERT = "insert"

    class DatabaseClientFactory:
        _clients = {}

        @classmethod
        def register_client(cls, db_type, client_class):
            cls._clients[db_type] = client_class

logger = logging.getLogger(__name__)


class ClickHouseClient(AbstractDatabaseClient):
    """ClickHouse analytics database client."""

    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.client = None

    async def connect(self) -> bool:
        """Connect to ClickHouse."""
        try:
            # Build connection parameters
            connection_params = {
                "host": self.config.host,
                "port": self.config.port or 9000,
                "database": self.config.database,
                "user": self.config.username,
                "password": self.config.password,
                "secure": self.config.ssl_enabled,
                "compression": self.config.compression_enabled,
                "send_receive_timeout": self.config.pool_timeout,
            }

            # Add custom options
            connection_params.update(self.config.options)

            self.client = Client(**connection_params)

            # Test connection
            result = self.client.execute("SELECT 1")
            if result == [(1,)]:
                self.is_connected = True
                self.metrics["connections_created"] += 1
                logger.info(f" Connected to ClickHouse: {self.config.host}")
                return True
            else:
                return False

        except Exception as e:
            logger.error(f" ClickHouse connection failed: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from ClickHouse."""
        try:
            if self.client:
                self.client.disconnect()
                self.is_connected = False
            return True
        except Exception as e:
            logger.error(f" ClickHouse disconnect failed: {e}")
            return False

    async def execute_query(self, query: str, params: Dict[str, Any] = None,
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute ClickHouse query."""
        start_time = time.time()

        try:
            # Substitute parameters
            if params:
                for key, value in params.items():
                    if isinstance(value, str):
                        query = query.replace(f"${key}", f"'{value}'")
                    else:
                        query = query.replace(f"${key}", str(value))

            # Execute query
            if query_type == QueryType.SELECT:
                # For SELECT queries, return data with column names
                result = self.client.execute(query, with_column_types=True)
                if result:
                    columns = [col[0] for col in result[1]]  # Column names
                    rows = result[0]  # Data rows

                    # Convert to list of dictionaries
                    data = [dict(zip(columns, row)) for row in rows]
                    count = len(data)
                else:
                    data = []
                    count = 0
            else:
                # For INSERT/UPDATE/DELETE, just execute
                result = self.client.execute(query)
                data = {"affected_rows": result if isinstance(result, int) else 0}
                count = result if isinstance(result, int) else 0

            execution_time = time.time() - start_time
            self.metrics["queries_executed"] += 1
            self.metrics["total_execution_time"] += execution_time

            return QueryResult(
                data=data,
                count=count,
                execution_time=execution_time,
                metadata={"query_type": query_type.value}
            )

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"ClickHouse query failed: {e}")
            raise

    async def execute_batch(self, queries: List[Dict[str, Any]]) -> List[QueryResult]:
        """Execute batch of ClickHouse queries."""
        results = []

        for query_info in queries:
            if isinstance(query_info, dict):
                query = query_info.get("sql", "")
                params = query_info.get("params")
                query_type = QueryType(query_info.get("type", "select"))
            else:
                query = query_info
                params = None
                query_type = QueryType.SELECT

            result = await self.execute_query(query, params, query_type)
            results.append(result)

        return results

    async def create_table(self, table_name: str, schema: Dict[str, str],
                          engine: str = "MergeTree",
                          partition_by: Optional[List[str]] = None,
                          order_by: Optional[List[str]] = None) -> bool:
        """Create ClickHouse table optimized for analytics."""
        try:
            # Build column definitions
            columns = []
            for col_name, col_type in schema.items():
                columns.append(f"{col_name} {col_type}")

            columns_str = ",\n    ".join(columns)

            # Build CREATE TABLE statement
            create_sql = f"""
            CREATE TABLE {table_name} (
                {columns_str}
            ) ENGINE = {engine}()
            """

            # Add partitioning
            if partition_by:
                partition_expr = ", ".join(partition_by)
                create_sql += f"\nPARTITION BY ({partition_expr})"

            # Add ordering
            if order_by:
                order_expr = ", ".join(order_by)
                create_sql += f"\nORDER BY ({order_expr})"
            elif engine == "MergeTree":
                # MergeTree requires ORDER BY
                first_col = list(schema.keys())[0]
                create_sql += f"\nORDER BY {first_col}"

            # Execute CREATE TABLE
            await self.execute_query(create_sql, query_type=QueryType.INSERT)
            logger.info(f" Created ClickHouse table: {table_name}")
            return True

        except Exception as e:
            logger.error(f" Failed to create ClickHouse table {table_name}: {e}")
            return False

    async def create_materialized_view(self, view_name: str, source_table: str,
                                     select_query: str, target_table: Optional[str] = None) -> bool:
        """Create materialized view for real-time aggregations."""
        try:
            if target_table:
                # Materialized view with target table
                create_sql = f"""
                CREATE MATERIALIZED VIEW {view_name} TO {target_table}
                AS {select_query}
                """
            else:
                # Simple materialized view
                create_sql = f"""
                CREATE MATERIALIZED VIEW {view_name}
                ENGINE = MergeTree()
                ORDER BY tuple()
                AS {select_query}
                """

            await self.execute_query(create_sql, query_type=QueryType.INSERT)
            logger.info(f" Created ClickHouse materialized view: {view_name}")
            return True

        except Exception as e:
            logger.error(f" Failed to create materialized view {view_name}: {e}")
            return False

    async def optimize_table(self, table_name: str) -> bool:
        """Optimize ClickHouse table."""
        try:
            optimize_sql = f"OPTIMIZE TABLE {table_name} FINAL"
            await self.execute_query(optimize_sql, query_type=QueryType.INSERT)
            logger.info(f" Optimized ClickHouse table: {table_name}")
            return True
        except Exception as e:
            logger.error(f" Failed to optimize table {table_name}: {e}")
            return False

    async def health_check(self) -> Dict[str, Any]:
        """Check ClickHouse health."""
        try:
            # Get system information
            version_result = await self.execute_query("SELECT version()")
            version = version_result.data[0]["version()"] if version_result.data else "unknown"

            # Get system metrics
            metrics_query = """
            SELECT
                formatReadableSize(total_bytes) as total_size,
                formatReadableSize(total_rows) as total_rows,
                count() as table_count
            FROM system.parts
            WHERE active = 1
            """
            metrics_result = await self.execute_query(metrics_query)

            return {
                "status": "healthy",
                "version": version,
                "metrics": metrics_result.data[0] if metrics_result.data else {},
                "client_metrics": self.metrics
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "client_metrics": self.metrics
            }

    async def get_schema_info(self) -> Dict[str, Any]:
        """Get ClickHouse schema information."""
        try:
            # Get all tables
            tables_query = """
            SELECT
                database,
                name as table_name,
                engine,
                total_rows,
                total_bytes
            FROM system.tables
            WHERE database = $database
            """

            tables_result = await self.execute_query(
                tables_query,
                {"database": self.config.database}
            )

            schema_info = {
                "database": self.config.database,
                "tables": {}
            }

            for table_info in tables_result.data:
                table_name = table_info["table_name"]

                # Get column information
                columns_query = f"""
                SELECT
                    name,
                    type,
                    default_kind,
                    default_expression
                FROM system.columns
                WHERE database = '{self.config.database}'
                AND table = '{table_name}'
                ORDER BY position
                """

                columns_result = await self.execute_query(columns_query)

                schema_info["tables"][table_name] = {
                    "engine": table_info["engine"],
                    "total_rows": table_info["total_rows"],
                    "total_bytes": table_info["total_bytes"],
                    "columns": columns_result.data
                }

            return schema_info
        except Exception as e:
            logger.error(f"Failed to get ClickHouse schema info: {e}")
            return {}

    async def stream_data(self, query: str, params: Dict[str, Any] = None) -> AsyncGenerator:
        """Stream large ClickHouse result sets."""
        try:
            # For streaming, we'll use chunked queries
            chunk_size = 10000
            offset = 0

            while True:
                # Add LIMIT and OFFSET to query
                chunked_query = f"{query} LIMIT {chunk_size} OFFSET {offset}"

                result = await self.execute_query(chunked_query, params)

                if not result.data:
                    break

                for row in result.data:
                    yield row

                if len(result.data) < chunk_size:
                    break

                offset += chunk_size

        except Exception as e:
            logger.error(f"ClickHouse streaming failed: {e}")
            raise


class TimescaleDBClient(AbstractDatabaseClient):
    """TimescaleDB time-series analytics client."""

    def __init__(self, config: DatabaseConfig):
        super().__init__(config)
        self.connection_pool = None

    async def connect(self) -> bool:
        """Connect to TimescaleDB."""
        try:
            # Build connection string
            connection_string = f"postgresql://{self.config.username}:{self.config.password}@{self.config.host}:{self.config.port or 5432}/{self.config.database}"

            # Create connection pool
            self.connection_pool = await asyncpg.create_pool(
                connection_string,
                min_size=1,
                max_size=self.config.pool_size,
                command_timeout=self.config.pool_timeout
            )

            # Test connection
            async with self.connection_pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                if result == 1:
                    self.is_connected = True
                    self.metrics["connections_created"] += 1
                    logger.info(f" Connected to TimescaleDB: {self.config.host}")
                    return True

            return False

        except Exception as e:
            logger.error(f" TimescaleDB connection failed: {e}")
            return False

    async def disconnect(self) -> bool:
        """Disconnect from TimescaleDB."""
        try:
            if self.connection_pool:
                await if self.connection_pool: self.connection_pool.close()
                self.is_connected = False
            return True
        except Exception as e:
            logger.error(f" TimescaleDB disconnect failed: {e}")
            return False

    async def execute_query(self, query: str, params: Dict[str, Any] = None,
                          query_type: QueryType = QueryType.SELECT) -> QueryResult:
        """Execute TimescaleDB query."""
        start_time = time.time()

        try:
            async with self.connection_pool.acquire() as conn:
                if query_type == QueryType.SELECT:
                    # For SELECT queries
                    if params:
                        # Convert named parameters to positional
                        param_values = []
                        for key, value in params.items():
                            query = query.replace(f"${key}", f"${len(param_values) + 1}")
                            param_values.append(value)

                        rows = await conn.fetch(query, *param_values)
                    else:
                        rows = await conn.fetch(query)

                    # Convert to list of dictionaries
                    data = [dict(row) for row in rows]
                    count = len(data)
                else:
                    # For INSERT/UPDATE/DELETE
                    if params:
                        param_values = []
                        for key, value in params.items():
                            query = query.replace(f"${key}", f"${len(param_values) + 1}")
                            param_values.append(value)

                        result = await conn.execute(query, *param_values)
                    else:
                        result = await conn.execute(query)

                    # Parse affected rows from result
                    affected_rows = int(result.split()[-1]) if result else 0
                    data = {"affected_rows": affected_rows}
                    count = affected_rows

            execution_time = time.time() - start_time
            self.metrics["queries_executed"] += 1
            self.metrics["total_execution_time"] += execution_time

            return QueryResult(
                data=data,
                count=count,
                execution_time=execution_time,
                metadata={"query_type": query_type.value}
            )

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"TimescaleDB query failed: {e}")
            raise

    async def create_hypertable(self, table_name: str, time_column: str,
                              chunk_time_interval: str = "1 day") -> bool:
        """Create TimescaleDB hypertable for time-series data."""
        try:
            create_sql = f"""
            SELECT create_hypertable('{table_name}', '{time_column}',
                                    chunk_time_interval => INTERVAL '{chunk_time_interval}')
            """

            await self.execute_query(create_sql, query_type=QueryType.INSERT)
            logger.info(f" Created TimescaleDB hypertable: {table_name}")
            return True

        except Exception as e:
            logger.error(f" Failed to create hypertable {table_name}: {e}")
            return False

    async def execute_batch(self, queries: List[Dict[str, Any]]) -> List[QueryResult]:
        """Execute batch of TimescaleDB queries."""
        results = []

        for query_info in queries:
            if isinstance(query_info, dict):
                query = query_info.get("sql", "")
                params = query_info.get("params")
                query_type = QueryType(query_info.get("type", "select"))
            else:
                query = query_info
                params = None
                query_type = QueryType.SELECT

            result = await self.execute_query(query, params, query_type)
            results.append(result)

        return results

    async def health_check(self) -> Dict[str, Any]:
        """Check TimescaleDB health."""
        try:
            version_result = await self.execute_query("SELECT version()")
            version = version_result.data[0]["version"] if version_result.data else "unknown"

            return {
                "status": "healthy",
                "version": version,
                "client_metrics": self.metrics
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "client_metrics": self.metrics
            }

    async def get_schema_info(self) -> Dict[str, Any]:
        """Get TimescaleDB schema information."""
        try:
            # Get hypertables
            hypertables_query = """
            SELECT hypertable_name, associated_schema_name, num_dimensions
            FROM timescaledb_information.hypertables
            """

            hypertables_result = await self.execute_query(hypertables_query)

            return {
                "database": self.config.database,
                "hypertables": hypertables_result.data,
                "client_metrics": self.metrics
            }
        except Exception as e:
            logger.error(f"Failed to get TimescaleDB schema info: {e}")
            return {}


# Register analytics clients
DatabaseClientFactory.register_client(DatabaseType.CLICKHOUSE, ClickHouseClient)
DatabaseClientFactory.register_client(DatabaseType.TIMESCALEDB, TimescaleDBClient)
