import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

    from .enhanced_abstraction import AbstractDatabaseClient, DatabaseType  # type: ignore

"""
PlexiChat Schema and Data Type Optimizer

Advanced database schema optimization system featuring:
- Data type analysis and optimization recommendations
- Schema normalization and denormalization strategies
- Column size optimization and storage efficiency
- Constraint optimization for performance and integrity
- Table partitioning recommendations
- Foreign key optimization
- Data compression strategies
- Schema evolution and migration planning

Key Optimization Areas:
- Appropriate data type selection (INTEGER vs TEXT for numeric values)
- Column size optimization (VARCHAR length optimization)
- Normalization vs denormalization trade-offs
- Constraint optimization for performance
- Partitioning strategies for large tables
- Index-friendly schema design
"""

try:
    ENHANCED_ABSTRACTION_AVAILABLE = True
except ImportError:
    ENHANCED_ABSTRACTION_AVAILABLE = False
    # Create placeholder classes
    class AbstractDatabaseClient:
        def __init__(self, config):
            self.config = config
        async def execute_query(self, query, params=None):
            return {"success": True, "data": []}

    class DatabaseType:
        POSTGRESQL = "postgresql"
        MYSQL = "mysql"
        SQLITE = "sqlite"

logger = logging.getLogger(__name__)


def _get_result_data(result, default_value=None):
    """Helper function to safely get data from result objects or dicts."""
    if hasattr(result, 'data'):
        return getattr(result, 'data')
    elif hasattr(result, 'get') and callable(getattr(result, 'get')):
        return result.get('data', default_value)
    else:
        return default_value


class DataTypeCategory(Enum):
    """Categories of data types."""
    NUMERIC = "numeric"
    TEXT = "text"
    DATE_TIME = "datetime"
    BOOLEAN = "boolean"
    JSON = "json"
    BINARY = "binary"
    UUID = "uuid"
    ENUM = "enum"


class OptimizationPriority(Enum):
    """Optimization priority levels."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class ColumnAnalysis:
    """Analysis of a database column."""
    table_name: str
    column_name: str
    current_data_type: str
    data_category: DataTypeCategory
    
    # Data characteristics
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    avg_length: Optional[float] = None
    null_percentage: float = 0.0
    unique_values: Optional[int] = None
    total_rows: Optional[int] = None
    
    # Value analysis
    sample_values: List[Any] = field(default_factory=list)
    is_numeric: bool = False
    is_date: bool = False
    is_uuid: bool = False
    is_enum_candidate: bool = False
    
    # Performance metrics
    index_usage: int = 0
    query_frequency: int = 0
    storage_size_bytes: Optional[int] = None


@dataclass
class DataTypeRecommendation:
    """Data type optimization recommendation."""
    table_name: str
    column_name: str
    current_type: str
    recommended_type: str
    reason: str
    priority: OptimizationPriority
    estimated_space_savings: float  # Percentage
    estimated_performance_gain: float  # Percentage
    migration_complexity: str  # "simple", "moderate", "complex"
    migration_sql: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class SchemaOptimization:
    """Schema-level optimization recommendation."""
    optimization_type: str
    description: str
    tables_affected: List[str]
    priority: OptimizationPriority
    estimated_benefit: str
    implementation_steps: List[str]
    sql_statements: List[str] = field(default_factory=list)


class DataTypeAnalyzer:
    """Analyze data types and recommend optimizations."""
    
    def __init__(self):
        self.type_mappings = {
            DatabaseType.POSTGRESQL: {
                "integer_types": ["SMALLINT", "INTEGER", "BIGINT"],
                "text_types": ["VARCHAR", "TEXT", "CHAR"],
                "numeric_types": ["DECIMAL", "NUMERIC", "REAL", "DOUBLE PRECISION"],
                "datetime_types": ["DATE", "TIME", "TIMESTAMP", "TIMESTAMPTZ"],
                "boolean_type": "BOOLEAN",
                "json_types": ["JSON", "JSONB"],
                "uuid_type": "UUID"
            },
            DatabaseType.MYSQL: {
                "integer_types": ["TINYINT", "SMALLINT", "MEDIUMINT", "INT", "BIGINT"],
                "text_types": ["VARCHAR", "TEXT", "CHAR"],
                "numeric_types": ["DECIMAL", "FLOAT", "DOUBLE"],
                "datetime_types": ["DATE", "TIME", "DATETIME", "TIMESTAMP"],
                "boolean_type": "BOOLEAN",
                "json_types": ["JSON"],
                "uuid_type": "CHAR(36)"
            },
            DatabaseType.SQLITE: {
                "integer_types": ["INTEGER"],
                "text_types": ["TEXT", "VARCHAR"],
                "numeric_types": ["REAL", "NUMERIC"],
                "datetime_types": ["TEXT"],  # SQLite stores dates as text
                "boolean_type": "INTEGER",
                "json_types": ["TEXT"],
                "uuid_type": "TEXT"
            }
        }
    
    async def analyze_column(self, client: AbstractDatabaseClient, table_name: str, 
                           column_name: str) -> ColumnAnalysis:
        """Analyze a specific column for optimization opportunities."""
        database_type = getattr(client.config, 'type', DatabaseType.SQLITE)
        
        # Get column metadata
        column_info = await self._get_column_info(client, table_name, column_name, database_type)
        
        # Analyze data characteristics
        data_analysis = await self._analyze_column_data(client, table_name, column_name)
        
        # Create analysis object
        analysis = ColumnAnalysis(
            table_name=table_name,
            column_name=column_name,
            current_data_type=column_info.get("data_type", "UNKNOWN"),
            data_category=self._categorize_data_type(column_info.get("data_type", "")),
            **data_analysis
        )
        
        return analysis
    
    async def recommend_data_type_optimizations(self, client: AbstractDatabaseClient, 
                                              table_name: str) -> List[DataTypeRecommendation]:
        """Recommend data type optimizations for a table."""
        recommendations = []
        database_type = getattr(client.config, 'type', DatabaseType.SQLITE)
        
        # Get all columns for the table
        columns = await self._get_table_columns(client, table_name, database_type)
        
        for column_info in columns:
            column_name = column_info["column_name"]
            column_info["data_type"]
            
            # Analyze the column
            analysis = await self.analyze_column(client, table_name, column_name)
            
            # Generate recommendations based on analysis
            column_recommendations = self._generate_column_recommendations(analysis, database_type)
            recommendations.extend(column_recommendations)
        
        return recommendations
    
    def _generate_column_recommendations(self, analysis: ColumnAnalysis, 
                                       database_type: DatabaseType) -> List[DataTypeRecommendation]:
        """Generate data type recommendations for a column."""
        recommendations = []
        current_type = analysis.current_data_type.upper()
        
        # Text to numeric optimization
        if analysis.data_category == DataTypeCategory.TEXT and analysis.is_numeric:
            if analysis.sample_values and all(isinstance(v, (int, float)) or str(v).isdigit() for v in analysis.sample_values):
                # Recommend INTEGER type
                recommended_type = self._get_optimal_integer_type(analysis, database_type)
                recommendations.append(DataTypeRecommendation(
                    table_name=analysis.table_name,
                    column_name=analysis.column_name,
                    current_type=current_type,
                    recommended_type=recommended_type,
                    reason="Column contains only numeric values but stored as text",
                    priority=OptimizationPriority.HIGH,
                    estimated_space_savings=30.0,
                    estimated_performance_gain=25.0,
                    migration_complexity="moderate",
                    migration_sql=self._generate_type_change_sql(analysis, recommended_type, database_type)
                ))
        
        # VARCHAR size optimization
        if "VARCHAR" in current_type and analysis.max_length:
            current_size = self._extract_varchar_size(current_type)
            optimal_size = min(analysis.max_length * 2, 255)  # 2x max with reasonable limit
            
            if current_size and current_size > optimal_size * 1.5:  # Only if significant savings
                recommended_type = f"VARCHAR({optimal_size})"
                recommendations.append(DataTypeRecommendation(
                    table_name=analysis.table_name,
                    column_name=analysis.column_name,
                    current_type=current_type,
                    recommended_type=recommended_type,
                    reason=f"VARCHAR size can be reduced from {current_size} to {optimal_size}",
                    priority=OptimizationPriority.MEDIUM,
                    estimated_space_savings=((current_size - optimal_size) / current_size) * 100,
                    estimated_performance_gain=10.0,
                    migration_complexity="simple",
                    migration_sql=self._generate_type_change_sql(analysis, recommended_type, database_type)
                ))
        
        # Text to UUID optimization
        if (analysis.data_category == DataTypeCategory.TEXT and 
            analysis.is_uuid and 
            database_type == DatabaseType.POSTGRESQL):
            
            recommendations.append(DataTypeRecommendation(
                table_name=analysis.table_name,
                column_name=analysis.column_name,
                current_type=current_type,
                recommended_type="UUID",
                reason="Column contains UUID values, native UUID type is more efficient",
                priority=OptimizationPriority.MEDIUM,
                estimated_space_savings=50.0,
                estimated_performance_gain=20.0,
                migration_complexity="moderate",
                migration_sql=self._generate_type_change_sql(analysis, "UUID", database_type)
            ))
        
        # Enum optimization for low cardinality text columns
        if (analysis.data_category == DataTypeCategory.TEXT and 
            analysis.is_enum_candidate and 
            analysis.unique_values and analysis.unique_values < 20):
            
            if database_type == DatabaseType.POSTGRESQL:
                enum_values = "', '".join(str(v) for v in analysis.sample_values[:analysis.unique_values])
                recommended_type = f"ENUM('{enum_values}')"
                
                recommendations.append(DataTypeRecommendation(
                    table_name=analysis.table_name,
                    column_name=analysis.column_name,
                    current_type=current_type,
                    recommended_type=recommended_type,
                    reason=f"Column has only {analysis.unique_values} unique values, ENUM would be more efficient",
                    priority=OptimizationPriority.LOW,
                    estimated_space_savings=40.0,
                    estimated_performance_gain=15.0,
                    migration_complexity="complex",
                    migration_sql=self._generate_enum_migration_sql(analysis, enum_values, database_type)
                ))
        
        # JSON optimization for PostgreSQL
        if (database_type == DatabaseType.POSTGRESQL and 
            "TEXT" in current_type and 
            self._appears_to_be_json(analysis.sample_values)):
            
            recommendations.append(DataTypeRecommendation(
                table_name=analysis.table_name,
                column_name=analysis.column_name,
                current_type=current_type,
                recommended_type="JSONB",
                reason="Column contains JSON data, JSONB type provides better performance and indexing",
                priority=OptimizationPriority.MEDIUM,
                estimated_space_savings=20.0,
                estimated_performance_gain=40.0,
                migration_complexity="moderate",
                migration_sql=self._generate_type_change_sql(analysis, "JSONB", database_type)
            ))
        
        return recommendations
    
    async def _get_column_info(self, client: AbstractDatabaseClient, table_name: str, 
                             column_name: str, database_type: DatabaseType) -> Dict[str, Any]:
        """Get column metadata from database."""
        try:
            if database_type == DatabaseType.POSTGRESQL:
                query = """
                SELECT column_name, data_type, character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_name = $1 AND column_name = $2
                """
                params = {"1": table_name, "2": column_name}
            elif database_type == DatabaseType.MYSQL:
                query = """
                SELECT COLUMN_NAME as column_name, DATA_TYPE as data_type, 
                       CHARACTER_MAXIMUM_LENGTH as character_maximum_length,
                       IS_NULLABLE as is_nullable
                FROM information_schema.COLUMNS
                WHERE TABLE_NAME = %s AND COLUMN_NAME = %s
                """
                params = {"1": table_name, "2": column_name}
            else:  # SQLite
                query = f"PRAGMA table_info({table_name})"
                params = {}
            
            result = await client.execute_query(query, params)

            data = _get_result_data(result, [])
            if data:
                return data[0]
            
        except Exception as e:
            logger.error(f"Failed to get column info for {table_name}.{column_name}: {e}")
        
        return {}
    
    async def _analyze_column_data(self, client: AbstractDatabaseClient, 
                                 table_name: str, column_name: str) -> Dict[str, Any]:
        """Analyze the actual data in a column."""
        try:
            # Sample data analysis query
            query = f"""
            SELECT 
                MAX(LENGTH({column_name})) as max_length,
                MIN(LENGTH({column_name})) as min_length,
                AVG(LENGTH({column_name})) as avg_length,
                COUNT(*) as total_rows,
                COUNT(DISTINCT {column_name}) as unique_values,
                SUM(CASE WHEN {column_name} IS NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as null_percentage
            FROM {table_name}
            """
            
            result = await client.execute_query(query)

            data = _get_result_data(result, [])
            if data:
                stats = data[0]

                # Get sample values
                sample_query = f"SELECT DISTINCT {column_name} FROM {table_name} LIMIT 20"
                sample_result = await client.execute_query(sample_query)
                sample_data = _get_result_data(sample_result, [])
                sample_values = [row[column_name] for row in sample_data if row[column_name] is not None]
                
                # Analyze value patterns
                is_numeric = self._is_numeric_column(sample_values)
                is_date = self._is_date_column(sample_values)
                is_uuid = self._is_uuid_column(sample_values)
                is_enum_candidate = len(sample_values) <= 20 and stats.get("unique_values", 0) <= 20
                
                return {
                    "max_length": stats.get("max_length"),
                    "min_length": stats.get("min_length"),
                    "avg_length": stats.get("avg_length"),
                    "total_rows": stats.get("total_rows"),
                    "unique_values": stats.get("unique_values"),
                    "null_percentage": stats.get("null_percentage", 0.0),
                    "sample_values": sample_values,
                    "is_numeric": is_numeric,
                    "is_date": is_date,
                    "is_uuid": is_uuid,
                    "is_enum_candidate": is_enum_candidate
                }
        
        except Exception as e:
            logger.error(f"Failed to analyze column data for {table_name}.{column_name}: {e}")
        
        return {}
    
    async def _get_table_columns(self, client: AbstractDatabaseClient, 
                               table_name: str, database_type: DatabaseType) -> List[Dict[str, Any]]:
        """Get all columns for a table."""
        try:
            if database_type == DatabaseType.POSTGRESQL:
                query = """
                SELECT column_name, data_type, character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_name = $1
                ORDER BY ordinal_position
                """
                params = {"1": table_name}
            elif database_type == DatabaseType.MYSQL:
                query = """
                SELECT COLUMN_NAME as column_name, DATA_TYPE as data_type,
                       CHARACTER_MAXIMUM_LENGTH as character_maximum_length,
                       IS_NULLABLE as is_nullable
                FROM information_schema.COLUMNS
                WHERE TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
                """
                params = {"1": table_name}
            else:  # SQLite
                query = f"PRAGMA table_info({table_name})"
                params = {}
            
            result = await client.execute_query(query, params)
            return _get_result_data(result, [])
            
        except Exception as e:
            logger.error(f"Failed to get table columns for {table_name}: {e}")
            return []
    
    def _categorize_data_type(self, data_type: str) -> DataTypeCategory:
        """Categorize a data type."""
        data_type_upper = data_type.upper()
        
        if any(t in data_type_upper for t in ["INT", "SERIAL", "BIGINT", "SMALLINT"]):
            return DataTypeCategory.NUMERIC
        elif any(t in data_type_upper for t in ["VARCHAR", "TEXT", "CHAR"]):
            return DataTypeCategory.TEXT
        elif any(t in data_type_upper for t in ["DATE", "TIME", "TIMESTAMP"]):
            return DataTypeCategory.DATE_TIME
        elif "BOOL" in data_type_upper:
            return DataTypeCategory.BOOLEAN
        elif "JSON" in data_type_upper:
            return DataTypeCategory.JSON
        elif "UUID" in data_type_upper:
            return DataTypeCategory.UUID
        else:
            return DataTypeCategory.TEXT
    
    def _is_numeric_column(self, sample_values: List[Any]) -> bool:
        """Check if column values are numeric."""
        if not sample_values:
            return False
        
        numeric_count = 0
        for value in sample_values:
            try:
                float(str(value))
                numeric_count += 1
            except (ValueError, TypeError):
                pass
        
        return numeric_count / len(sample_values) > 0.8
    
    def _is_date_column(self, sample_values: List[Any]) -> bool:
        """Check if column values are dates."""
        if not sample_values:
            return False
        
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # YYYY-MM-DD HH:MM:SS
        ]
        
        date_count = 0
        for value in sample_values:
            value_str = str(value)
            if any(re.match(pattern, value_str) for pattern in date_patterns):
                date_count += 1
        
        return date_count / len(sample_values) > 0.8
    
    def _is_uuid_column(self, sample_values: List[Any]) -> bool:
        """Check if column values are UUIDs."""
        if not sample_values:
            return False
        
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        
        uuid_count = 0
        for value in sample_values:
            if re.match(uuid_pattern, str(value), re.IGNORECASE):
                uuid_count += 1
        
        return uuid_count / len(sample_values) > 0.8
    
    def _appears_to_be_json(self, sample_values: List[Any]) -> bool:
        """Check if values appear to be JSON."""
        if not sample_values:
            return False
        
        json_count = 0
        for value in sample_values:
            try:
                json.loads(str(value))
                json_count += 1
            except (json.JSONDecodeError, TypeError):
                pass
        
        return json_count / len(sample_values) > 0.8
    
    def _get_optimal_integer_type(self, analysis: ColumnAnalysis, 
                                database_type: DatabaseType) -> str:
        """Get optimal integer type based on value range."""
        if not analysis.sample_values:
            return "INTEGER"
        
        try:
            max_val = max(int(float(str(v))) for v in analysis.sample_values)
            min_val = min(int(float(str(v))) for v in analysis.sample_values)
            
            if database_type == DatabaseType.POSTGRESQL:
                if -32768 <= min_val and max_val <= 32767:
                    return "SMALLINT"
                elif -2147483648 <= min_val and max_val <= 2147483647:
                    return "INTEGER"
                else:
                    return "BIGINT"
            elif database_type == DatabaseType.MYSQL:
                if 0 <= min_val and max_val <= 255:
                    return "TINYINT UNSIGNED"
                elif -32768 <= min_val and max_val <= 32767:
                    return "SMALLINT"
                elif -2147483648 <= min_val and max_val <= 2147483647:
                    return "INT"
                else:
                    return "BIGINT"
            else:  # SQLite
                return "INTEGER"
                
        except (ValueError, TypeError):
            return "INTEGER"
    
    def _extract_varchar_size(self, data_type: str) -> Optional[int]:
        """Extract size from VARCHAR(n) type."""
        match = re.search(r'VARCHAR\((\d+)\)', data_type, re.IGNORECASE)
        return int(match.group(1)) if match else None
    
    def _generate_type_change_sql(self, analysis: ColumnAnalysis, 
                                new_type: str, database_type: DatabaseType) -> str:
        """Generate SQL for changing column type."""
        table = analysis.table_name
        column = analysis.column_name
        
        if database_type == DatabaseType.POSTGRESQL:
            return f"ALTER TABLE {table} ALTER COLUMN {column} TYPE {new_type} USING {column}::{new_type};"
        elif database_type == DatabaseType.MYSQL:
            return f"ALTER TABLE {table} MODIFY COLUMN {column} {new_type};"
        else:  # SQLite
            return f"-- SQLite requires table recreation for type changes\n-- ALTER TABLE {table} ..."
    
    def _generate_enum_migration_sql(self, analysis: ColumnAnalysis, 
                                   enum_values: str, database_type: DatabaseType) -> str:
        """Generate SQL for creating ENUM type."""
        if database_type == DatabaseType.POSTGRESQL:
            enum_name = f"{analysis.table_name}_{analysis.column_name}_enum"
            return f"""
            CREATE TYPE {enum_name} AS ENUM ('{enum_values}');
            ALTER TABLE {analysis.table_name} ALTER COLUMN {analysis.column_name} TYPE {enum_name} USING {analysis.column_name}::{enum_name};
            """
        else:
            db_type_str = getattr(database_type, 'value', str(database_type))
            return f"-- ENUM types not supported in {db_type_str}"


# Global instance
schema_optimizer = DataTypeAnalyzer()
