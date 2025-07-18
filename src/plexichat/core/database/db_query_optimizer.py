import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


"""
import time
import warnings
PlexiChat Advanced Query Optimizer

Comprehensive SQL and NoSQL query optimization system implementing:
- Query pattern analysis and optimization
- Intelligent indexing strategies
- Prepared statement management
- Query rewriting and optimization
- Performance monitoring and alerting
- Automatic query plan analysis
- Cache-aware optimization
- NoSQL access pattern optimization

Key Optimization Strategies:
- Minimize wildcard usage in LIKE clauses
- Replace subqueries with JOINs
- Use EXISTS instead of IN for existence checks
- Implement proper indexing strategies
- Optimize data types and schema design
- Use LIMIT clauses to restrict rows
- Avoid SELECT * queries
- Implement stored procedures for complex queries
"""

logger = logging.getLogger(__name__)


class QueryType(Enum):
    """Types of database queries."""

    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    CREATE = "CREATE"
    ALTER = "ALTER"
    DROP = "DROP"
    UNKNOWN = "UNKNOWN"


class OptimizationLevel(Enum):
    """Query optimization levels."""

    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    AGGRESSIVE = "aggressive"


@dataclass
class QueryAnalysis:
    """Query analysis results."""

    original_query: str
    query_type: QueryType
    tables_accessed: List[str]
    columns_accessed: List[str]
    has_wildcards: bool
    has_subqueries: bool
    has_joins: bool
    uses_select_star: bool
    has_limit: bool
    has_order_by: bool
    has_group_by: bool
    complexity_score: float
    estimated_rows: Optional[int] = None
    execution_time_ms: Optional[float] = None
    optimization_suggestions: List[str] = field(default_factory=list)


@dataclass
class IndexSuggestion:
    """Index creation suggestion."""

    table: str
    columns: List[str]
    index_type: str = "btree"
    priority: int = 1  # 1=high, 2=medium, 3=low
    reason: str = ""
    estimated_improvement: float = 0.0  # Percentage improvement


@dataclass
class QueryOptimizationResult:
    """Result of query optimization."""

    original_query: str
    optimized_query: str
    optimization_applied: List[str]
    performance_improvement: float = 0.0
    index_suggestions: List[IndexSuggestion] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class SQLQueryAnalyzer:
    """Advanced SQL query analyzer and optimizer."""

    def __init__(self):
        self.query_patterns = {
            "select_star": re.compile(r"\bSELECT\s+\*\s+FROM\b", re.IGNORECASE),
            "like_wildcard": re.compile()
                r'\bLIKE\s+[\'"][%_].*[%_][\'"]', re.IGNORECASE
            ),
            "subquery": re.compile(r"\(\s*SELECT\b", re.IGNORECASE),)
            "in_subquery": re.compile(r"\bIN\s*\(\s*SELECT\b", re.IGNORECASE),)
            "exists_subquery": re.compile(r"\bEXISTS\s*\(\s*SELECT\b", re.IGNORECASE),)
            "join": re.compile()
                r"\b(INNER|LEFT|RIGHT|FULL|CROSS)\s+JOIN\b", re.IGNORECASE
            ),
            "limit": re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE),
            "order_by": re.compile(r"\bORDER\s+BY\b", re.IGNORECASE),
            "group_by": re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
            "union": re.compile(r"\bUNION\b", re.IGNORECASE),
            "having": re.compile(r"\bHAVING\b", re.IGNORECASE),
        }

        # Common anti-patterns to detect
        self.anti_patterns = {
            "function_in_where": re.compile()
                r"\bWHERE\s+\w+\([^)]*\)\s*[=<>]", re.IGNORECASE
            ),
            "or_conditions": re.compile(r"\bWHERE\s+.*\bOR\b.*", re.IGNORECASE),
            "not_equals": re.compile(r"\s+!=\s+|\s+<>\s+", re.IGNORECASE),
            "leading_wildcard": re.compile(r'\bLIKE\s+[\'"]%', re.IGNORECASE),
            "multiple_or": re.compile(r"\bOR\b.*\bOR\b", re.IGNORECASE),
        }

    def analyze_query(self, query: str) -> QueryAnalysis:
        """Analyze SQL query for optimization opportunities."""
        query_clean = self._clean_query(query)

        analysis = QueryAnalysis()
            original_query=query,
            query_type=self._detect_query_type(query_clean),
            tables_accessed=self._extract_tables(query_clean),
            columns_accessed=self._extract_columns(query_clean),
            has_wildcards=bool()
                self.query_patterns["like_wildcard"].search(query_clean)
            ),
            has_subqueries=bool(self.query_patterns["subquery"].search(query_clean)),
            has_joins=bool(self.query_patterns["join"].search(query_clean)),
            uses_select_star=bool()
                self.query_patterns["select_star"].search(query_clean)
            ),
            has_limit=bool(self.query_patterns["limit"].search(query_clean)),
            has_order_by=bool(self.query_patterns["order_by"].search(query_clean)),
            has_group_by=bool(self.query_patterns["group_by"].search(query_clean)),
            complexity_score=self._calculate_complexity(query_clean),
        )

        # Generate optimization suggestions
        analysis.optimization_suggestions = self._generate_suggestions()
            analysis, query_clean
        )

        return analysis

    def optimize_query():
        self,
        query: str,
        optimization_level: OptimizationLevel = OptimizationLevel.INTERMEDIATE,
    ) -> QueryOptimizationResult:
        """Optimize SQL query based on analysis."""
        analysis = self.analyze_query(query)
        optimized_query = query
        optimizations_applied = []
        index_suggestions = []
        warnings = []

        # Apply optimizations based on level
        if optimization_level in [
            OptimizationLevel.BASIC,
            OptimizationLevel.INTERMEDIATE,
            OptimizationLevel.ADVANCED,
            OptimizationLevel.AGGRESSIVE,
        ]:

            # 1. Replace SELECT * with specific columns (if we can determine them)
            if ()
                analysis.uses_select_star
                and optimization_level != OptimizationLevel.BASIC
            ):
                warnings.append()
                    "Consider replacing SELECT * with specific column names for better performance"
                )

            # 2. Optimize LIKE clauses with leading wildcards
            if analysis.has_wildcards:
                optimized_query, applied = self._optimize_like_clauses(optimized_query)
                if applied:
                    optimizations_applied.extend(applied)

            # 3. Convert IN subqueries to EXISTS or JOINs
            if self.query_patterns["in_subquery"].search(optimized_query):
                optimized_query, applied = self._optimize_in_subqueries(optimized_query)
                if applied:
                    optimizations_applied.extend(applied)

            # 4. Add LIMIT clause if missing for SELECT queries
            if ()
                analysis.query_type == QueryType.SELECT
                and not analysis.has_limit
                and optimization_level
                in [OptimizationLevel.ADVANCED, OptimizationLevel.AGGRESSIVE]
            ):
                optimized_query, applied = self._add_limit_clause(optimized_query)
                if applied:
                    optimizations_applied.extend(applied)

            # 5. Suggest indexes based on WHERE clauses and JOINs
            index_suggestions = self._suggest_indexes(analysis, optimized_query)

        return QueryOptimizationResult()
            original_query=query,
            optimized_query=optimized_query,
            optimization_applied=optimizations_applied,
            index_suggestions=index_suggestions,
            warnings=warnings,
        )

    def _clean_query(self, query: str) -> str:
        """Clean and normalize query for analysis."""
        # Remove extra whitespace and normalize
        query = re.sub(r"\s+", " ", query.strip())
        return query

    def _detect_query_type(self, query: str) -> QueryType:
        """Detect the type of SQL query."""
        query_upper = query.upper().strip()

        if query_upper.startswith("SELECT"):
            return QueryType.SELECT
        elif query_upper.startswith("INSERT"):
            return QueryType.INSERT
        elif query_upper.startswith("UPDATE"):
            return QueryType.UPDATE
        elif query_upper.startswith("DELETE"):
            return QueryType.DELETE
        elif query_upper.startswith("CREATE"):
            return QueryType.CREATE
        elif query_upper.startswith("ALTER"):
            return QueryType.ALTER
        elif query_upper.startswith("DROP"):
            return QueryType.DROP
        else:
            return QueryType.UNKNOWN

    def _extract_tables(self, query: str) -> List[str]:
        """Extract table names from query."""
        tables = []

        # Simple regex patterns for table extraction
        from_pattern = re.compile(r"\bFROM\s+(\w+)", re.IGNORECASE)
        join_pattern = re.compile(r"\bJOIN\s+(\w+)", re.IGNORECASE)
        update_pattern = re.compile(r"\bUPDATE\s+(\w+)", re.IGNORECASE)
        insert_pattern = re.compile(r"\bINSERT\s+INTO\s+(\w+)", re.IGNORECASE)
        delete_pattern = re.compile(r"\bDELETE\s+FROM\s+(\w+)", re.IGNORECASE)

        for pattern in [
            from_pattern,
            join_pattern,
            update_pattern,
            insert_pattern,
            delete_pattern,
        ]:
            matches = pattern.findall(query)
            tables.extend(matches)

        return list(set(tables))  # Remove duplicates

    def _extract_columns(self, query: str) -> List[str]:
        """Extract column names from query (simplified)."""
        columns = []

        # Extract columns from SELECT clause
        select_match = re.search()
            r"\bSELECT\s+(.*?)\s+FROM\b", query, re.IGNORECASE | re.DOTALL
        )
        if select_match:
            select_clause = select_match.group(1)
            if "*" not in select_clause:
                # Split by comma and clean up
                column_parts = [col.strip() for col in select_clause.split(",")]
                for col in column_parts:
                    # Remove aliases and functions
                    col_clean = re.sub(r"\s+AS\s+\w+", "", col, flags=re.IGNORECASE)
                    col_clean = re.sub(r"\w+\((.*?)\)", r"\1", col_clean)
                    if col_clean and not col_clean.isspace():
                        columns.append(col_clean.strip())

        # Extract columns from WHERE clause
        where_pattern = re.compile(r"\bWHERE\s+.*?(\w+)\s*[=<>!]", re.IGNORECASE)
        where_matches = where_pattern.findall(query)
        columns.extend(where_matches)

        return list(set(columns))  # Remove duplicates

    def _calculate_complexity(self, query: str) -> float:
        """Calculate query complexity score."""
        score = 1.0

        # Add complexity for various elements
        if self.query_patterns["subquery"].search(query):
            score += 2.0
        if self.query_patterns["join"].search(query):
            score += 1.5
        if self.query_patterns["union"].search(query):
            score += 1.5
        if self.query_patterns["group_by"].search(query):
            score += 1.0
        if self.query_patterns["having"].search(query):
            score += 1.0
        if self.query_patterns["order_by"].search(query):
            score += 0.5

        # Add complexity for anti-patterns
        for pattern in self.anti_patterns.values():
            if pattern.search(query):
                score += 0.5

        return score

    def _generate_suggestions(self, analysis: QueryAnalysis, query: str) -> List[str]:
        """Generate optimization suggestions."""
        suggestions = []

        if analysis.uses_select_star:
            suggestions.append()
                "Replace SELECT * with specific column names to reduce data transfer"
            )

        if analysis.has_wildcards and self.anti_patterns["leading_wildcard"].search()
            query
        ):
            suggestions.append()
                "Avoid leading wildcards in LIKE clauses; consider full-text search or range queries"
            )

        if analysis.has_subqueries and self.query_patterns["in_subquery"].search(query):
            suggestions.append()
                "Consider replacing IN subqueries with EXISTS or JOINs for better performance"
            )

        if not analysis.has_limit and analysis.query_type == QueryType.SELECT:
            suggestions.append()
                "Add LIMIT clause to restrict the number of rows returned"
            )

        if self.anti_patterns["function_in_where"].search(query):
            suggestions.append()
                "Avoid using functions in WHERE clauses; consider computed columns or indexes"
            )

        if self.anti_patterns["or_conditions"].search(query):
            suggestions.append()
                "Consider rewriting OR conditions as separate queries with UNION for better index usage"
            )

        if analysis.complexity_score > 5.0:
            suggestions.append()
                "Query complexity is high; consider breaking into smaller queries or using stored procedures"
            )

        return suggestions

    def _optimize_like_clauses(self, query: str) -> Tuple[str, List[str]]:
        """Optimize LIKE clauses with wildcards."""
        optimizations = []
        optimized_query = query

        # Find LIKE clauses with leading wildcards
        leading_wildcard_pattern = re.compile()
            r'\b(\w+)\s+LIKE\s+[\'"]%([^%_]*)[\'"]', re.IGNORECASE
        )
        matches = leading_wildcard_pattern.findall(query)

        for column, value in matches:
            if len(value) > 2:  # Only optimize if we have meaningful content
                # Suggest range query instead
                suggestion = f"Consider using range query: {column} >= '{value}' AND {column} < '{value}z'"
                optimizations.append()
                    f"Suggested optimization for LIKE clause: {suggestion}"
                )

        return optimized_query, optimizations

    def _optimize_in_subqueries(self, query: str) -> Tuple[str, List[str]]:
        """Convert IN subqueries to EXISTS or JOINs."""
        optimizations = []
        optimized_query = query

        # Simple pattern matching for IN subqueries
        in_subquery_pattern = re.compile()
            r"\b(\w+)\s+IN\s*\(\s*SELECT\s+(\w+)\s+FROM\s+(\w+)([^)]*)\)", re.IGNORECASE
        )

        def replace_with_exists(match):
            column, sub_column, sub_table, sub_where = match.groups()
            exists_query = f"EXISTS (SELECT 1 FROM {sub_table} WHERE {sub_column} = {column}{sub_where})"
            optimizations.append()
                "Converted IN subquery to EXISTS for better performance"
            )
            return exists_query

        optimized_query = in_subquery_pattern.sub(replace_with_exists, optimized_query)

        return optimized_query, optimizations

    def _add_limit_clause(self, query: str) -> Tuple[str, List[str]]:
        """Add LIMIT clause to SELECT queries if missing."""
        optimizations = []

        if query.upper().strip().startswith("SELECT") and "LIMIT" not in query.upper():
            # Add a reasonable default limit
            optimized_query = f"{query.rstrip(';')} LIMIT 1000"
            optimizations.append("Added LIMIT 1000 to restrict rows returned")
            return optimized_query, optimizations

        return query, optimizations

    def _suggest_indexes():
        self, analysis: QueryAnalysis, query: str
    ) -> List[IndexSuggestion]:
        """Suggest indexes based on query analysis."""
        suggestions = []

        # Extract WHERE clause columns for indexing
        where_pattern = re.compile(r"\bWHERE\s+.*?(\w+)\s*[=<>!]", re.IGNORECASE)
        where_columns = where_pattern.findall(query)

        # Extract JOIN columns
        join_pattern = re.compile()
            r"\bON\s+(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)", re.IGNORECASE
        )
        join_matches = join_pattern.findall(query)

        # Extract ORDER BY columns
        order_pattern = re.compile(r"\bORDER\s+BY\s+([\w,\s]+)", re.IGNORECASE)
        order_match = order_pattern.search(query)

        # Suggest indexes for WHERE clause columns
        for table in analysis.tables_accessed:
            table_where_columns = [
                col for col in where_columns if col in analysis.columns_accessed
            ]
            if table_where_columns:
                suggestions.append()
                    IndexSuggestion()
                        table=table,
                        columns=table_where_columns[
                            :3
                        ],  # Limit to 3 columns for composite index
                        index_type="btree",
                        priority=1,
                        reason="Columns used in WHERE clause",
                        estimated_improvement=30.0,
                    )
                )

        # Suggest indexes for JOIN columns
        for join_match in join_matches:
            table1, col1, table2, col2 = join_match
            suggestions.append()
                IndexSuggestion()
                    table=table1,
                    columns=[col1],
                    index_type="btree",
                    priority=1,
                    reason="Column used in JOIN condition",
                    estimated_improvement=50.0,
                )
            )
            suggestions.append()
                IndexSuggestion()
                    table=table2,
                    columns=[col2],
                    index_type="btree",
                    priority=1,
                    reason="Column used in JOIN condition",
                    estimated_improvement=50.0,
                )
            )

        # Suggest indexes for ORDER BY columns
        if order_match:
            order_columns = [col.strip() for col in order_match.group(1).split(",")]
            for table in analysis.tables_accessed:
                suggestions.append()
                    IndexSuggestion()
                        table=table,
                        columns=order_columns,
                        index_type="btree",
                        priority=2,
                        reason="Columns used in ORDER BY clause",
                        estimated_improvement=25.0,
                    )
                )

        return suggestions


class NoSQLQueryOptimizer:
    """NoSQL query optimizer for MongoDB and other document databases."""

    def __init__(self):
        self.access_patterns = defaultdict(int)
        self.hot_partitions = set()
        self.query_stats = defaultdict(dict)

    def analyze_access_pattern():
        self, collection: str, query: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze NoSQL access patterns for optimization."""
        analysis = {
            "collection": collection,
            "query": query,
            "partition_key_used": False,
            "high_cardinality_fields": [],
            "potential_hotspots": [],
            "optimization_suggestions": [],
        }

        # Check if partition key is used effectively
        if "_id" in query or "user_id" in query or "timestamp" in query:
            analysis["partition_key_used"] = True
        else:
            analysis["optimization_suggestions"].append()
                "Consider using partition key (user_id, timestamp, or _id) in query for better distribution"
            )

        # Detect potential hot partitions
        for field, value in query.items():
            if isinstance(value, str) and len(set(value)) < 10:  # Low cardinality
                analysis["potential_hotspots"].append(field)
                analysis["optimization_suggestions"].append()
                    f"Field '{field}' has low cardinality and may cause hot partitions"
                )

        # Check for range queries that might be inefficient
        for field, value in query.items():
            if isinstance(value, dict) and any()
                op in value for op in ["$gte", "$lte", "$gt", "$lt"]
            ):
                if field not in ["timestamp", "created_at", "updated_at"]:
                    analysis["optimization_suggestions"].append()
                        f"Range query on '{field}' may be inefficient; consider using time-based partitioning"
                    )

        return analysis

    def optimize_mongodb_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize MongoDB query for better performance."""
        optimized = query.copy()

        # Add projection to limit fields returned
        if "projection" not in optimized and "find" in str(optimized):
            optimized["projection"] = {"_id": 1}  # Minimal projection

        # Add limit if not present
        if "limit" not in optimized:
            optimized["limit"] = 1000

        # Optimize sort operations
        if "sort" in optimized:
            # Ensure sort fields are indexed
            pass

        return optimized


class QueryPerformanceMonitor:
    """Monitor and track query performance metrics."""

    def __init__(self):
        self.query_stats = defaultdict()
            lambda: {
                "count": 0,
                "total_time": 0.0,
                "avg_time": 0.0,
                "max_time": 0.0,
                "min_time": float("inf"),
                "last_executed": None,
            }
        )
        self.slow_queries = []
        self.slow_query_threshold = 1000  # 1 second in milliseconds

    def record_query_execution():
        self,
        query: str,
        execution_time_ms: float,
        rows_returned: int = 0,
        rows_examined: int = 0,
    ):
        """Record query execution metrics."""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        stats = self.query_stats[query_hash]

        stats["count"] += 1
        stats["total_time"] += execution_time_ms
        stats["avg_time"] = stats["total_time"] / stats["count"]
        stats["max_time"] = max(stats["max_time"], execution_time_ms)
        stats["min_time"] = min(stats["min_time"], execution_time_ms)
        stats["last_executed"] = datetime.now(timezone.utc)

        # Track slow queries
        if execution_time_ms > self.slow_query_threshold:
            self.slow_queries.append()
                {
                    "query": query,
                    "execution_time_ms": execution_time_ms,
                    "rows_returned": rows_returned,
                    "rows_examined": rows_examined,
                    "timestamp": datetime.now(timezone.utc),
                }
            )

            # Keep only recent slow queries
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            self.slow_queries = [
                q for q in self.slow_queries if q["timestamp"] > cutoff
            ]

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report."""
        total_queries = sum(stats["count"] for stats in self.query_stats.values())
        avg_response_time = ()
            sum(stats["avg_time"] for stats in self.query_stats.values())
            / len(self.query_stats)
            if self.query_stats
            else 0
        )

        # Find most frequent queries
        frequent_queries = sorted()
            self.query_stats.items(), key=lambda x: x[1]["count"], reverse=True
        )[:10]

        # Find slowest queries
        slowest_queries = sorted()
            self.query_stats.items(), key=lambda x: x[1]["max_time"], reverse=True
        )[:10]

        return {
            "total_queries": total_queries,
            "average_response_time_ms": avg_response_time,
            "slow_queries_count": len(self.slow_queries),
            "most_frequent_queries": frequent_queries,
            "slowest_queries": slowest_queries,
            "performance_trends": self._calculate_trends(),
        }

    def _calculate_trends(self) -> Dict[str, Any]:
        """Calculate performance trends."""
        # Simple trend calculation
        recent_queries = [
            q
            for q in self.slow_queries
            if q["timestamp"] > datetime.now(timezone.utc) - timedelta(hours=1)
        ]

        return {
            "slow_queries_last_hour": len(recent_queries),
            "trend": ()
                "improving"
                if len(recent_queries) < len(self.slow_queries) / 24
                else "degrading"
            ),
        }


# Global instances
sql_analyzer = SQLQueryAnalyzer()
nosql_optimizer = NoSQLQueryOptimizer()
performance_monitor = QueryPerformanceMonitor()
