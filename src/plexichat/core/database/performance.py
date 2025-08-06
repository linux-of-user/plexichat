"""
PlexiChat Database Performance Monitor
Simple database performance monitoring and optimization.


import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class QueryStats:
    """Query execution statistics."""
        query_hash: str
    execution_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    last_executed: Optional[datetime] = None


@dataclass
class PerformanceReport:
    Database performance report."""
        database_name: str
    total_queries: int = 0
    slow_queries_count: int = 0
    avg_query_time_ms: float = 0.0
    performance_score: float = 100.0
    optimization_priority: str = "low"
    top_recommendations: List[str] = None
    
    def __post_init__(self):
        if self.top_recommendations is None:
            self.top_recommendations = []


class DatabasePerformanceMonitor:
    """Simple database performance monitor."""
        def __init__(self, slow_query_threshold: float = 1.0):
        self.slow_query_threshold = slow_query_threshold  # seconds
        self.query_stats: Dict[str, QueryStats] = {}
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0
        }
    
    def record_query(self, query: str, execution_time: float):
        """Record query execution statistics.
        query_hash = self._hash_query(query)
        
        if query_hash not in self.query_stats:
            self.query_stats[query_hash] = QueryStats(query_hash=query_hash)
        
        stats = self.query_stats[query_hash]
        stats.execution_count += 1
        stats.total_time += execution_time
        stats.avg_time = stats.total_time / stats.execution_count
        stats.min_time = min(stats.min_time, execution_time)
        stats.max_time = max(stats.max_time, execution_time)
        stats.last_executed = datetime.now()
    
    def _hash_query(self, query: str) -> str:
        """Create a hash for query identification."""
        import hashlib
        # Normalize query for hashing
        normalized = ' '.join(query.strip().split())
        return hashlib.md5(normalized.encode()).hexdigest()[:8]
    
    def get_slow_queries(self) -> List[QueryStats]:
        Get queries that exceed the slow query threshold."""
        return [
            stats for stats in self.query_stats.values()
            if stats.avg_time > self.slow_query_threshold
        ]
    
    def get_frequent_queries(self, min_count: int = 10) -> List[QueryStats]:
        """Get frequently executed queries.
        return [
            stats for stats in self.query_stats.values()
            if stats.execution_count >= min_count
        ]
    
    def generate_report(self, database_name: str) -> PerformanceReport:
        """Generate a performance report."""
        report = PerformanceReport(database_name=database_name)
        
        if not self.query_stats:
            return report
        
        # Calculate basic metrics
        all_stats = list(self.query_stats.values())
        report.total_queries = sum(stats.execution_count for stats in all_stats)
        
        if report.total_queries > 0:
            total_time = sum(stats.total_time for stats in all_stats)
            report.avg_query_time_ms = (total_time / report.total_queries) * 1000
        
        # Count slow queries
        slow_queries = self.get_slow_queries()
        report.slow_queries_count = len(slow_queries)
        
        # Calculate performance score (simple heuristic)
        if report.total_queries > 0:
            slow_query_ratio = report.slow_queries_count / len(all_stats)
            report.performance_score = max(0, 100 - (slow_query_ratio * 50))
            
            if report.avg_query_time_ms > 1000:  # > 1 second average
                report.performance_score -= 30
            elif report.avg_query_time_ms > 500:  # > 500ms average
                report.performance_score -= 15
        
        # Determine optimization priority
        if report.performance_score < 50:
            report.optimization_priority = "high"
        elif report.performance_score < 75:
            report.optimization_priority = "medium"
        else:
            report.optimization_priority = "low"
        
        # Generate recommendations
        report.top_recommendations = self._generate_recommendations(report, slow_queries)
        
        return report
    
    def _generate_recommendations(self, report: PerformanceReport, slow_queries: List[QueryStats]) -> List[str]:
        """Generate optimization recommendations."""
        recommendations = []
        
        if slow_queries:
            recommendations.append(f"Optimize {len(slow_queries)} slow queries")
        
        if report.avg_query_time_ms > 1000:
            recommendations.append("Consider adding database indexes for frequently used columns")
        
        frequent_queries = self.get_frequent_queries()
        if frequent_queries:
            recommendations.append("Consider caching results for frequently executed queries")
        
        if self.connection_stats["failed_connections"] > 0:
            recommendations.append("Review connection pool settings")
        
        if not recommendations:
            recommendations.append("Database performance is optimal")
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def record_connection(self, success: bool = True):
        """Record connection attempt."""
        self.connection_stats["total_connections"] += 1
        if success:
            self.connection_stats["active_connections"] += 1
        else:
            self.connection_stats["failed_connections"] += 1
    
    def close_connection(self):
        """Record connection closure."""
        if self.connection_stats["active_connections"] > 0:
            self.connection_stats["active_connections"] -= 1
    
    def get_connection_stats(self) -> Dict[str, int]:
        """Get connection statistics.
        return self.connection_stats.copy()
    
    def clear_stats(self):
        """Clear all statistics."""
        self.query_stats.clear()
        self.connection_stats = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0
        }
    
    def get_top_queries_by_time(self, limit: int = 10) -> List[QueryStats]:
        """Get queries with highest total execution time.
        return sorted(
            self.query_stats.values(),
            key=lambda x: x.total_time,
            reverse=True
        )[:limit]
    
    def get_top_queries_by_count(self, limit: int = 10) -> List[QueryStats]:
        """Get most frequently executed queries."""
        return sorted(
            self.query_stats.values(),
            key=lambda x: x.execution_count,
            reverse=True
        )[:limit]


class QueryOptimizer:
    Simple query optimization suggestions."""
        @staticmethod
    def analyze_query(query: str) -> List[str]:
        """Analyze a query and provide optimization suggestions."""
        suggestions = []
        query_lower = query.lower().strip()
        
        # Check for SELECT *
        if "select *" in query_lower:
            suggestions.append("Avoid SELECT * - specify only needed columns")
        
        # Check for missing WHERE clause in SELECT
        if query_lower.startswith("select") and "where" not in query_lower:
            suggestions.append("Consider adding WHERE clause to limit results")
        
        # Check for missing LIMIT
        if query_lower.startswith("select") and "limit" not in query_lower:
            suggestions.append("Consider adding LIMIT clause for large result sets")
        
        # Check for OR conditions
        if " or " in query_lower:
            suggestions.append("Consider rewriting OR conditions for better index usage")
        
        # Check for functions in WHERE clause
        if "where" in query_lower:
            where_part = query_lower.split("where", 1)[1]
            if any(func in where_part for func in ["upper(", "lower(", "substr(", "length("]):
                suggestions.append("Avoid functions in WHERE clause - consider computed columns")
        
        return suggestions


# Global performance monitor instance
performance_monitor = DatabasePerformanceMonitor()
query_optimizer = QueryOptimizer()

__all__ = [
    "QueryStats", "PerformanceReport", "DatabasePerformanceMonitor", "QueryOptimizer",
    "performance_monitor", "query_optimizer"
]
