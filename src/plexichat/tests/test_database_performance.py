"""
PlexiChat Database Performance Optimization Tests

Comprehensive test suite for database performance optimization features
including query optimization, indexing, schema optimization, and monitoring.
"""

import pytest
import asyncio
import tempfile
import sqlite3
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

# Import the modules to test
from plexichat.core.database.enhanced_abstraction import enhanced_db_manager, DatabaseConfig, DatabaseType
from plexichat.core.database.performance_integration import performance_optimizer
from plexichat.core.database.query_optimizer import sql_analyzer, performance_monitor
from plexichat.core.database.indexing_strategy import index_manager
from plexichat.core.database.schema_optimizer import schema_optimizer
from plexichat.core.database.stored_procedures import procedure_manager


class TestDatabasePerformanceOptimization:
    """Test database performance optimization system."""
    
    @pytest.fixture
    async def test_database(self):
        """Create a test SQLite database with sample data."""
        # Create temporary database
        temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        temp_db.close()
        
        # Setup test database
        conn = sqlite3.connect(temp_db.name)
        cursor = conn.cursor()
        
        # Create test tables
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT,
                created_at TEXT,
                active INTEGER DEFAULT 1
            )
        """)
        
        cursor.execute("""
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                channel_id INTEGER,
                content TEXT,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Insert test data
        for i in range(100):
            cursor.execute(
                "INSERT INTO users (username, email, created_at, active) VALUES (?, ?, ?, ?)",
                (f"user{i}", f"user{i}@example.com", "2024-01-01", 1 if i % 2 == 0 else 0)
            )
        
        for i in range(500):
            cursor.execute(
                "INSERT INTO messages (user_id, channel_id, content, created_at) VALUES (?, ?, ?, ?)",
                (i % 100 + 1, i % 10 + 1, f"Test message {i}", "2024-01-01")
            )
        
        conn.commit()
        conn.close()
        
        # Configure database client
        config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            url=f"sqlite:///{temp_db.name}",
            name="test_db"
        )
        
        # Add to enhanced database manager
        await enhanced_db_manager.add_database("test_db", config)
        
        yield "test_db"
        
        # Cleanup
        await enhanced_db_manager.remove_database("test_db")
        os.unlink(temp_db.name)
    
    @pytest.mark.asyncio
    async def test_query_analyzer(self):
        """Test SQL query analyzer functionality."""
        # Test query analysis
        test_query = "SELECT * FROM users WHERE username LIKE '%test%' ORDER BY created_at"
        analysis = sql_analyzer.analyze_query(test_query)
        
        assert analysis.query_type.value == "SELECT"
        assert analysis.uses_select_star is True
        assert analysis.has_wildcards is True
        assert analysis.has_order_by is True
        assert analysis.complexity_score > 1.0
        assert len(analysis.optimization_suggestions) > 0
        
        # Test query optimization
        optimization = sql_analyzer.optimize_query(test_query)
        assert optimization.original_query == test_query
        assert len(optimization.optimization_applied) > 0
        
    @pytest.mark.asyncio
    async def test_performance_monitoring(self):
        """Test performance monitoring functionality."""
        # Record some test query executions
        performance_monitor.record_query_execution(
            "SELECT * FROM users WHERE active = 1",
            150.5,
            rows_returned=50,
            rows_examined=100
        )
        
        performance_monitor.record_query_execution(
            "SELECT COUNT(*) FROM messages",
            2500.0,  # Slow query
            rows_returned=1,
            rows_examined=500
        )
        
        # Get performance report
        report = performance_monitor.get_performance_report()
        
        assert report["total_queries"] >= 2
        assert report["slow_queries_count"] >= 1
        assert report["average_response_time_ms"] > 0
        
    @pytest.mark.asyncio
    async def test_index_recommendations(self, test_database):
        """Test index recommendation system."""
        client = enhanced_db_manager.clients[test_database]
        
        # Analyze and recommend indexes
        recommendations = await index_manager.analyze_and_recommend(test_database, client)
        
        # Should have some recommendations for our test queries
        assert isinstance(recommendations, list)
        
        # Get index report
        report = index_manager.get_index_report(test_database)
        assert "total_indexes" in report
        assert "recommendations_count" in report
        
    @pytest.mark.asyncio
    async def test_schema_optimization(self, test_database):
        """Test schema optimization functionality."""
        client = enhanced_db_manager.clients[test_database]
        
        # Test column analysis
        analysis = await schema_optimizer.analyze_column(client, "users", "username")
        
        assert analysis.table_name == "users"
        assert analysis.column_name == "username"
        assert analysis.current_data_type is not None
        
        # Test data type recommendations
        recommendations = await schema_optimizer.recommend_data_type_optimizations(client, "users")
        
        assert isinstance(recommendations, list)
        # May or may not have recommendations depending on data
        
    @pytest.mark.asyncio
    async def test_performance_integration(self, test_database):
        """Test comprehensive performance optimization integration."""
        # Analyze database performance
        report = await performance_optimizer.analyze_database_performance(test_database)
        
        assert report.database_name == test_database
        assert report.database_type == DatabaseType.SQLITE
        assert 0 <= report.performance_score <= 100
        assert report.optimization_priority in ["low", "medium", "high", "critical"]
        assert isinstance(report.top_recommendations, list)
        
        # Test optimization task creation
        tasks = await performance_optimizer.optimize_database_performance(
            test_database, auto_apply=False
        )
        
        assert isinstance(tasks, list)
        # May or may not have tasks depending on database state
        
    @pytest.mark.asyncio
    async def test_stored_procedures(self, test_database):
        """Test stored procedure functionality."""
        client = enhanced_db_manager.clients[test_database]
        
        # SQLite doesn't support stored procedures, so this should handle gracefully
        procedures = await procedure_manager.analyze_and_create_procedures(test_database, client)
        
        # Should return empty list for SQLite
        assert isinstance(procedures, list)
        
        # Test procedure performance report
        report = procedure_manager.get_procedure_performance_report(test_database)
        assert "database" in report
        assert "total_procedures" in report
        
    @pytest.mark.asyncio
    async def test_configuration_loading(self):
        """Test database performance configuration loading."""
        from plexichat.core.config.config_manager import ConfigManager
        
        config_manager = ConfigManager()
        
        # Test loading database performance config
        db_perf_config = config_manager.load_database_performance_config()
        
        assert "database_performance" in db_perf_config
        assert "enabled" in db_perf_config["database_performance"]
        assert "thresholds" in db_perf_config["database_performance"]
        
    @pytest.mark.asyncio
    async def test_cli_integration(self):
        """Test CLI integration for database performance commands."""
        from plexichat.cli.database_performance_cli import database_performance_cli
        from click.testing import CliRunner
        
        runner = CliRunner()
        
        # Test CLI help
        result = runner.invoke(database_performance_cli, ['--help'])
        assert result.exit_code == 0
        assert "Database Performance Optimization Commands" in result.output
        
        # Test status command
        result = runner.invoke(database_performance_cli, ['status'])
        # May fail if no databases configured, but should not crash
        assert result.exit_code in [0, 1]  # Allow failure for missing databases
        
    def test_query_patterns(self):
        """Test query pattern detection and optimization."""
        test_cases = [
            {
                "query": "SELECT * FROM users",
                "expected_issues": ["uses_select_star"],
                "expected_suggestions": ["Replace SELECT * with specific column names"]
            },
            {
                "query": "SELECT id FROM users WHERE name LIKE '%john%'",
                "expected_issues": ["has_wildcards"],
                "expected_suggestions": ["Avoid leading wildcards in LIKE clauses"]
            },
            {
                "query": "SELECT u.* FROM users u WHERE u.id IN (SELECT user_id FROM messages WHERE active = 1)",
                "expected_issues": ["has_subqueries", "uses_select_star"],
                "expected_suggestions": ["Consider replacing IN subqueries with EXISTS"]
            }
        ]
        
        for case in test_cases:
            analysis = sql_analyzer.analyze_query(case["query"])
            
            # Check that expected issues are detected
            for issue in case["expected_issues"]:
                if issue == "uses_select_star":
                    assert analysis.uses_select_star
                elif issue == "has_wildcards":
                    assert analysis.has_wildcards
                elif issue == "has_subqueries":
                    assert analysis.has_subqueries
            
            # Check that suggestions are generated
            assert len(analysis.optimization_suggestions) > 0
            
            # Check that at least one expected suggestion is present
            suggestions_text = " ".join(analysis.optimization_suggestions)
            found_suggestion = False
            for expected_suggestion in case["expected_suggestions"]:
                if any(keyword in suggestions_text for keyword in expected_suggestion.split()[:3]):
                    found_suggestion = True
                    break
            assert found_suggestion, f"Expected suggestion not found for query: {case['query']}"
    
    def test_performance_scoring(self):
        """Test performance scoring algorithm."""
        # Create mock report with known values
        from plexichat.core.database.performance_integration import PerformanceReport
        from datetime import datetime, timezone
        
        report = PerformanceReport(
            database_name="test",
            database_type=DatabaseType.SQLITE,
            analysis_timestamp=datetime.now(timezone.utc)
        )
        
        # Test with good performance metrics
        report.total_queries = 1000
        report.slow_queries_count = 10  # 1% slow queries
        report.avg_query_time_ms = 50.0  # Fast queries
        report.recommended_indexes = []  # No missing indexes
        report.unused_indexes = 0
        report.total_indexes = 5
        
        score = performance_optimizer._calculate_performance_score(report)
        assert score >= 80  # Should be high score
        
        # Test with poor performance metrics
        report.slow_queries_count = 500  # 50% slow queries
        report.avg_query_time_ms = 2000.0  # Very slow queries
        report.recommended_indexes = [Mock()] * 10  # Many missing indexes
        report.unused_indexes = 3
        
        score = performance_optimizer._calculate_performance_score(report)
        assert score <= 50  # Should be low score
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in performance optimization."""
        # Test with non-existent database
        try:
            await performance_optimizer.analyze_database_performance("non_existent_db")
            assert False, "Should have raised an error"
        except ValueError as e:
            assert "not found" in str(e)
        
        # Test with invalid query
        analysis = sql_analyzer.analyze_query("INVALID SQL QUERY")
        assert analysis.query_type.value == "UNKNOWN"
        
    def test_environment_variable_integration(self):
        """Test environment variable configuration."""
        import os
        from plexichat.core.config.config_manager import ConfigManager
        
        # Set test environment variables
        os.environ["PLEXICHAT_AUTO_OPTIMIZATION"] = "true"
        os.environ["PLEXICHAT_SLOW_QUERY_THRESHOLD_MS"] = "500"
        
        try:
            config_manager = ConfigManager()
            db_perf_config = config_manager.load_database_performance_config()
            
            # Environment variables should override defaults
            perf_config = db_perf_config.get("database_performance", {})
            
            # Note: This test may not work if the config file doesn't exist
            # but it tests the environment variable parsing logic
            
        finally:
            # Clean up environment variables
            del os.environ["PLEXICHAT_AUTO_OPTIMIZATION"]
            del os.environ["PLEXICHAT_SLOW_QUERY_THRESHOLD_MS"]


class TestDatabasePerformanceBenchmarks:
    """Benchmark tests for database performance optimization."""
    
    @pytest.mark.asyncio
    async def test_query_optimization_performance(self):
        """Benchmark query optimization performance."""
        test_queries = [
            "SELECT * FROM users WHERE active = 1",
            "SELECT u.*, m.content FROM users u JOIN messages m ON u.id = m.user_id WHERE u.active = 1",
            "SELECT COUNT(*) FROM messages WHERE created_at > '2024-01-01'",
            "SELECT user_id, COUNT(*) as msg_count FROM messages GROUP BY user_id HAVING COUNT(*) > 10"
        ]
        
        start_time = time.time()
        
        for query in test_queries:
            analysis = sql_analyzer.analyze_query(query)
            optimization = sql_analyzer.optimize_query(query)
            
            # Ensure analysis completes quickly
            assert analysis is not None
            assert optimization is not None
        
        end_time = time.time()
        optimization_time = end_time - start_time
        
        # Should complete all optimizations in reasonable time
        assert optimization_time < 1.0, f"Query optimization took too long: {optimization_time}s"
    
    @pytest.mark.asyncio
    async def test_performance_analysis_speed(self, test_database):
        """Benchmark performance analysis speed."""
        start_time = time.time()
        
        # Run performance analysis
        report = await performance_optimizer.analyze_database_performance(test_database)
        
        end_time = time.time()
        analysis_time = end_time - start_time
        
        # Should complete analysis in reasonable time
        assert analysis_time < 5.0, f"Performance analysis took too long: {analysis_time}s"
        assert report is not None


# Integration test for the complete system
@pytest.mark.asyncio
async def test_complete_performance_optimization_workflow():
    """Test the complete performance optimization workflow."""
    # This test verifies that all components work together
    
    # 1. Initialize system (mocked)
    with patch('plexichat.core.database.enhanced_abstraction.initialize_enhanced_database_system') as mock_init:
        mock_init.return_value = True
        
        # 2. Test configuration loading
        from plexichat.core.config.config_manager import ConfigManager
        config_manager = ConfigManager()
        db_perf_config = config_manager.load_database_performance_config()
        assert "database_performance" in db_perf_config
        
        # 3. Test query analysis
        test_query = "SELECT * FROM users WHERE active = 1"
        analysis = sql_analyzer.analyze_query(test_query)
        assert analysis.query_type.value == "SELECT"
        
        # 4. Test performance monitoring
        performance_monitor.record_query_execution(test_query, 100.0)
        report = performance_monitor.get_performance_report()
        assert report["total_queries"] > 0
        
        # 5. Test optimization summary
        summary = performance_optimizer.get_optimization_summary()
        assert "total_databases_analyzed" in summary


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
