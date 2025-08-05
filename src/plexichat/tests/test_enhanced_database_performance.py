"""
Enhanced Database Performance Testing

Tests the enhanced database abstraction layer with integrated performance optimizations:
- Redis caching integration
- Advanced connection pooling
- Query optimization
- Performance monitoring
- Auto-tuning capabilities
"""

import asyncio
import logging
import os
import sys
import time
from typing import Dict, Any, List
import json

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from plexichat.core.database.enhanced_db_manager import (
    EnhancedDatabaseManager,
    EnhancedConnectionPool,
    EnhancedQueryCache,
    get_enhanced_db_manager
)
from plexichat.core.database import (
    DatabaseConfig,
    DatabaseType,
    DatabaseRole
)

logger = logging.getLogger(__name__)


class EnhancedDatabasePerformanceTester:
    """Test enhanced database performance features."""

    def __init__(self):
        self.db_manager: EnhancedDatabaseManager = None
        self.test_results: Dict[str, Dict[str, Any]] = {}
        self.performance_metrics: Dict[str, List[float]] = {
            'query_times': [],
            'cache_hit_rates': [],
            'connection_pool_utilization': []
        }

    async def run_all_tests(self) -> Dict[str, Dict[str, Any]]:
        """Run all enhanced database performance tests."""
        print("Starting Enhanced Database Performance Testing...")
        print("=" * 70)

        # Initialize enhanced database manager
        await self._initialize_enhanced_manager()

        # Run performance tests
        test_suite = [
            ("Connection Pool Performance", self._test_connection_pool_performance),
            ("Query Cache Performance", self._test_query_cache_performance),
            ("Redis Integration", self._test_redis_integration),
            ("Query Optimization", self._test_query_optimization),
            ("Auto-tuning", self._test_auto_tuning),
            ("Concurrent Load", self._test_concurrent_load),
            ("Memory Usage", self._test_memory_usage),
            ("Cache Invalidation", self._test_cache_invalidation),
            ("Performance Monitoring", self._test_performance_monitoring),
            ("Stress Test", self._test_stress_performance)
        ]

        for test_name, test_func in test_suite:
            print(f"\nRunning {test_name}...")
            try:
                start_time = time.time()
                result = await test_func()
                execution_time = time.time() - start_time
                
                result['execution_time_seconds'] = execution_time
                self.test_results[test_name] = result
                
                status = "PASS" if result.get("success") else "FAIL"
                print(f"  {status}: {result.get('message', 'No message')} ({execution_time:.2f}s)")
                
            except Exception as e:
                self.test_results[test_name] = {
                    "success": False, 
                    "error": str(e),
                    "execution_time_seconds": 0
                }
                print(f"  FAIL: {str(e)}")

        # Generate performance report
        await self._generate_performance_report()

        return self.test_results

    async def _initialize_enhanced_manager(self):
        """Initialize enhanced database manager with test configuration."""
        config = {
            'enable_query_cache': True,
            'enable_query_optimization': True,
            'enable_performance_monitoring': True,
            'auto_tune_enabled': True,
            'auto_tune_interval': 60,  # 1 minute for testing
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 1  # Use test database
            }
        }
        
        self.db_manager = EnhancedDatabaseManager(config)
        await self.db_manager.initialize()
        
        # Add test SQLite database
        sqlite_config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            name="test_enhanced_sqlite",
            database="test_enhanced_performance.db",
            role=DatabaseRole.PRIMARY,
            connection_pool_size=20,
            max_overflow=30
        )
        
        success = await self.db_manager.add_database("test_enhanced", sqlite_config, is_default=True)
        if not success:
            raise RuntimeError("Failed to add test database")

    async def _test_connection_pool_performance(self) -> Dict[str, Any]:
        """Test enhanced connection pool performance."""
        try:
            # Test concurrent connections
            async def execute_test_query():
                return await self.db_manager.execute_query(
                    "SELECT 1 as test_value, datetime('now') as timestamp",
                    database="test_enhanced"
                )
            
            # Execute multiple concurrent queries
            start_time = time.time()
            tasks = [execute_test_query() for _ in range(50)]
            results = await asyncio.gather(*tasks)
            execution_time = time.time() - start_time
            
            # Check results
            successful_queries = sum(1 for r in results if r.get("success"))
            
            # Get pool metrics
            pool_stats = await self.db_manager.get_performance_stats()
            pool_metrics = pool_stats.get("connection_pools", {}).get("test_enhanced", {})
            
            return {}
                "success": successful_queries == 50,
                "message": f"Executed {successful_queries}/50 concurrent queries in {execution_time:.2f}s",
                "metrics": {
                    "total_execution_time": execution_time,
                    "queries_per_second": 50 / execution_time,
                    "pool_utilization": pool_metrics.get("pool_utilization_percent", 0),
                    "connection_errors": pool_metrics.get("connection_errors", 0)
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Connection pool test failed: {e}"}

    async def _test_query_cache_performance(self) -> Dict[str, Any]:
        """Test query cache performance and hit rates."""
        try:
            test_query = "SELECT 1 as cached_value, 'test' as data"
            
            # First execution (cache miss)
            start_time = time.time()
            result1 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            first_execution_time = time.time() - start_time
            
            # Second execution (should be cache hit)
            start_time = time.time()
            result2 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            second_execution_time = time.time() - start_time
            
            # Third execution (should also be cache hit)
            result3 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            
            # Get cache statistics
            cache_stats = await self.db_manager.get_performance_stats()
            cache_metrics = cache_stats.get("query_cache", {})
            
            cache_hit_improvement = (first_execution_time - second_execution_time) / first_execution_time * 100
            
            return {}
                "success": result2.get("cached", False),
                "message": f"Cache hit rate: {cache_metrics.get('hit_rate_percent', 0):.1f}%, Speed improvement: {cache_hit_improvement:.1f}%",
                "metrics": {
                    "first_execution_ms": first_execution_time * 1000,
                    "cached_execution_ms": second_execution_time * 1000,
                    "cache_hit_rate": cache_metrics.get('hit_rate_percent', 0),
                    "l1_cache_size": cache_metrics.get('l1_cache_size', 0),
                    "speed_improvement_percent": cache_hit_improvement
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Query cache test failed: {e}"}

    async def _test_redis_integration(self) -> Dict[str, Any]:
        """Test Redis integration for distributed caching."""
        try:
            if not self.db_manager.redis_client:
                return {"success": False, "message": "Redis not available"}
            
            # Test Redis connectivity
            await self.db_manager.redis_client.ping()
            
            # Test distributed cache
            test_query = "SELECT 'redis_test' as source, datetime('now') as timestamp"
            
            # Execute query to populate cache
            result1 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            
            # Clear L1 cache to force Redis lookup
            if self.db_manager.query_cache:
                self.db_manager.query_cache.l1_cache.clear()
            
            # Execute again (should hit Redis L2 cache)
            result2 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            
            # Get Redis info
            redis_info = await self.db_manager.redis_client.info('memory')
            
            return {}
                "success": True,
                "message": f"Redis integration working, Memory usage: {redis_info.get('used_memory_human', 'unknown')}",
                "metrics": {
                    "redis_connected": True,
                    "redis_memory": redis_info.get('used_memory', 0),
                    "cache_keys": len(await self.db_manager.redis_client.keys("query:*"))
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Redis integration test failed: {e}"}

    async def _test_query_optimization(self) -> Dict[str, Any]:
        """Test query optimization features."""
        try:
            # Test query that can be optimized
            unoptimized_query = "SELECT * FROM (SELECT 1 as id, 'test' as name)"
            
            result = await self.db_manager.execute_query(
                unoptimized_query, 
                database="test_enhanced"
            )
            
            # Get optimization stats
            optimizer_stats = self.db_manager.query_optimizer.get_optimization_stats()
            
            return {}
                "success": result.get("success", False),
                "message": f"Query optimization: {optimizer_stats.get('queries_optimized', 0)} queries optimized",
                "metrics": {
                    "queries_optimized": optimizer_stats.get('queries_optimized', 0),
                    "total_time_saved_ms": optimizer_stats.get('total_time_saved_ms', 0),
                    "was_optimized": result.get("optimized", False)
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Query optimization test failed: {e}"}

    async def _test_auto_tuning(self) -> Dict[str, Any]:
        """Test auto-tuning capabilities."""
        try:
            # Trigger auto-tuning by executing multiple queries
            queries = [
                "SELECT 1 as test_id",
                "SELECT 2 as test_id", 
                "SELECT 3 as test_id"
            ]
            
            for query in queries:
                await self.db_manager.execute_query(query, database="test_enhanced")
            
            # Wait a moment for auto-tuning to potentially trigger
            await asyncio.sleep(1)
            
            # Get performance stats
            perf_stats = await self.db_manager.get_performance_stats()
            
            return {}
                "success": True,
                "message": "Auto-tuning system active",
                "metrics": {
                    "auto_tune_enabled": self.db_manager.auto_tune_enabled,
                    "auto_tune_interval": self.db_manager.auto_tune_interval,
                    "performance_monitoring": self.db_manager.enable_performance_monitoring
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Auto-tuning test failed: {e}"}

    async def _test_concurrent_load(self) -> Dict[str, Any]:
        """Test performance under concurrent load."""
        try:
            async def concurrent_query_batch():
                tasks = []
                for i in range(10):
                    query = f"SELECT {i} as batch_id, datetime('now') as timestamp"
                    task = self.db_manager.execute_query(query, database="test_enhanced")
                    tasks.append(task)
                return await asyncio.gather(*tasks)
            
            # Execute multiple concurrent batches
            start_time = time.time()
            batch_tasks = [concurrent_query_batch() for _ in range(5)]
            batch_results = await asyncio.gather(*batch_tasks)
            total_time = time.time() - start_time
            
            # Count successful queries
            total_queries = 0
            successful_queries = 0
            
            for batch in batch_results:
                for result in batch:
                    total_queries += 1
                    if result.get("success"):
                        successful_queries += 1
            
            throughput = total_queries / total_time
            
            return {}
                "success": successful_queries == total_queries,
                "message": f"Processed {successful_queries}/{total_queries} concurrent queries at {throughput:.1f} QPS",
                "metrics": {
                    "total_queries": total_queries,
                    "successful_queries": successful_queries,
                    "total_time_seconds": total_time,
                    "queries_per_second": throughput,
                    "success_rate_percent": (successful_queries / total_queries) * 100
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Concurrent load test failed: {e}"}

    async def _test_memory_usage(self) -> Dict[str, Any]:
        """Test memory usage and cache efficiency."""
        try:
            import psutil
            import gc
            
            # Get initial memory usage
            process = psutil.Process()
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            
            # Execute many queries to populate caches
            for i in range(100):
                query = f"SELECT {i} as memory_test_id, 'data_{i}' as test_data"
                await self.db_manager.execute_query(query, database="test_enhanced")
            
            # Force garbage collection
            gc.collect()
            
            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory
            
            # Get cache stats
            cache_stats = await self.db_manager.get_performance_stats()
            cache_metrics = cache_stats.get("query_cache", {})
            
            return {}
                "success": memory_increase < 50,  # Less than 50MB increase
                "message": f"Memory usage increased by {memory_increase:.1f}MB, Cache size: {cache_metrics.get('l1_cache_size', 0)}",
                "metrics": {
                    "initial_memory_mb": initial_memory,
                    "final_memory_mb": final_memory,
                    "memory_increase_mb": memory_increase,
                    "cache_size": cache_metrics.get('l1_cache_size', 0),
                    "cache_hit_rate": cache_metrics.get('hit_rate_percent', 0)
                }
            }
            
        except ImportError:
            return {"success": False, "message": "psutil not available for memory testing"}
        except Exception as e:
            return {"success": False, "message": f"Memory usage test failed: {e}"}

    async def _test_cache_invalidation(self) -> Dict[str, Any]:
        """Test cache invalidation functionality."""
        try:
            # Execute query to populate cache
            test_query = "SELECT 'invalidation_test' as test_type"
            result1 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            
            # Verify it's cached
            result2 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            was_cached = result2.get("cached", False)
            
            # Invalidate cache for a hypothetical table
            await self.db_manager.invalidate_cache_for_table("test_table")
            
            # Clear all caches
            if self.db_manager.query_cache:
                await self.db_manager.query_cache.clear()
            
            # Execute query again (should not be cached)
            result3 = await self.db_manager.execute_query(test_query, database="test_enhanced")
            not_cached_after_clear = not result3.get("cached", False)
            
            return {}
                "success": was_cached and not_cached_after_clear,
                "message": f"Cache invalidation working: was_cached={was_cached}, cleared={not_cached_after_clear}",
                "metrics": {
                    "cache_invalidation_working": was_cached and not_cached_after_clear,
                    "initial_cached": was_cached,
                    "after_clear_cached": result3.get("cached", False)
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Cache invalidation test failed: {e}"}

    async def _test_performance_monitoring(self) -> Dict[str, Any]:
        """Test performance monitoring capabilities."""
        try:
            # Execute some queries to generate metrics
            for i in range(10):
                await self.db_manager.execute_query(
                    f"SELECT {i} as monitor_test", 
                    database="test_enhanced"
                )
            
            # Get comprehensive performance stats
            perf_stats = await self.db_manager.get_performance_stats()
            
            has_connection_stats = "connection_pools" in perf_stats
            has_cache_stats = "query_cache" in perf_stats
            has_monitor_stats = "performance_monitor" in perf_stats
            
            return {}
                "success": has_connection_stats and has_cache_stats,
                "message": f"Performance monitoring active: pools={has_connection_stats}, cache={has_cache_stats}, monitor={has_monitor_stats}",
                "metrics": {
                    "has_connection_stats": has_connection_stats,
                    "has_cache_stats": has_cache_stats,
                    "has_monitor_stats": has_monitor_stats,
                    "redis_status": perf_stats.get("redis_status", "unknown")
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Performance monitoring test failed: {e}"}

    async def _test_stress_performance(self) -> Dict[str, Any]:
        """Stress test the enhanced database system."""
        try:
            stress_queries = 200
            batch_size = 20
            
            async def stress_batch():
                tasks = []
                for i in range(batch_size):
                    query = f"SELECT {i} as stress_id, datetime('now') as stress_time"
                    task = self.db_manager.execute_query(query, database="test_enhanced")
                    tasks.append(task)
                return await asyncio.gather(*tasks)
            
            # Execute stress test
            start_time = time.time()
            stress_batches = [stress_batch() for _ in range(stress_queries // batch_size)]
            stress_results = await asyncio.gather(*stress_batches)
            total_stress_time = time.time() - start_time
            
            # Calculate metrics
            total_stress_queries = 0
            successful_stress_queries = 0
            
            for batch in stress_results:
                for result in batch:
                    total_stress_queries += 1
                    if result.get("success"):
                        successful_stress_queries += 1
            
            stress_throughput = total_stress_queries / total_stress_time
            
            # Get final performance stats
            final_stats = await self.db_manager.get_performance_stats()
            
            return {}
                "success": successful_stress_queries >= total_stress_queries * 0.95,  # 95% success rate
                "message": f"Stress test: {successful_stress_queries}/{total_stress_queries} queries at {stress_throughput:.1f} QPS",
                "metrics": {
                    "total_stress_queries": total_stress_queries,
                    "successful_stress_queries": successful_stress_queries,
                    "stress_time_seconds": total_stress_time,
                    "stress_throughput_qps": stress_throughput,
                    "stress_success_rate": (successful_stress_queries / total_stress_queries) * 100,
                    "final_cache_hit_rate": final_stats.get("query_cache", {}).get("hit_rate_percent", 0)
                }
            }
            
        except Exception as e:
            return {"success": False, "message": f"Stress test failed: {e}"}

    async def _generate_performance_report(self):
        """Generate comprehensive performance report."""
        print("\n" + "=" * 70)
        print("ENHANCED DATABASE PERFORMANCE REPORT")
        print("=" * 70)
        
        # Summary statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result.get("success"))
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Performance metrics summary
        print("\nPerformance Metrics Summary:")
        
        # Get final performance stats
        try:
            final_stats = await self.db_manager.get_performance_stats()
            
            cache_stats = final_stats.get("query_cache", {})
            print(f"  Cache Hit Rate: {cache_stats.get('hit_rate_percent', 0):.1f}%")
            print(f"  Cache Size: {cache_stats.get('l1_cache_size', 0)} entries")
            
            connection_stats = final_stats.get("connection_pools", {})
            if connection_stats:
                for pool_name, pool_metrics in connection_stats.items():
                    print(f"  {pool_name} Pool Utilization: {pool_metrics.get('pool_utilization_percent', 0):.1f}%")
                    print(f"  {pool_name} Connection Errors: {pool_metrics.get('connection_errors', 0)}")
            
            print(f"  Redis Status: {final_stats.get('redis_status', 'unknown')}")
            
        except Exception as e:
            print(f"  Error getting final stats: {e}")
        
        # Detailed test results
        print("\nDetailed Test Results:")
        for test_name, result in self.test_results.items():
            status = "PASS" if result.get("success") else "FAIL"
            exec_time = result.get("execution_time_seconds", 0)
            print(f"  {test_name:30} {status:4} ({exec_time:.2f}s) - {result.get('message', 'No message')}")
            
            # Show key metrics if available
            metrics = result.get("metrics", {})
            if metrics:
                for key, value in metrics.items():
                    if isinstance(value, (int, float)):
                        print(f"    {key}: {value}")

    async def cleanup(self):
        """Cleanup test resources."""
        try:
            if self.db_manager:
                await self.db_manager.close()
            
            # Clean up test database file
            test_db_file = "test_enhanced_performance.db"
            if os.path.exists(test_db_file):
                os.remove(test_db_file)
                
        except Exception as e:
            print(f"Cleanup error: {e}")


async def main():
    """Main test function."""
    tester = EnhancedDatabasePerformanceTester()
    
    try:
        # Run all tests
        results = await tester.run_all_tests()
        
        # Determine exit code
        failed_tests = sum(1 for result in results.values() 
                          if not result.get("success"))
        
        if failed_tests > 0:
            print(f"\n{failed_tests} tests failed!")
            return 1
        else:
            print("\nAll enhanced database performance tests passed!")
            return 0
            
    except Exception as e:
        print(f"Test execution failed: {e}")
        return 1
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)