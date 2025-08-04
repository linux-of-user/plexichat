"""
Database Abstraction Layer Testing

Tests the enhanced database abstraction layer with support for multiple database types.
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, List

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from plexichat.core.database import (
    ConsolidatedDatabaseManager,
    DatabaseConfig,
    DatabaseType,
    DatabaseRole,
    ConnectionStatus
)

logger = logging.getLogger(__name__)


class DatabaseAbstractionTester:
    """Test the database abstraction layer with multiple database types."""

    def __init__(self):
        self.db_manager = ConsolidatedDatabaseManager()
        self.test_results: Dict[str, Dict[str, Any]] = {}

    async def test_all_databases(self) -> Dict[str, Dict[str, Any]]:
        """Test all supported database types."""
        print("Starting Database Abstraction Layer Testing...")
        print("=" * 60)

        # Test database types that don't require external services
        local_databases = [
            ("SQLite", DatabaseType.SQLITE, self._test_sqlite),
        ]

        # Test database types that require external services (optional)
        external_databases = [
            ("PostgreSQL", DatabaseType.POSTGRESQL, self._test_postgresql),
            ("MySQL", DatabaseType.MYSQL, self._test_mysql),
            ("MariaDB", DatabaseType.MARIADB, self._test_mariadb),
            ("MongoDB", DatabaseType.MONGODB, self._test_mongodb),
            ("Redis", DatabaseType.REDIS, self._test_redis),
            ("ClickHouse", DatabaseType.CLICKHOUSE, self._test_clickhouse),
            ("TimescaleDB", DatabaseType.TIMESCALEDB, self._test_timescaledb),
            ("Cassandra", DatabaseType.CASSANDRA, self._test_cassandra),
            ("Elasticsearch", DatabaseType.ELASTICSEARCH, self._test_elasticsearch),
            ("Neo4j", DatabaseType.NEO4J, self._test_neo4j),
            ("InfluxDB", DatabaseType.INFLUXDB, self._test_influxdb),
        ]

        # Test local databases first
        for name, db_type, test_func in local_databases:
            print(f"\nTesting {name}...")
            try:
                result = await test_func()
                self.test_results[name] = result
                status = "PASS" if result.get("success") else "FAIL"
                print(f"  {status}: {result.get('message', 'No message')}")
            except Exception as e:
                self.test_results[name] = {"success": False, "error": str(e)}
                print(f"  FAIL: {str(e)}")

        # Test external databases (only if environment variables are set)
        for name, db_type, test_func in external_databases:
            env_var = f"PLEXICHAT_{name.upper().replace(' ', '_')}_URL"
            if os.getenv(env_var):
                print(f"\nTesting {name}...")
                try:
                    result = await test_func()
                    self.test_results[name] = result
                    status = "PASS" if result.get("success") else "FAIL"
                    print(f"  {status}: {result.get('message', 'No message')}")
                except Exception as e:
                    self.test_results[name] = {"success": False, "error": str(e)}
                    print(f"  FAIL: {str(e)}")
            else:
                self.test_results[name] = {"success": False, "skipped": True, "message": f"No {env_var} environment variable"}
                print(f"\nSkipping {name}: No environment configuration")

        return self.test_results

    async def _test_sqlite(self) -> Dict[str, Any]:
        """Test SQLite database."""
        try:
            config = DatabaseConfig(
                type=DatabaseType.SQLITE,
                name="test_sqlite",
                database="test_plexichat.db",
                role=DatabaseRole.PRIMARY
            )

            success = await self.db_manager.add_database("test_sqlite", config)
            if not success:
                return {}}"success": False, "message": "Failed to add SQLite database"}

            # Test connection
            connection_test = await self.db_manager._test_connection("test_sqlite")
            if not connection_test:
                return {}}"success": False, "message": "SQLite connection test failed"}

            # Test query execution
            result = await self.db_manager.execute_query(
                "SELECT 1 as test_value",
                database="test_sqlite"
            )

            if result.get("success") and result.get("result", {}).get("rows"):
                return {}}"success": True, "message": "SQLite test completed successfully"}
            else:
                return {}}"success": False, "message": f"SQLite query failed: {result}"}

        except Exception as e:
            return {}}"success": False, "message": f"SQLite test error: {str(e)}"}

    async def _test_postgresql(self) -> Dict[str, Any]:
        """Test PostgreSQL database."""
        try:
            config = DatabaseConfig(
                type=DatabaseType.POSTGRESQL,
                name="test_postgres",
                host=os.getenv("PLEXICHAT_POSTGRES_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_POSTGRES_PORT", "5432")),
                database=os.getenv("PLEXICHAT_POSTGRES_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_POSTGRES_USER", "postgres"),
                password=os.getenv("PLEXICHAT_POSTGRES_PASS", ""),
                role=DatabaseRole.PRIMARY
            )

            success = await self.db_manager.add_database("test_postgres", config)
            if not success:
                return {}}"success": False, "message": "Failed to add PostgreSQL database"}

            # Test connection
            connection_test = await self.db_manager._test_connection("test_postgres")
            if not connection_test:
                return {}}"success": False, "message": "PostgreSQL connection test failed"}

            return {}}"success": True, "message": "PostgreSQL test completed successfully"}

        except Exception as e:
            return {}}"success": False, "message": f"PostgreSQL test error: {str(e)}"}

    async def _test_mysql(self) -> Dict[str, Any]:
        """Test MySQL database."""
        try:
            config = DatabaseConfig(
                type=DatabaseType.MYSQL,
                name="test_mysql",
                host=os.getenv("PLEXICHAT_MYSQL_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MYSQL_PORT", "3306")),
                database=os.getenv("PLEXICHAT_MYSQL_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MYSQL_USER", "root"),
                password=os.getenv("PLEXICHAT_MYSQL_PASS", ""),
                role=DatabaseRole.PRIMARY
            )

            success = await self.db_manager.add_database("test_mysql", config)
            if not success:
                return {}}"success": False, "message": "Failed to add MySQL database"}

            return {}}"success": True, "message": "MySQL test completed successfully"}

        except Exception as e:
            return {}}"success": False, "message": f"MySQL test error: {str(e)}"}

    async def _test_mariadb(self) -> Dict[str, Any]:
        """Test MariaDB database."""
        return await self._test_mysql()  # MariaDB uses same driver as MySQL

    async def _test_mongodb(self) -> Dict[str, Any]:
        """Test MongoDB database."""
        try:
            config = DatabaseConfig(
                type=DatabaseType.MONGODB,
                name="test_mongodb",
                host=os.getenv("PLEXICHAT_MONGODB_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_MONGODB_PORT", "27017")),
                database=os.getenv("PLEXICHAT_MONGODB_DB", "plexichat"),
                username=os.getenv("PLEXICHAT_MONGODB_USER", ""),
                password=os.getenv("PLEXICHAT_MONGODB_PASS", ""),
                role=DatabaseRole.PRIMARY
            )

            success = await self.db_manager.add_database("test_mongodb", config)
            if not success:
                return {}}"success": False, "message": "Failed to add MongoDB database"}

            return {}}"success": True, "message": "MongoDB test completed successfully"}

        except Exception as e:
            return {}}"success": False, "message": f"MongoDB test error: {str(e)}"}

    async def _test_redis(self) -> Dict[str, Any]:
        """Test Redis database."""
        try:
            config = DatabaseConfig(
                type=DatabaseType.REDIS,
                name="test_redis",
                host=os.getenv("PLEXICHAT_REDIS_HOST", "localhost"),
                port=int(os.getenv("PLEXICHAT_REDIS_PORT", "6379")),
                password=os.getenv("PLEXICHAT_REDIS_PASS", ""),
                role=DatabaseRole.CACHE
            )

            success = await self.db_manager.add_database("test_redis", config)
            if not success:
                return {}}"success": False, "message": "Failed to add Redis database"}

            return {}}"success": True, "message": "Redis test completed successfully"}

        except Exception as e:
            return {}}"success": False, "message": f"Redis test error: {str(e)}"}

    # Placeholder test methods for other databases
    async def _test_clickhouse(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "ClickHouse test not implemented yet"}

    async def _test_timescaledb(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "TimescaleDB test not implemented yet"}

    async def _test_cassandra(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "Cassandra test not implemented yet"}

    async def _test_elasticsearch(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "Elasticsearch test not implemented yet"}

    async def _test_neo4j(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "Neo4j test not implemented yet"}

    async def _test_influxdb(self) -> Dict[str, Any]:
        return {}}"success": False, "message": "InfluxDB test not implemented yet"}

    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 60)
        print("DATABASE ABSTRACTION LAYER TEST SUMMARY")
        print("=" * 60)

        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result.get("success"))
        skipped_tests = sum(1 for result in self.test_results.values() if result.get("skipped"))
        failed_tests = total_tests - passed_tests - skipped_tests

        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Skipped: {skipped_tests}")

        print("\nDetailed Results:")
        for db_name, result in self.test_results.items():
            if result.get("success"):
                status = "PASS"
            elif result.get("skipped"):
                status = "SKIP"
            else:
                status = "FAIL"
            
            print(f"  {db_name:15} {status:4} - {result.get('message', 'No message')}")


async def main():
    """Main test function."""
    tester = DatabaseAbstractionTester()
    
    try:
        await tester.test_all_databases()
        tester.print_summary()
        
        # Return appropriate exit code
        failed_tests = sum(1 for result in tester.test_results.values() 
                          if not result.get("success") and not result.get("skipped"))
        
        if failed_tests > 0:
            print(f"\n{failed_tests} tests failed!")
            sys.exit(1)
        else:
            print("\nAll available database tests passed!")
            sys.exit(0)
            
    except Exception as e:
        print(f"Test execution failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
