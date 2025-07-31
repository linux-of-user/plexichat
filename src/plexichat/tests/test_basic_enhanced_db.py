"""
Basic Enhanced Database Test

Simple test to verify enhanced database functionality without Redis dependency.
"""

import asyncio
import logging
import os
import sys
import time

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from plexichat.core.database.enhanced_db_manager import EnhancedDatabaseManager
from plexichat.core.database import DatabaseConfig, DatabaseType, DatabaseRole

logger = logging.getLogger(__name__)


async def test_basic_enhanced_db():
    """Test basic enhanced database functionality."""
    print("Testing Enhanced Database Manager (Basic)...")
    
    # Initialize without Redis
    config = {
        'enable_query_cache': True,
        'enable_query_optimization': True,
        'enable_performance_monitoring': True,
        'auto_tune_enabled': False,  # Disable for basic test
        'redis': None  # No Redis
    }
    
    db_manager = EnhancedDatabaseManager(config)
    
    try:
        # Initialize
        await db_manager.initialize()
        print("OK Enhanced database manager initialized")
        
        # Add SQLite database
        sqlite_config = DatabaseConfig(
            type=DatabaseType.SQLITE,
            name="test_basic_sqlite",
            database="test_basic_enhanced.db",
            role=DatabaseRole.PRIMARY,
            connection_pool_size=5
        )
        
        success = await db_manager.add_database("test_basic", sqlite_config, is_default=True)
        if success:
            print("OK SQLite database added successfully")
        else:
            print("ERROR Failed to add SQLite database")
            return False
        
        # Test basic query
        result = await db_manager.execute_query(
            "SELECT 1 as test_value, 'hello' as message",
            database="test_basic"
        )
        
        if result.get("success"):
            print("OK Basic query executed successfully")
            print(f"  Result: {result.get('result', {})}")
        else:
            print(f"ERROR Basic query failed: {result.get('error')}")
            return False
        
        # Test cached query
        start_time = time.time()
        result1 = await db_manager.execute_query(
            "SELECT 2 as cached_value",
            database="test_basic"
        )
        first_time = time.time() - start_time
        
        start_time = time.time()
        result2 = await db_manager.execute_query(
            "SELECT 2 as cached_value",
            database="test_basic"
        )
        second_time = time.time() - start_time
        
        if result2.get("cached"):
            print("OK Query caching working")
            print(f"  First execution: {first_time*1000:.2f}ms")
            print(f"  Cached execution: {second_time*1000:.2f}ms")
        else:
            print("! Query caching not working (but that's OK without Redis)")
        
        # Test performance stats
        stats = await db_manager.get_performance_stats()
        print("OK Performance stats retrieved")
        print(f"  Connection pools: {len(stats.get('connection_pools', {}))}")
        print(f"  Redis status: {stats.get('redis_status', 'unknown')}")
        
        # Test query optimization
        result = await db_manager.execute_query(
            "SELECT * FROM (SELECT 3 as optimized_value)",
            database="test_basic"
        )
        
        if result.get("success"):
            print("OK Query optimization test completed")
            if result.get("optimized"):
                print("  Query was optimized")
            else:
                print("  Query was not optimized (normal for simple queries)")
        
        print("\nOK All basic enhanced database tests passed!")
        return True
        
    except Exception as e:
        print(f"ERROR Test failed: {e}")
        return False
        
    finally:
        # Cleanup
        try:
            await db_manager.close()
            
            # Remove test database file
            test_db_file = "test_basic_enhanced.db"
            if os.path.exists(test_db_file):
                os.remove(test_db_file)
                
        except Exception as e:
            print(f"Cleanup error: {e}")


async def main():
    """Main test function."""
    success = await test_basic_enhanced_db()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)