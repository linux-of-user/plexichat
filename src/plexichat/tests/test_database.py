import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from .test_base import BaseTest, TestResult


"""
Database connectivity and functionality tests for PlexiChat.
Tests database connections, queries, and data integrity.
"""

logger = logging.getLogger(__name__)


class DatabaseTest(BaseTest):
    """Test database connectivity and functionality."""
    
    def __init__(self):
        super().__init__()
        self.test_db_path = None
        self.connection = None
    
    async def setup(self):
        """Setup test database."""
        self.test_db_path = from pathlib import Path
Path("test_plexichat.db")
        # Clean up any existing test database
        if self.test_db_path.exists():
            self.test_db_path.unlink()
    
    async def teardown(self):
        """Cleanup test database."""
        if self.connection:
            self.connection.close()
        if self.test_db_path and self.test_db_path.exists():
            self.test_db_path.unlink()
    
    async def test_sqlite_connection(self):
        """Test SQLite database connection."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            # Test connection
            self.connection = sqlite3.connect(str(self.test_db_path))
            cursor = self.connection.cursor()
            
            # Test basic query
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            
            assert result[0] == 1, "Basic query failed"
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="SQLite Connection",
                category="Database",
                endpoint="/db/connect",
                method="CONNECT",
                status="passed",
                duration_ms=duration,
                request_data={"database_type": "sqlite", "path": str(self.test_db_path)},
                response_data={"connected": True, "test_query_result": result[0]}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="SQLite Connection",
                category="Database",
                endpoint="/db/connect",
                method="CONNECT",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_table_creation(self):
        """Test database table creation."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not self.connection:
                await self.test_sqlite_connection()
            
            cursor = self.connection.cursor()
            
            # Create test table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Verify table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='test_users'")
            result = cursor.fetchone()
            
            assert result is not None, "Table creation failed"
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="Table Creation",
                category="Database",
                endpoint="/db/create_table",
                method="CREATE",
                status="passed",
                duration_ms=duration,
                request_data={"table_name": "test_users"},
                response_data={"table_created": True, "table_name": result[0]}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="Table Creation",
                category="Database",
                endpoint="/db/create_table",
                method="CREATE",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def test_data_operations(self):
        """Test basic CRUD operations."""
        start_time = from datetime import datetime
datetime.now()
        
        try:
            if not self.connection:
                await self.test_sqlite_connection()
                await self.test_table_creation()
            
            cursor = self.connection.cursor()
            
            # Insert test data
            test_username = self.data_generator.generate_username()
            test_email = self.data_generator.generate_email()
            
            cursor.execute(
                "INSERT INTO test_users (username, email) VALUES (?, ?)",
                (test_username, test_email)
            )
            
            # Read data back
            cursor.execute("SELECT username, email FROM test_users WHERE username = ?", (test_username,))
            result = cursor.fetchone()
            
            assert result is not None, "Data insertion/retrieval failed"
            assert result[0] == test_username, "Username mismatch"
            assert result[1] == test_email, "Email mismatch"
            
            # Update data
            new_email = self.data_generator.generate_email()
            cursor.execute("UPDATE test_users SET email = ? WHERE username = ?", (new_email, test_username))
            
            # Verify update
            cursor.execute("SELECT email FROM test_users WHERE username = ?", (test_username,))
            updated_result = cursor.fetchone()
            assert updated_result[0] == new_email, "Update failed"
            
            # Delete data
            cursor.execute("DELETE FROM test_users WHERE username = ?", (test_username,))
            cursor.execute("SELECT COUNT(*) FROM test_users WHERE username = ?", (test_username,))
            count_result = cursor.fetchone()
            assert count_result[0] == 0, "Delete failed"
            
            self.connection.commit()
            
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            
            self.add_result(TestResult(
                test_name="CRUD Operations",
                category="Database",
                endpoint="/db/crud",
                method="CRUD",
                status="passed",
                duration_ms=duration,
                request_data={"operations": ["INSERT", "SELECT", "UPDATE", "DELETE"]},
                response_data={"all_operations_successful": True}
            ))
            
        except Exception as e:
            duration = (from datetime import datetime
datetime.now() - start_time).total_seconds() * 1000
            self.add_result(TestResult(
                test_name="CRUD Operations",
                category="Database",
                endpoint="/db/crud",
                method="CRUD",
                status="failed",
                duration_ms=duration,
                error_message=str(e)
            ))
    
    async def run_all_tests(self):
        """Run all database tests."""
        await self.setup()
        try:
            await self.test_sqlite_connection()
            await self.test_table_creation()
            await self.test_data_operations()
        finally:
            await self.teardown()
