# app/utils/self_tests/database.py
"""
Enhanced database tests with comprehensive schema validation,
performance testing, and connection pool monitoring.
"""

import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy import text, inspect, func
from sqlmodel import Session, select

from app.db import engine
from app.logger_config import settings, selftest_logger
from app.models.user import User
from app.models.message import Message
from app.utils.self_tests.test_executor import with_retry, with_timeout


class DatabaseTests:
    """Comprehensive database test suite."""

    def __init__(self):
        self.logger = selftest_logger
        self.test_prefix = f"__selftest_{int(time.time())}"

    @with_retry(max_retries=3, delay_seconds=2)
    @with_timeout(10)
    def test_basic_connectivity(self) -> Dict[str, Any]:
        """Test basic database connectivity."""
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as test_value"))
                value = result.scalar()

            if value == 1:
                self.logger.debug("Database connectivity test passed")
                return {"ok": True, "detail": "SELECT 1 successful"}
            else:
                return {"ok": False, "detail": f"Unexpected result: {value}"}

        except Exception as e:
            self.logger.warning("Database connectivity test failed: %s", e)
            return {"ok": False, "detail": str(e)}

    @with_timeout(15)
    def test_schema_validation(self) -> Dict[str, Any]:
        """Validate database schema and required tables."""
        try:
            inspector = inspect(engine)
            tables = inspector.get_table_names()

            required_tables = ["users", "messages"]
            missing_tables = [table for table in required_tables if table not in tables]

            if missing_tables:
                return {
                    "ok": False,
                    "detail": f"Missing tables: {missing_tables}",
                    "found_tables": tables
                }

            # Check table structures
            table_info = {}
            for table in required_tables:
                columns = inspector.get_columns(table)
                table_info[table] = {
                    "columns": len(columns),
                    "column_names": [col["name"] for col in columns]
                }

            self.logger.debug("Schema validation passed: %s", table_info)
            return {
                "ok": True,
                "detail": f"All required tables present: {required_tables}",
                "table_info": table_info
            }

        except Exception as e:
            self.logger.warning("Schema validation failed: %s", e)
            return {"ok": False, "detail": str(e)}

    @with_timeout(20)
    def test_user_crud_operations(self) -> Dict[str, Any]:
        """Test complete CRUD operations on User model."""
        test_user_data = {
            "username": f"{self.test_prefix}_user",
            "email": f"{self.test_prefix}@example.com",
            "password_hash": "test_hash_123",
            "public_key": "test_public_key",
            "display_name": "Test User"
        }

        operations = {}
        user_id = None

        try:
            with Session(engine) as session:
                # CREATE
                user = User(**test_user_data)
                session.add(user)
                session.commit()
                session.refresh(user)
                user_id = user.id
                operations["create"] = {"ok": True, "user_id": user_id}

                # READ
                retrieved_user = session.get(User, user_id)
                operations["read"] = {
                    "ok": retrieved_user is not None,
                    "username_match": retrieved_user.username == test_user_data["username"] if retrieved_user else False
                }

                # UPDATE
                if retrieved_user:
                    new_display_name = f"{test_user_data['display_name']} Updated"
                    retrieved_user.display_name = new_display_name
                    session.commit()
                    session.refresh(retrieved_user)
                    operations["update"] = {
                        "ok": retrieved_user.display_name == new_display_name,
                        "new_display_name": retrieved_user.display_name
                    }

                # DELETE
                if retrieved_user:
                    session.delete(retrieved_user)
                    session.commit()

                    # Verify deletion
                    deleted_user = session.get(User, user_id)
                    operations["delete"] = {"ok": deleted_user is None}

            all_ok = all(op.get("ok", False) for op in operations.values())
            self.logger.debug("User CRUD operations completed: %s", operations)

            return {
                "ok": all_ok,
                "detail": f"CRUD operations: {len([op for op in operations.values() if op.get('ok')])} passed",
                "operations": operations
            }

        except Exception as e:
            self.logger.warning("User CRUD operations failed: %s", e)
            # Cleanup on error
            if user_id:
                try:
                    with Session(engine) as session:
                        user = session.get(User, user_id)
                        if user:
                            session.delete(user)
                            session.commit()
                except:
                    pass  # Ignore cleanup errors

            return {"ok": False, "detail": str(e), "operations": operations}

    @with_timeout(15)
    def test_transaction_handling(self) -> Dict[str, Any]:
        """Test database transaction handling and rollback."""
        try:
            test_username = f"{self.test_prefix}_transaction_test"

            # Test successful transaction
            with Session(engine) as session:
                user = User(
                    username=test_username,
                    email=f"{test_username}@example.com",
                    password_hash="test_hash",
                    public_key="test_key"
                )
                session.add(user)
                session.commit()
                user_id = user.id

            # Test rollback
            try:
                with Session(engine) as session:
                    user = session.get(User, user_id)
                    user.username = "updated_name"
                    # Force an error to test rollback
                    session.execute(text("SELECT * FROM non_existent_table"))
                    session.commit()
            except Exception:
                pass  # Expected to fail

            # Verify rollback worked
            with Session(engine) as session:
                user = session.get(User, user_id)
                rollback_worked = user.username == test_username

                # Cleanup
                session.delete(user)
                session.commit()

            self.logger.debug("Transaction handling test completed")
            return {
                "ok": rollback_worked,
                "detail": "Transaction rollback working correctly" if rollback_worked else "Transaction rollback failed"
            }

        except Exception as e:
            self.logger.warning("Transaction handling test failed: %s", e)
            return {"ok": False, "detail": str(e)}

    @with_timeout(10)
    def test_performance_metrics(self) -> Dict[str, Any]:
        """Test basic database performance metrics."""
        try:
            metrics = {}

            # Test simple query performance
            start_time = time.time()
            with engine.connect() as conn:
                conn.execute(text("SELECT COUNT(*) FROM users"))
            metrics["simple_query_ms"] = (time.time() - start_time) * 1000

            # Test connection pool
            start_time = time.time()
            with engine.connect() as conn:
                pass  # Just test connection acquisition
            metrics["connection_acquisition_ms"] = (time.time() - start_time) * 1000

            # Performance thresholds
            slow_query_threshold = 1000  # 1 second
            slow_connection_threshold = 500  # 0.5 seconds

            performance_ok = (
                metrics["simple_query_ms"] < slow_query_threshold and
                metrics["connection_acquisition_ms"] < slow_connection_threshold
            )

            self.logger.debug("Performance metrics: %s", metrics)
            return {
                "ok": performance_ok,
                "detail": f"Query: {metrics['simple_query_ms']:.1f}ms, Connection: {metrics['connection_acquisition_ms']:.1f}ms",
                "metrics": metrics
            }

        except Exception as e:
            self.logger.warning("Performance metrics test failed: %s", e)
            return {"ok": False, "detail": str(e)}


def run_database_tests() -> Dict[str, Any]:
    """Run all database tests and return results."""
    tests = DatabaseTests()

    test_functions = {
        "connectivity": tests.test_basic_connectivity,
        "schema": tests.test_schema_validation,
        "user_crud": tests.test_user_crud_operations,
        "transactions": tests.test_transaction_handling,
        "performance": tests.test_performance_metrics
    }

    results = {}
    for test_name, test_func in test_functions.items():
        try:
            results[test_name] = test_func()
        except Exception as e:
            selftest_logger.error("Database test %s failed: %s", test_name, e)
            results[test_name] = {"ok": False, "detail": str(e)}

    # Calculate overall status
    passed_tests = sum(1 for result in results.values() if result.get("ok", False))
    total_tests = len(results)

    selftest_logger.info("Database tests completed: %d/%d passed", passed_tests, total_tests)

    return results
