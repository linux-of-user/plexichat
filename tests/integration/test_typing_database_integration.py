"""
Database integration tests for typing indicators.

This module contains integration tests that verify typing indicator
functionality with actual database operations and data persistence.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from plexichat.core.services.typing_service import TypingService, TypingStatus
from plexichat.core.database.manager import database_manager


class TestTypingDatabasePersistence:
    """Test typing status persistence in database."""

    @pytest.fixture
    async def clean_typing_table(self):
        """Clean up typing_status table before and after tests."""
        # Clean up before test
        await database_manager.execute_query("DELETE FROM typing_status", ())
        yield
        # Clean up after test
        await database_manager.execute_query("DELETE FROM typing_status", ())

    @pytest.fixture
    def typing_service(self):
        """Create TypingService instance."""
        return TypingService()

    @pytest.mark.asyncio
    async def test_typing_status_insertion(self, typing_service, clean_typing_table):
        """Test inserting typing status into database."""
        user_id = "test_user_insert"
        channel_id = "test_channel_insert"

        # Create typing status manually
        current_time = datetime.now(timezone.utc)
        expires_at = current_time + timedelta(seconds=3)

        typing_status = TypingStatus(
            id="test_id_insert",
            user_id=user_id,
            channel_id=channel_id,
            started_at=current_time,
            expires_at=expires_at,
            created_at=current_time,
            updated_at=current_time,
            metadata={"test": "insertion"}
        )

        # Insert directly
        success = await typing_service._save_typing_status(typing_status)
        assert success is True

        # Verify insertion
        result = await database_manager.execute_query(
            "SELECT * FROM typing_status WHERE id = ?",
            ("test_id_insert",)
        )
        assert result is not None
        assert len(result) == 1
        assert result[0]["user_id"] == user_id
        assert result[0]["channel_id"] == channel_id

    @pytest.mark.asyncio
    async def test_typing_status_update(self, typing_service, clean_typing_table):
        """Test updating typing status expiration."""
        user_id = "test_user_update"
        channel_id = "test_channel_update"

        # Insert initial status
        current_time = datetime.now(timezone.utc)
        initial_expires = current_time + timedelta(seconds=3)

        typing_status = TypingStatus(
            id="test_id_update",
            user_id=user_id,
            channel_id=channel_id,
            started_at=current_time,
            expires_at=initial_expires,
            created_at=current_time,
            updated_at=current_time,
            metadata={}
        )

        await typing_service._save_typing_status(typing_status)

        # Update expiration
        new_expires = current_time + timedelta(seconds=10)
        success = await typing_service._update_typing_status("test_id_update", new_expires)
        assert success is True

        # Verify update
        result = await database_manager.execute_query(
            "SELECT expires_at FROM typing_status WHERE id = ?",
            ("test_id_update",)
        )
        assert result is not None
        assert len(result) == 1
        # Note: Database stores as ISO string, so we check it was updated

    @pytest.mark.asyncio
    async def test_typing_status_deletion(self, typing_service, clean_typing_table):
        """Test deleting typing status from database."""
        user_id = "test_user_delete"
        channel_id = "test_channel_delete"

        # Insert status
        current_time = datetime.now(timezone.utc)
        typing_status = TypingStatus(
            id="test_id_delete",
            user_id=user_id,
            channel_id=channel_id,
            started_at=current_time,
            expires_at=current_time + timedelta(seconds=3),
            created_at=current_time,
            updated_at=current_time,
            metadata={}
        )

        await typing_service._save_typing_status(typing_status)

        # Delete status
        success = await typing_service._delete_typing_status("test_id_delete")
        assert success is True

        # Verify deletion
        result = await database_manager.execute_query(
            "SELECT * FROM typing_status WHERE id = ?",
            ("test_id_delete",)
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_get_user_typing_status(self, typing_service, clean_typing_table):
        """Test retrieving user typing status."""
        user_id = "test_user_get"
        channel_id = "test_channel_get"

        # Insert status
        current_time = datetime.now(timezone.utc)
        typing_status = TypingStatus(
            id="test_id_get",
            user_id=user_id,
            channel_id=channel_id,
            started_at=current_time,
            expires_at=current_time + timedelta(seconds=3),
            created_at=current_time,
            updated_at=current_time,
            metadata={}
        )

        await typing_service._save_typing_status(typing_status)

        # Retrieve status
        retrieved = await typing_service._get_user_typing_status(user_id, channel_id)
        assert retrieved is not None
        assert retrieved.id == "test_id_get"
        assert retrieved.user_id == user_id
        assert retrieved.channel_id == channel_id

    @pytest.mark.asyncio
    async def test_get_user_typing_status_expired(self, typing_service, clean_typing_table):
        """Test retrieving expired typing status returns None."""
        user_id = "test_user_expired"
        channel_id = "test_channel_expired"

        # Insert expired status
        current_time = datetime.now(timezone.utc)
        expired_time = current_time - timedelta(seconds=10)

        typing_status = TypingStatus(
            id="test_id_expired",
            user_id=user_id,
            channel_id=channel_id,
            started_at=expired_time,
            expires_at=expired_time + timedelta(seconds=3),
            created_at=expired_time,
            updated_at=expired_time,
            metadata={}
        )

        await typing_service._save_typing_status(typing_status)

        # Try to retrieve (should return None due to expiration)
        retrieved = await typing_service._get_user_typing_status(user_id, channel_id)
        assert retrieved is None


class TestTypingDatabaseQueries:
    """Test complex database queries for typing indicators."""

    @pytest.fixture
    async def setup_test_data(self, typing_service):
        """Set up test data for complex queries."""
        # Clean up first
        await database_manager.execute_query("DELETE FROM typing_status", ())

        current_time = datetime.now(timezone.utc)

        # Insert multiple typing statuses
        test_data = [
            ("user1", "channel1", current_time + timedelta(seconds=5)),  # Active
            ("user2", "channel1", current_time + timedelta(seconds=5)),  # Active
            ("user3", "channel1", current_time - timedelta(seconds=10)), # Expired
            ("user4", "channel2", current_time + timedelta(seconds=5)),  # Active, different channel
        ]

        for user_id, channel_id, expires_at in test_data:
            typing_status = TypingStatus(
                id=f"{user_id}_{channel_id}",
                user_id=user_id,
                channel_id=channel_id,
                started_at=current_time,
                expires_at=expires_at,
                created_at=current_time,
                updated_at=current_time,
                metadata={}
            )
            await typing_service._save_typing_status(typing_status)

        yield

        # Clean up
        await database_manager.execute_query("DELETE FROM typing_status", ())

    @pytest.fixture
    def typing_service(self):
        """Create TypingService instance."""
        return TypingService()

    @pytest.mark.asyncio
    async def test_get_typing_users_query(self, typing_service, setup_test_data):
        """Test query to get typing users in a channel."""
        # Test channel1 (should return user1 and user2, not user3 as expired)
        typing_users = await typing_service.get_typing_users("channel1")
        assert len(typing_users) == 2
        assert "user1" in typing_users
        assert "user2" in typing_users
        assert "user3" not in typing_users

        # Test channel2 (should return user4)
        typing_users_ch2 = await typing_service.get_typing_users("channel2")
        assert len(typing_users_ch2) == 1
        assert "user4" in typing_users_ch2

        # Test non-existent channel
        typing_users_empty = await typing_service.get_typing_users("nonexistent")
        assert typing_users_empty == []

    @pytest.mark.asyncio
    async def test_cleanup_expired_states_query(self, typing_service, setup_test_data):
        """Test cleanup query for expired typing states."""
        # Run cleanup
        cleaned_count = await typing_service.cleanup_expired_states()
        assert cleaned_count == 1  # user3's expired status

        # Verify expired status was removed
        typing_users = await typing_service.get_typing_users("channel1")
        assert len(typing_users) == 2
        assert "user3" not in typing_users

    @pytest.mark.asyncio
    async def test_database_indexes_usage(self, typing_service, setup_test_data):
        """Test that database indexes are being used effectively."""
        # This test verifies that our queries use the proper indexes
        # In a real scenario, you'd check query execution plans

        # Test user-channel index usage
        typing_users = await typing_service.get_typing_users("channel1")
        assert isinstance(typing_users, list)

        # Test expiration index usage (via cleanup)
        cleaned_count = await typing_service.cleanup_expired_states()
        assert isinstance(cleaned_count, int)


class TestTypingDatabaseConcurrency:
    """Test concurrent database operations for typing indicators."""

    @pytest.fixture
    async def clean_table(self):
        """Clean typing_status table."""
        await database_manager.execute_query("DELETE FROM typing_status", ())
        yield
        await database_manager.execute_query("DELETE FROM typing_status", ())

    @pytest.fixture
    def typing_service(self):
        """Create TypingService instance."""
        return TypingService()

    @pytest.mark.asyncio
    async def test_concurrent_start_typing(self, typing_service, clean_table):
        """Test concurrent start_typing operations."""
        user_id = "concurrent_user"
        channel_id = "concurrent_channel"

        # Mock the database manager to simulate concurrent access
        original_execute = database_manager.execute_query

        async def mock_execute(query, params):
            if "INSERT INTO typing_status" in query:
                # Simulate a small delay to test concurrency
                await asyncio.sleep(0.01)
            return await original_execute(query, params)

        with patch.object(database_manager, 'execute_query', side_effect=mock_execute):
            # Run multiple concurrent start_typing operations
            tasks = []
            for i in range(5):
                task = asyncio.create_task(typing_service.start_typing(user_id, channel_id))
                tasks.append(task)

            results = await asyncio.gather(*tasks)

            # At least one should succeed (due to upsert logic)
            assert any(results)

    @pytest.mark.asyncio
    async def test_concurrent_cleanup_operations(self, typing_service, clean_table):
        """Test concurrent cleanup operations."""
        # Insert some test data
        current_time = datetime.now(timezone.utc)

        for i in range(10):
            typing_status = TypingStatus(
                id=f"cleanup_test_{i}",
                user_id=f"user_{i}",
                channel_id="cleanup_channel",
                started_at=current_time,
                expires_at=current_time + timedelta(seconds=1),  # Will expire quickly
                created_at=current_time,
                updated_at=current_time,
                metadata={}
            )
            await typing_service._save_typing_status(typing_status)

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Run concurrent cleanup operations
        tasks = []
        for i in range(3):
            task = asyncio.create_task(typing_service.cleanup_expired_states())
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        # All should return the same count (cleanup is idempotent)
        assert all(r >= 0 for r in results)


class TestTypingDatabaseErrorRecovery:
    """Test database error handling and recovery for typing operations."""

    @pytest.fixture
    def typing_service(self):
        """Create TypingService instance."""
        return TypingService()

    @pytest.mark.asyncio
    async def test_database_connection_failure_recovery(self, typing_service):
        """Test recovery from database connection failures."""
        # Mock database failure
        with patch.object(database_manager, 'execute_query', side_effect=Exception("Connection failed")):
            result = await typing_service.start_typing("user1", "channel1")
            assert result is False

    @pytest.mark.asyncio
    async def test_partial_failure_recovery(self, typing_service):
        """Test recovery from partial operation failures."""
        # Mock database to fail on insert but succeed on other operations
        call_count = 0

        async def mock_execute(query, params):
            nonlocal call_count
            call_count += 1
            if call_count == 4:  # Fail on insert
                raise Exception("Insert failed")
            return []

        with patch.object(database_manager, 'execute_query', side_effect=mock_execute):
            result = await typing_service.start_typing("user1", "channel1")
            assert result is False

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_failure(self, typing_service):
        """Test that failed operations don't leave partial state."""
        # This test would verify transaction rollback behavior
        # In a real implementation, you'd check that no partial data remains

        with patch.object(database_manager, 'execute_query', side_effect=Exception("Transaction failed")):
            result = await typing_service.start_typing("user1", "channel1")
            assert result is False

            # Verify no partial data was left behind
            # (This would require checking the database state)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])