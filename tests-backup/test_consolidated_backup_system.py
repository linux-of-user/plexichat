"""
PlexiChat Consolidated Backup System Tests

Comprehensive test suite combining unit, integration, performance, and security tests
for the consolidated backup system with government-level security features.
"""

import pytest
import asyncio
import tempfile
import json
import time
import hashlib
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

# Import consolidated backup system components
try:
    from src.plexichat.core.backup import (
        GovernmentBackupManager,
        ImmutableShardManager,
        QuantumEncryptionManager,
        IntelligentDistributionManager,
        AdvancedRecoveryManager,
        DatabaseProxyManager,
        BackupNodeAuthManager,
        UniversalBackupManager,
        BackupNodeClient,
        BackupNodeManager
    )
    BACKUP_AVAILABLE = True
except ImportError as e:
    BACKUP_AVAILABLE = False
    pytest.skip(f"Consolidated backup system not available: {e}", allow_module_level=True)


# Test fixtures
@pytest.fixture
async def temp_backup_dir():
    """Create temporary backup directory."""
    temp_dir = Path(tempfile.mkdtemp(prefix="plexichat_backup_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
async def government_backup_manager(temp_backup_dir):
    """Create government backup manager instance."""
    manager = GovernmentBackupManager(backup_dir=temp_backup_dir)
    await manager.initialize()
    yield manager
    await manager.shutdown()


@pytest.fixture
def sample_backup_data():
    """Sample data for backup testing."""
    return {
        "users": [
            {"id": 1, "username": "user1", "email": "user1@example.com", "created": "2024-01-01"},
            {"id": 2, "username": "user2", "email": "user2@example.com", "created": "2024-01-02"}
        ],
        "messages": [
            {"id": 1, "user_id": 1, "content": "Hello world", "timestamp": "2024-01-01T10:00:00Z"},
            {"id": 2, "user_id": 2, "content": "Hi there", "timestamp": "2024-01-01T11:00:00Z"},
            {"id": 3, "user_id": 1, "content": "How are you?", "timestamp": "2024-01-01T12:00:00Z"}
        ],
        "settings": {
            "server_name": "PlexiChat Test Server",
            "max_users": 1000,
            "features": ["chat", "file_sharing", "video_calls", "backup"],
            "security_level": "government"
        },
        "metadata": {
            "version": "3.0.0",
            "created": "2024-01-01T00:00:00Z",
            "last_modified": "2024-01-01T12:00:00Z"
        }
    }


@pytest.fixture
def large_backup_data():
    """Large dataset for performance testing."""
    return {
        "users": [{"id": i, "username": f"user{i}", "data": "x" * 1000} for i in range(1000)],
        "messages": [{"id": i, "content": f"message {i} " * 50} for i in range(5000)],
        "files": [{"id": i, "name": f"file{i}.txt", "content": "file content " * 100} for i in range(500)]
    }


# Unit Tests
@pytest.mark.unit
class TestGovernmentBackupManagerUnit:
    """Unit tests for GovernmentBackupManager."""
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self, temp_backup_dir):
        """Test backup manager initialization."""
        manager = GovernmentBackupManager(backup_dir=temp_backup_dir)
        
        # Test initial state
        assert manager.backup_dir == temp_backup_dir
        assert manager.shard_manager is not None
        assert manager.encryption_manager is not None
        
        # Initialize
        await manager.initialize()
        
        # Test post-initialization state
        assert manager.distribution_manager is not None
        assert manager.recovery_manager is not None
        assert manager.proxy_manager is not None
        assert manager.auth_manager is not None
        assert manager.user_backup_manager is not None
        assert manager.node_manager is not None
        
        await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_backup_creation(self, government_backup_manager, sample_backup_data):
        """Test basic backup creation."""
        # Create backup
        backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full",
            description="Unit test backup"
        )
        
        assert backup_id is not None
        assert isinstance(backup_id, str)
        assert len(backup_id) > 0
        
        # Verify backup exists
        backup_info = await government_backup_manager.get_backup_info(backup_id)
        assert backup_info is not None
        assert backup_info["type"] == "full"
        assert backup_info["description"] == "Unit test backup"
    
    @pytest.mark.asyncio
    async def test_backup_restoration(self, government_backup_manager, sample_backup_data):
        """Test backup restoration."""
        # Create backup
        backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full"
        )
        
        # Restore backup
        restored_data = await government_backup_manager.restore_backup(backup_id)
        
        assert restored_data is not None
        assert restored_data["users"] == sample_backup_data["users"]
        assert restored_data["messages"] == sample_backup_data["messages"]
        assert restored_data["settings"] == sample_backup_data["settings"]


@pytest.mark.unit
class TestImmutableShardManagerUnit:
    """Unit tests for ImmutableShardManager."""
    
    @pytest.mark.asyncio
    async def test_shard_creation(self, government_backup_manager, sample_backup_data):
        """Test shard creation and verification."""
        shard_manager = government_backup_manager.shard_manager
        
        # Create shard
        data_bytes = json.dumps(sample_backup_data).encode('utf-8')
        shard_id = await shard_manager.create_shard(data_bytes, "test_backup")
        
        assert shard_id is not None
        assert isinstance(shard_id, str)
        
        # Verify shard
        shard_info = await shard_manager.get_shard_info(shard_id)
        assert shard_info is not None
        assert shard_info["size"] == len(data_bytes)
        assert shard_info["sha256_hash"] is not None
        assert shard_info["sha512_hash"] is not None
        assert shard_info["blake2b_hash"] is not None
    
    @pytest.mark.asyncio
    async def test_shard_integrity_verification(self, government_backup_manager, sample_backup_data):
        """Test shard integrity verification."""
        shard_manager = government_backup_manager.shard_manager
        
        # Create shard
        data_bytes = json.dumps(sample_backup_data).encode('utf-8')
        shard_id = await shard_manager.create_shard(data_bytes, "integrity_test")
        
        # Verify integrity
        is_valid = await shard_manager.verify_shard_integrity(shard_id)
        assert is_valid is True
        
        # Get shard data and verify manually
        shard_data = await shard_manager.get_shard_data(shard_id)
        assert shard_data == data_bytes


@pytest.mark.unit
class TestQuantumEncryptionManagerUnit:
    """Unit tests for QuantumEncryptionManager."""
    
    @pytest.mark.asyncio
    async def test_encryption_key_generation(self, government_backup_manager):
        """Test encryption key generation."""
        encryption_manager = government_backup_manager.encryption_manager
        
        # Generate key
        key_id = await encryption_manager.generate_key("test_key")
        
        assert key_id is not None
        assert isinstance(key_id, str)
        
        # Verify key exists
        key_info = await encryption_manager.get_key_info(key_id)
        assert key_info is not None
        assert key_info["algorithm"] is not None
        assert key_info["created_at"] is not None
    
    @pytest.mark.asyncio
    async def test_data_encryption_decryption(self, government_backup_manager):
        """Test data encryption and decryption."""
        encryption_manager = government_backup_manager.encryption_manager
        
        # Test data
        test_data = b"This is sensitive government data that needs quantum-proof encryption"
        
        # Generate key
        key_id = await encryption_manager.generate_key("test_encryption")
        
        # Encrypt data
        encrypted_data = await encryption_manager.encrypt_data(test_data, key_id)
        assert encrypted_data != test_data
        assert len(encrypted_data) > len(test_data)  # Encrypted data should be larger
        
        # Decrypt data
        decrypted_data = await encryption_manager.decrypt_data(encrypted_data, key_id)
        assert decrypted_data == test_data


# Integration Tests
@pytest.mark.integration
class TestBackupSystemIntegration:
    """Integration tests for complete backup system."""
    
    @pytest.mark.asyncio
    async def test_full_backup_workflow(self, government_backup_manager, sample_backup_data):
        """Test complete backup workflow with all components."""
        # Create encrypted, sharded backup
        backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full",
            options={
                "encryption_enabled": True,
                "sharding_enabled": True,
                "compression_enabled": True,
                "redundancy_level": 3
            }
        )
        
        assert backup_id is not None
        
        # Verify backup components
        backup_info = await government_backup_manager.get_backup_info(backup_id)
        assert backup_info["encrypted"] is True
        assert backup_info["sharded"] is True
        assert backup_info["compressed"] is True
        
        # Get shard information
        shards = await government_backup_manager.get_backup_shards(backup_id)
        assert len(shards) >= 1
        
        # Verify each shard is encrypted and has integrity hashes
        for shard in shards:
            assert shard["encrypted"] is True
            assert shard["sha256_hash"] is not None
            assert shard["sha512_hash"] is not None
            assert shard["blake2b_hash"] is not None
        
        # Restore and verify data integrity
        restored_data = await government_backup_manager.restore_backup(backup_id)
        assert restored_data == sample_backup_data
    
    @pytest.mark.asyncio
    async def test_incremental_backup_workflow(self, government_backup_manager, sample_backup_data):
        """Test incremental backup workflow."""
        # Create initial full backup
        full_backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full"
        )
        
        # Modify data
        modified_data = sample_backup_data.copy()
        modified_data["users"].append({
            "id": 3, 
            "username": "user3", 
            "email": "user3@example.com", 
            "created": "2024-01-03"
        })
        modified_data["messages"].append({
            "id": 4, 
            "user_id": 3, 
            "content": "New message", 
            "timestamp": "2024-01-03T10:00:00Z"
        })
        
        # Create incremental backup
        incremental_backup_id = await government_backup_manager.create_backup(
            data=modified_data,
            backup_type="incremental",
            base_backup_id=full_backup_id
        )
        
        assert incremental_backup_id != full_backup_id
        
        # Verify incremental backup
        backup_info = await government_backup_manager.get_backup_info(incremental_backup_id)
        assert backup_info["type"] == "incremental"
        assert backup_info["base_backup_id"] == full_backup_id
        
        # Restore incremental backup
        restored_data = await government_backup_manager.restore_backup(incremental_backup_id)
        assert len(restored_data["users"]) == 3
        assert len(restored_data["messages"]) == 4
        assert restored_data["users"][2]["username"] == "user3"
    
    @pytest.mark.asyncio
    async def test_distributed_backup_integration(self, government_backup_manager, sample_backup_data):
        """Test distributed backup across multiple nodes."""
        # Mock multiple backup nodes
        nodes = ["node1", "node2", "node3"]
        
        # Create distributed backup
        backup_id = await government_backup_manager.create_distributed_backup(
            data=sample_backup_data,
            target_nodes=nodes,
            redundancy_level=2
        )
        
        assert backup_id is not None
        
        # Verify distribution
        distribution_info = await government_backup_manager.get_backup_distribution(backup_id)
        assert len(distribution_info["nodes"]) >= 2
        assert distribution_info["redundancy_achieved"] >= 2
        
        # Test partial restoration (simulate node failure)
        available_nodes = nodes[:2]  # Only 2 of 3 nodes available
        restored_data = await government_backup_manager.restore_from_nodes(
            backup_id=backup_id,
            available_nodes=available_nodes
        )
        
        assert restored_data == sample_backup_data


# Performance Tests
@pytest.mark.performance
class TestBackupSystemPerformance:
    """Performance tests for backup system."""
    
    @pytest.mark.asyncio
    async def test_large_backup_performance(self, government_backup_manager, large_backup_data):
        """Test performance with large datasets."""
        start_time = time.time()
        
        # Create large backup
        backup_id = await government_backup_manager.create_backup(
            data=large_backup_data,
            backup_type="full",
            options={"compression_enabled": True}
        )
        
        creation_time = time.time() - start_time
        
        assert backup_id is not None
        assert creation_time < 60.0  # Should complete within 60 seconds
        
        # Test restoration performance
        start_time = time.time()
        restored_data = await government_backup_manager.restore_backup(backup_id)
        restoration_time = time.time() - start_time
        
        assert restored_data is not None
        assert restoration_time < 30.0  # Restoration should be faster
        assert len(restored_data["users"]) == 1000
        assert len(restored_data["messages"]) == 5000
    
    @pytest.mark.asyncio
    async def test_concurrent_backup_performance(self, government_backup_manager, sample_backup_data):
        """Test concurrent backup operations."""
        start_time = time.time()
        
        # Create multiple concurrent backups
        tasks = []
        for i in range(10):
            modified_data = sample_backup_data.copy()
            modified_data["sequence"] = i
            modified_data["timestamp"] = time.time()
            
            task = government_backup_manager.create_backup(
                data=modified_data,
                backup_type="full",
                description=f"Concurrent backup {i}"
            )
            tasks.append(task)
        
        # Wait for all backups to complete
        backup_ids = await asyncio.gather(*tasks)
        total_time = time.time() - start_time
        
        # Verify all backups completed successfully
        assert len(backup_ids) == 10
        assert all(backup_id is not None for backup_id in backup_ids)
        assert total_time < 20.0  # Should complete within 20 seconds
        
        # Verify each backup is unique
        assert len(set(backup_ids)) == 10  # All backup IDs should be unique


# Security Tests
@pytest.mark.security
class TestBackupSystemSecurity:
    """Security tests for backup system."""
    
    @pytest.mark.asyncio
    async def test_encryption_security(self, government_backup_manager):
        """Test encryption security with sensitive data."""
        sensitive_data = {
            "passwords": ["admin123", "user456", "secret789"],
            "api_keys": ["sk-1234567890abcdef", "pk-abcdef1234567890"],
            "personal_info": {
                "ssn": "123-45-6789",
                "credit_card": "4111-1111-1111-1111",
                "phone": "+1-555-123-4567"
            },
            "classified": {
                "level": "TOP_SECRET",
                "clearance": "GOVERNMENT_ONLY",
                "data": "This is classified government information"
            }
        }
        
        # Create encrypted backup
        backup_id = await government_backup_manager.create_backup(
            data=sensitive_data,
            backup_type="full",
            options={"encryption_level": "GOVERNMENT"}
        )
        
        # Verify backup file is encrypted (not readable as plain text)
        backup_file_path = await government_backup_manager.get_backup_file_path(backup_id)
        
        with open(backup_file_path, 'rb') as f:
            backup_content = f.read()
        
        # Convert to text and check for sensitive data
        backup_text = backup_content.decode('utf-8', errors='ignore')
        
        # Sensitive data should NOT appear in plain text
        assert "admin123" not in backup_text
        assert "123-45-6789" not in backup_text
        assert "sk-1234567890abcdef" not in backup_text
        assert "TOP_SECRET" not in backup_text
        assert "classified government information" not in backup_text.lower()
        
        # But restoration should work correctly
        restored_data = await government_backup_manager.restore_backup(backup_id)
        assert restored_data == sensitive_data
    
    @pytest.mark.asyncio
    async def test_access_control_security(self, government_backup_manager, sample_backup_data):
        """Test backup access control and authentication."""
        # Create backup with access control
        backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full",
            options={
                "access_level": "admin_only",
                "require_authentication": True
            }
        )
        
        # Test unauthorized access (should fail)
        with pytest.raises(Exception) as exc_info:
            await government_backup_manager.restore_backup(
                backup_id=backup_id,
                auth_token="invalid_token"
            )
        
        assert "unauthorized" in str(exc_info.value).lower() or "access denied" in str(exc_info.value).lower()
        
        # Test authorized access (should succeed)
        # Note: In a real implementation, this would use proper authentication
        restored_data = await government_backup_manager.restore_backup(
            backup_id=backup_id,
            bypass_auth=True  # For testing purposes
        )
        
        assert restored_data == sample_backup_data


# End-to-End Tests
@pytest.mark.e2e
class TestBackupSystemEndToEnd:
    """End-to-end tests for complete backup workflows."""
    
    @pytest.mark.asyncio
    async def test_complete_backup_lifecycle(self, government_backup_manager, sample_backup_data):
        """Test complete backup lifecycle from creation to cleanup."""
        # 1. Create initial backup
        backup_id = await government_backup_manager.create_backup(
            data=sample_backup_data,
            backup_type="full",
            description="E2E test backup"
        )
        
        # 2. Verify backup creation
        backup_info = await government_backup_manager.get_backup_info(backup_id)
        assert backup_info["status"] == "completed"
        
        # 3. Create incremental backup
        modified_data = sample_backup_data.copy()
        modified_data["new_field"] = "incremental_data"
        
        incremental_id = await government_backup_manager.create_backup(
            data=modified_data,
            backup_type="incremental",
            base_backup_id=backup_id
        )
        
        # 4. List all backups
        all_backups = await government_backup_manager.list_backups()
        backup_ids = [b["id"] for b in all_backups]
        assert backup_id in backup_ids
        assert incremental_id in backup_ids
        
        # 5. Restore both backups
        original_data = await government_backup_manager.restore_backup(backup_id)
        incremental_data = await government_backup_manager.restore_backup(incremental_id)
        
        assert original_data == sample_backup_data
        assert incremental_data["new_field"] == "incremental_data"
        
        # 6. Verify backup integrity
        integrity_result = await government_backup_manager.verify_backup_integrity(backup_id)
        assert integrity_result["valid"] is True
        
        # 7. Clean up old backups
        cleanup_result = await government_backup_manager.cleanup_old_backups(
            retention_days=0  # Clean up immediately for testing
        )
        
        assert cleanup_result["cleaned_count"] >= 0
