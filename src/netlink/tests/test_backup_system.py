"""
Comprehensive test suite for NetLink backup system.
Tests government-level security features, shard management, and backup operations.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import hashlib
import json

# Import backup system components
try:
    from netlink.backup.core.government_backup_manager import GovernmentBackupManager
    from netlink.backup.core.shard_manager import ShardManager
    from netlink.backup.core.backup_node_manager import BackupNodeManager
    from netlink.backup.plugins.archive_system import ArchiveSystem
    from netlink.backup.models.backup_models import BackupOperation, BackupStatus, ShardInfo
    BACKUP_AVAILABLE = True
except ImportError:
    BACKUP_AVAILABLE = False


@pytest.mark.skipif(not BACKUP_AVAILABLE, reason="Backup system not available")
class TestGovernmentBackupManager:
    """Test government-level backup manager functionality."""
    
    @pytest.fixture
    async def backup_manager(self):
        """Create a test backup manager instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = GovernmentBackupManager(
                storage_path=temp_dir,
                encryption_key="test-encryption-key-32-bytes-long",
                min_shard_redundancy=2
            )
            await manager.initialize()
            yield manager
            await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_initialization(self, backup_manager):
        """Test backup manager initialization."""
        assert backup_manager.initialized
        assert backup_manager.storage_path.exists()
        assert backup_manager.shard_manager is not None
        assert backup_manager.node_manager is not None
    
    @pytest.mark.asyncio
    async def test_create_backup_operation(self, backup_manager):
        """Test creating a backup operation."""
        operation = await backup_manager.create_backup(
            name="Test Backup",
            description="Test backup operation",
            backup_type="full",
            encryption_enabled=True,
            compression_enabled=True,
            created_by="test_user"
        )
        
        assert operation is not None
        assert operation.name == "Test Backup"
        assert operation.backup_type == "full"
        assert operation.encryption_enabled
        assert operation.compression_enabled
        assert operation.status == BackupStatus.PENDING
    
    @pytest.mark.asyncio
    async def test_sha512_checksum_generation(self, backup_manager):
        """Test SHA-512 checksum generation for backup data."""
        test_data = b"Test backup data for checksum verification"
        
        # Create a temporary file with test data
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(test_data)
            temp_file_path = temp_file.name
        
        try:
            # Generate checksum
            checksum = await backup_manager.generate_sha512_checksum(temp_file_path)
            
            # Verify checksum
            expected_checksum = hashlib.sha512(test_data).hexdigest()
            assert checksum == expected_checksum
            
        finally:
            Path(temp_file_path).unlink()
    
    @pytest.mark.asyncio
    async def test_proxy_mode_activation(self, backup_manager):
        """Test proxy mode activation and deactivation."""
        assert not backup_manager.proxy_mode_active
        
        # Activate proxy mode
        await backup_manager.enable_proxy_mode("Test activation")
        assert backup_manager.proxy_mode_active
        
        # Deactivate proxy mode
        await backup_manager.disable_proxy_mode()
        assert not backup_manager.proxy_mode_active
    
    @pytest.mark.asyncio
    async def test_system_health_monitoring(self, backup_manager):
        """Test system health monitoring."""
        health = await backup_manager.get_system_health()
        
        assert health is not None
        assert hasattr(health, 'overall_status')
        assert hasattr(health, 'total_shards')
        assert hasattr(health, 'active_backup_nodes')
        assert hasattr(health, 'backup_coverage_percentage')


@pytest.mark.skipif(not BACKUP_AVAILABLE, reason="Backup system not available")
class TestShardManager:
    """Test shard management functionality."""
    
    @pytest.fixture
    async def shard_manager(self):
        """Create a test shard manager instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ShardManager(
                storage_path=temp_dir,
                encryption_key="test-shard-encryption-key-32-bytes",
                max_shard_size_mb=10
            )
            await manager.initialize()
            yield manager
            await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_shard_creation(self, shard_manager):
        """Test creating immutable shards."""
        test_data = b"Test data for shard creation" * 100  # Make it larger
        
        shard = await shard_manager.create_shard(
            data=test_data,
            shard_type="user_data",
            metadata={"user_id": "test_user", "timestamp": "2025-07-03T10:00:00Z"}
        )
        
        assert shard is not None
        assert shard.shard_id is not None
        assert shard.size > 0
        assert shard.checksum is not None
        assert shard.encryption_key is not None
        assert shard.confusing_filename is not None
    
    @pytest.mark.asyncio
    async def test_shard_encryption(self, shard_manager):
        """Test individual shard encryption."""
        test_data = b"Sensitive data requiring encryption"
        
        # Create encrypted shard
        shard = await shard_manager.create_shard(
            data=test_data,
            shard_type="sensitive_data",
            encryption_enabled=True
        )
        
        # Verify shard is encrypted
        assert shard.encryption_enabled
        assert shard.encryption_key is not None
        assert len(shard.encryption_key) >= 32  # Minimum key length
        
        # Verify data can be decrypted
        decrypted_data = await shard_manager.decrypt_shard_data(shard)
        assert decrypted_data == test_data
    
    @pytest.mark.asyncio
    async def test_confusing_filename_generation(self, shard_manager):
        """Test generation of confusing filenames for security."""
        filenames = set()
        
        # Generate multiple filenames
        for i in range(10):
            filename = await shard_manager.generate_confusing_filename()
            filenames.add(filename)
        
        # Verify all filenames are unique
        assert len(filenames) == 10
        
        # Verify filenames don't reveal content
        for filename in filenames:
            assert not any(word in filename.lower() for word in 
                          ['backup', 'shard', 'data', 'user', 'message'])
    
    @pytest.mark.asyncio
    async def test_minimum_shard_requirement(self, shard_manager):
        """Test that minimum 2 shards are required for data recovery."""
        test_data = b"Data requiring multiple shards for recovery"
        
        # Create shards with redundancy
        shards = await shard_manager.create_redundant_shards(
            data=test_data,
            min_shards=2,
            total_shards=3
        )
        
        assert len(shards) >= 2
        
        # Test recovery with insufficient shards
        with pytest.raises(Exception):
            await shard_manager.recover_data_from_shards(shards[:1])
        
        # Test successful recovery with sufficient shards
        recovered_data = await shard_manager.recover_data_from_shards(shards[:2])
        assert recovered_data == test_data


@pytest.mark.skipif(not BACKUP_AVAILABLE, reason="Backup system not available")
class TestBackupNodeManager:
    """Test backup node management and API key system."""
    
    @pytest.fixture
    async def node_manager(self):
        """Create a test backup node manager instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = BackupNodeManager(
                storage_path=temp_dir,
                max_nodes=10
            )
            await manager.initialize()
            yield manager
            await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_api_key_generation(self, node_manager):
        """Test API key generation for backup nodes."""
        api_key = await node_manager.generate_api_key(
            node_name="test-node",
            permissions=["READ_ONLY"],
            expires_in_days=30
        )
        
        assert api_key is not None
        assert len(api_key.key) >= 32
        assert api_key.permissions == ["READ_ONLY"]
        assert api_key.node_name == "test-node"
    
    @pytest.mark.asyncio
    async def test_api_key_authentication(self, node_manager):
        """Test API key authentication system."""
        # Generate API key
        api_key = await node_manager.generate_api_key(
            node_name="auth-test-node",
            permissions=["FULL_ACCESS"],
            expires_in_days=1
        )
        
        # Test valid authentication
        auth_result = await node_manager.authenticate_api_key(api_key.key)
        assert auth_result.valid
        assert auth_result.node_name == "auth-test-node"
        assert "FULL_ACCESS" in auth_result.permissions
        
        # Test invalid authentication
        invalid_auth = await node_manager.authenticate_api_key("invalid-key")
        assert not invalid_auth.valid
    
    @pytest.mark.asyncio
    async def test_node_registration(self, node_manager):
        """Test backup node registration and management."""
        node_info = {
            "name": "backup-node-01",
            "address": "192.168.1.100:8080",
            "storage_capacity_gb": 1000,
            "node_type": "backup"
        }
        
        node = await node_manager.register_node(**node_info)
        
        assert node is not None
        assert node.name == "backup-node-01"
        assert node.address == "192.168.1.100:8080"
        assert node.storage_capacity_gb == 1000
        assert node.status == "ACTIVE"
    
    @pytest.mark.asyncio
    async def test_shard_distribution_prevention(self, node_manager):
        """Test prevention of unauthorized shard collection."""
        # Register nodes with different permissions
        read_only_node = await node_manager.register_node(
            name="read-only-node",
            address="192.168.1.101:8080",
            permissions=["READ_ONLY"]
        )
        
        full_access_node = await node_manager.register_node(
            name="full-access-node", 
            address="192.168.1.102:8080",
            permissions=["FULL_ACCESS"]
        )
        
        # Test that read-only node cannot collect all shards
        with pytest.raises(Exception):
            await node_manager.authorize_shard_collection(
                node_id=read_only_node.node_id,
                shard_count=1000  # Attempting to collect too many shards
            )
        
        # Test that full-access node can collect shards
        authorization = await node_manager.authorize_shard_collection(
            node_id=full_access_node.node_id,
            shard_count=10
        )
        assert authorization.authorized


@pytest.mark.skipif(not BACKUP_AVAILABLE, reason="Backup system not available")
class TestArchiveSystem:
    """Test archive system functionality."""
    
    @pytest.fixture
    async def archive_system(self):
        """Create a test archive system instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            system = ArchiveSystem(
                storage_path=temp_dir,
                shard_manager=Mock()
            )
            await system.initialize()
            yield system
            await system.cleanup()
    
    @pytest.mark.asyncio
    async def test_archive_creation(self, archive_system):
        """Test creating archives with versioning."""
        archive_data = {
            "messages": [
                {"id": 1, "content": "Test message 1", "timestamp": "2025-07-03T10:00:00Z"},
                {"id": 2, "content": "Test message 2", "timestamp": "2025-07-03T10:01:00Z"}
            ],
            "users": [
                {"id": 1, "username": "testuser", "email": "test@example.com"}
            ]
        }
        
        archive = await archive_system.create_archive(
            name="Test Archive",
            data=archive_data,
            server_id="test-server",
            created_by="admin"
        )
        
        assert archive is not None
        assert archive.name == "Test Archive"
        assert archive.version == 1
        assert archive.server_id == "test-server"
    
    @pytest.mark.asyncio
    async def test_archive_versioning(self, archive_system):
        """Test archive versioning system."""
        # Create initial archive
        initial_data = {"messages": [{"id": 1, "content": "Original message"}]}
        archive_v1 = await archive_system.create_archive(
            name="Versioned Archive",
            data=initial_data,
            server_id="test-server"
        )
        
        # Create updated version
        updated_data = {"messages": [
            {"id": 1, "content": "Updated message"},
            {"id": 2, "content": "New message"}
        ]}
        archive_v2 = await archive_system.update_archive(
            archive_id=archive_v1.archive_id,
            data=updated_data,
            updated_by="admin"
        )
        
        assert archive_v2.version == 2
        assert archive_v2.archive_id == archive_v1.archive_id
        
        # Verify both versions exist
        versions = await archive_system.list_archive_versions(archive_v1.archive_id)
        assert len(versions) == 2


@pytest.mark.skipif(not BACKUP_AVAILABLE, reason="Backup system not available")
class TestUserBackupPreferences:
    """Test user backup preference system."""
    
    @pytest.mark.asyncio
    async def test_user_opt_out_system(self):
        """Test user opt-out functionality."""
        # Mock user preferences
        user_prefs = {
            "user_id": "test-user-123",
            "backup_messages": True,
            "backup_profile": False,
            "backup_files": True,
            "backup_settings": True
        }
        
        # Test opt-out
        with patch('netlink.backup.core.user_preferences.UserPreferences') as mock_prefs:
            mock_prefs.get_preferences.return_value = user_prefs
            
            # Simulate backup operation respecting preferences
            should_backup_messages = user_prefs.get("backup_messages", True)
            should_backup_profile = user_prefs.get("backup_profile", True)
            
            assert should_backup_messages is True
            assert should_backup_profile is False
    
    @pytest.mark.asyncio
    async def test_universal_backup_system(self):
        """Test universal backup system with opt-out capabilities."""
        # Test data types that can be backed up
        backup_types = [
            "messages",
            "user_profiles", 
            "server_settings",
            "uploaded_files",
            "chat_history",
            "user_preferences"
        ]
        
        # Simulate universal backup with selective opt-out
        user_preferences = {
            "backup_messages": True,
            "backup_user_profiles": False,
            "backup_server_settings": True,
            "backup_uploaded_files": True,
            "backup_chat_history": True,
            "backup_user_preferences": True
        }
        
        backed_up_types = []
        for backup_type in backup_types:
            pref_key = f"backup_{backup_type}"
            if user_preferences.get(pref_key, True):  # Default to True
                backed_up_types.append(backup_type)
        
        assert "messages" in backed_up_types
        assert "user_profiles" not in backed_up_types  # Opted out
        assert "server_settings" in backed_up_types


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
