"""Backup system tests."""
import pytest
from src.netlink.backups import backup_manager, BackupType, BackupPriority

@pytest.mark.unit
class TestBackupSystem:
    """Test backup system functionality."""
    
    def test_backup_manager_initialization(self):
        """Test backup manager initializes correctly."""
        assert backup_manager is not None
        assert hasattr(backup_manager, 'config')
    
    def test_backup_types(self):
        """Test backup type enumeration."""
        assert BackupType.FULL.value == "full"
        assert BackupType.INCREMENTAL.value == "incremental"
    
    def test_backup_priorities(self):
        """Test backup priority enumeration."""
        assert BackupPriority.LOW.value == 1
        assert BackupPriority.CRITICAL.value == 4
    
    @pytest.mark.asyncio
    async def test_backup_creation(self):
        """Test backup creation flow."""
        # Initialize backup manager first
        await backup_manager.initialize()
        
        # Test backup creation
        backup_id = await backup_manager.create_backup(
            "test data", BackupType.FULL, BackupPriority.NORMAL
        )
        
        assert isinstance(backup_id, str)
        assert backup_id.startswith("backup_")
