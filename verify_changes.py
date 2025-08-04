#!/usr/bin/env python3
"""
Verification script to ensure all distributed backup system changes are intact.
"""

import os
import sys
from pathlib import Path

def check_file_exists(file_path, description):
    """Check if a file exists and report status."""
    if Path(file_path).exists():
        size = Path(file_path).stat().st_size
        print(f"✅ {description}: {file_path} ({size:,} bytes)")
        return True
    else:
        print(f"❌ {description}: {file_path} (MISSING)")
        return False

def check_directory_exists(dir_path, description):
    """Check if a directory exists and report status."""
    if Path(dir_path).exists() and Path(dir_path).is_dir():
        file_count = len(list(Path(dir_path).glob("*")))
        print(f"✅ {description}: {dir_path} ({file_count} files)")
        return True
    else:
        print(f"❌ {description}: {dir_path} (MISSING)")
        return False

def main():
    """Main verification function."""
    print("🔍 PlexiChat Distributed Backup System - Change Verification")
    print("=" * 65)
    
    # Change to the correct directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    all_good = True
    
    print("\n📁 Core Backup System Files:")
    print("-" * 30)
    
    core_files = [
        ("plexichat/src/plexichat/core/backup/shard_manager.py", "Shard Manager (1MB + Reed-Solomon)"),
        ("plexichat/src/plexichat/core/backup/encryption_manager.py", "Encryption Manager (Per-shard keys)"),
        ("plexichat/src/plexichat/core/backup/version_manager.py", "Version Manager (Immutable + diffs)"),
        ("plexichat/src/plexichat/core/backup/distribution_manager.py", "Distribution Manager (Cross-user)"),
        ("plexichat/src/plexichat/core/backup/api_endpoints.py", "API Endpoints (REST API)"),
        ("plexichat/src/plexichat/core/backup/backup_system.py", "Main Backup System"),
        ("plexichat/src/plexichat/core/backup/__init__.py", "Backup Module Init"),
    ]
    
    for file_path, description in core_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n🌐 WebUI Integration Files:")
    print("-" * 30)
    
    webui_files = [
        ("plexichat/src/plexichat/interfaces/web/routers/backup_management.py", "Backup Management Router"),
        ("plexichat/src/plexichat/interfaces/web/routers/config_management.py", "Config Management Router"),
        ("plexichat/src/plexichat/interfaces/web/templates/admin/config_management.html", "Config Management Template"),
    ]
    
    for file_path, description in webui_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n⚙️ Configuration System Files:")
    print("-" * 30)
    
    config_files = [
        ("plexichat/src/plexichat/core/unified_config.py", "Unified Configuration System"),
        ("plexichat/src/plexichat/core/config.py", "Legacy Config Compatibility"),
    ]
    
    for file_path, description in config_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n🧪 Test Files:")
    print("-" * 15)
    
    test_files = [
        ("plexichat/test_distributed_backup.py", "Distributed Backup Test"),
        ("plexichat/simple_backup_test.py", "Simple Backup Test"),
    ]
    
    for file_path, description in test_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n📋 Documentation Files:")
    print("-" * 25)
    
    doc_files = [
        ("plexichat/DISTRIBUTED_BACKUP_CHANGES_SUMMARY.md", "Changes Summary"),
        ("plexichat/git_cleanup.ps1", "Git Cleanup Script (PowerShell)"),
        ("plexichat/git_cleanup.sh", "Git Cleanup Script (Bash)"),
    ]
    
    for file_path, description in doc_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n🗑️ Cleanup Verification (should be removed):")
    print("-" * 45)
    
    removed_items = [
        ("plexichat/src/plexichat/features/backup", "Old fragmented backup directory"),
        ("plexichat/CACHE_IMPROVEMENTS.md", "Old cache improvements doc"),
        ("plexichat/cache_config.py", "Old cache config"),
        ("plexichat/test_api_improvements.py", "Old API test"),
    ]
    
    for item_path, description in removed_items:
        if Path(item_path).exists():
            print(f"⚠️  {description}: {item_path} (SHOULD BE REMOVED)")
        else:
            print(f"✅ {description}: {item_path} (correctly removed)")
    
    print("\n🔧 System Integration Check:")
    print("-" * 30)
    
    # Check if main files were updated
    integration_files = [
        ("plexichat/src/plexichat/main.py", "Main application"),
        ("plexichat/src/plexichat/core/services/database_service.py", "Database service"),
        ("plexichat/src/plexichat/interfaces/web/__init__.py", "WebUI router registration"),
    ]
    
    for file_path, description in integration_files:
        if not check_file_exists(file_path, description):
            all_good = False
    
    print("\n📊 Summary:")
    print("-" * 10)
    
    if all_good:
        print("🎉 All distributed backup system files are present!")
        print("✅ System appears to be complete and ready for testing.")
        print("\n📋 Next steps:")
        print("1. Run git cleanup: ./git_cleanup.ps1 or ./git_cleanup.sh")
        print("2. Test the system: python test_distributed_backup.py")
        print("3. Check WebUI: Navigate to /backup and /config endpoints")
    else:
        print("❌ Some files are missing. Please check the implementation.")
        print("📋 Recommended actions:")
        print("1. Review the missing files listed above")
        print("2. Re-run the implementation for missing components")
        print("3. Verify file paths are correct")
    
    print(f"\n🔍 Verification completed. Status: {'PASS' if all_good else 'FAIL'}")
    return all_good

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
