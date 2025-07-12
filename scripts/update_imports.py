#!/usr/bin/env python3
"""
PlexiChat Import Path Update Script
Phase VII: Global Import Path Correction

This script updates all import statements across the codebase to use the new
file paths established in Phase VI refactoring.

Updates:
- src/plexichat/core_system/ → src/plexichat/core/
- Old file names → New file names following naming convention
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Set
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Define import mappings from old paths to new paths
IMPORT_MAPPINGS = {
    # Core system base path
    'plexichat.core_system': 'plexichat.core',
    
    # Authentication mappings
    'plexichat.core_system.auth.admin_credentials': 'plexichat.core.auth.credentials_admin',
    'plexichat.core_system.auth.admin_manager': 'plexichat.core.auth.manager_admin',
    'plexichat.core_system.auth.audit_manager': 'plexichat.core.auth.manager_audit',
    'plexichat.core_system.auth.auth_manager': 'plexichat.core.auth.manager_auth',
    'plexichat.core_system.auth.biometric_manager': 'plexichat.core.auth.manager_biometric',
    'plexichat.core_system.auth.device_manager': 'plexichat.core.auth.manager_device',
    'plexichat.core_system.auth.mfa_manager': 'plexichat.core.auth.manager_mfa',
    'plexichat.core_system.auth.oauth_manager': 'plexichat.core.auth.manager_oauth',
    'plexichat.core_system.auth.password_manager': 'plexichat.core.auth.manager_password',
    'plexichat.core_system.auth.session_manager': 'plexichat.core.auth.manager_session',
    'plexichat.core_system.auth.token_manager': 'plexichat.core.auth.manager_token',
    'plexichat.core_system.auth.unified_auth_manager': 'plexichat.core.auth.manager_unified',
    'plexichat.core_system.auth.auth': 'plexichat.core.auth.auth_core',
    'plexichat.core_system.auth.decorators': 'plexichat.core.auth.decorators_auth',
    'plexichat.core_system.auth.exceptions': 'plexichat.core.auth.exceptions_auth',
    'plexichat.core_system.auth.middleware': 'plexichat.core.auth.middleware_auth',
    'plexichat.core_system.auth.validators': 'plexichat.core.auth.validators_auth',
    
    # Configuration mappings
    'plexichat.core_system.config.manager': 'plexichat.core.config.manager_config',
    'plexichat.core_system.config.config_manager': 'plexichat.core.config.manager_config',
    
    # Database mappings
    'plexichat.core_system.database.manager': 'plexichat.core.database.manager_database',
    'plexichat.core_system.database.analytics_clients': 'plexichat.core.database.client_analytics',
    'plexichat.core_system.database.global_data_distribution': 'plexichat.core.database.strategy_distribution',
    'plexichat.core_system.database.database_factory': 'plexichat.core.database.factory_database',
    'plexichat.core_system.database.engines': 'plexichat.core.database.engines_database',
    'plexichat.core_system.database.indexing_strategy': 'plexichat.core.database.strategy_indexing',
    'plexichat.core_system.database.lakehouse': 'plexichat.core.database.lakehouse_database',
    'plexichat.core_system.database.migrations': 'plexichat.core.database.migrations_database',
    'plexichat.core_system.database.nosql_clients': 'plexichat.core.database.client_nosql',
    'plexichat.core_system.database.partitioning_strategy': 'plexichat.core.database.strategy_partitioning',
    'plexichat.core_system.database.performance_integration': 'plexichat.core.database.integration_performance',
    'plexichat.core_system.database.query_optimizer': 'plexichat.core.database.optimizer_query',
    'plexichat.core_system.database.schema_optimizer': 'plexichat.core.database.optimizer_schema',
    'plexichat.core_system.database.setup_wizard': 'plexichat.core.database.wizard_setup',
    'plexichat.core_system.database.sql_clients': 'plexichat.core.database.client_sql',
    'plexichat.core_system.database.stored_procedures': 'plexichat.core.database.procedures_stored',
    'plexichat.core_system.database.zero_downtime_migration': 'plexichat.core.database.migration_zero_downtime',
    'plexichat.core_system.database.enhanced_abstraction': 'plexichat.core.database.abstraction_enhanced',
    
    # Error handling mappings
    'plexichat.core_system.error_handling.beautiful_error_handler': 'plexichat.core.error.handler_beautiful',
    'plexichat.core_system.error_handling.context': 'plexichat.core.error.context_error',
    'plexichat.core_system.error_handling.error_manager': 'plexichat.core.error.manager_error',
    
    # Integration mappings
    'plexichat.core_system.integration.orchestrator': 'plexichat.core.integration.orchestrator_core',
    
    # Logging mappings
    'plexichat.core_system.logging.advanced_logger': 'plexichat.core.logging.logger_advanced',
    'plexichat.core_system.logging.config': 'plexichat.core.logging.config_logging',
    'plexichat.core_system.logging.log_api': 'plexichat.core.logging.api_log',
    'plexichat.core_system.logging.performance_logger': 'plexichat.core.logging.logger_performance',
    
    # Security mappings
    'plexichat.core_system.security.automated_security_testing': 'plexichat.core.security.testing_automated',
    'plexichat.core_system.security.certificate_manager': 'plexichat.core.security.manager_certificate',
    'plexichat.core_system.security.input_validation': 'plexichat.core.security.validation_input',
    'plexichat.core_system.security.unified_audit_system': 'plexichat.core.security.system_audit',
    'plexichat.core_system.security.unified_hsm_manager': 'plexichat.core.security.manager_hsm',
    'plexichat.core_system.security.unified_security_manager': 'plexichat.core.security.manager_security',
    'plexichat.core_system.security.unified_threat_intelligence': 'plexichat.core.security.intelligence_threat',
    
    # Updates mappings
    'plexichat.core_system.updates.git_update_manager': 'plexichat.core.updates.manager_git',
    'plexichat.core_system.updates.updater': 'plexichat.core.updates.updater_core',
    
    # Versioning mappings
    'plexichat.core_system.versioning.api_version_manager': 'plexichat.core.versioning.manager_api_version',
    'plexichat.core_system.versioning.canary_deployment_manager': 'plexichat.core.versioning.manager_canary_deployment',
    'plexichat.core_system.versioning.canary_health_monitor': 'plexichat.core.versioning.monitor_canary_health',
    'plexichat.core_system.versioning.canary_node_selector': 'plexichat.core.versioning.selector_canary_node',
    'plexichat.core_system.versioning.changelog_manager': 'plexichat.core.versioning.manager_changelog',
    'plexichat.core_system.versioning.update_system': 'plexichat.core.versioning.system_update',
    'plexichat.core_system.versioning.version_manager': 'plexichat.core.versioning.manager_version',
}

def find_python_files(root_dir: Path) -> List[Path]:
    """Find all Python files in the directory tree."""
    python_files = []
    for file_path in root_dir.rglob("*.py"):
        # Skip __pycache__ directories
        if "__pycache__" not in str(file_path):
            python_files.append(file_path)
    return python_files

def update_imports_in_file(file_path: Path) -> Tuple[bool, int]:
    """
    Update import statements in a single file.
    Returns (was_modified, num_changes)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        changes_made = 0
        
        # Update import statements
        for old_import, new_import in IMPORT_MAPPINGS.items():
            # Pattern for 'from X import Y' statements
            from_pattern = rf'\bfrom\s+{re.escape(old_import)}\b'
            if re.search(from_pattern, content):
                content = re.sub(from_pattern, f'from {new_import}', content)
                changes_made += 1
                logger.debug(f"Updated 'from {old_import}' to 'from {new_import}' in {file_path}")
            
            # Pattern for 'import X' statements
            import_pattern = rf'\bimport\s+{re.escape(old_import)}\b'
            if re.search(import_pattern, content):
                content = re.sub(import_pattern, f'import {new_import}', content)
                changes_made += 1
                logger.debug(f"Updated 'import {old_import}' to 'import {new_import}' in {file_path}")
        
        # Write back if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True, changes_made
        
        return False, 0
        
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        return False, 0

def main():
    """Main function to update all import statements."""
    logger.info("🔄 Starting PlexiChat Import Path Update Process...")
    
    # Get the project root directory
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    src_dir = project_root / "src"
    
    if not src_dir.exists():
        logger.error(f"Source directory not found: {src_dir}")
        sys.exit(1)
    
    # Find all Python files
    logger.info("📁 Scanning for Python files...")
    python_files = find_python_files(src_dir)
    logger.info(f"Found {len(python_files)} Python files to process")
    
    # Process each file
    total_files_modified = 0
    total_changes = 0
    
    for file_path in python_files:
        was_modified, changes = update_imports_in_file(file_path)
        if was_modified:
            total_files_modified += 1
            total_changes += changes
            logger.info(f"✅ Updated {changes} imports in {file_path.relative_to(project_root)}")
    
    # Also check key files outside src/
    additional_files = [
        project_root / "scripts" / "run_security_tests.py",
        project_root / "run.py",
    ]
    
    for file_path in additional_files:
        if file_path.exists():
            was_modified, changes = update_imports_in_file(file_path)
            if was_modified:
                total_files_modified += 1
                total_changes += changes
                logger.info(f"✅ Updated {changes} imports in {file_path.relative_to(project_root)}")
    
    # Summary
    logger.info("\n📊 Import Update Summary:")
    logger.info(f"   Total files processed: {len(python_files) + len(additional_files)}")
    logger.info(f"   Files modified: {total_files_modified}")
    logger.info(f"   Total import changes: {total_changes}")
    
    if total_changes > 0:
        logger.info("\n🎉 Import path updates completed successfully!")
        logger.info("✅ All import statements now use the new file structure")
    else:
        logger.info("\n✅ No import updates needed - all paths are already current")
    
    return total_changes

if __name__ == "__main__":
    try:
        changes = main()
        sys.exit(0 if changes >= 0 else 1)
    except KeyboardInterrupt:
        logger.info("\n⚠️ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Script failed: {e}")
        sys.exit(1)
