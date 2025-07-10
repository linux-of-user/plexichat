# PlexiChat Advanced Update System

## Overview

PlexiChat features a comprehensive update system with a new versioning scheme designed for enterprise-grade deployments. The system supports in-place upgrades, downgrades, rollbacks, and seamless integration with clustering.

## New Versioning Scheme

### Format: `{major}{type}{minor}`

- **Major**: Major version number (0, 1, 2, ...)
- **Type**: Version type (`a` = alpha, `b` = beta, `r` = release)
- **Minor**: Minor version number (1, 2, 3, ...)

### Examples
- `0a1` - Version 0, Alpha 1 (first alpha of major version 0)
- `0b1` - Version 0, Beta 1 (first beta of major version 0)
- `0r1` - Version 0, Release 1 (first release of major version 0)
- `0a2` - Version 0, Alpha 2 (second alpha of major version 0)
- `1r1` - Version 1, Release 1 (first release of major version 1)

### Version Lifecycle

```
0a1 → 0b1 → 0r1 → 0a2 → 0b2 → 0r2 → 1a1 → 1b1 → 1r1
```

- **Alpha**: Development versions with new features, potentially unstable
- **Beta**: Feature-complete versions for testing, more stable than alpha
- **Release**: Production-ready stable versions

## Core Features

### 1. In-Place Updates
- Update without full system reinstallation
- Preserve user data and configurations
- Minimal downtime during updates
- Automatic service restart when required

### 2. Version Management
- Track complete version history
- Compare versions and compatibility
- Validate upgrade/downgrade paths
- Support for custom build identifiers

### 3. Dependency Management
- Automatic dependency updates
- Dependency conflict resolution
- Rollback of dependency changes
- Support for multiple package managers

### 4. Configuration Migration
- Automatic configuration file migration
- Preserve custom settings
- Validate configuration after migration
- Rollback configuration changes

### 5. Database Migration
- Automatic schema migrations
- Data preservation during updates
- Migration validation and testing
- Schema rollback capabilities

### 6. Backup & Restore
- Automatic backups before updates
- Encrypted backup storage
- Complete system restoration
- Selective restore capabilities

### 7. Rollback Support
- Complete rollback to previous versions
- Automatic rollback on failure
- Manual rollback commands
- Rollback validation and testing

### 8. Clustering Integration
- Coordinated updates across cluster nodes
- Maintenance mode during updates
- Rolling updates for zero downtime
- Cluster state synchronization

## CLI Commands

### Basic Commands

```bash
# Check for available updates
plexichat update check

# Show current version information
plexichat update version
plexichat update version --detailed

# Show update system status
plexichat update status
```

### Upgrade Commands

```bash
# Upgrade to latest version
plexichat update upgrade --latest

# Upgrade to latest stable version
plexichat update upgrade --stable

# Upgrade to specific version
plexichat update upgrade --to 0b1

# Dry run (show what would be done)
plexichat update upgrade --to 0b1 --dry-run

# Force upgrade (skip warnings)
plexichat update upgrade --to 0b1 --force
```

### Downgrade Commands

```bash
# Downgrade to specific version
plexichat update downgrade --to 0a1

# Dry run downgrade
plexichat update downgrade --to 0a1 --dry-run

# Force downgrade
plexichat update downgrade --to 0a1 --force
```

### Changelog Commands

```bash
# Show current version changelog
plexichat update changelog

# Show changelog for specific version
plexichat update changelog --version 1b1

# Show changes since version
plexichat update changelog --since 1a1

# Show changelog in different formats
plexichat update changelog --format json
plexichat update changelog --format markdown
```

### Maintenance Commands

```bash
# Reinstall all dependencies
plexichat update reinstall-deps

# Upgrade database schema only
plexichat update upgrade-db
plexichat update upgrade-db --to 1b1

# Show update history
plexichat update history
plexichat update history --limit 20

# Rollback last update
plexichat update rollback

# Rollback specific update
plexichat update rollback --update-id update_0a1_0b1_20241219_120000
```

## Update Process

### 1. Pre-Update Phase
- Check system requirements
- Validate target version compatibility
- Create system backup
- Enter maintenance mode (if clustering)

### 2. Update Phase
- Update dependencies
- Migrate configuration files
- Migrate database schema
- Apply code updates
- Update version information

### 3. Post-Update Phase
- Run system tests
- Verify update success
- Exit maintenance mode
- Synchronize cluster state
- Restart services if required

### 4. Rollback Phase (if needed)
- Stop system services
- Restore from backup
- Restore database
- Restore configuration
- Update version information
- Restart system

## Configuration

### Update System Configuration

```yaml
# config/update.yml
update_system:
  # Backup settings
  backup:
    enabled: true
    directory: "backups/updates"
    encryption: true
    retention_days: 30
  
  # Update behavior
  behavior:
    auto_backup: true
    auto_restart: true
    maintenance_mode: true
    cluster_coordination: true
  
  # Safety settings
  safety:
    require_confirmation: true
    validate_migrations: true
    test_after_update: true
    rollback_on_failure: true
  
  # Clustering
  clustering:
    enabled: true
    coordination_timeout: 300
    rolling_updates: true
    max_concurrent_nodes: 1
```

### Version Configuration

```json
{
  "current_version": "a.1.1-1",
  "last_updated": "2025-07-09T00:00:00Z",
  "history": [
    {
      "version": "a.1.1-1",
      "release_date": "2025-07-09T00:00:00Z",
      "status": "development",
      "migration_required": true,
      "database_version": "a.1.1-1",
      "config_version": "a.1.1-1"
    }
  ]
}
```

## API Integration

### Python API

```python
from plexichat.core.versioning import (
    get_current_version,
    check_for_updates,
    upgrade_to_version,
    downgrade_to_version,
    get_changelog
)

# Get current version
current = get_current_version()
print(f"Current version: {current}")

# Check for updates
updates = await check_for_updates()
if updates['updates_available']:
    print(f"Latest version: {updates['latest_version']}")

# Upgrade to specific version
result = await upgrade_to_version("0b1")
if result.success:
    print("Upgrade completed successfully!")

# Get changelog
changelog = get_changelog(since_version="0a1")
print(changelog)
```

### REST API

```bash
# Check for updates
GET /api/v1/system/updates/check

# Get version information
GET /api/v1/system/version

# Start update
POST /api/v1/system/updates/upgrade
{
  "target_version": "0b1",
  "force": false
}

# Get update status
GET /api/v1/system/updates/status/{update_id}

# Rollback update
POST /api/v1/system/updates/rollback
{
  "update_id": "update_0a1_0b1_20241219_120000"
}
```

## Security Features

### Update Verification
- Cryptographic signature verification
- Checksum validation
- Source authentication
- Integrity checks

### Secure Backup
- Encrypted backup storage
- Secure key management
- Access control
- Audit logging

### Safe Rollback
- Integrity verification
- Data consistency checks
- Permission validation
- Secure restoration

## Clustering Integration

### Coordinated Updates
- Cluster-wide update coordination
- Maintenance mode management
- Node synchronization
- Consensus-based decisions

### Rolling Updates
- Zero-downtime updates
- Sequential node updates
- Health monitoring
- Automatic failover

### Cluster State Management
- State synchronization
- Configuration replication
- Service coordination
- Load balancing updates

## Troubleshooting

### Common Issues

#### Update Fails
```bash
# Check update logs
plexichat update status

# View detailed logs
tail -f logs/update.log

# Rollback if needed
plexichat update rollback
```

#### Version Mismatch
```bash
# Check current version
plexichat update version --detailed

# Validate version format
plexichat update check

# Reset version if corrupted
plexichat update reinstall-deps
```

#### Database Migration Issues
```bash
# Check database status
plexichat update upgrade-db --dry-run

# Manual database upgrade
plexichat update upgrade-db --to 0b1

# Rollback database
plexichat update rollback --update-id <id>
```

### Recovery Procedures

#### Complete System Recovery
1. Stop PlexiChat services
2. Restore from backup: `plexichat update rollback`
3. Verify system integrity
4. Restart services

#### Partial Recovery
1. Identify failed component
2. Use selective restore
3. Re-run specific migration
4. Validate functionality

## Best Practices

### Before Updating
1. Create manual backup
2. Test in staging environment
3. Review changelog for breaking changes
4. Plan maintenance window
5. Notify users of downtime

### During Updates
1. Monitor update progress
2. Watch for error messages
3. Keep rollback plan ready
4. Document any issues
5. Test critical functionality

### After Updates
1. Verify all services running
2. Test core functionality
3. Monitor system performance
4. Update documentation
5. Notify users of completion

## Migration Guide

### From Legacy Versioning (3.0.0 → 0a1)

1. **Backup Current System**
   ```bash
   # Create full backup
   plexichat backup create --full
   ```

2. **Update to New System**
   ```bash
   # Install new update system
   python run.py upgrade
   ```

3. **Verify Migration**
   ```bash
   # Check new version
   plexichat update version --detailed
   
   # Verify functionality
   plexichat update check
   ```

4. **Update Scripts and Automation**
   - Update version parsing in scripts
   - Modify CI/CD pipelines
   - Update monitoring systems
   - Adjust deployment procedures

This comprehensive update system provides enterprise-grade update management with safety, reliability, and seamless integration with all PlexiChat components.
