# NetLink Backup System Documentation

## Overview

NetLink's backup system provides government-level security with advanced shard distribution, encryption, and redundancy. The system is designed to ensure data integrity and availability even in the event of catastrophic failures.

## Architecture

### Core Components

1. **Government Backup Manager** (`src/netlink/backup/core/government_backup_manager.py`)
   - Central orchestration of all backup operations
   - Government-level security implementation
   - Proxy mode for resilient operation

2. **Shard Manager** (`src/netlink/backup/core/shard_manager.py`)
   - Immutable shard creation and management
   - SHA-512 checksums for integrity verification
   - Advanced encryption with individual shard keys

3. **Backup Node Manager** (`src/netlink/backup/core/backup_node_manager.py`)
   - Distributed backup node coordination
   - API key authentication system
   - Intelligent shard distribution

4. **Archive System** (`src/netlink/backup/plugins/archive_system.py`)
   - Version-controlled data archival
   - Server-by-server activation
   - Premium user permissions

### Security Features

#### SHA-512 Checksums
- All backup operations use SHA-512 for integrity verification
- Checksums stored separately from data for tamper detection
- Automatic verification during restoration

#### Advanced Encryption
- Individual encryption keys for each shard
- Minimum 2-shard requirement for data recovery
- Quantum-resistant encryption algorithms
- Confusing filename generation for security through obscurity

#### Backup Node Authentication
- API key-based authentication system
- Permission levels (READ_ONLY, WRITE_ONLY, FULL_ACCESS)
- Rate limiting and audit logging
- Prevents unauthorized shard collection

## API Endpoints

### System Health
```
GET /api/v1/backup/health
```
Returns overall backup system health status.

**Response:**
```json
{
  "status": "HEALTHY|WARNING|CRITICAL",
  "total_shards": 1250,
  "active_nodes": 5,
  "coverage_percentage": 98.5,
  "last_backup": "2025-07-03T10:30:00Z",
  "proxy_mode_active": false
}
```

### Create Backup
```
POST /api/v1/backup/create
```
Creates a new backup operation.

**Request Body:**
```json
{
  "name": "Daily Backup",
  "backup_type": "full|incremental|differential",
  "description": "Automated daily backup",
  "encryption_enabled": true,
  "compression_enabled": true,
  "created_by": "admin"
}
```

### List Backups
```
GET /api/v1/backup/operations?limit=10&offset=0
```
Lists backup operations with pagination.

### Shard Management
```
GET /api/v1/backup/shards/distribution
POST /api/v1/backup/shards/redistribute
GET /api/v1/backup/shards/{shard_id}/verify
```

### Backup Node Management
```
GET /api/v1/backup/nodes
POST /api/v1/backup/nodes/add
DELETE /api/v1/backup/nodes/{node_id}
POST /api/v1/backup/nodes/api-keys/generate
```

## User Interface

### WebUI
Access backup management through the admin dashboard at `/web/admin/backup-management`.

Features:
- Real-time system health monitoring
- Interactive backup creation
- Shard distribution visualization
- Node management interface
- Archive system controls

### GUI Application
Desktop application provides full backup management capabilities with:
- Tabbed interface for different management areas
- Real-time charts and visualizations
- Auto-refresh functionality
- Offline operation support

## Configuration

### Environment Variables
```bash
# Backup System Configuration
BACKUP_ENCRYPTION_KEY=your-master-encryption-key
BACKUP_SHARD_SIZE_MB=100
BACKUP_MIN_REDUNDANCY=3
BACKUP_MAX_SHARD_AGE_DAYS=365

# Backup Node Configuration
BACKUP_NODE_API_TIMEOUT=30
BACKUP_NODE_MAX_CONNECTIONS=10
BACKUP_NODE_RETRY_ATTEMPTS=3
```

### Database Configuration
The backup system uses encrypted databases for shard location information:
- Primary shard location database
- Redundant backup location database
- Separate encryption keys for each database

## User Backup Preferences

### Opt-Out System
Users can control what data is backed up:

```python
# User backup preferences
{
  "backup_messages": true,
  "backup_profile": true,
  "backup_files": false,
  "backup_settings": true
}
```

### API Endpoints
```
GET /api/v1/backup/user-preferences
PUT /api/v1/backup/user-preferences
POST /api/v1/backup/user-preferences/opt-out
POST /api/v1/backup/user-preferences/opt-in
```

## Proxy Mode

When the main database is unavailable, the backup system can operate in proxy mode:
- Server continues to function as message proxy
- Limited functionality maintained
- Automatic recovery when database restored
- No data loss during proxy operation

## Monitoring and Alerts

### Health Checks
- Continuous monitoring of backup operations
- Automatic detection of failed nodes
- Shard integrity verification
- Storage capacity monitoring

### Alerting
- Email notifications for critical issues
- WebUI dashboard alerts
- API endpoints for external monitoring
- Configurable alert thresholds

## Troubleshooting

### Common Issues

1. **Backup Operation Fails**
   - Check node connectivity
   - Verify encryption keys
   - Review storage capacity
   - Check API key permissions

2. **Shard Verification Fails**
   - Run integrity check
   - Verify SHA-512 checksums
   - Check for corruption
   - Redistribute affected shards

3. **Node Communication Issues**
   - Verify network connectivity
   - Check API key validity
   - Review firewall settings
   - Test node endpoints

### Log Files
- Backup operations: `logs/backup/operations.log`
- Shard management: `logs/backup/shards.log`
- Node communication: `logs/backup/nodes.log`
- Security events: `logs/backup/security.log`

## Best Practices

1. **Regular Testing**
   - Test backup restoration monthly
   - Verify shard integrity weekly
   - Monitor node performance daily

2. **Security**
   - Rotate API keys quarterly
   - Update encryption keys annually
   - Review access logs regularly

3. **Capacity Planning**
   - Monitor storage usage trends
   - Plan for 20% growth annually
   - Maintain 3x redundancy minimum

4. **Disaster Recovery**
   - Test proxy mode functionality
   - Maintain offline backup copies
   - Document recovery procedures
   - Train staff on emergency procedures
