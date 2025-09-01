# Backup Runbook

## Overview
This runbook provides procedures for backing up and restoring PlexiChat data and systems.

## Backup Types

### Database Backups
- **Full backups**: Complete database snapshots
- **Incremental backups**: Changes since last backup
- **Point-in-time recovery**: Restore to specific timestamp

### File System Backups
- **Application files**: Source code and configurations
- **User uploads**: Files uploaded by users
- **Logs**: Application and system logs

### Configuration Backups
- **Environment files**: .env and configuration files
- **Kubernetes manifests**: Deployment configurations
- **Infrastructure as Code**: Terraform/AWS configurations

## Backup Schedule

### Daily Backups
- Database full backup at 02:00 UTC
- File system incremental backup at 03:00 UTC
- Configuration backup at 04:00 UTC

### Weekly Backups
- Full system backup on Sundays at 02:00 UTC
- Archive old backups (older than 30 days)

### Monthly Backups
- Long-term archive creation
- Backup verification and testing

## Backup Procedures

### Database Backup
```bash
# PostgreSQL backup
pg_dump -h localhost -U plexichat -d plexichat_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Compress backup
gzip backup_$(date +%Y%m%d_%H%M%S).sql

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d_%H%M%S).sql.gz s3://plexichat-backups/database/
```

### File System Backup
```bash
# Create backup archive
tar -czf backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    /var/www/plexichat/uploads \
    /var/log/plexichat \
    /etc/plexichat

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d_%H%M%S).tar.gz s3://plexichat-backups/files/
```

### Configuration Backup
```bash
# Backup Kubernetes configs
kubectl get all -o yaml > k8s_backup_$(date +%Y%m%d_%H%M%S).yaml

# Backup environment files
tar -czf config_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    /etc/plexichat/.env \
    /etc/plexichat/config.yaml

# Upload to S3
aws s3 cp k8s_backup_$(date +%Y%m%d_%H%M%S).yaml s3://plexichat-backups/config/
aws s3 cp config_backup_$(date +%Y%m%d_%H%M%S).tar.gz s3://plexichat-backups/config/
```

## Restore Procedures

### Database Restore
```bash
# Download latest backup
aws s3 cp s3://plexichat-backups/database/latest.sql.gz .

# Decompress
gunzip latest.sql.gz

# Restore database
psql -h localhost -U plexichat -d plexichat_db < latest.sql

# Run migrations if needed
alembic upgrade head
```

### File System Restore
```bash
# Download backup
aws s3 cp s3://plexichat-backups/files/latest.tar.gz .

# Extract files
tar -xzf latest.tar.gz -C /

# Set correct permissions
chown -R plexichat:plexichat /var/www/plexichat/uploads
chmod -R 755 /var/log/plexichat
```

### Configuration Restore
```bash
# Download config backup
aws s3 cp s3://plexichat-backups/config/latest.tar.gz .

# Extract configurations
tar -xzf latest.tar.gz -C /etc/plexichat

# Apply Kubernetes configurations
kubectl apply -f k8s_backup_latest.yaml
```

## Backup Verification

### Automated Verification
```bash
# Check backup integrity
aws s3 ls s3://plexichat-backups/ --recursive | tail -10

# Test database backup
pg_restore --list backup_test.sql

# Verify file backup
tar -tzf backup_test.tar.gz | head -20
```

### Manual Testing
- Restore to staging environment monthly
- Test application functionality after restore
- Verify data integrity and consistency

## Disaster Recovery

### Complete System Recovery
1. Provision new infrastructure
2. Restore configurations
3. Restore database
4. Restore file system
5. Start application services
6. Verify system functionality

### Point-in-Time Recovery
```bash
# Restore to specific timestamp
pg_restore -h localhost -U plexichat -d plexichat_db \
    --target-time "2024-01-15 14:30:00" backup.sql
```

## Retention Policy

### Database Backups
- Daily backups: 30 days
- Weekly backups: 1 year
- Monthly backups: 7 years

### File System Backups
- Daily backups: 30 days
- Weekly backups: 1 year
- Monthly backups: 7 years

### Configuration Backups
- All backups: 1 year

## Monitoring and Alerts

### Backup Success Monitoring
- Alert if backup fails
- Alert if backup size changes significantly
- Alert if backup takes too long

### Storage Monitoring
- Monitor S3 storage usage
- Alert when approaching storage limits
- Clean up old backups automatically

## Security Considerations

### Encryption
- Encrypt backups at rest
- Use secure transfer protocols
- Store encryption keys securely

### Access Control
- Limit backup access to authorized personnel
- Use IAM roles for automated backups
- Audit backup access logs

## Contacts
- **Backup Team**: backup@plexichat.com
- **DevOps Team**: devops@plexichat.com
- **Security Team**: security@plexichat.com
- **On-call Engineer**: +1-555-0123