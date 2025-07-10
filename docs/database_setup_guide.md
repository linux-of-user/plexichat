# PlexiChat Database Setup Guide

This comprehensive guide covers setting up databases for PlexiChat, including local and external database configurations.

## Quick Start

### Using the Setup Wizard (Recommended)

1. **Access the Setup Wizard**
   - Web UI: Navigate to `/api/v1/database/setup/status`
   - API: Use the database setup endpoints

2. **Follow the Wizard Steps**
   - Choose database type
   - Configure connection details
   - Set authentication (if required)
   - Configure advanced settings
   - Test connection
   - Initialize schema

## Supported Databases

### Local Databases

#### SQLite (Default)
- **Best for**: Development, small deployments
- **Configuration**: Automatic, no server required
- **File location**: `data/plexichat.db`

#### PostgreSQL
- **Best for**: Production deployments
- **Requirements**: PostgreSQL server 12+
- **Features**: Full-text search, JSON support, advanced indexing

#### MySQL/MariaDB
- **Best for**: Existing MySQL infrastructure
- **Requirements**: MySQL 8.0+ or MariaDB 10.5+
- **Features**: JSON support, good performance

### External Database Providers

#### Amazon RDS
- **Supported Engines**: PostgreSQL, MySQL
- **Setup Steps**:
  1. Create RDS instance in AWS Console
  2. Configure security groups
  3. Note endpoint and credentials
  4. Use setup wizard with provider "aws_rds"

#### Google Cloud SQL
- **Supported Engines**: PostgreSQL, MySQL
- **Setup Steps**:
  1. Create Cloud SQL instance
  2. Configure authorized networks
  3. Create database and user
  4. Use setup wizard with provider "google_cloud_sql"

#### Supabase
- **Supported Engines**: PostgreSQL
- **Setup Steps**:
  1. Create Supabase project
  2. Go to Settings > Database
  3. Copy connection details
  4. Use setup wizard with provider "supabase"

#### PlanetScale
- **Supported Engines**: MySQL
- **Setup Steps**:
  1. Create PlanetScale database
  2. Create branch and connection string
  3. Use setup wizard with provider "planetscale"

## Manual Configuration

### Environment Variables

```bash
# Basic database URL
DATABASE_URL=sqlite:///data/plexichat.db

# PostgreSQL example
DATABASE_URL=postgresql://user:password@localhost:5432/plexichat

# MySQL example
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/plexichat
```

### Configuration File

Edit `config/database.yaml`:

```yaml
database:
  type: "postgresql"
  postgresql:
    host: "localhost"
    port: 5432
    database: "plexichat"
    username: "plexichat_user"
    password: "secure_password"
    ssl_mode: "require"
```

## API Endpoints

### Setup Wizard Endpoints

- `GET /api/v1/database/setup/status` - Get wizard status
- `GET /api/v1/database/setup/database-types` - Get available database types
- `POST /api/v1/database/setup/database-type` - Set database type
- `POST /api/v1/database/setup/connection-details` - Set connection details
- `POST /api/v1/database/setup/authentication` - Set authentication
- `POST /api/v1/database/setup/test-connection` - Test connection
- `POST /api/v1/database/setup/initialize-schema` - Initialize database schema
- `POST /api/v1/database/setup/save-configuration` - Save configuration

### External Database Endpoints

- `GET /api/v1/database/setup/external/providers` - Get external providers
- `GET /api/v1/database/setup/external/provider/{provider}/guide` - Get setup guide
- `POST /api/v1/database/setup/external/configure` - Configure external database
- `POST /api/v1/database/setup/external/test` - Test external connection
- `GET /api/v1/database/setup/external/health` - Get connection health

## Database Migration

### From SQLite to PostgreSQL

```bash
# 1. Backup current database
curl -X POST "http://localhost:8000/api/v1/database/setup/backup" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# 2. Set up PostgreSQL database
# 3. Use migration endpoint
curl -X POST "http://localhost:8000/api/v1/database/setup/migration/analyze" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_database_url": "sqlite:///data/plexichat.db",
    "backup_source": true
  }'
```

## Troubleshooting

### Common Issues

#### Connection Refused
- **SQLite**: Check file permissions and directory existence
- **PostgreSQL**: Verify server is running and accepting connections
- **MySQL**: Check server status and port availability

#### Authentication Failed
- Verify username and password
- Check user permissions and database access
- For external providers, verify API keys and connection strings

#### SSL/TLS Issues
- Ensure SSL certificates are valid
- Check SSL mode configuration
- For external providers, SSL is usually required

### Health Monitoring

Check database health:
```bash
curl "http://localhost:8000/api/v1/database/setup/health"
```

Monitor connection pool:
```bash
curl "http://localhost:8000/api/v1/database/setup/external/health" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Performance Optimization

### Connection Pooling

Adjust pool settings in `config/database.yaml`:

```yaml
database:
  pool_size: 20          # Concurrent connections
  max_overflow: 30       # Additional connections when needed
  pool_timeout: 30       # Wait time for connection
  pool_recycle: 3600     # Connection lifetime (seconds)
```

### Query Optimization

Enable query monitoring:

```yaml
monitoring:
  monitor_queries: true
  slow_query_threshold: 1000  # milliseconds
```

## Security Best Practices

### Connection Security
- Always use SSL/TLS for external connections
- Use strong passwords and rotate regularly
- Limit database user permissions
- Configure firewall rules appropriately

### Data Protection
- Enable encryption at rest (provider-dependent)
- Regular backups with encryption
- Monitor access logs
- Use connection pooling to prevent connection exhaustion

### Network Security
- Use VPC/private networks for cloud databases
- Configure IP whitelisting
- Monitor connection attempts
- Use connection limits per IP

## Backup and Recovery

### Automatic Backups

Configure in `config/database.yaml`:

```yaml
backup:
  enabled: true
  interval: 86400        # 24 hours
  retention_days: 30
  compress: true
  backup_dir: "backups/database"
```

### Manual Backup

```bash
# Create backup
curl -X POST "http://localhost:8000/api/v1/database/backup" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# List backups
curl "http://localhost:8000/api/v1/database/backups" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

## Advanced Configuration

### Multiple Database Support

PlexiChat supports multiple database connections:

```yaml
databases:
  primary:
    type: "postgresql"
    url: "postgresql://user:pass@host:5432/plexichat"
  
  analytics:
    type: "mysql"
    url: "mysql://user:pass@host:3306/analytics"
  
  cache:
    type: "sqlite"
    url: "sqlite:///data/cache.db"
```

### Custom Connection Parameters

For advanced use cases:

```yaml
database:
  postgresql:
    # Custom connection parameters
    connect_timeout: 30
    command_timeout: 60
    server_settings:
      application_name: "plexichat"
      timezone: "UTC"
```

## Support

For additional help:
- Check the logs in `logs/database.log`
- Use the health endpoints for diagnostics
- Consult provider-specific documentation
- Contact PlexiChat support with configuration details
