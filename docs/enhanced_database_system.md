# PlexiChat Enhanced Database System

## Overview

PlexiChat's Enhanced Database System is a comprehensive, multi-database architecture that provides:

- **Unified Database Abstraction**: Single interface for SQL, NoSQL, Analytics, and Lakehouse databases
- **Data Lakehouse Architecture**: Modern data platform combining data lake flexibility with warehouse performance
- **Real-time Data Ingestion**: Stream application events and data to analytics systems
- **ETL/ELT Pipelines**: Automated data transformation and processing
- **Multi-Database Support**: PostgreSQL, MongoDB, Redis, ClickHouse, MinIO, and more

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PlexiChat Application                        │
├─────────────────────────────────────────────────────────────────┤
│              Enhanced Database Abstraction Layer               │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│   SQL Databases │ NoSQL Databases │ Analytics DBs   │ Lakehouse │
│   - PostgreSQL  │   - MongoDB     │  - ClickHouse   │  - MinIO  │
│   - MySQL       │   - Redis       │  - TimescaleDB  │  + Iceberg│
│   - SQLite      │   - Cassandra   │  - Apache Druid │  + Spark  │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
```

## Components

### 1. Database Abstraction Layer

**File**: `src/plexichat/core/database/enhanced_abstraction.py`

Provides a unified interface for all database types:

```python
from plexichat.core.database.enhanced_abstraction import enhanced_db_manager

# Execute query on any database
result = await enhanced_db_manager.execute_query(
    "SELECT * FROM users WHERE active = $active",
    params={"active": True},
    database="mongodb"
)
```

### 2. NoSQL Database Clients

**File**: `src/plexichat/core/database/nosql_clients.py`

Supports:
- **MongoDB**: Document storage for flexible schemas
- **Redis**: Caching and session storage
- **Cassandra**: Wide-column store for time-series data

### 3. Analytics Database Clients

**File**: `src/plexichat/core/database/analytics_clients.py`

Supports:
- **ClickHouse**: Column-oriented OLAP for fast analytics
- **TimescaleDB**: Time-series analytics on PostgreSQL
- **Apache Druid**: Real-time analytics

### 4. Data Lakehouse

**File**: `src/plexichat/core/database/lakehouse.py`

Modern lakehouse architecture with:
- **MinIO**: S3-compatible object storage
- **Apache Iceberg**: Table format with ACID transactions
- **Apache Spark**: Distributed query engine
- **Delta Lake**: Alternative table format support

### 5. Data Ingestion Service

**File**: `src/plexichat/services/data_ingestion_service.py`

Real-time data streaming:
- Application logs
- User events
- Database changes
- System metrics
- API requests

### 6. ETL/ELT Pipeline Service

**File**: `src/plexichat/services/etl_pipeline_service.py`

Automated data processing:
- Extract from multiple sources
- Transform with business logic
- Load to analytics systems
- Scheduled and event-driven execution

## Configuration

### Basic Setup

1. **Copy configuration template**:
   ```bash
   cp config/database_enhanced.yaml.example config/database_enhanced.yaml
   ```

2. **Enable desired databases**:
   ```yaml
   nosql:
     mongodb:
       enabled: true
       host: localhost
       port: 27017
   
   analytics:
     clickhouse:
       enabled: true
       host: localhost
       port: 9000
   ```

3. **Set environment variables**:
   ```bash
   export PLEXICHAT_MONGODB_HOST=localhost
   export PLEXICHAT_CLICKHOUSE_HOST=localhost
   export PLEXICHAT_MINIO_ENDPOINT=localhost:9000
   ```

### Environment-Specific Configuration

The system supports different configurations per environment:

```yaml
environments:
  development:
    # Simplified setup for development
  
  production:
    # Full-scale production setup with all databases
```

## Usage Examples

### 1. Basic Database Operations

```python
# Add a new database
from plexichat.core.database.enhanced_abstraction import enhanced_db_manager, DatabaseConfig, DatabaseType

config = DatabaseConfig(
    type=DatabaseType.MONGODB,
    name="documents",
    host="localhost",
    port=27017,
    database="plexichat_docs"
)

await enhanced_db_manager.add_database("documents", config)

# Execute queries
result = await enhanced_db_manager.execute_query(
    '{"collection": "messages", "operation": "find", "filter": {"user_id": "$user_id"}}',
    params={"user_id": "123"},
    database="documents"
)
```

### 2. Data Ingestion

```python
from plexichat.services.data_ingestion_service import data_ingestion_service

# Ingest user event
await data_ingestion_service.ingest_user_event(
    user_id="user123",
    event_type="message_sent",
    data={"channel_id": "general", "message_length": 50}
)

# Ingest API request
await data_ingestion_service.ingest_api_request(
    method="POST",
    endpoint="/api/v1/messages",
    user_id="user123",
    response_code=201,
    response_time=0.15
)
```

### 3. ETL Pipelines

```python
from plexichat.services.etl_pipeline_service import etl_pipeline_service, PipelineConfig, PipelineType

# Define a pipeline
pipeline = PipelineConfig(
    name="daily_user_stats",
    pipeline_type=PipelineType.SCHEDULED,
    source_type="lakehouse",
    source_config={
        "query": "SELECT user_id, COUNT(*) as message_count FROM raw_user_events GROUP BY user_id"
    },
    target_type="analytics_warehouse",
    target_config={"table": "user_daily_stats"},
    schedule_cron="0 1 * * *"  # Daily at 1 AM
)

etl_pipeline_service.register_pipeline(pipeline)

# Execute pipeline manually
run = await etl_pipeline_service.execute_pipeline("daily_user_stats")
```

### 4. Analytics Queries

```python
from plexichat.core.database.enhanced_abstraction import execute_analytics_query

# Run analytics query on ClickHouse
result = await execute_analytics_query("""
    SELECT 
        toDate(timestamp) as date,
        count() as message_count,
        uniq(user_id) as unique_users
    FROM messages_daily
    WHERE date >= today() - 30
    GROUP BY date
    ORDER BY date
""")
```

### 5. Lakehouse Operations

```python
# Get lakehouse client
lakehouse = await enhanced_db_manager.get_database_client("lakehouse")

# Create table
await lakehouse.create_table(
    "user_events",
    schema={
        "event_id": "STRING",
        "user_id": "STRING", 
        "event_type": "STRING",
        "timestamp": "TIMESTAMP",
        "data": "STRING"
    },
    partition_by=["year", "month", "day"]
)

# Time travel query
historical_data = await lakehouse.time_travel_query(
    "user_events",
    datetime(2024, 1, 1)
)
```

## Monitoring and Metrics

### Health Checks

```python
# Check overall system health
health = await enhanced_db_manager.get_health_status()

# Check specific database health
mongo_health = await enhanced_db_manager.clients["mongodb"].health_check()
```

### Metrics

The system provides comprehensive metrics:

- Query execution times
- Connection pool usage
- Data ingestion rates
- Pipeline success/failure rates
- Storage utilization

### Alerts

Configure alerts for:
- High connection usage
- Slow queries
- Pipeline failures
- Storage capacity
- Error rates

## Performance Optimization

### 1. Connection Pooling

```yaml
default:
  pool_size: 20
  max_overflow: 30
  pool_timeout: 30
```

### 2. Query Optimization

- Use appropriate indexes
- Leverage database-specific features
- Implement query caching
- Use read replicas for analytics

### 3. Data Partitioning

```python
# Partition large tables by date
await clickhouse_client.create_table(
    "messages",
    schema={"id": "UInt64", "content": "String", "created_at": "DateTime"},
    partition_by=["toYYYYMM(created_at)"],
    order_by=["created_at", "id"]
)
```

### 4. Batch Processing

```yaml
data_ingestion:
  batch_size: 5000
  flush_interval_seconds: 30
```

## Security

### 1. Encryption

- **At Rest**: Database-level encryption
- **In Transit**: SSL/TLS connections
- **Application Level**: Field-level encryption for sensitive data

### 2. Access Control

```yaml
security:
  role_based_access: true
  audit_logging: true
  connection_encryption: true
```

### 3. Data Privacy

- PII detection and masking
- GDPR compliance features
- Data retention policies
- Audit trails

## Deployment

### Development

```bash
# Start with SQLite only
python run.py

# Enable MongoDB
export PLEXICHAT_MONGODB_URL=mongodb://localhost:27017
python run.py
```

### Production

```bash
# Set all environment variables
export PLEXICHAT_DB_HOST=postgres.example.com
export PLEXICHAT_MONGODB_HOST=mongo.example.com
export PLEXICHAT_CLICKHOUSE_HOST=clickhouse.example.com
export PLEXICHAT_MINIO_ENDPOINT=minio.example.com:9000

# Start with full configuration
python run.py
```

### Docker Compose

```yaml
version: '3.8'
services:
  plexichat:
    build: .
    environment:
      - PLEXICHAT_ENV=production
      - PLEXICHAT_DB_HOST=postgres
      - PLEXICHAT_MONGODB_HOST=mongodb
      - PLEXICHAT_CLICKHOUSE_HOST=clickhouse
      - PLEXICHAT_MINIO_ENDPOINT=minio:9000
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: plexichat
      POSTGRES_USER: plexichat
      POSTGRES_PASSWORD: secure_password
  
  mongodb:
    image: mongo:6
    environment:
      MONGO_INITDB_DATABASE: plexichat
  
  clickhouse:
    image: clickhouse/clickhouse-server:latest
  
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
```

## Troubleshooting

### Common Issues

1. **Connection Failures**
   - Check network connectivity
   - Verify credentials
   - Check firewall settings

2. **Performance Issues**
   - Monitor connection pool usage
   - Check query execution plans
   - Review indexing strategy

3. **Data Ingestion Lag**
   - Increase batch size
   - Add more workers
   - Check target database performance

### Debugging

```python
# Enable debug logging
import logging
logging.getLogger("plexichat.core.database").setLevel(logging.DEBUG)

# Check metrics
metrics = enhanced_db_manager.get_metrics()
print(f"Total queries: {metrics['total_queries']}")
print(f"Average response time: {metrics['average_response_time']}")
```

## Migration Guide

### From Legacy System

1. **Gradual Migration**: Enable enhanced system alongside legacy
2. **Data Migration**: Use ETL pipelines to migrate existing data
3. **Feature Flags**: Gradually enable new features
4. **Monitoring**: Monitor performance during transition

### Database Migrations

```python
# Create migration pipeline
migration_pipeline = PipelineConfig(
    name="migrate_legacy_data",
    source_type="database",
    source_config={"database": "legacy", "query": "SELECT * FROM old_table"},
    target_type="database", 
    target_config={"database": "new", "table": "new_table"}
)
```

## Future Enhancements

- **Vector Databases**: Support for AI/ML embeddings
- **Graph Databases**: Neo4j integration for relationship data
- **Stream Processing**: Apache Kafka integration
- **Data Mesh**: Distributed data architecture
- **Real-time Analytics**: Apache Pinot integration
- **Multi-Cloud**: Support for multiple cloud providers
