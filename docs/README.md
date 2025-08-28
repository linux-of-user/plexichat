# PlexiChat

**Government-Level Secure Communication Platform**

PlexiChat is a production-ready, enterprise-grade secure communication platform designed for organizations requiring the highest levels of security, performance, and reliability. Built with modern Python architecture and optimized for microsecond-level response times, PlexiChat delivers government-level security with enterprise scalability.

## 🚀 Key Features

### Security & Protection
- **Web Application Firewall (WAF)** - Advanced threat detection and prevention
- **Multi-layer Security** - CSRF protection, XSS prevention, SQL injection blocking
- **End-to-End Encryption** - Military-grade cryptographic protection
- **IP Reputation Filtering** - Real-time threat intelligence integration
- **Rate Limiting & DDoS Protection** - Integrated protection against abuse

### Performance & Scalability
- **Microsecond Optimization** - Sub-millisecond response times for 10K+ requests/minute
- **Multi-Tier Caching** - L1 (memory), L2 (Redis), L3 (Memcached) caching layers
- **Dynamic Scaling** - Automatic resource adjustment under load
- **Async Architecture** - Non-blocking I/O for maximum throughput

### Backup & Recovery
- **1MB Shard System** - Efficient data segmentation for optimal backup performance
- **Multi-Cloud Support** - AWS S3, Google Cloud Storage, Azure Blob Storage
- **Encrypted Backups** - AES-256 encryption for data at rest
- **Automated Recovery** - Point-in-time restoration capabilities

### Communication Features
- **Real-Time Messaging** - WebSocket-based instant communication
- **Dual Interface** - Both CLI and GUI interfaces available
- **Professional Logging** - Comprehensive audit trails and compliance logging
- **Plugin System** - Extensible architecture for custom integrations

## 📋 Requirements

### System Requirements
- **Python**: 3.11+ (recommended 3.12)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB available space
- **Network**: Stable internet connection for cloud features

### Supported Platforms
- **Linux**: Ubuntu 20.04+, CentOS 8+, Debian 11+
- **Windows**: Windows 10/11, Windows Server 2019+
- **macOS**: macOS 11+ (Big Sur and later)

## 🛠️ Installation

### Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/plexichat.git
cd plexichat

# Run the automated installer
python run.py setup --level full

# Start the application
python run.py start
```

### Manual Installation

#### 1. Install Dependencies

**Minimal Installation** (Core features only):
```bash
pip install -r requirements.txt --constraint minimal
```

**Full Installation** (All features):
```bash
pip install -r requirements.txt
```

**Development Installation** (With dev tools):
```bash
pip install -r requirements.txt --constraint development
```

#### 2. Platform-Specific Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3-dev build-essential libssl-dev libffi-dev \
                 libjpeg-dev libpng-dev libfreetype6-dev redis-server \
                 postgresql postgresql-contrib nginx
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install python3-devel gcc gcc-c++ openssl-devel libffi-devel \
                 libjpeg-turbo-devel libpng-devel freetype-devel \
                 redis postgresql postgresql-server nginx
```

**macOS (with Homebrew):**
```bash
brew install python3 openssl libffi jpeg libpng freetype redis postgresql nginx
```

**Windows (with Chocolatey):**
```bash
choco install python3 git redis-64 postgresql nginx visualstudio2022buildtools
```

#### 3. Database Setup

**PostgreSQL (Recommended for Production):**
```bash
# Create database and user
sudo -u postgres createdb plexichat
sudo -u postgres createuser plexichat_user
sudo -u postgres psql -c "ALTER USER plexichat_user PASSWORD 'your_secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE plexichat TO plexichat_user;"
```

**SQLite (Development):**
```bash
# No additional setup required - database file created automatically
```

## ⚙️ Configuration

### Environment Configuration

Create a `.env` file in the project root:

```bash
# === CORE CONFIGURATION ===
PLEXICHAT_ENVIRONMENT=production  # or development
PLEXICHAT_SECRET_KEY=your-super-secret-key-here
PLEXICHAT_DEBUG=false

# === DATABASE CONFIGURATION ===
DATABASE_URL=postgresql://plexichat_user:password@localhost/plexichat
# For SQLite: DATABASE_URL=sqlite:///./plexichat.db

# === SECURITY CONFIGURATION ===
# WAF Settings
WAF_ENABLED=true
WAF_BLOCK_SQL_INJECTION=true
WAF_BLOCK_XSS=true
WAF_MAX_PAYLOAD_MB=4
WAF_IP_REPUTATION_ENABLED=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
RATE_LIMIT_BURST_LIMIT=100

# === NETWORK CONFIGURATION ===
HOST=0.0.0.0
PORT=8000
SSL_ENABLED=true
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
MAX_REQUEST_SIZE_MB=4

# CORS Settings
CORS_ORIGINS=["https://yourdomain.com"]

# === CACHING CONFIGURATION ===
CACHE_ENABLED=true
CACHE_L1_MAX_ITEMS=10000
CACHE_L1_MEMORY_SIZE_MB=256
CACHE_DEFAULT_TTL_SECONDS=3600

# Redis (L2 Cache)
REDIS_ENABLED=true
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=your_redis_password

# Memcached (L3 Cache)
MEMCACHED_ENABLED=false
MEMCACHED_HOST=localhost
MEMCACHED_PORT=11211

# === BACKUP CONFIGURATION ===
BACKUP_ENABLED=true
BACKUP_SHARD_SIZE_MB=1
BACKUP_ENCRYPTION_ENABLED=true
BACKUP_ENCRYPTION_KEY=your-backup-encryption-key

# Cloud Storage (choose one or more)
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_S3_BUCKET=your-backup-bucket
AWS_S3_REGION=us-east-1

GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_BUCKET=your-backup-bucket
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

AZURE_STORAGE_ACCOUNT=your_storage_account
AZURE_STORAGE_KEY=your_storage_key
AZURE_CONTAINER_NAME=your-backup-container

# === LOGGING CONFIGURATION ===
LOG_LEVEL=INFO
LOG_FORMAT=structured
LOG_FILE_ENABLED=true
LOG_FILE_PATH=./logs/plexichat.log
LOG_ROTATION_SIZE_MB=100
LOG_RETENTION_DAYS=30

# === MONITORING CONFIGURATION ===
METRICS_ENABLED=true
PROMETHEUS_PORT=9090
SENTRY_DSN=your_sentry_dsn
OPENTELEMETRY_ENABLED=true
```

### Advanced Configuration

For advanced configuration options, edit `config/settings.yaml`:

```yaml
# Advanced PlexiChat Configuration
system:
  environment: production
  debug: false
  timezone: UTC
  max_workers: 4

security:
  waf:
    enabled: true
    block_sql_injection: true
    block_xss: true
    max_payload_bytes: 4194304  # 4MB
    ip_reputation_blocklist: []
    rate_limit_integration: true
    threat_intelligence_enabled: true
  
  encryption:
    algorithm: AES-256-GCM
    key_rotation_days: 90
    backup_encryption: true
  
  authentication:
    session_timeout_minutes: 30
    max_login_attempts: 5
    lockout_duration_minutes: 15
    require_2fa: true

performance:
  microsecond_optimization: true
  response_compression: true
  static_file_caching: true
  database_connection_pool: 20
  
backup:
  shard_size_mb: 1
  compression_enabled: true
  encryption_enabled: true
  retention_days: 365
  cloud_providers:
    - aws_s3
    - google_cloud
    - azure_blob

monitoring:
  metrics_collection: true
  performance_tracking: true
  error_reporting: true
  audit_logging: true
```

## 🚀 Running PlexiChat

### Production Deployment

```bash
# Start with production configuration
python run.py start --environment production --workers 4

# Or use the production script
./scripts/start_production.sh
```

### Development Mode

```bash
# Start in development mode with auto-reload
python run.py start --environment development --reload

# Or use the development script
./scripts/start_development.sh
```

### Docker Deployment

```bash
# Build the Docker image
docker build -t plexichat:latest .

# Run with Docker Compose
docker-compose up -d

# Scale for high availability
docker-compose up -d --scale plexichat=3
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=plexichat

# Scale deployment
kubectl scale deployment plexichat --replicas=5
```

## 🔧 Usage

### Web Interface

Access the web interface at:
- **HTTP**: `http://localhost:8000`
- **HTTPS**: `https://localhost:8443` (if SSL enabled)

### API Endpoints

#### Authentication
```bash
# Register a new user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "email": "user@example.com", "password": "secure_password"}'

# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "secure_password"}'
```

#### Messaging
```bash
# Send a message
curl -X POST http://localhost:8000/api/messages/send \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipient": "user2", "content": "Hello, World!", "encrypted": true}'

# Get messages
curl -X GET http://localhost:8000/api/messages/inbox \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### System Status
```bash
# Health check
curl http://localhost:8000/health

# System metrics
curl http://localhost:8000/metrics

# WAF status
curl http://localhost:8000/api/security/waf/status
```

### CLI Interface

```bash
# Start CLI mode
python run.py cli

# Send a message via CLI
python run.py cli send --to user2 --message "Hello from CLI"

# Check system status
python run.py cli status

# Backup operations
python run.py cli backup create --name "daily_backup"
python run.py cli backup restore --name "daily_backup"
```

## 🛡️ Security Features

### Web Application Firewall (WAF)

PlexiChat includes a comprehensive WAF that protects against:

- **SQL Injection**: Pattern-based detection and blocking
- **Cross-Site Scripting (XSS)**: Content sanitization and validation
- **Malicious Payloads**: Size limits and content inspection
- **IP Reputation**: Real-time threat intelligence integration
- **Rate Limiting**: Automatic abuse prevention

For detailed WAF configuration and rule management, see [WAF Rules Documentation](WAF_RULES.md).

### Security Headers

All responses include security headers:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

### Encryption

- **Data in Transit**: TLS 1.3 encryption
- **Data at Rest**: AES-256-GCM encryption
- **Message Encryption**: End-to-end encryption for all communications
- **Backup Encryption**: Encrypted backup shards with separate keys

## 💾 Backup System

### Automated Backups

PlexiChat uses a sophisticated 1MB shard-based backup system:

```bash
# Create manual backup
python run.py backup create --name "manual_backup_$(date +%Y%m%d)"

# Schedule automated backups
python run.py backup schedule --frequency daily --time "02:00"

# List available backups
python run.py backup list

# Restore from backup
python run.py backup restore --name "backup_20240101" --confirm
```

### Cloud Storage Integration

Configure multiple cloud providers for redundancy:

```yaml
backup:
  cloud_providers:
    aws_s3:
      bucket: "plexichat-backups"
      region: "us-east-1"
      encryption: true
    
    google_cloud:
      project: "your-project"
      bucket: "plexichat-backups-gcs"
      encryption: true
    
    azure_blob:
      account: "your-storage-account"
      container: "plexichat-backups"
      encryption: true
```

## 📊 Monitoring & Performance

### Metrics Collection

PlexiChat provides comprehensive metrics:

- **Response Times**: Microsecond-level timing
- **Request Rates**: Requests per second/minute
- **Error Rates**: 4xx/5xx response tracking
- **Cache Performance**: Hit/miss ratios across all cache tiers
- **Security Events**: WAF blocks, rate limit triggers

### Prometheus Integration

```bash
# Access Prometheus metrics
curl http://localhost:9090/metrics

# Example metrics
plexichat_requests_total{method="GET",endpoint="/api/messages"}
plexichat_response_time_microseconds{endpoint="/api/auth/login"}
plexichat_cache_hits_total{tier="L1"}
plexichat_waf_blocks_total{rule="sql_injection"}
```

### Performance Optimization

PlexiChat is optimized for high-performance scenarios:

- **10K+ requests/minute** capability
- **Sub-millisecond** response times for cached content
- **Automatic scaling** under load
- **Connection pooling** for database efficiency
- **Compression** for reduced bandwidth usage

## 🔧 Troubleshooting

### Common Issues

#### Installation Problems

**Issue**: `pip install` fails with compilation errors
```bash
# Solution: Install system dependencies first
sudo apt install python3-dev build-essential  # Ubuntu/Debian
sudo dnf install python3-devel gcc gcc-c++    # CentOS/RHEL
```

**Issue**: Redis connection fails
```bash
# Check Redis status
sudo systemctl status redis
sudo systemctl start redis

# Test connection
redis-cli ping
```

#### Runtime Issues

**Issue**: High memory usage
```bash
# Check cache configuration
python run.py config show caching

# Reduce cache sizes if needed
export CACHE_L1_MEMORY_SIZE_MB=128
```

**Issue**: Slow response times
```bash
# Enable performance monitoring
export METRICS_ENABLED=true

# Check database connections
python run.py db status

# Optimize database if needed
python run.py db optimize
```

#### Security Issues

**Issue**: WAF blocking legitimate requests
```bash
# Check WAF logs
tail -f logs/waf.log

# Adjust WAF rules if needed
python run.py waf whitelist --ip 192.168.1.100
```

**Issue**: SSL certificate errors
```bash
# Verify certificate files
openssl x509 -in /path/to/cert.pem -text -noout

# Generate self-signed certificate for testing
python run.py ssl generate-cert --domain localhost
```

### Log Analysis

PlexiChat provides structured logging for easy troubleshooting:

```bash
# View application logs
tail -f logs/plexichat.log

# Filter by log level
grep "ERROR" logs/plexichat.log

# View security events
grep "WAF" logs/plexichat.log

# Performance analysis
grep "PERF" logs/plexichat.log
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
# Start in debug mode
python run.py start --debug

# Or set environment variable
export PLEXICHAT_DEBUG=true
python run.py start
```

### Security Incident Response

For security incidents and emergency response procedures, refer to the [Incident Response Guide](INCIDENT_RESPONSE.md), which provides comprehensive procedures for handling security events, escalation paths, and recovery processes.

## 📚 Documentation System

PlexiChat features a comprehensive automated documentation system built with MkDocs and Material theme, providing:

### Features
- **Automated API Documentation** - Generated from OpenAPI schema
- **Static Site Generation** - Fast, searchable documentation
- **Continuous Integration** - Automated builds and deployment
- **Quality Assurance** - Link validation and content linting
- **Multi-format Output** - HTML and PDF documentation

### Building Documentation

```bash
# Install documentation dependencies
make docs-install

# Build documentation locally
make docs

# Serve documentation for development
make docs-serve
# Access at http://localhost:8000

# Run documentation quality checks
make docs-lint

# Clean generated files
make docs-clean
```

### Documentation Structure

The documentation is organized into the following sections:

- **[Getting Started](GETTING_STARTED.md)** - Installation and quick start guide
- **[Architecture](ARCHITECTURE.md)** - System design and components
- **[Security](SECURITY.md)** - Security policies and procedures
- **[WAF Rules](WAF_RULES.md)** - Web Application Firewall configuration
- **[Incident Response](INCIDENT_RESPONSE.md)** - Security incident procedures
- **[API Reference](API.md)** - API documentation and examples
- **[Deployment](DEPLOYMENT.md)** - Installation and configuration guide
- **[Backup System](BACKUP_SYSTEM.md)** - Data protection procedures
- **[Plugin Development](PLUGIN_DEVELOPMENT.md)** - Extension development guide
- **[Documentation Maintenance](MAINTAINING_DOCUMENTATION.md)** - Documentation contribution guide

### Contributing to Documentation

We welcome contributions to improve our documentation! To contribute:

1. **Follow the Documentation Standards** - See [Documentation Maintenance Guide](MAINTAINING_DOCUMENTATION.md)
2. **Test Your Changes** - Run `make docs-serve` to preview changes locally
3. **Validate Quality** - Run `make docs-lint` to check for issues
4. **Submit Pull Request** - Include documentation changes in your PR

For detailed guidelines on maintaining and contributing to documentation, see the [Documentation Maintenance Guide](MAINTAINING_DOCUMENTATION.md).

## 🤝 Contributing

We welcome contributions to PlexiChat! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/plexichat.git
cd plexichat

# Install development dependencies
python run.py setup --level development

# Run tests
python -m pytest tests/

# Run linting
python -m black src/
python -m isort src/
python -m flake8 src/
```

### Testing

```bash
# Run all tests
python -m pytest

# Run specific test categories
python -m pytest tests/test_security/
python -m pytest tests/test_performance/
python -m pytest tests/test_backup/

# Run with coverage
python -m pytest --cov=plexichat --cov-report=html
```

## 📄 License

PlexiChat is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🆘 Support

### Documentation
- [Getting Started Guide](GETTING_STARTED.md) - Quick start and installation
- [Architecture Guide](ARCHITECTURE.md) - System design and components
- [Security Documentation](SECURITY.md) - Security policies and procedures
- [WAF Rules Documentation](WAF_RULES.md) - Web Application Firewall configuration
- [Incident Response Guide](INCIDENT_RESPONSE.md) - Security incident procedures
- [API Reference](API.md) - API documentation and examples
- [Deployment Guide](DEPLOYMENT.md) - Installation and configuration
- [Backup System Guide](BACKUP_SYSTEM.md) - Data protection procedures
- [Plugin Development Guide](PLUGIN_DEVELOPMENT.md) - Extension development
- [Documentation Maintenance](MAINTAINING_DOCUMENTATION.md) - Documentation contribution guide

### Community
- **Issues**: [GitHub Issues](https://github.com/your-org/plexichat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/plexichat/discussions)
- **Security**: [Security Policy](SECURITY.md)
- **Documentation**: [Documentation Site](https://plexichat.github.io/docs/) (Auto-generated)

### Commercial Support
For enterprise support, training, and custom development, contact us at enterprise@plexichat.com.

---

**PlexiChat** - Government-Level Secure Communication Platform
Built with ❤️ for organizations that demand the highest levels of security and performance.
