# PlexiChat Troubleshooting Guide

Comprehensive troubleshooting guide for common issues, error resolution, and system diagnostics.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Database Problems](#database-problems)
4. [Authentication Issues](#authentication-issues)
5. [Performance Problems](#performance-problems)
6. [Security Issues](#security-issues)
7. [Network & Connectivity](#network--connectivity)
8. [Plugin Issues](#plugin-issues)
9. [Logging & Monitoring](#logging--monitoring)
10. [Getting Help](#getting-help)

## Quick Diagnostics

### System Health Check

```bash
# Check overall system status
python -m plexichat status

# Detailed health check
python -m plexichat health --verbose

# Check specific components
python -m plexichat health --component database
python -m plexichat health --component redis
python -m plexichat health --component security
```

### Common Commands

```bash
# View logs
python -m plexichat logs --tail 100
python -m plexichat logs --level error
python -m plexichat logs --follow

# Check configuration
python -m plexichat config --validate
python -m plexichat config --show

# Test database connection
python -m plexichat db test-connection

# Check permissions
python -m plexichat permissions --user admin
```

### Environment Information

```bash
# System information
python -m plexichat info

# Dependencies check
python -m plexichat check-deps

# Configuration summary
python -m plexichat config --summary
```

## Installation Issues

### Python Version Compatibility

**Problem**: Python version not supported
```
Error: PlexiChat requires Python 3.8 or higher
```

**Solution**:
```bash
# Check Python version
python --version

# Install correct Python version (Ubuntu/Debian)
sudo apt update
sudo apt install python3.10 python3.10-pip python3.10-venv

# Create virtual environment with correct Python
python3.10 -m venv venv
source venv/bin/activate
```

### Dependency Installation Failures

**Problem**: Package installation fails
```
ERROR: Failed building wheel for cryptography
```

**Solution**:
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Install system dependencies (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel libffi-devel python3-devel

# Upgrade pip and setuptools
pip install --upgrade pip setuptools wheel

# Install with verbose output
pip install -r requirements.txt -v
```

### Permission Errors

**Problem**: Permission denied during installation
```
PermissionError: [Errno 13] Permission denied
```

**Solution**:
```bash
# Use virtual environment (recommended)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Or install with --user flag
pip install --user -r requirements.txt

# Fix file permissions
sudo chown -R $USER:$USER /path/to/plexichat
chmod -R 755 /path/to/plexichat
```

### Docker Issues

**Problem**: Docker container fails to start
```
Error: Cannot connect to the Docker daemon
```

**Solution**:
```bash
# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Check Docker status
docker --version
docker ps

# Rebuild container
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Database Problems

### Connection Failures

**Problem**: Cannot connect to database
```
sqlalchemy.exc.OperationalError: (psycopg2.OperationalError) could not connect to server
```

**Solution**:
```bash
# Check database status
sudo systemctl status postgresql

# Start database service
sudo systemctl start postgresql

# Test connection manually
psql -h localhost -U plexichat -d plexichat

# Check connection string
python -c "
import os
from sqlalchemy import create_engine
engine = create_engine(os.getenv('PLEXICHAT_DATABASE_URL'))
print('Connection successful!')
"
```

### Migration Issues

**Problem**: Database migration fails
```
alembic.util.exc.CommandError: Can't locate revision identified by 'abc123'
```

**Solution**:
```bash
# Check migration status
python -m plexichat db current

# Reset migrations (CAUTION: This will lose data)
python -m plexichat db reset --confirm

# Manual migration
python -m plexichat db upgrade head

# Downgrade and retry
python -m plexichat db downgrade -1
python -m plexichat db upgrade head
```

### Database Corruption

**Problem**: Database corruption detected
```
ERROR: database corruption detected
```

**Solution**:
```bash
# Stop PlexiChat
sudo systemctl stop plexichat

# Backup current database
pg_dump plexichat > backup_$(date +%Y%m%d_%H%M%S).sql

# Check database integrity
python -m plexichat db check-integrity

# Restore from backup
python -m plexichat backup restore --latest

# If no backup available, reinitialize (CAUTION: Data loss)
python -m plexichat db reset --confirm
python -m plexichat db init
```

### Performance Issues

**Problem**: Slow database queries
```
WARNING: Query took 5.2 seconds to execute
```

**Solution**:
```bash
# Analyze slow queries
python -m plexichat db analyze-slow-queries

# Update database statistics
python -m plexichat db analyze

# Rebuild indexes
python -m plexichat db reindex

# Check database size
python -m plexichat db size

# Vacuum database (PostgreSQL)
python -m plexichat db vacuum
```

## Authentication Issues

### Login Failures

**Problem**: Cannot login with correct credentials
```
Error: Invalid username or password
```

**Solution**:
```bash
# Check user exists
python -m plexichat user list | grep username

# Reset password
python -m plexichat user reset-password username

# Check account status
python -m plexichat user info username

# Unlock account if locked
python -m plexichat user unlock username

# Check authentication logs
python -m plexichat logs --filter auth --level error
```

### JWT Token Issues

**Problem**: JWT token validation fails
```
Error: Token has expired
```

**Solution**:
```bash
# Check JWT configuration
python -m plexichat config --show | grep JWT

# Regenerate JWT secret (will invalidate all tokens)
python -m plexichat auth regenerate-jwt-secret

# Check token expiration settings
python -c "
import os
print(f'JWT Expire Minutes: {os.getenv(\"PLEXICHAT_JWT_EXPIRE_MINUTES\", 30)}')
"

# Clear all sessions
python -m plexichat auth clear-sessions
```

### MFA Problems

**Problem**: MFA codes not working
```
Error: Invalid MFA code
```

**Solution**:
```bash
# Check time synchronization
sudo ntpdate -s time.nist.gov

# Reset MFA for user
python -m plexichat user reset-mfa username

# Generate backup codes
python -m plexichat user generate-backup-codes username

# Check MFA configuration
python -m plexichat config --show | grep MFA
```

### OAuth Issues

**Problem**: OAuth authentication fails
```
Error: OAuth provider returned error
```

**Solution**:
```bash
# Check OAuth configuration
python -m plexichat config --show | grep OAUTH

# Test OAuth endpoints
curl -I https://login.microsoftonline.com/common/oauth2/v2.0/authorize

# Verify redirect URLs
python -m plexichat oauth check-config

# Clear OAuth cache
python -m plexichat oauth clear-cache
```

## Performance Problems

### High Memory Usage

**Problem**: PlexiChat consuming too much memory
```
WARNING: Memory usage at 95%
```

**Solution**:
```bash
# Check memory usage
python -m plexichat status --memory

# Analyze memory usage
python -m plexichat debug memory-profile

# Restart with memory limits
docker run --memory=4g plexichat/plexichat

# Clear caches
python -m plexichat cache clear

# Optimize database connections
# Edit configuration:
PLEXICHAT_DATABASE_POOL_SIZE=5
PLEXICHAT_DATABASE_MAX_OVERFLOW=10
```

### High CPU Usage

**Problem**: High CPU utilization
```
WARNING: CPU usage at 90%
```

**Solution**:
```bash
# Check CPU usage by component
python -m plexichat status --cpu

# Profile CPU usage
python -m plexichat debug cpu-profile --duration 60

# Check for infinite loops
python -m plexichat debug stack-trace

# Optimize AI processing
# Disable AI features temporarily:
PLEXICHAT_AI_ENABLED=false

# Scale horizontally
docker-compose scale plexichat=3
```

### Slow Response Times

**Problem**: API responses are slow
```
WARNING: Average response time: 2.5 seconds
```

**Solution**:
```bash
# Check response times
python -m plexichat status --performance

# Enable query logging
PLEXICHAT_DATABASE_ECHO=true

# Optimize database
python -m plexichat db optimize

# Check network latency
ping your-database-host

# Enable caching
PLEXICHAT_REDIS_ENABLED=true
PLEXICHAT_CACHE_TTL=300
```

### WebSocket Issues

**Problem**: Real-time features not working
```
Error: WebSocket connection failed
```

**Solution**:
```bash
# Check WebSocket endpoint
curl -i -N -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: test" \
  http://localhost:8000/ws

# Check proxy configuration (Nginx)
# Add to nginx.conf:
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";

# Check firewall rules
sudo ufw status
sudo ufw allow 8000/tcp
```

## Security Issues

### SSL/TLS Problems

**Problem**: SSL certificate issues
```
Error: SSL certificate verification failed
```

**Solution**:
```bash
# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Test SSL configuration
openssl s_client -connect your-domain.com:443

# Renew Let's Encrypt certificate
certbot renew --dry-run

# Check certificate permissions
ls -la /etc/letsencrypt/live/your-domain.com/

# Update certificate paths
PLEXICHAT_SSL_CERT_PATH=/etc/letsencrypt/live/your-domain.com/fullchain.pem
PLEXICHAT_SSL_KEY_PATH=/etc/letsencrypt/live/your-domain.com/privkey.pem
```

### Security Alerts

**Problem**: Security threats detected
```
CRITICAL: Multiple failed login attempts detected
```

**Solution**:
```bash
# Check security logs
python -m plexichat logs --filter security --level warning

# Review failed login attempts
python -m plexichat security failed-logins --last 24h

# Block suspicious IPs
python -m plexichat security block-ip 192.168.1.100

# Enable additional security measures
PLEXICHAT_SECURITY_STRICT_MODE=true
PLEXICHAT_RATE_LIMIT_ENABLED=true

# Force password reset for all users
python -m plexichat security force-password-reset
```

### Encryption Issues

**Problem**: Encryption/decryption failures
```
Error: Failed to decrypt data
```

**Solution**:
```bash
# Check encryption configuration
python -m plexichat security check-encryption

# Rotate encryption keys
python -m plexichat security rotate-keys

# Verify key integrity
python -m plexichat security verify-keys

# Re-encrypt data with new keys
python -m plexichat security re-encrypt-data
```

## Network & Connectivity

### Port Binding Issues

**Problem**: Cannot bind to port
```
Error: [Errno 98] Address already in use
```

**Solution**:
```bash
# Find process using port
sudo lsof -i :8000
sudo netstat -tulpn | grep :8000

# Kill process using port
sudo kill -9 <PID>

# Use different port
python run.py --port 8080

# Check firewall rules
sudo ufw status
sudo ufw allow 8000/tcp
```

### Proxy Configuration

**Problem**: Reverse proxy not working
```
Error: 502 Bad Gateway
```

**Solution**:
```bash
# Check Nginx configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx

# Check upstream servers
curl -I http://localhost:8000/health

# Example Nginx configuration:
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### DNS Issues

**Problem**: Domain resolution problems
```
Error: Name or service not known
```

**Solution**:
```bash
# Test DNS resolution
nslookup your-domain.com
dig your-domain.com

# Check /etc/hosts
cat /etc/hosts

# Flush DNS cache
sudo systemctl restart systemd-resolved

# Use public DNS servers
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

## Plugin Issues

### Plugin Loading Failures

**Problem**: Plugin fails to load
```
Error: Plugin 'my-plugin' failed to load
```

**Solution**:
```bash
# Check plugin status
python -m plexichat plugins list

# View plugin logs
python -m plexichat plugins logs my-plugin

# Validate plugin
python -m plexichat plugins validate my-plugin

# Reinstall plugin
python -m plexichat plugins uninstall my-plugin
python -m plexichat plugins install my-plugin

# Check plugin dependencies
python -m plexichat plugins check-deps my-plugin
```

### Plugin Permission Issues

**Problem**: Plugin permission denied
```
Error: Plugin does not have required permission
```

**Solution**:
```bash
# Check plugin permissions
python -m plexichat plugins permissions my-plugin

# Grant permissions
python -m plexichat plugins grant-permission my-plugin messages.write

# Review plugin manifest
cat plugins/my-plugin/plugin.yaml

# Reset plugin permissions
python -m plexichat plugins reset-permissions my-plugin
```

## Logging & Monitoring

### Log Analysis

```bash
# View recent errors
python -m plexichat logs --level error --tail 50

# Search logs
python -m plexichat logs --search "database"

# Export logs
python -m plexichat logs --export --format json > logs.json

# Monitor logs in real-time
python -m plexichat logs --follow --level warning
```

### Performance Monitoring

```bash
# System metrics
python -m plexichat metrics --system

# Application metrics
python -m plexichat metrics --app

# Database metrics
python -m plexichat metrics --database

# Export metrics
python -m plexichat metrics --export prometheus
```

### Debug Mode

```bash
# Enable debug mode
PLEXICHAT_DEBUG=true python run.py

# Debug specific component
PLEXICHAT_LOG_LEVEL=DEBUG python run.py

# Generate debug report
python -m plexichat debug generate-report

# Memory profiling
python -m plexichat debug memory-profile --output profile.html
```

## Getting Help

### Community Support

1. **GitHub Issues**: [Report bugs and request features](https://github.com/linux-of-user/plexichat/issues)
2. **GitHub Discussions**: [Community discussions and Q&A](https://github.com/linux-of-user/plexichat/discussions)
3. **Documentation**: [Complete documentation](https://docs.plexichat.com)

### Professional Support

1. **Email Support**: support@plexichat.com
2. **Security Issues**: security@plexichat.com
3. **Enterprise Support**: enterprise@plexichat.com

### Before Reporting Issues

1. **Check logs**: Review error logs for specific error messages
2. **Search existing issues**: Check if the issue has been reported
3. **Minimal reproduction**: Create a minimal example that reproduces the issue
4. **Environment details**: Include system information and configuration

### Issue Report Template

```markdown
## Issue Description
Brief description of the issue

## Environment
- PlexiChat Version: a.1.1-1
- Python Version: 3.10.0
- Operating System: Ubuntu 20.04
- Database: PostgreSQL 14
- Deployment: Docker

## Steps to Reproduce
1. Step one
2. Step two
3. Step three

## Expected Behavior
What you expected to happen

## Actual Behavior
What actually happened

## Error Messages
```
Paste error messages here
```

## Additional Context
Any additional information that might be helpful
```

---

This troubleshooting guide covers the most common issues. If you encounter a problem not covered here, please check the documentation or reach out to the community for help.
