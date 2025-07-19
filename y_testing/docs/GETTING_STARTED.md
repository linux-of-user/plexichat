# Getting Started with PlexiChat

This comprehensive guide will help you set up, configure, and start using PlexiChat in your environment.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Initial Configuration](#initial-configuration)
4. [First Run Setup](#first-run-setup)
5. [Basic Usage](#basic-usage)
6. [Configuration Options](#configuration-options)
7. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Operating System**: Linux (Ubuntu 18.04+), macOS (10.15+), Windows 10+
- **Python**: 3.8 or higher
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 5GB free space minimum
- **Network**: Internet connection for initial setup and AI features

### Recommended Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS (12+), Windows 11
- **Python**: 3.10 or higher
- **Memory**: 8GB RAM or more
- **Storage**: 20GB free space
- **Database**: PostgreSQL 12+ or MySQL 8.0+
- **Cache**: Redis 6.0+
- **CPU**: Multi-core processor (4+ cores recommended)

### Dependencies

#### Required
- **FastAPI**: Web framework
- **SQLAlchemy**: Database ORM
- **Pydantic**: Data validation
- **Cryptography**: Security and encryption
- **WebSockets**: Real-time communication

#### Optional
- **PostgreSQL**: Production database (recommended)
- **Redis**: Caching and session storage
- **Docker**: Containerized deployment
- **Node.js**: Web interface development

## Installation Methods

### Method 1: Standard Python Installation

```bash
# Clone the repository
git clone https://github.com/linux-of-user/plexichat.git
cd plexichat

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install PlexiChat in development mode
pip install -e .
```

### Method 2: Docker Installation

```bash
# Clone the repository
git clone https://github.com/linux-of-user/plexichat.git
cd plexichat

# Using Docker Compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t plexichat .
docker run -p 8000:8000 -v $(pwd)/data:/app/data plexichat
```

### Method 3: Production Installation

```bash
# For production deployment
pip install plexichat

# Or using pipx for isolated installation
pipx install plexichat
```

## Initial Configuration

### 1. Environment Setup

Create a `.env` file in your project root:

```bash
# Core Configuration
PLEXICHAT_ENV=development
PLEXICHAT_SECRET_KEY=your-super-secret-key-here
PLEXICHAT_DEBUG=true

# Database Configuration
PLEXICHAT_DATABASE_URL=sqlite:///./plexichat.db
# For PostgreSQL: postgresql://user:password@localhost:5432/plexichat
# For MySQL: mysql://user:password@localhost:3306/plexichat

# Security Configuration
PLEXICHAT_ENCRYPTION_KEY=your-encryption-key-here
PLEXICHAT_JWT_SECRET=your-jwt-secret-here
PLEXICHAT_JWT_EXPIRE_MINUTES=30

# AI Configuration (optional)
OPENAI_API_KEY=your-openai-api-key
ANTHROPIC_API_KEY=your-anthropic-api-key
GOOGLE_AI_API_KEY=your-google-ai-api-key

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379/0

# Email Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

### 2. Database Setup

#### SQLite (Development)
```bash
# SQLite is used by default - no additional setup required
python -m plexichat db init
```

#### PostgreSQL (Recommended for Production)
```bash
# Install PostgreSQL and create database
sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian
# or
brew install postgresql  # macOS

# Create database and user
sudo -u postgres psql
CREATE DATABASE plexichat;
CREATE USER plexichat_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE plexichat TO plexichat_user;
\q

# Update .env file with PostgreSQL URL
PLEXICHAT_DATABASE_URL=postgresql://plexichat_user:your_password@localhost:5432/plexichat

# Initialize database
python -m plexichat db init
```

#### MySQL (Alternative)
```bash
# Install MySQL and create database
sudo apt-get install mysql-server  # Ubuntu/Debian
# or
brew install mysql  # macOS

# Create database and user
mysql -u root -p
CREATE DATABASE plexichat;
CREATE USER 'plexichat_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON plexichat.* TO 'plexichat_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Update .env file with MySQL URL
PLEXICHAT_DATABASE_URL=mysql://plexichat_user:your_password@localhost:3306/plexichat

# Initialize database
python -m plexichat db init
```

### 3. Redis Setup (Optional but Recommended)

```bash
# Install Redis
sudo apt-get install redis-server  # Ubuntu/Debian
# or
brew install redis  # macOS

# Start Redis service
sudo systemctl start redis-server  # Linux
# or
brew services start redis  # macOS

# Test Redis connection
redis-cli ping
# Should return: PONG
```

## First Run Setup

### 1. Initialize PlexiChat

```bash
# Run the setup wizard
python -m plexichat setup

# Or initialize manually
python -m plexichat init --admin-user admin --admin-email admin@example.com
```

### 2. Start the Server

```bash
# Development mode (with auto-reload)
python run.py --dev

# Production mode
python run.py

# With custom configuration
python run.py --config config/production.yaml

# With specific host and port
python run.py --host 0.0.0.0 --port 8080
```

### 3. Access the Web Interface

1. Open your browser and navigate to: `http://localhost:8000`
2. You should see the PlexiChat login page
3. Use the default admin credentials:
   - **Username**: `admin`
   - **Password**: `admin123`
4. **Important**: Change the default password immediately after first login

### 4. Complete the Setup Wizard

The setup wizard will guide you through:

1. **Admin Account Setup**: Change default credentials
2. **Security Configuration**: Set up encryption keys and security policies
3. **Database Configuration**: Verify database connection
4. **AI Integration**: Configure AI providers (optional)
5. **Email Settings**: Set up email notifications (optional)
6. **Backup Configuration**: Configure backup settings

## Basic Usage

### Web Interface

1. **Dashboard**: Overview of system status and recent activity
2. **Messages**: Send and receive messages in channels
3. **Files**: Upload, share, and manage files
4. **Users**: Manage user accounts and permissions
5. **Settings**: Configure system settings and preferences
6. **Admin Panel**: Administrative functions and system management

### Command Line Interface

```bash
# Show system status
plexichat status

# User management
plexichat user create username --email user@example.com
plexichat user list
plexichat user delete username

# Channel management
plexichat channel create general --description "General discussion"
plexichat channel list

# Backup operations
plexichat backup create
plexichat backup list
plexichat backup restore backup_id

# System maintenance
plexichat db migrate
plexichat cache clear
plexichat logs --tail 100

# Discover all available commands (including plugin commands)
plexichat --help

# Get help for a specific command or plugin
plexichat user --help
plexichat mega --help

# All CLI commands (including those from plugins like mega_cli) support --help for detailed usage and options.
# Example: List all mega_cli commands
plexichat mega --help
# Example: Get help for a specific mega_cli command
plexichat mega user create --help
```

Plugins can add their own CLI commands, which will appear in the help output. Use --help to discover and learn about all available commands.

### API Usage

```python
# Python SDK example
from plexichat import PlexiChatClient

# Initialize client
client = PlexiChatClient(
    base_url="http://localhost:8000",
    api_key="your-api-key"
)

# Send a message
response = client.messages.send(
    channel="general",
    content="Hello, PlexiChat!",
    user_id="user123"
)

# Upload a file
with open("document.pdf", "rb") as f:
    file_response = client.files.upload(
        file=f,
        filename="document.pdf",
        channel="general"
    )
```

## Configuration Options

### Core Settings

```yaml
# config/settings.yaml
app:
  name: "PlexiChat"
  version: "a.1.1-1"
  debug: false
  host: "0.0.0.0"
  port: 8000

security:
  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_hours: 24
  authentication:
    require_2fa: true
    session_timeout_minutes: 30
    max_failed_attempts: 3

database:
  url: "postgresql://user:pass@localhost:5432/plexichat"
  pool_size: 10
  max_overflow: 20
  echo: false

ai:
  providers:
    openai:
      enabled: true
      model: "gpt-4"
    anthropic:
      enabled: true
      model: "claude-3-sonnet"
```

### Environment Variables

All configuration can be overridden with environment variables:

```bash
# App configuration
export PLEXICHAT_APP_NAME="My PlexiChat"
export PLEXICHAT_APP_DEBUG=false
export PLEXICHAT_APP_HOST=0.0.0.0
export PLEXICHAT_APP_PORT=8000

# Security configuration
export PLEXICHAT_SECURITY_ENCRYPTION_ALGORITHM="AES-256-GCM"
export PLEXICHAT_SECURITY_AUTHENTICATION_REQUIRE_2FA=true

# Database configuration
export PLEXICHAT_DATABASE_URL="postgresql://user:pass@localhost:5432/plexichat"
export PLEXICHAT_DATABASE_POOL_SIZE=10
```

## Troubleshooting

### Common Issues

#### 1. Database Connection Errors

```bash
# Check database status
python -m plexichat db status

# Test database connection
python -m plexichat db test-connection

# Reinitialize database
python -m plexichat db reset --confirm
```

#### 2. Permission Errors

```bash
# Fix file permissions
chmod +x run.py
chmod -R 755 data/

# Check user permissions
python -m plexichat user check-permissions admin
```

#### 3. Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000  # Linux/macOS
netstat -ano | findstr :8000  # Windows

# Kill process or use different port
python run.py --port 8080
```

#### 4. Missing Dependencies

```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check for missing packages
python -m plexichat check-dependencies
```

### Getting Help

1. **Documentation**: Check the [docs/](../docs/) directory
2. **Logs**: Check application logs in `logs/` directory
3. **Debug Mode**: Run with `--debug` flag for verbose output
4. **Community**: Visit our [GitHub Discussions](https://github.com/linux-of-user/plexichat/discussions)
5. **Issues**: Report bugs on [GitHub Issues](https://github.com/linux-of-user/plexichat/issues)

### Next Steps

- [Architecture Overview](ARCHITECTURE.md) - Understand the system design
- [Security Guide](SECURITY.md) - Learn about security features
- [API Reference](API.md) - Explore the API endpoints
- [Deployment Guide](DEPLOYMENT.md) - Deploy to production
- [Plugin Development](PLUGINS.md) - Create custom plugins

---

**Congratulations!** You now have PlexiChat up and running. Explore the features and customize it to your needs.
