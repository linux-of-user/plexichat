# PlexiChat - Advanced AI-Powered Chat Platform

PlexiChat is a next-generation, enterprise-grade chat and collaboration platform designed for advanced AI integration, security, and scalability. Built with a modular architecture, it provides comprehensive communication solutions with extensive customization capabilities.

## 🌟 Overview

PlexiChat combines the power of modern AI with robust infrastructure to deliver:

- **AI-First Design**: Native integration with multiple AI providers (OpenAI, Anthropic, local models)
- **Enterprise Security**: Government-grade authentication, encryption, and audit systems
- **Modular Architecture**: Cleanly separated core, features, plugins, and interfaces
- **Multi-Interface Support**: Web UI, CLI, and Desktop GUI for complete control
- **Scalable Infrastructure**: Built-in clustering, load balancing, and distributed systems
- **Extensible Plugin System**: Rich ecosystem with sandboxed plugin execution
- **Advanced Analytics**: Real-time monitoring, performance tracking, and business intelligence

## 🚀 Key Features

### 🤖 AI & Intelligence
- **Multi-Provider AI Support**: OpenAI, Anthropic Claude, local LLMs, custom models
- **Intelligent Moderation**: AI-powered content filtering and safety systems
- **Smart Recommendations**: Context-aware suggestions and automated responses
- **Semantic Search**: Advanced search capabilities across all content
- **Translation Engine**: Real-time multi-language communication
- **Sentiment Analysis**: Automated mood and tone detection

### 🔒 Security & Authentication
- **Zero-Trust Architecture**: Comprehensive security model with continuous verification
- **Multi-Factor Authentication**: TOTP, biometric, hardware keys, government ID
- **End-to-End Encryption**: Military-grade encryption for all communications
- **Advanced Audit Logging**: Complete activity tracking and compliance reporting
- **Role-Based Access Control**: Granular permissions and security policies
- **Government-Grade Compliance**: FIPS 140-2, Common Criteria, SOC 2 Type II

### 🏗️ Architecture & Infrastructure
- **Microservices Design**: Scalable, maintainable, and fault-tolerant architecture
- **Database Abstraction**: Support for SQLite, PostgreSQL, MongoDB, Redis, ClickHouse
- **Message Queue Systems**: Redis, RabbitMQ, Apache Kafka integration
- **Caching Layers**: Multi-tier caching with Redis and in-memory systems
- **Load Balancing**: Automatic traffic distribution and failover
- **Container Support**: Docker and Kubernetes deployment ready

### 🔌 Plugin Ecosystem
- **Sandboxed Execution**: Secure plugin runtime with resource limits
- **Plugin Marketplace**: Discover, install, and manage plugins
- **Custom Development**: Rich SDK for building custom integrations
- **Hot Reloading**: Update plugins without system restart
- **Permission System**: Granular control over plugin capabilities
- **Version Management**: Automatic updates and rollback capabilities

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.8+** (Python 3.10+ recommended)
- **4GB RAM minimum** (8GB+ recommended for AI features)
- **2GB disk space** for full installation
- **Internet connection** for initial setup and AI features

### Option 1: One-Command Installation (Recommended)

1. **Download the installer**:
   ```bash
   curl -L -o run.py https://raw.githubusercontent.com/linux-of-user/plexichat/main/run.py
   ```
   Or [download run.py directly](https://raw.githubusercontent.com/linux-of-user/plexichat/main/run.py)

2. **Install PlexiChat**:
   ```bash
   python run.py install
   ```
   This will:
   - Download the latest stable release
   - Install all dependencies
   - Set up the database
   - Create default configuration

3. **Complete setup**:
   ```bash
   python run.py setup
   ```
   Choose your installation level:
   - **Minimal**: Basic chat functionality
   - **Standard**: Full features with AI
   - **Full**: All features + development tools
   - **Developer**: Everything + debugging tools

4. **Start PlexiChat**:
   ```bash
   python run.py              # Default: API server with CLI
   python run.py gui          # Desktop GUI interface
   python run.py --help       # See all options
   ```

### Option 2: Manual Installation

1. **Download from releases**:
   ```bash
   wget https://github.com/linux-of-user/plexichat/archive/refs/tags/latest.zip
   unzip latest.zip
   cd plexichat-*
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run setup**:
   ```bash
   python run.py setup --level standard
   ```

### First-Time Configuration

After installation, PlexiChat will guide you through:

1. **Admin Account Setup**: Create your administrator account
2. **Database Configuration**: Choose your database backend
3. **Security Settings**: Configure encryption and authentication
4. **AI Provider Setup**: Connect to AI services (optional)
5. **Plugin Selection**: Choose initial plugins to install

## 🖥️ Interface Options

### Web Interface (Default)
Access the full-featured web interface at `http://localhost:8000`
- Modern responsive design
- Real-time messaging
- Admin dashboard
- Plugin management
- Analytics and monitoring

### Command Line Interface
```bash
python run.py cli          # Interactive CLI
python run.py admin        # Admin commands
python run.py logs         # View logs
python run.py status       # System status
python run.py update       # Check for updates
```

### Desktop GUI
```bash
python run.py gui
```
- Native desktop application
- System tray integration
- Offline capabilities
- Local file management

## Admin Interfaces
### Web Admin
- Access at `/admin` in the web UI.
- Manage users, plugins, system, security, and plugin module permissions.
- Approve/revoke plugin module import requests live from the dashboard.

### CLI Admin
- Use `python run.py cli` and the `admin` command group:
  - `plugin-module-requests`: List pending plugin module requests.
  - `grant-plugin-module <plugin> <module>`: Grant permission.
  - `revoke-plugin-module <plugin> <module>`: Revoke permission.

### GUI Admin
- Launch the GUI and open the Plugin Manager tab.
- Use the "Module Permissions" tab to view and manage plugin module requests.

## Plugin System
- Plugins are sandboxed by default and can only import allowed modules.
- If a plugin needs a new module, it requests it; admins can approve via web, CLI, or GUI.
- Plugins can add web/GUI pages, CLI commands, and more.

## Module Permission Management
- All plugin module import requests are tracked.
- Admins can grant/revoke permissions at any time.
- Denied plugins do not block startup; they simply do not load.

## Testing
- Run the integrated test suite from the web UI, GUI, or CLI.
- All core features and plugins are covered by tests.

## 🏗️ System Architecture Overview

### Core Systems
- **Authentication & Authorization**: Multi-factor auth, RBAC, session management
- **Database Management**: Unified abstraction for SQLite, PostgreSQL, MongoDB, Redis
- **Configuration System**: Centralized YAML-based config with environment overrides
- **AI Integration**: Multi-provider support (OpenAI, Anthropic, local models)
- **Security**: End-to-end encryption, audit logging, zero-trust architecture
- **Performance**: Multi-tier caching, load balancing, auto-scaling
- **Monitoring**: Real-time metrics, alerting, comprehensive logging

### Plugin Ecosystem
- **Sandboxed Execution**: Secure plugin runtime with resource limits
- **Rich SDK**: Comprehensive development framework
- **Permission System**: Granular control over plugin capabilities
- **Hot Reloading**: Update plugins without system restart

## 📊 Monitoring & Analytics

Access comprehensive monitoring at `http://localhost:8000/admin/monitoring`:
- Real-time system metrics (CPU, memory, disk, network)
- Application performance (request rates, response times, errors)
- Business analytics (user activity, message volume, feature usage)
- Security monitoring (auth attempts, security events, audit logs)

## 🔧 Configuration Management

PlexiChat uses a unified configuration system:

1. **Environment Variables**: `PLEXICHAT_*` (highest priority)
2. **Main Config**: `config/plexichat.yaml`
3. **Plugin Configs**: `config/plugins/*.yaml`
4. **Built-in Defaults**: Fallback values

Example configuration:
```yaml
# config/plexichat.yaml
server:
  host: "0.0.0.0"
  port: 8000
  debug: false

database:
  url: "sqlite:///data/plexichat.db"

security:
  jwt_secret: "your-secret-key"

ai:
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"
      model: "gpt-3.5-turbo"
```

## 🚀 Deployment Options

### Development
```bash
python run.py setup --level developer
python run.py --debug
```

### Production with Docker
```yaml
# docker-compose.yml
version: '3.8'
services:
  plexichat:
    build: .
    ports: ["8000:8000"]
    environment:
      - PLEXICHAT_DATABASE_URL=postgresql://postgres:password@db:5432/plexichat
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: plexichat
```

### Cloud Deployment
- **AWS**: ECS/Fargate + RDS + ElastiCache
- **Azure**: Container Instances + Azure Database + Azure Cache
- **GCP**: Cloud Run + Cloud SQL + Memorystore

## 🛠️ Administration

### CLI Admin Commands
```bash
# User management
python run.py admin users list
python run.py admin users create --username admin

# System management
python run.py admin config show
python run.py admin health --detailed
python run.py admin logs --level error --tail 100

# Plugin management
python run.py admin plugins list
python run.py admin plugins install plugin_name

# Backup and maintenance
python run.py admin backup create
python run.py admin database vacuum
```

## 🔍 Troubleshooting

### Common Issues

**Installation Problems**:
```bash
# Check Python version (3.8+ required)
python --version

# Update pip and retry
pip install --upgrade pip
pip install -r requirements.txt --verbose
```

**Runtime Issues**:
```bash
# Check system health
python run.py admin health

# View error logs
python run.py admin logs --level error

# Reset database if needed
python run.py admin database reset --confirm
```

**Performance Issues**:
```bash
# Check metrics
python run.py admin metrics --system

# Optimize database
python run.py admin database analyze-slow-queries
python run.py admin database reindex
```

## 📚 Documentation

- **[Installation Guide](docs/installation.md)**: Detailed setup instructions
- **[Configuration Reference](docs/configuration.md)**: Complete config options
- **[API Documentation](docs/api.md)**: REST API and WebSocket docs
- **[Plugin Development](docs/plugin-development.md)**: Create custom plugins
- **[Security Guide](docs/security.md)**: Security best practices
- **[Troubleshooting](docs/troubleshooting.md)**: Common issues and solutions

### API Documentation
- **Interactive Docs**: `http://localhost:8000/docs` (Swagger UI)
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Spec**: `http://localhost:8000/openapi.json`

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/linux-of-user/plexichat.git
cd plexichat
python run.py setup --level developer
python run.py test
python run.py --debug --reload
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**PlexiChat** - Advanced AI-powered communication platform with enterprise-grade security and scalability.

## Contribution
- Fork the repo and submit pull requests.
- Follow the code style and add tests for new features.
- See `CONTRIBUTING.md` for more details.

## License
MIT License 