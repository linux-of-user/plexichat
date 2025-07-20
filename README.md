# PlexiChat - Government-Level Secure Communication Platform

[![Version](https://img.shields.io/badge/version-a.1.1--34-blue.svg)](https://github.com/linux-of-user/plexichat)
[![License](https://img.shields.io/badge/license-CC0-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/security-quantum--resistant-green.svg)](docs/SECURITY.md)
[![Architecture](https://img.shields.io/badge/architecture-enterprise-blue.svg)](docs/ARCHITECTURE.md)

PlexiChat is a comprehensive, government-level secure communication platform designed for organizations requiring the highest levels of security, reliability, and performance. Built with quantum-resistant encryption, advanced clustering capabilities, AI integration, and enterprise-grade features.

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- PostgreSQL 12+ (recommended) or SQLite for development
- Redis 6+ for caching and real-time features
- Node.js 16+ for web interface development (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/linux-of-user/plexichat.git
cd plexichat

# Install dependencies
pip install -r requirements.txt

# Initialize the application (optional - auto-setup on first run)
python run.py setup

# Start the server (choose interface)
python run.py gui      # GUI with splitscreen CLI
python run.py webui    # Web UI with splitscreen CLI
python run.py api      # API server only
python run.py cli      # Splitscreen CLI only
```

### Docker Installation

```bash
# Using Docker Compose (recommended)
docker-compose up -d

# Or build from source
docker build -t plexichat .
docker run -p 8000:8000 plexichat
```

### First Run

1. **Access the web interface**: Open http://localhost:8000
2. **Default admin credentials**:
   - Username: `admin`
   - Password: `admin123` (change immediately)
3. **Complete setup wizard**: Follow the guided setup process

## 🏗️ Architecture

PlexiChat follows a modern, modular enterprise architecture:

```
PlexiChat/
├── Core System/           # Fundamental infrastructure
│   ├── Authentication    # Unified auth with MFA, OAuth, biometrics
│   ├── Security          # Quantum encryption, threat detection
│   ├── Database          # Multi-database support with encryption
│   ├── Configuration     # Dynamic config management
│   └── Logging           # Structured logging and monitoring
├── Features/             # Business logic modules
│   ├── AI Integration    # Multi-provider AI with local models
│   ├── Backup System     # Distributed quantum backup
│   ├── Clustering        # Multi-node clustering and load balancing
│   └── Security          # Advanced security features
├── Interfaces/           # User-facing interfaces
│   ├── API              # RESTful API with versioning
│   ├── Web              # Modern responsive web interface
│   └── CLI              # Splitscreen CLI with real-time monitoring
└── Infrastructure/       # Supporting services
    ├── Services         # Microservices architecture
    ├── Modules          # Plugin system
    └── Performance      # Optimization and caching
```

## 🔐 Security Features

- **Quantum-Resistant Encryption**: Future-proof cryptographic algorithms
- **Zero-Knowledge Architecture**: End-to-end encryption for all communications
- **Multi-Factor Authentication**: Support for TOTP, hardware keys, biometrics
- **Behavioral Analysis**: AI-powered threat detection and anomaly detection
- **Distributed Key Management**: Secure key distribution across multiple vaults
- **Real-time Monitoring**: Continuous security monitoring and alerting
- **Compliance Ready**: GDPR, HIPAA, SOX, ISO 27001 compliance support

## 🤖 AI Integration

- **Multi-Provider Support**: OpenAI, Anthropic, Google, local models
- **Intelligent Search**: Semantic search across messages and files
- **Content Moderation**: AI-powered content filtering and safety
- **Smart Suggestions**: Context-aware message and response suggestions
- **Document Analysis**: Automated document processing and insights
- **Translation**: Real-time multi-language translation

## 📊 Enterprise Features

- **Multi-Node Clustering**: Horizontal scaling with automatic load balancing
- **Distributed Backup**: Quantum-encrypted backup with intelligent sharding
- **Plugin Marketplace**: Extensible functionality with secure plugin system
- **Advanced Analytics**: Comprehensive metrics and reporting
- **Audit Logging**: Complete audit trail for compliance
- **Role-Based Access**: Granular permissions and access control

## 🛠️ Development

### Project Structure

```bash
src/plexichat/
├── __init__.py           # Main package initialization
├── main.py              # FastAPI application entry point
├── cli/                 # Command-line interface
├── core/                # Legacy core components
├── core_system/         # New unified core system
├── features/            # Feature modules
├── infrastructure/      # Infrastructure services
└── interfaces/          # User interfaces (API, Web, CLI)
```

### Running in Development Mode

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run with auto-reload
python run.py --dev

# Run tests
pytest

# Run with specific configuration
python run.py --config config/development.yaml
```

### API Documentation

- **Interactive API Docs**: http://localhost:8000/docs
- **ReDoc Documentation**: http://localhost:8000/redoc
- **API Reference**: [docs/API.md](docs/API.md)

## 📚 Documentation

- [**Getting Started Guide**](docs/GETTING_STARTED.md) - Complete setup and configuration
- [**Architecture Overview**](docs/ARCHITECTURE.md) - System design and components
- [**Security Guide**](docs/SECURITY.md) - Security features and best practices
- [**API Reference**](docs/API.md) - Complete API documentation
- [**Deployment Guide**](docs/DEPLOYMENT.md) - Production deployment instructions
- [**Plugin Development**](docs/PLUGINS.md) - Creating custom plugins
- [**Troubleshooting**](docs/TROUBLESHOOTING.md) - Common issues and solutions

## 🚀 Deployment

### Production Deployment

```bash
# Using Docker Compose (recommended)
docker-compose -f docker-compose.prod.yml up -d

# Manual deployment
python -m plexichat deploy --environment production

# Kubernetes deployment
kubectl apply -f k8s/
```

### Environment Variables

```bash
# Core configuration
PLEXICHAT_ENV=production
PLEXICHAT_SECRET_KEY=your-secret-key
PLEXICHAT_DATABASE_URL=postgresql://user:pass@host:5432/plexichat

# Security configuration
PLEXICHAT_ENCRYPTION_KEY=your-encryption-key
PLEXICHAT_JWT_SECRET=your-jwt-secret

# AI configuration
OPENAI_API_KEY=your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/your-username/plexichat.git
cd plexichat

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Submit a pull request
```

## 📄 License

This project is licensed under the CC0 License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/linux-of-user/plexichat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/linux-of-user/plexichat/discussions)
- **Security Issues**: security@plexichat.com

## 🏆 Features Highlights

- ✅ **Government-Level Security** - Quantum-resistant encryption
- ✅ **Enterprise Architecture** - Microservices with clustering
- ✅ **AI Integration** - Multi-provider AI support
- ✅ **Real-time Communication** - WebSocket-based messaging
- ✅ **Plugin System** - Extensible functionality
- ✅ **Multi-Database Support** - PostgreSQL, MySQL, SQLite
- ✅ **Comprehensive API** - RESTful API with versioning
- ✅ **Modern Web Interface** - Responsive and accessible
- ✅ **Splitscreen CLI** - Enhanced CLI with real-time monitoring
- ✅ **Distributed Backup** - Quantum-encrypted backups

---

**PlexiChat** - Secure. Scalable. Intelligent.