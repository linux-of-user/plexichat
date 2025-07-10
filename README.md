# PlexiChat - Government-Level Secure Communication Platform

[![Version](https://img.shields.io/badge/version-a.1.1--1-blue.svg)](https://github.com/linux-of-user/netlink)
[![License](https://img.shields.io/badge/license-CC0-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Security](https://img.shields.io/badge/security-government--level-red.svg)](docs/security.md)

PlexiChat is a comprehensive, government-level secure communication platform designed for organizations requiring the highest levels of security, reliability, and performance. Built with quantum-resistant encryption, advanced clustering capabilities, and seamless update management.

## 🚀 Quick Start

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/linux-of-user/netlink.git
   cd netlink
   ```

2. **Run PlexiChat**:
   ```bash
   python run.py
   ```
   
   The `run.py` script automatically:
   - Detects your operating system
   - Sets up virtual environment
   - Installs dependencies
   - Configures the system
   - Starts PlexiChat

3. **Access the interfaces**:
   - **WebUI**: http://localhost:8000
   - **API**: http://localhost:8000/api/v1
   - **Documentation**: http://localhost:8000/docs
   - **CLI**: `plexichat --help`

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`

⚠️ **Change the default password immediately**: `plexichat admin password --change`

## 🌟 Key Features

### 🔒 Government-Level Security
- **Quantum-resistant encryption** with post-quantum cryptography
- **Zero-knowledge architecture** with end-to-end encryption
- **Advanced DDoS protection** with behavioral analysis
- **Comprehensive penetration testing** with automated vulnerability scanning
- **Multi-factor authentication** with biometric support

### 🏗️ Enterprise Architecture
- **Multi-node clustering** with automatic load balancing
- **Seamless zero-downtime updates** with automatic rollback
- **Intelligent backup system** with encrypted shard distribution
- **Service mesh architecture** with hybrid cloud support
- **Microservices design** with containerization support

### 💬 Advanced Communication
- **Real-time messaging** with presence indicators
- **Voice and video calling** with encrypted channels
- **File sharing** with virus scanning and encryption
- **Collaboration tools** with shared workspaces
- **AI-powered moderation** with content analysis

### 🔧 Developer Experience
- **Comprehensive API** with versioning (/api, /api/v1, /api/beta)
- **Interactive documentation** with Swagger UI
- **Plugin architecture** with marketplace
- **CLI tools** for administration and automation
- **GitHub-based updates** with automatic deployment

## 📋 System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.15+, Linux (Ubuntu 18.04+)
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB available space
- **Network**: Internet connection for updates

### Recommended for Production
- **OS**: Linux (Ubuntu 20.04+ LTS)
- **Python**: 3.11+
- **RAM**: 16GB+
- **Storage**: 100GB+ SSD
- **Network**: Dedicated network interface
- **CPU**: 4+ cores

## 🏃‍♂️ Installation Types

PlexiChat supports multiple installation types:

### Minimal Installation
```bash
python run.py --minimal
```
- Core functionality only
- Reduced dependencies
- Faster startup
- Suitable for testing

### Full Installation (Default)
```bash
python run.py
```
- All features enabled
- Complete dependency set
- Production-ready
- Recommended for deployment

### Development Installation
```bash
python run.py --dev
```
- Development tools included
- Debug mode enabled
- Hot reload support
- Testing frameworks

## 🔧 Configuration

PlexiChat uses YAML configuration files in the `config/` directory:

- `plexichat.yaml` - Main configuration
- `security.yaml` - Security settings
- `clustering.yaml` - Cluster configuration
- `backup.yaml` - Backup settings

### Environment Variables
```bash
export PLEXICHAT_ENV=production
export PLEXICHAT_SECRET_KEY=your-secret-key
export PLEXICHAT_DB_URL=postgresql://user:pass@host/db
```

## 🌐 API Endpoints

PlexiChat provides three API versions:

### Stable API (`/api`)
- Production-ready endpoints
- Backward compatibility guaranteed
- Rate limiting: 1000 req/hour

### Current API (`/api/v1`)
- Latest features
- Active development
- Rate limiting: 5000 req/hour

### Beta API (`/api/beta`)
- Experimental features
- May have breaking changes
- Rate limiting: 10000 req/hour

### Key Endpoints
```bash
# Authentication
POST /api/v1/auth/login
GET  /api/v1/auth/me

# Messages
GET  /api/v1/messages
POST /api/v1/messages
GET  /api/v1/messages/search

# Files
POST /api/v1/files/upload
GET  /api/v1/files/{file_id}

# Updates
GET  /api/v1/updates/check
POST /api/v1/updates/install
```

## 🛠️ CLI Commands

```bash
# Server management
netlink server start
netlink server stop
netlink server status

# User management
netlink users list
netlink users create username

# Admin management
netlink admin password --change
netlink admin password --reset username

# System testing
netlink test run
netlink test health
netlink test security

# Updates
netlink version update
netlink version history

# Backup and recovery
netlink backup create
netlink backup restore backup-id

# Documentation
netlink docs list
netlink docs view api_reference
```

## 🔄 Updates and Versioning

NetLink uses semantic versioning with a special format: `letter.major.minor-build`

- **Alpha**: `a.1.1-1` (Development)
- **Beta**: `b.1.1-1` (Pre-release)
- **Release**: `r.1.1-1` (Stable)

### Automatic Updates
```bash
# Enable auto-updates
netlink version update --auto --channel stable

# Check for updates
netlink version update --check-only

# Manual update
netlink version update
```

## 🏢 Deployment

### Docker Deployment
```bash
docker build -t netlink .
docker run -p 8000:8000 netlink
```

### Production Deployment
```bash
# Using gunicorn
gunicorn src.netlink.app.main:app -w 4 -k uvicorn.workers.UvicornWorker

# Using systemd
sudo systemctl enable netlink
sudo systemctl start netlink
```

### Clustering
```bash
# Join cluster
netlink cluster join --node-id node-2 --host 192.168.1.100

# Check cluster status
netlink cluster status
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [User Manual](docs/user-guide.md)
- [API Reference](docs/api_reference.md)
- [Admin Guide](docs/admin_deployment_guide.md)
- [Security Documentation](docs/security.md)
- [Clustering Guide](docs/clustering-system.md)
- [Backup System](docs/backup-system.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the CC0 License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/linux-of-user/netlink/issues)
- **Discussions**: [GitHub Discussions](https://github.com/linux-of-user/netlink/discussions)

## 🔒 Security

For security vulnerabilities, please email security@netlink.local instead of using the issue tracker.

## 🏆 Features Roadmap

### Phase 1 (Current - a.1.x)
- ✅ Core messaging and file sharing
- ✅ Government-level security
- ✅ Multi-node clustering
- ✅ Seamless updates
- ✅ Comprehensive API

### Phase 2 (b.1.x - b.2.x)
- 🔄 Discord/Telegram feature parity
- 🔄 Advanced AI integration
- 🔄 Mobile applications
- 🔄 Advanced analytics

### Phase 3 (r.2.x+)
- 📋 Quantum security implementation
- 📋 Blockchain audit trails
- 📋 Decentralized identity
- 📋 Hardware security modules

---

**NetLink** - Secure. Scalable. Seamless.

*Built with ❤️ for organizations that demand the highest levels of security and reliability.*
