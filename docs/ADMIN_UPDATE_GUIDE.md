# PlexiChat Admin Update & Push Guide

This guide provides step-by-step instructions for administrators to update PlexiChat, test changes, and push updates to production.

## 🚀 Quick Update Commands

### Basic Update Commands
```bash
# Check current version
python run.py version

# Update to latest version
python run.py update

# Refresh current version (redownload files)
python run.py refresh

# Check system status
python run.py system
```

### Interface Commands
```bash
# Start GUI with splitscreen CLI
python run.py gui

# Start Web UI with splitscreen CLI  
python run.py webui

# Start API server only
python run.py api

# Start splitscreen CLI only
python run.py cli
```

## 📋 Pre-Update Checklist

### 1. System Health Check
```bash
# Check system status
python run.py system

# Check dependencies
python run.py deps

# Run diagnostics
python run.py test

# Check logs for errors
python run.py clean  # Clean old logs first
```

### 2. Backup Current System
```bash
# Create backup before update
python run.py backup

# Or manual backup
cp -r src/ backup_$(date +%Y%m%d_%H%M%S)/
cp run.py backup_$(date +%Y%m%d_%H%M%S)/
cp version.json backup_$(date +%Y%m%d_%H%M%S)/
```

## 🔄 Update Process

### Method 1: Automatic Update (Recommended)
```bash
# 1. Check for updates
python run.py update

# 2. Follow prompts to download and install
# 3. System will automatically backup and update
# 4. Restart services after update
```

### Method 2: Manual Update
```bash
# 1. Download latest version
git pull origin main

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run setup if needed
python run.py setup

# 4. Test the update
python run.py test
```

### Method 3: Refresh Current Version
```bash
# Redownload current version files (useful for corruption)
python run.py refresh

# This will:
# - Backup current files
# - Download fresh copy from GitHub
# - Verify file integrity
# - Restore if download fails
```

## 🧪 Testing Updates

### 1. Create Testing Environment
```bash
# Create separate testing directory
mkdir plexichat_testing
cd plexichat_testing

# Download PlexiChat to test directory
# (Use the update system to download)
python ../plexichat/run.py update --target-dir .
```

### 2. Test All Interfaces
```bash
# Test CLI
python run.py cli
# Should show splitscreen interface (press 'q' to quit)

# Test API
python run.py api
# Should start on http://localhost:8000

# Test GUI  
python run.py gui
# Should start API + splitscreen CLI

# Test WebUI
python run.py webui  
# Should start API + splitscreen CLI
```

### 3. Test Core Functions
```bash
# Test system commands
python run.py version
python run.py system
python run.py deps
python run.py help

# Test update system
python run.py update --check-only

# Test configuration
python run.py wizard
```

## 🚀 Push to Production

### 1. Version Management
```bash
# Check current version
python run.py version

# Update version.json if needed
# Edit version.json manually or use:
python run.py version --set a.1.1.35
```

### 2. Git Workflow
```bash
# 1. Stage all changes
git add .

# 2. Commit with proper message
git commit -m "[a.1.1.35] feat: description of changes

CHANGELOG:
- List major changes
- Include bug fixes
- Note new features
- Document breaking changes"

# 3. Push to main branch
git push origin main

# 4. Create and push tag
git tag a.1.1.35
git push origin a.1.1.35
```

### 3. Production Deployment
```bash
# Option 1: Use update system
python run.py update --environment production

# Option 2: Manual deployment
git pull origin main
pip install -r requirements.txt
python run.py setup --production
systemctl restart plexichat  # If using systemd
```

## 🔧 Troubleshooting Updates

### Common Issues

#### 1. Syntax Errors After Update
```bash
# Check for syntax errors
python -m py_compile src/plexichat/main.py

# Fix common issues
python run.py clean
python run.py setup
```

#### 2. Missing Dependencies
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check for missing modules
python run.py deps
```

#### 3. Configuration Issues
```bash
# Reset configuration
python run.py wizard

# Or restore from backup
cp backup_*/config/* config/
```

#### 4. Database Issues
```bash
# Check database status
python run.py system

# Reset database if needed
python run.py setup --reset-db
```

### Recovery Procedures

#### 1. Rollback to Previous Version
```bash
# If using git
git checkout previous-tag
git checkout a.1.1.33  # Example

# If using backups
rm -rf src/
cp -r backup_*/src/ .
cp backup_*/run.py .
```

#### 2. Emergency Recovery
```bash
# Download fresh copy
rm -rf src/
python run.py refresh

# Or clone fresh
git clone https://github.com/linux-of-user/plexichat.git fresh_copy
cp -r fresh_copy/* .
```

## 📊 Monitoring After Updates

### 1. Check System Health
```bash
# Monitor logs
tail -f logs/plexichat.log

# Check system metrics
python run.py system

# Monitor with splitscreen CLI
python run.py cli
```

### 2. Performance Monitoring
```bash
# Check performance metrics
python run.py system --detailed

# Monitor memory usage
python run.py system --memory

# Check API health
curl http://localhost:8000/health
```

## 🔐 Security Considerations

### 1. Update Security
- Always backup before updates
- Test updates in isolated environment
- Verify checksums of downloaded files
- Check for security patches in changelog

### 2. Production Security
- Use HTTPS in production
- Update SSL certificates
- Review security logs after updates
- Test authentication systems

## 📞 Support

### Getting Help
- **Documentation**: Check `docs/` directory
- **Logs**: Check `logs/plexichat.log` for errors
- **System Info**: Run `python run.py system`
- **GitHub Issues**: Report bugs on GitHub

### Emergency Contacts
- **Critical Issues**: Create GitHub issue with "urgent" label
- **Security Issues**: Follow responsible disclosure
- **System Down**: Check logs and try recovery procedures

---

**Remember**: Always test updates in a separate environment before applying to production!
