# NetLink Update System Guide

## How NetLink Updates Work

NetLink uses a **hybrid Git + ZIP distribution system** that combines the best of both worlds:

### 🔄 **The Update Process**

1. **Git Repository**: Source code is maintained at `https://github.com/linux-of-user/netlink`
2. **GitHub Releases**: Updates are distributed as ZIP files via GitHub Releases
3. **Automatic Download**: NetLink downloads ZIP files (not git pulls)
4. **Hot Updates**: Many updates can be applied without restarting the server

### 📦 **Version Format**

NetLink uses the format: `letter.major.minor-build`

- **Alpha**: `a.1.1-1` (Development/Testing)
- **Beta**: `b.1.1-1` (Pre-release/RC)  
- **Release**: `r.1.1-1` (Stable/Production)

Examples:
- `a.1.1-1` = Alpha version 1.1 build 1
- `b.2.0-5` = Beta version 2.0 build 5
- `r.1.5-12` = Release version 1.5 build 12

## 🚀 Creating a New Update (For Developers)

### Step 1: Prepare Your Changes

```bash
# Make your changes to the codebase
git add .
git commit -m "feat: your changes here"
git push origin main
```

### Step 2: Update Version Information

Edit `version.json` in the root directory:

```json
{
  "current_version": "a.1.2-1",
  "last_updated": "2024-01-09T10:30:00Z",
  "history": [
    {
      "version": "a.1.2-1", 
      "updated_at": "2024-01-09T10:30:00Z",
      "method": "manual_release"
    }
  ]
}
```

### Step 3: Create GitHub Release

1. **Go to GitHub**: Navigate to `https://github.com/linux-of-user/netlink/releases`

2. **Click "Create a new release"**

3. **Set the tag**: Use the version format (e.g., `a.1.2-1`)

4. **Release title**: Use format like "NetLink Alpha 1.2-1"

5. **Description**: Add changelog and release notes

6. **Attach files** (optional): Any additional files

7. **Pre-release**: Check this for alpha/beta versions

8. **Click "Publish release"**

### Step 4: GitHub Automatically Creates ZIP

When you create a release, GitHub automatically:
- Creates a ZIP file of the entire repository
- Makes it available at: `https://github.com/linux-of-user/netlink/archive/refs/tags/a.1.2-1.zip`
- Updates the releases API

## 📥 How Users Get Updates

### Automatic Updates (Default)

```bash
# NetLink automatically checks for updates every 24 hours
# Users see notifications in WebUI and CLI

# Manual check
netlink update check

# Install available update  
netlink update install
```

### Manual Updates

```bash
# Check current version
netlink version

# Check for updates
netlink update check --verbose

# Download and install specific version
netlink update install --version a.1.2-1

# Install from local ZIP file
netlink update install --file netlink-a.1.2-1.zip
```

### Update Channels

Users can choose their update channel:

```bash
# Stable channel (release versions only)
netlink update channel stable

# Beta channel (beta + release)  
netlink update channel beta

# Alpha channel (all versions)
netlink update channel alpha
```

## 🔧 Update System Components

### 1. GitHub Updater (`src/netlink/core/updates/github_updater.py`)
- Checks GitHub API for new releases
- Downloads ZIP files from GitHub
- Verifies package integrity
- Manages update installation

### 2. Version Manager (`src/netlink/core/versioning/version_manager.py`)
- Tracks current version
- Manages version history
- Handles version comparisons

### 3. Update CLI (`src/netlink/cli/update_cli.py`)
- Command-line interface for updates
- Manual update controls
- Update status and history

### 4. Hot Update System
- Updates templates, static files, and Python modules
- No server restart required for many updates
- Automatic rollback on failure

## 🛡️ Update Security

### Package Verification
- SHA256 checksums
- Digital signatures (planned)
- Source verification from GitHub

### Backup System
- Automatic backup before updates
- Rollback capability
- Multiple backup retention

### Health Checks
- Post-update validation
- Automatic rollback on failure
- Service health monitoring

## 🔄 Update Workflow Example

### For End Users:

```bash
# 1. Check current version
$ netlink version
Current version: a.1.1-5

# 2. Check for updates  
$ netlink update check
✅ Update available: a.1.2-1
📋 Changelog: Bug fixes and performance improvements

# 3. Install update
$ netlink update install
🔄 Downloading update...
📦 Installing update...
✅ Update completed successfully!
🔄 Restarting services...
✅ NetLink updated to a.1.2-1

# 4. Verify update
$ netlink version
Current version: a.1.2-1
```

### For Developers:

```bash
# 1. Make changes and commit
git add .
git commit -m "feat: add new feature"
git push

# 2. Update version.json
# Edit version.json with new version number

# 3. Create GitHub release
# Go to GitHub → Releases → Create new release
# Tag: a.1.2-1
# Title: NetLink Alpha 1.2-1
# Publish release

# 4. GitHub automatically creates ZIP
# ZIP available at: github.com/linux-of-user/netlink/archive/refs/tags/a.1.2-1.zip

# 5. Users get notified
# NetLink instances automatically detect new release
# Users can install via WebUI or CLI
```

## 🚨 Troubleshooting

### Update Fails
```bash
# Check update logs
netlink logs tail --filter update

# Check system status
netlink system status

# Rollback if needed
netlink update rollback
```

### Version Mismatch
```bash
# Reset version info
netlink update reset-version

# Reinstall current version
netlink update reinstall
```

### Network Issues
```bash
# Use manual ZIP file
netlink update install --file /path/to/update.zip

# Check connectivity
netlink network test github.com
```

## 📊 Update Statistics

The system tracks:
- Update success/failure rates
- Download speeds and times
- Rollback frequency
- User update patterns
- System health post-update

This data helps improve the update system and identify issues early.

---

**Key Points:**
- ✅ Updates are distributed as ZIP files from GitHub Releases
- ✅ No git required on user systems
- ✅ Automatic backup and rollback
- ✅ Hot updates for many changes
- ✅ Multiple update channels (alpha/beta/stable)
- ✅ Comprehensive verification and health checks
