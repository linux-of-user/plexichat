# Getting Started with NetLink

Welcome to NetLink! This guide will get you up and running in just a few minutes.

## 🚀 Quick Start (30 seconds)

### Step 1: Get NetLink
```bash
git clone https://github.com/linux-of-user/netlink.git
cd netlink
```

### Step 2: Start Everything
```bash
python run.py
```

That's it! NetLink will automatically:
- ✅ Check your Python version (3.8+ required)
- ✅ Install missing dependencies
- ✅ Validate system configuration
- ✅ Start the web server
- ✅ Launch the CLI interface
- ✅ Open in split-screen mode

### Step 3: Access Your Platform

Once started, you'll see output like this:

```
============================================================
                    NETLINK v1.0.0
============================================================
ℹ️  Starting in SPLIT mode...
ℹ️  Timestamp: 2024-01-01 12:00:00

✅ System validation passed
✅ Single instance lock acquired
✅ Web server started successfully
ℹ️  Access at: http://localhost:8000
ℹ️  API Docs: http://localhost:8000/docs
ℹ️  Admin: http://localhost:8000/web/admin
ℹ️  Web CLI: http://localhost:8000/web/cli

──────────────────────────────────────────────────────────
WEB SERVER RUNNING - Starting CLI Interface
──────────────────────────────────────────────────────────

✅ CLI interface ready
ℹ️  Type 'help' for available commands
ℹ️  Type 'exit' or Ctrl+C to shutdown

netlink>
```

## 🌐 Access Points

### Web Interface
Open your browser and go to: **http://localhost:8000**

**Default Login:**
- Username: `admin`
- Password: `admin123`

### Available Interfaces
- **Main Dashboard**: http://localhost:8000
- **Admin Panel**: http://localhost:8000/web/admin
- **API Documentation**: http://localhost:8000/docs
- **Web CLI**: http://localhost:8000/web/cli

### Desktop GUI (Optional)
```bash
python netlink_gui.py
```

## 🎮 Startup Options

### Default Mode (Recommended)
```bash
python run.py
```
- Starts web server + CLI in split-screen
- Perfect for development and administration

### Web Server Only
```bash
python run.py --web-only
```
- Production mode
- Only starts the web server
- No CLI interface

### CLI Only
```bash
python run.py --cli-only
```
- Administration mode
- Only starts the CLI
- No web server

### Force Start
```bash
python run.py --force
```
- Terminates any existing NetLink instance
- Useful if previous shutdown was unclean

### System Validation
```bash
python run.py --validate
```
- Checks system without starting services
- Useful for troubleshooting

## 🔧 Configuration

NetLink works out of the box with sensible defaults, but you can customize it:

### Environment Variables
Create a `.env` file in the NetLink directory:

```bash
# Server Configuration
HOST=0.0.0.0                    # Server host (default: 0.0.0.0)
PORT=8000                       # Server port (default: 8000)
WORKERS=4                       # Worker processes (default: 4)

# Database
DATABASE_URL=sqlite:///./data/netlink.db  # Database URL

# Security
SECRET_KEY=your-secret-key-here  # JWT signing key (auto-generated)

# Logging
LOG_LEVEL=INFO                  # Logging level (DEBUG, INFO, WARNING, ERROR)
LOG_TO_FILE=true               # Enable file logging
LOG_DIR=./logs                 # Log directory

# Features
CLUSTER_ENABLED=true           # Enable clustering
DEBUG=false                    # Debug mode
```

### Quick Configuration
```bash
# Change port
echo "PORT=8080" > .env
python run.py

# Enable debug mode
echo "DEBUG=true" >> .env
python run.py
```

## 🖥️ Using the CLI

The CLI provides full control over NetLink:

### Basic Commands
```bash
netlink> help              # Show all commands
netlink> status             # System status
netlink> info               # Detailed information
netlink> version            # Version information
```

### System Management
```bash
netlink> restart            # Restart server
netlink> shutdown           # Shutdown server
netlink> test               # Run system tests
netlink> performance        # Performance metrics
```

### User Management
```bash
netlink> users list         # List all users
netlink> users create       # Create new user
netlink> users delete       # Delete user
```

### Analytics & Monitoring
```bash
netlink> analytics          # View analytics
netlink> monitor status     # Monitor system
netlink> monitor logs 50    # View recent logs
```

### Updates
```bash
netlink> update check       # Check for updates
netlink> update start       # Start update process
netlink> update status      # Update status
```

### Clustering
```bash
netlink> cluster status     # Cluster status
netlink> cluster nodes      # List nodes
netlink> cluster join <url> # Join cluster
```

## 🌐 Web Interface Tour

### 1. Login Page
- Clean, modern interface
- Default credentials: admin/admin123
- Remember me option
- Responsive design

### 2. Main Dashboard
- System overview
- Real-time metrics
- Quick actions
- Navigation menu

### 3. Admin Panel
- User management
- System configuration
- Update management
- Cluster monitoring
- Analytics dashboard

### 4. API Documentation
- Interactive API explorer
- Try endpoints directly
- Authentication built-in
- Complete reference

## 🔄 Hot Updates

NetLink supports zero-downtime updates:

### Via Web Interface
1. Go to **Admin Panel** → **Updates**
2. Click **Check for Updates**
3. If available, click **Start Hot Update**
4. Updates apply instantly without downtime!

### Via CLI
```bash
netlink> update check
netlink> update start
```

### What Gets Updated
- **Hot Updates**: Web interface, templates, non-core components
- **Staged Updates**: Core components (applied on restart)
- **Automatic Rollback**: Failed updates are automatically rolled back

## 🌐 Multi-Server Setup

NetLink automatically discovers and coordinates with other instances:

### Automatic Discovery
1. Start NetLink on multiple machines
2. They automatically find each other on the local network
3. Form a cluster with leader election
4. Share load and provide redundancy

### Manual Clustering
```bash
# On second machine
netlink> cluster join http://first-machine:8000
```

### Load Balancing
```bash
# Get recommended server for new connections
curl http://localhost:8000/api/cluster/load-balance
```

## 🛑 Shutdown

### Graceful Shutdown
- **From CLI**: Type `exit` or press `Ctrl+C`
- **From Web**: Close browser (server keeps running)
- **Desktop GUI**: Click stop button

### Force Shutdown
```bash
python shutdown.py --force
```

### Clean Shutdown Script
```bash
python shutdown.py          # Interactive
python shutdown.py --list   # List processes
```

## 🧪 Testing Your Installation

### Quick Test
```bash
python quick_test.py
```

### Comprehensive Test
```bash
python final_validation.py
```

### Startup System Test
```bash
python test_startup_system.py
```

### From CLI
```bash
netlink> test               # Run all tests
netlink> test_health        # Quick health check
```

## 🆘 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
python shutdown.py --list

# Use different port
echo "PORT=8001" > .env
python run.py
```

#### Dependencies Missing
```bash
# Manual installation
pip install -r requirements.txt

# Or let NetLink handle it
python run.py  # Auto-installs dependencies
```

#### Permission Errors
```bash
# Linux/macOS: Make scripts executable
chmod +x run.sh

# Windows: Run as Administrator if needed
```

#### Can't Access Web Interface
```bash
# Check if server is running
netlink> status

# Check firewall settings
# Make sure port 8000 is open
```

### Getting Help

#### Built-in Help
```bash
python run.py --help        # Startup options
python cli.py               # CLI help
netlink> help               # All commands
netlink> help <command>     # Specific command help
```

#### System Validation
```bash
python run.py --validate    # Check system
python quick_test.py        # Quick test
```

#### Documentation
- **Troubleshooting Guide**: `TROUBLESHOOTING.md`
- **API Reference**: `docs/netlink_api.md`
- **Interactive Docs**: http://localhost:8000/docs

## 🎯 Next Steps

### For Users
1. **Explore the Web Interface** - Try all the features
2. **Create Additional Users** - Set up your team
3. **Customize Settings** - Configure to your needs
4. **Set Up Clustering** - Add more servers for redundancy

### For Developers
1. **Read the API Docs** - http://localhost:8000/docs
2. **Try the Examples** - Use the interactive API explorer
3. **Check the Code** - Explore the `app/` directory
4. **Run Tests** - `python final_validation.py`

### For Administrators
1. **Monitor System** - Use the admin dashboard
2. **Set Up Backups** - Configure data backup
3. **Plan Updates** - Use the hot update system
4. **Scale Out** - Add more servers to the cluster

## 🎉 You're Ready!

Congratulations! You now have NetLink running. Here's what you can do:

- ✅ **Web Interface**: Modern, responsive dashboard
- ✅ **API Access**: Complete REST API with documentation
- ✅ **CLI Control**: Full command-line administration
- ✅ **Hot Updates**: Zero-downtime updates
- ✅ **Clustering**: Multi-server coordination
- ✅ **Desktop GUI**: Native desktop application

**Happy networking with NetLink!** 🚀

---

Need help? Check the [Troubleshooting Guide](TROUBLESHOOTING.md) or run `python cli.py` and type `help`.
