# PlexiChat

PlexiChat is a next-generation, modular, and extensible chat platform designed for advanced collaboration, security, and automation. It features a robust plugin system, multi-interface support (web, CLI, GUI), and enterprise-grade management tools.

## Features
- **Modular architecture**: Core, features, plugins, infrastructure, and interfaces are cleanly separated.
- **Plugin system**: Discover, install, update, and manage plugins with advanced sandboxing and permission controls.
- **Multi-interface**: Web UI (FastAPI), CLI (Click), and GUI (Tkinter) for full admin and user control.
- **Database abstraction**: Supports SQL and NoSQL backends via a unified database manager.
- **Security**: Advanced authentication, 2FA, rate limiting, government-grade middleware, and audit logging.
- **Monitoring & Analytics**: Real-time metrics, performance tracking, and audit trails.
- **Backup & Recovery**: Unified backup system with quantum encryption support.
- **Cluster & Scaling**: Built-in clustering, load balancing, and failover management.
- **Testing**: Integrated plugin-based test suite, with web/GUI/CLI triggers.

## Quick Start (No Git Required)

1. **Download `run.py`**
   - [Right-click here and save as `run.py`](https://raw.githubusercontent.com/linux-of-user/plexichat/main/run.py)
   - Or download from the [latest release page](https://github.com/linux-of-user/plexichat/releases)

2. **Run the installer**
   ```sh
   python run.py setup
   ```
   - This will automatically download all required files and dependencies for you.
   - If prompted, allow the script to download and install additional files.

3. **Start PlexiChat**
   ```sh
   python run.py cli   # Command-line interface
   python run.py web   # Web interface
   python run.py gui   # Desktop GUI
   ```

## Alternative: Manual Download (Advanced)
If you cannot use the installer, you may manually download the full source from the [GitHub releases](https://github.com/linux-of-user/plexichat/releases) or as a ZIP. Extract all files to a folder, then run:
```sh
python run.py setup
```

## Troubleshooting
- If you have issues running `run.py`, ensure you have Python 3.8+ installed.
- If dependencies fail to install, try running:
  ```sh
  pip install -r requirements.txt
  ```
- For network/firewall issues, manually download the ZIP and extract all files.

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

## Contribution
- Fork the repo and submit pull requests.
- Follow the code style and add tests for new features.
- See `CONTRIBUTING.md` for more details.

## License
MIT License 