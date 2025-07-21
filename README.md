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

## Setup
1. **Clone the repository**
   ```sh
   git clone https://github.com/plexichat/plexichat.git
   cd plexichat
   ```
2. **Install dependencies**
   ```sh
   python run.py setup
   # or manually:
   pip install -r requirements.txt
   ```
3. **Run PlexiChat**
   ```sh
   python run.py cli
   # or
   python run.py web
   # or
   python run.py gui
   ```

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