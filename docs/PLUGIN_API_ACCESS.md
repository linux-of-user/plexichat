# PlexiChat Plugin Capabilities & System Access

## Philosophy and Warning

PlexiChat's plugin architecture is designed to be exceptionally powerful and flexible, treating plugins as trusted, first-class citizens. This means a well-written plugin can deeply integrate with and extend the core functionality of the application. However, this power comes with significant responsibility.

**WARNING:** A poorly designed or malicious plugin can have profound, system-wide effects, including but not limited to:
- Complete data loss or corruption.
- Critical security vulnerabilities.
- Full application instability and crashes.
- Severe performance degradation.

This document outlines the full scope of access a plugin can have. It is intended for developers to understand the capabilities they can leverage and the potential impact of their code.

---

## 1. Core Services & Event Bus

This is the primary and most powerful way plugins integrate with PlexiChat.

### Access Level: Unrestricted

- **Description:** Plugins have direct access to the central service locator and the main event bus. The service locator provides access to singleton instances of core managers (like the `ConfigManager`, `UserManager`, etc.). The event bus allows plugins to listen for and emit events that other parts of the system, including other plugins, can react to.
- **How to Edit/Modify:**
    - **Listen to any core event:** A plugin can subscribe to events like `user.login`, `config.changed`, or `database.backup.started`.
    - **Emit any core event:** A plugin can trigger core system actions by emitting the corresponding event, potentially causing other plugins or core components to perform actions.
    - **Intercept and modify data:** By listening for an event, a plugin can receive data, modify it, and then re-emit it or pass it to another function, effectively creating a middleware for core operations.
    - **Access any core service:** A plugin can request any registered service, such as the database service, and call its methods directly.

**Example:**
```python
# A plugin intercepting user creation to add a custom tag
class MyPlugin:
    def __init__(self, context):
        self.events = context.get_service('events')
        self.users = context.get_service('users')
        self.events.on('user.creating', self.on_user_creating)

    def on_user_creating(self, user_data):
        print(f"A new user is being created: {user_data['username']}")
        user_data['tags'].append('my_plugin_tag')
        # The core function will now receive the modified user_data
```

---

## 2. Configuration System

### Access Level: Full Read/Write

- **Description:** Plugins can read any configuration value in the system and can register and write their own configuration values. In most implementations, they can also overwrite core configuration settings.
- **How to Edit/Modify:**
    - **Read any setting:** Access database credentials, API keys for other services, security settings, etc.
    - **Overwrite core settings:** Change the application's port, logging level, or even security parameters like JWT secrets or rate limits. This is extremely dangerous.
    - **Register custom settings:** Add new configuration sections for the plugin's own use.

**Example:**
```python
class MyPlugin:
    def __init__(self, context):
        self.config = context.get_service('config')

    def disable_security_feature(self):
        # DANGEROUS: Overwriting a core security setting
        self.config.set('security.waf.enabled', False)
        print("Web Application Firewall has been disabled by MyPlugin.")
```

---

## 3. Database Access

### Access Level: Direct Model-Layer Access

- **Description:** Plugins are typically given access to the database abstraction layer (ORM or custom data repositories). This means they can create, read, update, and delete records for any data model in the system.
- **How to Edit/Modify:**
    - **Create/Read/Update/Delete (CRUD) any record:** A plugin can directly modify the `users` table, delete `settings`, alter `logs`, or interact with any data model defined in the core application.
    - **Introduce new data models:** A plugin can register its own database tables and manage them.
    - **Perform raw queries:** In some cases, a plugin might be able to execute raw SQL queries, bypassing the ORM/model layer entirely, allowing for arbitrary database manipulation.

**Example:**
```python
class MyPlugin:
    def __init__(self, context):
        self.db = context.get_service('database')
        self.User = self.db.get_model('User')

    def promote_user_to_admin(self, username):
        # Directly finding and modifying a user record
        user = self.User.find_one({'username': username})
        if user:
            user.role = 'admin'
            user.save()
            print(f"User {username} has been promoted to admin by MyPlugin.")
```

---

## 4. User & Session Management

### Access Level: Full Control

- **Description:** Plugins can hook directly into the authentication and user management lifecycle.
- **How to Edit/Modify:**
    - **Extend the User model:** Add new properties or methods to the core `User` object.
    - **Hook into authentication:** Execute code during login, logout, and registration. A plugin can block a login attempt, add a 2FA step, or log session details to an external system.
    - **Modify permissions:** Directly alter a user's roles and permissions.
    - **Impersonate users:** A plugin could potentially generate valid session tokens for any user, allowing it to perform actions on their behalf.

---

## 5. UI & Frontend

### Access Level: Full Injection

- **Description:** Plugins can add new elements to the web interface or modify existing ones.
- **How to Edit/Modify:**
    - **Register new pages/routes:** Create entirely new sections in the web UI.
    - **Inject panels and components:** Add widgets to the dashboard, new buttons to a settings page, or new tabs to a user profile.
    - **Inject custom CSS and JavaScript:** Arbitrarily change the look, feel, and behavior of the entire frontend for all users. A malicious script here could act as a keylogger or steal session cookies.

---

## 6. API Endpoints

### Access Level: Unrestricted Creation

- **Description:** Plugins can register their own REST API endpoints.
- **How to Edit/Modify:**
    - **Create new API routes:** A plugin can expose its functionality via a new API (e.g., `/api/v1/myplugin/status`).
    - **Bypass core API security:** If not carefully implemented, a plugin's API endpoint might not be protected by the same authentication and authorization checks as the core API, creating a security hole.

---

## 7. File System

### Access Level: Potentially Unsandboxed

- **Description:** Plugins can be granted the ability to read and write to the file system.
- **How to Edit/Modify:**
    - **Read arbitrary files:** Access source code, configuration files, or sensitive data stored on the server.
    - **Write arbitrary files:** Create or overwrite files, potentially planting malware, backdoors, or deleting critical application files.
    - **Execute system commands:** A plugin with file system write access could write a script and then use another capability to execute it.

---

## 8. Networking

### Access Level: Unrestricted

- **Description:** Plugins can initiate outbound network requests and potentially listen for inbound connections.
- **How to Edit/Modify:**
    - **Make outbound API calls:** Send data from the PlexiChat instance to any external service. This could be used to exfiltrate data.
    - **Open new ports:** A plugin could start its own web server or service, potentially exposing a new, unsecured attack surface.

---

## Summary Table

| System Component | Primary Access Method | Potential for "Big Time" Edits & Impact |
| :--- | :--- | :--- |
| **Core Services/Events** | `context.get_service()`, `events.on()`, `events.emit()` | **Critical**. Can intercept, modify, and trigger any core system logic. High risk of instability. |
| **Configuration** | `config.get()`, `config.set()` | **Critical**. Can disable security features, change credentials, and alter core application behavior. |
| **Database** | `db.get_model()`, `model.find/save/delete()` | **Critical**. Can read, modify, or delete any piece of data in the entire application. High risk of data loss. |
| **User Management** | Event Hooks (`user.login`), Service (`UserManager`) | **Critical**. Can bypass authentication, escalate privileges, and impersonate users. |
| **UI / Frontend** | `ui.register_panel()`, `ui.inject_script()` | **High**. Can alter the entire UI, inject malicious scripts (XSS), and capture user input. |
| **API Endpoints** | `api.register_route()` | **High**. Can expose unauthenticated endpoints that perform sensitive actions. |
| **File System** | `os` module, `open()` | **Critical**. Can read/write/delete any file on the server, leading to data theft or system compromise. |
| **Networking** | `requests` library, `socket` | **High**. Can exfiltrate any and all system data to an external location. Can open insecure ports. |
| **Scheduling** | `scheduler.add_job()` | **Medium**. Can schedule resource-intensive tasks that degrade performance. |
| **Plugin Management** | `plugins.disable()` | **High**. Can disable other plugins, including critical security or monitoring plugins. |
