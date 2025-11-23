# PlexiChat Design Bible

## Architecture Overview

PlexiChat follows a clean architecture pattern, separating concerns into distinct layers:

1.  **Interfaces**: Entry points (API, CLI, WebUI).
2.  **Core**: Business logic and domain entities.
3.  **Infrastructure**: External concerns (Database, File System, Network).
4.  **Shared**: Common utilities and constants.

## Main Systems & Usage

### 1. Logging

**Import**: `from plexichat.core.logging import get_logger`
**Usage**:

```python
logger = get_logger(__name__)
logger.info("System initialized")
logger.error("Connection failed", exc_info=True)
```

**Rules**:

- Always use `get_logger`.
- Never use `print`.
- Include context in log messages.

### 2. Configuration

**Import**: `from plexichat.core.config import config`
**Usage**:

```python
db_path = config.get("database.path", "data/db.sqlite")
```

**Rules**:

- All config comes from `config.yaml`.
- Use dot notation for keys.
- Provide sensible defaults.

### 3. Database

**Import**: `from plexichat.infrastructure.database import db`
**Usage**:

```python
async with db.transaction():
    user = await db.users.get(user_id)
```

**Rules**:

- Always use async context managers.
- Never write raw SQL in business logic.
- Use the repository pattern.

### 4. Security

**Import**: `from plexichat.core.security import security_manager`
**Usage**:

```python
hashed_pw = security_manager.hash_password(password)
```

**Rules**:

- Centralized security logic.
- No hardcoded secrets.

## Directory Structure

- `src/plexichat/core`: Business logic (Auth, Messaging, etc.)
- `src/plexichat/infrastructure`: DB, Redis, FS adapters.
- `src/plexichat/interfaces`: API routes, CLI commands.
- `src/plexichat/shared`: Utils, constants, exceptions.
