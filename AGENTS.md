# PlexiChat Development Guide

## Setup
```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# or source .venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
pip install -e .[dev,test]
```

## Commands
- **Build**: `python -m build` or `make docs`
- **Lint**: `ruff check src tests && pyright src` 
- **Test**: `pytest` or `pytest tests/`
- **Dev Server**: `uvicorn plexichat.main:app --reload --host 0.0.0.0 --port 8000`

## Tech Stack
- **Backend**: FastAPI, SQLAlchemy, Redis, PostgreSQL
- **Auth**: JWT with passlib/bcrypt  
- **Plugins**: Custom plugin system with sandboxing
- **Monitoring**: Prometheus, structlog
- **Testing**: pytest with asyncio support

## Architecture
- `src/plexichat/core/` - Core business logic
- `src/plexichat/infrastructure/` - External integrations
- `src/plexichat/interfaces/` - API endpoints
- `src/plexichat/plugins/` - Plugin system
- `src/plexichat/features/` - Feature modules

## Code Style
- Line length: 88 chars
- Type hints required
- Use ruff, black, isort for formatting
- Async/await for I/O operations
- Pydantic models for data validation