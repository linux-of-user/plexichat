# PlexiChat Development Guide

## Setup Commands

### Initial Setup
```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
# Or use the custom installer: python run.py setup --level full
```

### Build & Quality
```bash
# Run linting
ruff check src/
black --check src/
isort --check-only src/

# Run type checking
pyright src/

# Run tests
pytest
```

### Development Server
```bash
# Start development server
python run.py

# Or build documentation
make docs-serve
```

## Tech Stack & Architecture

- **Backend**: FastAPI + SQLAlchemy (async) + Pydantic
- **Database**: SQLite (default), PostgreSQL (production)
- **Plugin System**: Dynamic loading with sandboxing
- **Architecture**: Layered (core, infrastructure, interfaces, plugins)
- **Key directories**: `src/plexichat/` (main code), `core/` (business logic), `plugins/` (extensions)

## Code Style

- **Formatting**: Black (88 chars), isort for imports
- **Linting**: Ruff + Pyright for type checking
- **Testing**: pytest with asyncio support, 80%+ coverage required
- **Docstrings**: Google style, type hints mandatory