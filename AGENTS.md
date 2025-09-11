# PlexiChat Development Guide

## Setup Commands
```bash
# Initial setup
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev,test]"
```

## Development Commands
```bash
# Run tests
pytest tests/

# Run linting
ruff check src/ tests/
black --check src/ tests/
isort --check-only src/ tests/

# Run build
python -m build

# Run dev server
python run.py
```

## Tech Stack & Architecture
- **Backend**: FastAPI with SQLAlchemy, AsyncPG, Redis
- **Architecture**: Plugin-based system with core services
- **Structure**: Modular design with `core/`, `features/`, `infrastructure/`, `plugins/`
- **Database**: PostgreSQL with Alembic migrations
- **Auth**: JWT with bcrypt, MFA support

## Code Style
- Line length: 88 characters (Black)
- Type hints required (Pyright/MyPy)
- Import organization: isort with Black profile
- Testing: pytest with asyncio support, 100% coverage target
- Docstrings: Required for public APIs