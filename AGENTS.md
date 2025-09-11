# PlexiChat Development Guide

## Setup
```bash
# Create and activate virtual environment
python -m venv .venv
.venv/Scripts/activate  # Windows
source .venv/bin/activate  # Unix

# Install dependencies (choose one)
pip install -e ".[dev,test]"  # OR
python run.py setup --level developer
```

## Commands
- **Build**: `python -m build` (or no explicit build step required)
- **Lint**: `ruff check . && black --check . && pyright` OR `ruff check src/ && black --check src/ && mypy src/`
- **Format**: `black . && isort . && ruff check . --fix`
- **Test**: `pytest` OR `pytest tests/`
- **Dev Server**: `python -m uvicorn plexichat.main:app --reload --port 8000` OR `python run.py`
- **Documentation**: `make docs-serve`

## Tech Stack
- **Framework**: FastAPI with Pydantic v2
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Redis
- **Database**: PostgreSQL with SQLAlchemy 2.0 + Alembic (production), SQLite (dev)
- **Cache**: Redis
- **Architecture**: Clean Architecture with modular plugin system (core/features/infrastructure layers)
- **Auth**: JWT with passlib/bcrypt
- **Security**: JWT auth, passlib, cryptography

## Code Style
- **Formatting**: Black (88 char line length)
- **Imports**: isort with black profile
- **Linting**: Ruff + Pyright/mypy for type checking
- **Testing**: pytest with asyncio support
- **Coverage**: 100% requirement with pytest-cov
- Type hints required (strict mode)
- Use Pydantic for data validation
- Follow existing naming conventions in `src/plexichat/`