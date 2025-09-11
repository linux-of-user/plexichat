# PlexiChat Development Guide

## Setup Commands
```bash
python -m venv .venv
.venv/Scripts/activate  # Windows
source .venv/bin/activate  # Unix
pip install -e ".[dev,test]"
```

## Development Commands
- **Build**: `python -m build`
- **Lint**: `ruff check . && black --check . && pyright`
- **Format**: `black . && isort . && ruff check . --fix`
- **Test**: `pytest`
- **Dev Server**: `python -m uvicorn plexichat.main:app --reload --port 8000`
- **Documentation**: `make docs-serve`

## Tech Stack
- **Framework**: FastAPI with Pydantic v2
- **Database**: PostgreSQL with SQLAlchemy 2.0 + Alembic
- **Cache**: Redis
- **Architecture**: Clean Architecture with plugin system
- **Auth**: JWT with passlib/bcrypt

## Code Style
- **Formatting**: Black (88 char line length)
- **Imports**: isort with black profile
- **Linting**: Ruff + Pyright for type checking
- **Testing**: pytest with asyncio support
- **Coverage**: 100% requirement with pytest-cov