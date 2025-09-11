# PlexiChat - Agent Development Guide

## Setup Commands
- **Virtual environment**: `python -m venv venv` (virtual environment stored in `venv/`)
- **Install dependencies**: `python run.py setup --level developer`
- **Activate environment**: `source venv/bin/activate` (Unix) / `venv\Scripts\activate` (Windows)

## Development Commands
- **Build**: `make docs` (documentation build)
- **Lint**: `ruff check src/ && black --check src/ && mypy src/`
- **Tests**: `pytest` (with coverage reporting)
- **Dev server**: `python run.py serve`

## Tech Stack
- **Backend**: FastAPI with SQLAlchemy ORM, Redis, PostgreSQL
- **Architecture**: Plugin-based system with core/features/infrastructure layers
- **Authentication**: JWT with bcrypt hashing
- **Testing**: pytest with asyncio support

## Code Style
- **Formatting**: Black (88 char line length)
- **Import sorting**: isort with Black profile
- **Type checking**: MyPy in strict mode
- **Linting**: Ruff with extensive rule set (E, W, F, I, B, C4, UP, ARG, SIM, TCH, PTH, ERA, PL, RUF)
- **Coverage**: 100% required for test coverage