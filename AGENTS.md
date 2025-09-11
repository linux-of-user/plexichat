# PlexiChat Agent Guide

## Setup Commands
```bash
# Create and activate virtual environment
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"  # For development dependencies
```

## Build & Development
```bash
python -m build           # Build package
make docs                 # Build documentation
python run.py             # Run application (API server, WebUI, CLI)
python run.py --nowebui   # API server only
```

## Quality Checks
```bash
ruff check src/           # Lint code
black src/                # Format code
mypy src/                 # Type checking
pytest                    # Run tests
pytest -m "not slow"      # Run tests excluding slow ones
```

## Tech Stack
- **Backend**: FastAPI + Pydantic + SQLAlchemy + Redis
- **Architecture**: Plugin-based modular system with core/features/infrastructure layers
- **Database**: PostgreSQL with async support (asyncpg)
- **Security**: Distributed key management, JWT auth, passlib for hashing

## Code Style
- Line length: 88 characters (Black)
- Type hints required (`mypy --strict`)
- Imports organized with isort
- Follow existing patterns in `src/plexichat/` structure