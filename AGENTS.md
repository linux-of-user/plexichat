# PlexiChat Development Guide

## Setup & Commands

### Initial Setup
```bash
python run.py setup --level developer    # Full dev environment with linting/testing tools
python -m venv venv                      # Creates virtual env in ./venv (see .gitignore)
# On Windows: venv\Scripts\activate
# On Unix/macOS: source venv/bin/activate
pip install -r requirements.txt
```

### Build & Development
```bash
python run.py                            # Start API server, WebUI, and CLI
make docs                               # Build documentation 
make docs-serve                         # Serve docs locally (port 8000)
```

### Code Quality
```bash
ruff check src/                         # Lint code
ruff format src/                        # Format code 
mypy src/                              # Type checking
black src/                             # Code formatting
```

### Testing
```bash
pytest                                  # Run all tests
pytest -m unit                         # Unit tests only
pytest --cov=plexichat --cov-report=html  # With coverage
```

## Tech Stack

**Backend**: FastAPI, SQLAlchemy, Redis, PostgreSQL/SQLite  
**Frontend**: FastAPI + WebUI  
**Architecture**: Plugin-based modular system with core/plugins/infrastructure layers  
**Auth**: JWT + bcrypt, 2FA support, unified auth manager  

## Code Style

- **Python 3.11+** with type hints
- **Line length**: 88 chars (Black)
- **Import order**: stdlib → third-party → first-party (isort)
- **Docstrings**: Google style for public APIs
- **No comments** in simple code, prefer descriptive names
