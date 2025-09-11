# Multi-stage Dockerfile for PlexiChat
# Stage 1: Base
FROM python:3.11-slim as base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy pyproject.toml and lock files
COPY pyproject.toml poetry.lock* requirements*.txt ./

# Stage 2: Development stage
FROM base as dev

# Install development dependencies including Cython
RUN pip install --no-cache-dir -e ".[dev]"

# Copy source code
COPY . .

# Build Cython extensions
RUN make cythonize

# Stage 3: Production stage
FROM base as prod

# Copy minimal requirements
COPY requirements-minimal.txt .

# Install minimal runtime dependencies
RUN pip install --no-cache-dir -r requirements-minimal.txt

# Copy application code
COPY src/ ./src/

# Copy compiled Cython extensions from dev stage
COPY --from=dev /app/build/ ./build/

# Create non-root user
RUN useradd --uid 1000 --create-home app
USER app

# Expose port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "plexichat.main:app", "--host", "0.0.0.0", "--port", "8000"]