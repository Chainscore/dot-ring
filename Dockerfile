FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc g++ make swig \
    python3-dev libgmp-dev libmpfr-dev libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY . .

# Set version for setuptools-scm
ENV SETUPTOOLS_SCM_PRETEND_VERSION=1.0.0

# Install build tools first
RUN uv pip install --system setuptools wheel Cython build

# Build blst and Cython extensions
RUN python scripts/setup_env.py

# Install project with all dependencies from pyproject.toml
RUN uv pip install --system --no-build-isolation -e ".[dev]"

# Run tests
RUN uv run pytest tests/ -v --tb=short

# Default: run tests
CMD ["uv", "run", "pytest", "tests/", "-v"]
