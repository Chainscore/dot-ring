# Base Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for blst Python binding and Cython
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    python3-dev \
    make \
    swig \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY . .

# Install dependencies
RUN uv sync --extra dev

# Setup environment (blst + cython)
RUN uv run python scripts/setup_env.py

# Run tests
RUN uv run pytest tests/ \
    --cov=dot_ring \
    --cov-report=term-missing \
    --cov-report=html \
    -v \
    --tb=short

CMD ["uv", "run", "python"]
