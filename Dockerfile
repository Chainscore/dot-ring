# Base Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for blst Python binding
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    g++ \
    python3-dev \
    make \
    swig \
    && rm -rf /var/lib/apt/lists/*

# Copy project dependency definitions
COPY pyproject.toml ./

# Upgrade pip and install build tools
RUN pip install --upgrade pip setuptools wheel build

# Copy the rest of your library
COPY . .

# Build and install your library
RUN python -m build && pip install dist/*.whl

# Clone blst and build its Python bindings
RUN git clone https://github.com/supranational/blst.git /opt/blst \
    && cd /opt/blst/bindings/python \
    && ./run.me

# Add blst Python bindings to PYTHONPATH
ENV PYTHONPATH="/opt/blst/bindings/python"

# Install pytest and run tests with coverage
RUN pip install --no-cache-dir pytest pytest-cov
RUN pytest tests/ \
    --cov=dot_ring \
    --cov-report=term-missing \
    --cov-report=html \
    -v \
    --tb=short


CMD ["python"]
