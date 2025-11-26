#!/bin/bash
set -e

echo "🚀 Starting setup..."

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "uv could not be found. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source the env to make uv available in the current shell if possible, 
    # but usually it requires a shell restart or sourcing .cargo/env
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

# Install dependencies
echo "📦 Installing dependencies..."
uv sync --extra dev

# Run setup script (blst + cython)
echo "🔧 Setting up environment (blst + cython)..."
uv run python scripts/setup_env.py
