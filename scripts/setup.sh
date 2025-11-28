#!/bin/bash
set -e

echo "🚀 Starting setup..."

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "uv could not be found. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

echo "📦 Installing dependencies..."
uv sync --extra dev

echo "🔧 Setting up environment (blst + cython)..."
uv run python scripts/setup_env.py
