#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL="${1:-$SCRIPT_DIR/aegis_edge-0.1.0-py3-none-any.whl}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/aegis_edge}"

echo "Installing AEGIS EDGE v0.1.0"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    echo "Error: This installer requires Linux x86_64."
    exit 1
fi

if ! command -v python3.12 >/dev/null 2>&1; then
    echo "Error: Python 3.12 is required."
    exit 1
fi

if [[ ! -f "$WHEEL" ]]; then
    echo "Error: Wheel not found: $WHEEL"
    exit 1
fi

mkdir -p "$INSTALL_DIR"
python3.12 -m venv "$INSTALL_DIR/venv"

PYTHON="$INSTALL_DIR/venv/bin/python"

"$PYTHON" -m pip install --upgrade pip

echo "Installing CPU-only PyTorch..."
"$PYTHON" -m pip install torch==2.14.1 \
    --index-url https://download.pytorch.org/whl/cpu

echo "Installing AEGIS EDGE..."
"$PYTHON" -m pip install \
    --only-binary=:all: \
    --no-binary=antlr4-python3-runtime \
    "$WHEEL"

"$PYTHON" -m pip check

echo "Installation completed."
echo "Activate environment:"
echo "  source \"$INSTALL_DIR/venv/bin/activate\""
echo "Place llama32_1b_instruct in $INSTALL_DIR"
echo "Launch from $INSTALL_DIR:"
echo "  aegis-advisor --demo"
echo "  aegis-ui"
