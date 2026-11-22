#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  :
elif [[ -x "$ROOT_DIR/../venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT_DIR/../venv/bin/python"
else
  PYTHON_BIN="python3"
fi

ARCH="$(uname -m)"
if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
  echo "This build script must run on the Jetson/Linux ARM64 target." >&2
  exit 1
fi

"$PYTHON_BIN" -m pip install --upgrade build wheel pyinstaller
"$PYTHON_BIN" -m build --wheel

"$PYTHON_BIN" -m PyInstaller \
  --noconfirm --clean --onedir \
  --name aegis_advisor \
  --add-data "sms_detector:sms_detector" \
  --add-data "phishing_detector:phishing_detector" \
  --add-data "traffic_monitor:traffic_monitor" \
  --collect-all executorch \
  --collect-binaries executorch \
  --collect-submodules executorch \
  --collect-data executorch \
  --hidden-import executorch.extension.pybindings.data_loader \
  --hidden-import executorch.extension.pybindings._C \
  --collect-all optimum \
  --collect-all optimum.executorch \
  --collect-all torch \
  --collect-all torchao \
  --collect-all transformers \
  --collect-all scapy \
  --collect-all tldextract \
  --collect-all sklearn \
  --collect-all scipy \
  --collect-all pandas \
  --collect-all numpy \
  --collect-all joblib \
  llama_advisor.py

"$PYTHON_BIN" -m PyInstaller \
  --noconfirm --clean --onedir \
  --name aegis_ui \
  --add-data "sms_detector:sms_detector" \
  --add-data "phishing_detector:phishing_detector" \
  --add-data "traffic_monitor:traffic_monitor" \
  --collect-all executorch \
  --collect-binaries executorch \
  --collect-submodules executorch \
  --collect-data executorch \
  --hidden-import executorch.extension.pybindings.data_loader \
  --hidden-import executorch.extension.pybindings._C \
  --collect-all optimum \
  --collect-all optimum.executorch \
  --collect-all torch \
  --collect-all torchao \
  --collect-all transformers \
  --collect-all customtkinter \
  --collect-all scapy \
  --collect-all tldextract \
  --collect-all sklearn \
  --collect-all scipy \
  --collect-all pandas \
  --collect-all numpy \
  --collect-all joblib \
  aegis_ui.py

if find dist -type f -name "*.pte" -print -quit | grep -q .; then
  echo "Packaging verification failed: model.pte was bundled." >&2
  exit 1
fi

echo "Jetson/Linux ARM64 wheel: dist/aegis_edge-*.whl"
echo "Jetson/Linux ARM64 executables: dist/aegis_advisor/ and dist/aegis_ui/"
