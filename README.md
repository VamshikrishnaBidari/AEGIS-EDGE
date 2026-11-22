# AEGIS EDGE

**On-Device AI Cybersecurity Assistant**

ARM Bharat AI-SoC Challenge 2026-27 | Problem Statement 3

AEGIS EDGE combines fast, offline threat sensors with a local
Meta Llama-3.2-1B-Instruct model to explain and prioritize cybersecurity risks:

- SMS scam classification
- Hybrid phishing URL detection
- Network intrusion monitoring
- Offline plain-language security advice

Fast sensor verdicts normally return in milliseconds. The quantized
ExecuTorch/Llama stage generates responses locally without cloud API calls.

## Distribution Options

**Release downloads:** [AEGIS EDGE v0.1.0](https://github.com/VamshikrishnaBidari/AEGIS-EDGE/releases/tag/v0.1.0)

Choose the option appropriate for your platform:

| Option | Use |
| --- | --- |
| Source repository | Development, audit, or custom installation |
| Python wheel | Portable Python installation on a compatible OS and architecture |
| Linux `x86_64` onedir binary | Desktop Linux distribution without a Python environment |
| Linux ARM64 onedir binary | Released and tested on NVIDIA Jetson Orin Nano (Ubuntu 22.04 / JetPack 6) |
| Windows onedir binary | Not released or tested as a native binary |

The `llama32_1b_instruct/model.pte` file is deliberately distributed outside
source packages and executables. It can be generated once or copied as a
separate model folder.

## Quick Start from Source

### 1. Install system prerequisites

Ubuntu, Debian, Raspberry Pi OS, or Jetson:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk \
  libpcap-dev tcpdump
```

Fedora:

```bash
sudo dnf install -y python3 python3-pip python3-tkinter libpcap-devel tcpdump
```

Windows:

1. Install Python 3 and add it to `PATH`.
2. Install Npcap using the [official Npcap installer](https://npcap.com/#download).

### 2. Create a Python environment

Linux:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -3 -m venv venv
.\\venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` contains the portable dependency set.
`requirements-lock.txt` is a snapshot of a Jetson environment, not a portable
or guaranteed reproducible installation. The tested ARM64 release uses prebuilt
binaries and does not require installing Python dependencies.

### 3. Obtain the Llama model

Copy `llama32_1b_instruct/` into the repository root, or export it once.
The folder must contain:

```text
llama32_1b_instruct/
├── model.pte
├── tokenizer.json
├── tokenizer_config.json
└── special_tokens_map.json
```

To export the model, accept the
[Meta Llama model license](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct),
create a Hugging Face read token, and authenticate:

```bash
pip install coremltools
huggingface-cli login
```

Then run:

```bash
optimum-cli export executorch \
  --model "meta-llama/Llama-3.2-1B-Instruct" \
  --task "text-generation" \
  --recipe "xnnpack" \
  --use_custom_sdpa \
  --use_custom_kv_cache \
  --qlinear 8da4w \
  --qembedding 8w \
  --output_dir "./llama32_1b_instruct"
```

The model is approximately 914 MB and is not downloaded or packaged by the
wheel or standalone binary build.

### 4. Run AEGIS

Terminal advisor:

```bash
python llama_advisor.py --model-dir ./llama32_1b_instruct
```

Automated demo:

```bash
python llama_advisor.py --demo --model-dir ./llama32_1b_instruct
```

Desktop UI:

```bash
python aegis_ui.py
```

Standalone Llama test:

```bash
python tests/test_llama.py
```

## Install from the Python Wheel

The v0.1.0 wheel installation requires **Python 3.12** and compatible
architecture-specific PyTorch/ExecuTorch dependencies. For Jetson Orin Nano,
use the tested ARM64 standalone binaries below instead.

When a `aegis_edge-*.whl` release asset is available:

```bash
python3 -m venv aegis-venv
source aegis-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu \
  aegis_edge-0.1.0-py3-none-any.whl
```

Windows:

```powershell
py -3 -m venv aegis-venv
.\\aegis-venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install aegis_edge-0.1.0-py3-none-any.whl
```

Copy or export `llama32_1b_instruct/` into the working directory, then run:

```bash
aegis-advisor --model-dir ./llama32_1b_instruct
aegis-ui
```

The wheel contains AEGIS source modules and detector artifacts. It does not
contain the model weights. PyTorch and ExecuTorch dependencies remain
platform- and architecture-specific, so install the wheel in a compatible
Python environment.

## Run a Linux `x86_64` Binary Release

Download the x86_64 archive from the [v0.1.0 release](https://github.com/VamshikrishnaBidari/AEGIS-EDGE/releases/tag/v0.1.0).

Extract the released `aegis_advisor` or `aegis_ui` archive. Place
`llama32_1b_instruct/` beside the executable distribution:

```text
aegis-release/
├── aegis_advisor/
├── aegis_ui/
└── llama32_1b_instruct/
```

Run:

```bash
./aegis_advisor/aegis_advisor --model-dir ./llama32_1b_instruct
./aegis_ui/aegis_ui
```

Linux binaries require matching `x86_64` host libraries. Live packet capture
also requires `sudo` or the appropriate packet-capture privileges.

## Install the Linux ARM64 Release (NVIDIA Jetson Orin Nano)

The v0.1.0 ARM64 CLI and GUI binaries were built and tested on an NVIDIA
Jetson Orin Nano running Ubuntu 22.04 / JetPack 6. Other ARM64 distributions
have not been verified. These standalone packages do **not** require a Python
virtual environment.

From the [v0.1.0 release](https://github.com/VamshikrishnaBidari/AEGIS-EDGE/releases/tag/v0.1.0),
download all three files into the **same directory**:

- `aegis-advisor-0.1.0-linux-arm64.tar.gz`
- `aegis-ui-0.1.0-linux-arm64.tar.gz`
- `install_linux_arm64.sh`

Then run on the ARM64 device:

```bash
chmod +x install_linux_arm64.sh
./install_linux_arm64.sh
```

The installer extracts both applications to `~/aegis_edge/` (or
`$AEGIS_INSTALL_DIR`) and creates launch symlinks in `~/.local/bin/` (or
`$AEGIS_BIN_DIR`). The model is **not included**.

Place the exported model folder at `~/aegis_edge/llama32_1b_instruct/`,
containing `model.pte` and tokenizer files. If the model was present when the
installer ran, it links the model into both application directories. If you
added the model **after** installation, run:

```bash
for app in advisor ui; do
  ln -sfn "$HOME/aegis_edge/llama32_1b_instruct" \
    "$HOME/aegis_edge/aegis_${app}/llama32_1b_instruct"
done
```

Launch from each application directory so the model is found:

```bash
cd ~/aegis_edge/aegis_advisor && ./aegis_advisor
cd ~/aegis_edge/aegis_ui && ./aegis_ui
```

To verify downloads, use `sha256sum -c SHA256SUMS-arm64.txt` in a directory
containing the ARM64 release archives and checksum file.

## Benchmarking

Run the benchmark from the source repository:

```bash
python tests/benchmark_aegis.py \
  --model-dir ./llama32_1b_instruct \
  --quant "8da4w / 8w (qembedding)"
```

Recorded Jetson benchmark results are in
[tests/jetson_benchmark_results_001.txt](./tests/jetson_benchmark_results_001.txt).

## Network Monitor

Find the active interface and IP address, then run:

```bash
cd traffic_monitor
sudo python3 main.py --ip <YOUR_IPV4> --iface "<YOUR_INTERFACE>"
```

Simulate a DNS anomaly from another terminal:

```bash
cd traffic_monitor
sudo python3 test_dns.py
```

Scapy packet capture requires elevated privileges on Linux and Administrator
plus Npcap on Windows.

## Repository Layout

```text
.
├── README.md
├── SETUP.md
├── pyproject.toml
├── requirements.txt
├── requirements-lock.txt
├── llama_advisor.py
├── aegis_ui.py
├── llama32_1b_instruct/
├── phishing_detector/
├── sms_detector/
├── traffic_monitor/
├── tests/
└── packaging/
```

Detailed setup, test cases, export commands, and platform build instructions
are in [SETUP.md](./SETUP.md).
