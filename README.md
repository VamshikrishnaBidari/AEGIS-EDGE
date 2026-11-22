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

Choose the option appropriate for your platform:

| Option | Use |
| --- | --- |
| Source repository | Development, audit, or custom installation |
| Python wheel | Portable Python installation on a compatible OS and architecture |
| Linux `x86_64` onedir binary | Desktop Linux distribution without a Python environment |
| Linux ARM64 onedir binary | Jetson or other ARM64 Linux devices |
| Windows onedir binary | Windows distribution, when a native Windows build is released |

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
`requirements-lock.txt` is a Jetson Nano environment snapshot and is not
recommended for other platforms.

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
  --output_dir ".\llama32_1b_instruct"
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
