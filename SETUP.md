# AEGIS EDGE — Complete Setup, Export & Testing Guide (`SETUP.md`)

This guide walks you through setting up and running **AEGIS EDGE** (Problem Statement 3 — ARM Bharat AI-SoC Challenge 2026–27) on **Windows**, **Ubuntu / Debian / Raspberry Pi OS**, or **Fedora Linux**.

---

## 1. Prerequisites & System Packages

Because the Network Intrusion module (`traffic_monitor/`) uses `scapy` for live packet capture, install the packet capture library for your OS first:

* **Ubuntu / Debian / Raspberry Pi OS:**
  ```bash
  sudo apt update
  sudo apt install python3 python3-venv python3-pip libpcap-dev tcpdump
  ```
* **Fedora Linux:**
  ```bash
  sudo dnf update
  sudo dnf install python3 python3-pip libpcap-devel tcpdump
  ```
* **Windows:**
  1. Install **Python 3** from [python.org](https://www.python.org/downloads/) (check **"Add Python to PATH"** during installation).
  2. Install **Npcap** from [npcap.com/#download](https://npcap.com/#download) (required by Scapy on Windows; default installer options are fine).

---

## 2. Python Environment & Library Installation (`venv` is Optional!)

You can run this project **either** with your global Python installation **or** inside a Python virtual environment (`venv`).

### Option A: Without `venv` (Direct / Global Python)
If you have never used `venv` and already installed packages like `optimum-executorch`, `torch`, or `scikit-learn` globally, **you do not need `venv`**.
```bash
cd codebase
pip install -r requirements.txt
```
*(Any packages you already installed globally will be reused automatically without re-downloading. On Linux, if `pip` warns about an externally managed environment, add `--break-system-packages`.)*

### Option B: With `venv` (Optional Isolated Environment)
If you prefer an isolated environment (or are on Fedora/Ubuntu where `venv` is standard):
* **Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  cd codebase
  pip install -r requirements.txt
  ```
* **Windows (PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  cd codebase
  pip install -r requirements.txt
  ```

> **Why `requirements.txt` is fast and lightweight:**  
> It includes `--extra-index-url https://download.pytorch.org/whl/cpu` at the top so `pip` pulls the lightweight CPU wheels for `torch` and `optimum-executorch` (matching our XNNPACK `.pte` runtime) instead of downloading 3+ GB of unused NVIDIA CUDA libraries.

### Jetson Nano Reproducible Environment
For the pinned Jetson Nano environment used for benchmarking, install the Jetson lock file:
```bash
pip install -r requirements-lock.txt
```
`requirements-lock.txt` is a full environment snapshot, not a portable cross-platform dependency list. It contains Jetson/Ubuntu-specific packages and system generated local wheel references, so it may not install unchanged on Raspberry Pi, Windows, or a desktop Linux machine. Use `requirements.txt` for normal setup and the lock file when reproducing the recorded Jetson Nano environment.

---

## 3. Getting `model.pte` (Hugging Face Approval & ExecuTorch Export)

Because `model.pte` is large, it is excluded from GitHub via `.gitignore`. The current quantized export is approximately 915 MB. The offline tokenizer files (`tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json`) are already included inside `codebase/llama32_1b_instruct/`.

You can get `model.pte` in **one of two ways**:
* **Copy a published model folder:** If you have a separately distributed `llama32_1b_instruct` folder, copy it into `codebase/llama32_1b_instruct/`. You do **not** need a Hugging Face account or export step.
* **Export locally once via Hugging Face:** Follow the steps below once on your machine.

### Step 3.1: Request Meta Llama Access on Hugging Face
`Llama-3.2-1B-Instruct` is a gated model on Hugging Face—you must accept Meta's community license once:
1. Create or log in to your account at [huggingface.co](https://huggingface.co/).
2. Visit [**meta-llama/Llama-3.2-1B-Instruct**](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct).
3. Fill in the brief license form and click **"Agree and access repository"** (approval is usually granted within a few minutes).

### Step 3.2: Create a Hugging Face Read Token
1. Go to [**huggingface.co/settings/tokens**](https://huggingface.co/settings/tokens).
2. Click **"Create new token"**, select **Read** permissions, and copy the generated `hf_...` token.

### Step 3.3: Log in from Your Terminal
Run the login command and paste your token when prompted:
```bash
huggingface-cli login
```
*(Or on newer versions of `huggingface_hub`: `hf auth login`)*

### Step 3.4: Export the Quantized `.pte` Model (Run Once)
From inside the `codebase/` directory, install the export dependency and run the exact command:
```bash
pip install coremltools

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
On Windows PowerShell, use `--output_dir ".\llama32_1b_instruct"`.
* **What this does:** Downloads `Llama-3.2-1B-Instruct`, applies 8-bit dynamic activation / 4-bit linear weight quantization (`8da4w`) plus 8-bit embedding quantization (`8w`), enables custom SDPA and KV cache, compiles for the **XNNPACK** CPU backend, and writes `codebase/llama32_1b_instruct/model.pte`.
* Once the export is complete, run the advisor with `python llama_advisor.py --model-dir ".\llama32_1b_instruct"`. Everything runs 100% offline after export (you can completely disconnect from the internet).

---

## 4. Running & Testing the Unified 4-Pillar System (`llama_advisor.py`)

> ### ⚠️ Offline Model Response Time (Sub-5 Seconds)
> When you test `llama_advisor.py`, you will see **two stages** of output for every query:
> 1. **Stage 1 — `[FAST SENSOR BREAKDOWN]` (~5 to 35 milliseconds):**  
>    Prints **instantly**! It runs the SMS Ensemble ML classifier and the PhishTank/CompPhish Hybrid URL Detector **in parallel**, checks Indian OTP/UPI/KYC fraud patterns, and displays the fused verdict and technical evidence immediately.
> 2. **Stage 2 — `>>> AEGIS Llama Advisory` (typically ~3.5–4.0 seconds):**  
>    The 8-bit quantized `Llama-3.2-1B-Instruct` model generates the plain-English explanation and remediation steps **100% offline on your CPU via ExecuTorch/XNNPACK**. The recorded ARM benchmark averaged 13.08 end-to-end tokens/sec and 3.762 seconds per response.

### Run Interactive Mode
```bash
cd codebase
python llama_advisor.py
```

### Or Run the Automated 4-Case Demo
```bash
cd codebase
python llama_advisor.py --demo
```

### Run the Standalone Llama Test
```bash
python tests/test_llama.py
```

### Run the Desktop UI
```bash
cd codebase
python aegis_ui.py
```
The UI provides a Live Monitor tab with CPU/RAM/network telemetry and a Scam Simulator tab with preset and custom messages.

### Run the ARM/Edge Benchmark
```bash
cd codebase
python tests/benchmark_aegis.py \
  --model-dir ".\llama32_1b_instruct" \
  --quant "8da4w / 8w (qembedding)"
```
The benchmark writes a timestamped `benchmark_summary_*.txt` report under `tests/` unless `--out-file` is supplied. Use `--skip sustained` for a faster run, or `--skip sustained offline` for only detection and LLM measurements.

### Build a Wheel and Linux Executables

The wheel and standalone distributions exclude `llama32_1b_instruct/model.pte`. Keep the model outside the package and place it beside the executable distribution after build.

#### Desktop Linux (`x86_64`)
Run from the repository root on a Linux `x86_64` machine:
```bash
bash packaging/build_linux_x86_64.sh
```
The desktop build script prefers a sibling `../venv/bin/python` environment when it exists. Override it with `PYTHON_BIN=/path/to/python bash packaging/build_linux_x86_64.sh`.

#### Jetson/Linux (`aarch64`)
Run from the repository root on the actual Jetson/Linux ARM64 target:
```bash
bash packaging/build_jetson_linux_arm64.sh
```

The build scripts produce:
- `dist/aegis_edge-*.whl`
- `dist/aegis_advisor/` (`--onedir`)
- `dist/aegis_ui/` (`--onedir`)

Install the wheel without the model on a compatible Linux Python environment:
```bash
python -m pip install dist/aegis_edge-*.whl
aegis-advisor
aegis-ui
```

For the standalone builds, copy or generate `llama32_1b_instruct/` beside `dist/`, then run:
```bash
./dist/aegis_advisor/aegis_advisor
./dist/aegis_ui/aegis_ui
```

The model is intentionally outside the generated artifacts. This avoids embedding approximately 914 MB in the wheel and avoids one-time extraction delays and dynamic-library issues from a PyInstaller `--onefile` build.

Live packet capture still requires Linux `sudo` or Administrator privileges plus the platform's packet-capture library.

### Install from the Wheel
The wheel is a lightweight Python package. It does not include `llama32_1b_instruct/model.pte`.

```bash
python3 -m venv aegis-venv
source aegis-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --extra-index-url https://download.pytorch.org/whl/cpu \
  dist/aegis_edge-0.1.0-py3-none-any.whl
```

On Windows PowerShell:

```powershell
py -3 -m venv aegis-venv
.\\aegis-venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install dist\aegis_edge-0.1.0-py3-none-any.whl
```

After installation, place or export `llama32_1b_instruct/` in the working directory:

```text
working-directory/
├── llama32_1b_instruct/
│   ├── model.pte
│   ├── tokenizer.json
│   ├── tokenizer_config.json
│   └── special_tokens_map.json
└── aegis-wheel.whl
```

Run the installed console entry points:

```bash
aegis-advisor --model-dir ./llama32_1b_instruct
aegis-ui
```

Alternative source-style commands remain available in a source checkout:

```bash
python llama_advisor.py --model-dir ./llama32_1b_instruct
python aegis_ui.py
```

For live packet capture, run the Linux binary or source under `sudo` or the Windows executable under Administrator/Npcap.

---

## 5. Copy-Paste Test Suite for `llama_advisor.py`

When `Alert/SMS/URL>` appears in interactive mode, paste any of these to test all 4 pillars:

### Test 1: Indian UPI PIN Collect Trap + Phishing URL (Parallel SMS + URL Check)
```text
Dear Customer, Rs. 15,500 has been successfully credited to your bank account via PhonePe. Click here to claim your reward and enter UPI PIN to receive the money: http://claim-reward-fake.in
```
* **Expected Fast Sensor Verdict:** `CRITICAL_SCAM (100%)` — catches both the UPI PIN trap (*you never enter a UPI PIN to receive money*) and flags `http://claim-reward-fake.in` as `PHISHING` in parallel.

### Test 2: Fake Telecom SIM KYC Disconnection + Phishing Link
```text
Dear Vi User, your SIM card KYC is pending. Your outgoing calls will be stopped at 9:00 PM tonight. Update via Aadhaar link: http://vi-sim-update.com
```
* **Expected Fast Sensor Verdict:** `SCAM (100%)` — flags urgency coercion + `PHISHING` link.

### Test 3: HDFC Credit Card OTP-Sharing Social Engineering Trap
```text
URGENT: We detected a suspicious transaction of Rs 49,999 on your HDFC Credit Card. If this was NOT you, please share the 6-digit OTP sent to your phone with our agent to cancel the transaction.
```
* **Expected Fast Sensor Verdict:** `CRITICAL_SCAM (98%)` — catches the OTP-sharing social engineering trap (*banks never ask you to share an OTP to cancel a transaction*).

### Test 4: Genuine Indian Bank UPI Credit / OTP Notification (Zero False-Alarm Test)
```text
Dear Customer, Rs.12,500.00 credited to your A/c No XXXXXX9802 on 11-10-26 by UPI Ref No 628410987654. Available Balance: Rs 84,230.50. Download YONO SBI app for more details. - SBI
```
* **Expected Fast Sensor Verdict:** `LEGITIMATE_BANK_ALERT (SAFE)` — verifies there are no phishing links or OTP-sharing traps and reassures the user.

### Test 5: Standalone URLs (Phishing vs. Legitimate)
```text
http://google.com.example.test/verify-account
```
* **Expected Verdict:** `PHISHING_URL (100%)`

```text
https://arm-education.github.io/Arm-Developer-Labs/Bharat_AI_SoC_2026_27.html
```
* **Expected Verdict:** `SAFE_URL (80%)`

### Test 6: Simulated Network Intrusion Alert (DNS Exfiltration / DGA)
```text
net
```
* Typing `net` feeds a real `dns_anomaly` alert payload from `traffic_monitor` into `llama_advisor.py` and generates a plain-English explanation of the DNS exfiltration attack.

---

## 6. Running Individual Pillars Standalone

If you want to test or develop any of the 3 sensor modules independently without loading the quantized Llama model:

1. **Pillar 3 — Hybrid Phishing URL Scanner (`phishing_detector/`):**
   ```bash
   cd codebase/phishing_detector
   python evaluate_url.py
   ```
   *(To retrain `bloom_filter.bin` and `phishing_rf_model.joblib` from `phishtank_verified_online.csv` + `Mapping_File.xlsx`, run `python build_hybrid_engine.py`.)*

2. **Pillar 2 — SMS Scam Detector (`sms_detector/`):**
   ```bash
   cd codebase/sms_detector
   python sms_scam.py
   ```

3. **Pillar 1 — Network Intrusion Monitor (`traffic_monitor/`):**
   * Find your active IPv4 address and network interface (`ip a` on Linux; `ipconfig` and `Get-NetAdapter` on Windows).
   * Start live monitoring (requires `sudo` on Linux or Administrator PowerShell on Windows):
     ```bash
     cd codebase/traffic_monitor
     sudo python3 main.py --ip <YOUR_IPV4> --iface "<YOUR_INTERFACE>"
     ```
     If monitoring with a Linux virtual environment, use the environment's Python executable:
     ```bash
     cd codebase/traffic_monitor
     sudo ../../venv/bin/python main.py --ip <YOUR_IPV4> --iface "<YOUR_INTERFACE>"
     ```
   * Once `baseline ready` appears, simulate a DNS exfiltration attack from another terminal:
     ```bash
     sudo python3 test_dns.py
     ```
   * Or simulate a port scan from another device on the same hotspot using `nmap -Pn -p 1-100 <YOUR_IPV4>`.
