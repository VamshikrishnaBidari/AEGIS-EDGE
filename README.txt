# AEGIS (Autonomous Edge Guardian for Intelligent Security) EDGE — Complete Structured Codebase (Bharat AI-SoC 2026-27 PS3)

All 4 pillars of the on-device AI cybersecurity assistant and their datasets/models are organized inside `codebase/`:

codebase/
├── llama_advisor.py              # MAIN 4-PILLAR ENTRY POINT (SMS ML + URL Phishing ML + Network + Llama ExecuTorch)
├── aegis_ui.py                   # Desktop UI: Live Monitor + Scam Simulator
├── benchmark_aegis.py            # ARM/CPU benchmark report generator
├── jetson_benchmark_results_001.txt # Recorded benchmark report
├── test_llama.py                 # Standalone Llama-3.2-1B ExecuTorch chat test
├── llama32_1b_instruct/          # Pillar 4: Offline Meta Llama-3.2-1B-Instruct (ExecuTorch XNNPACK)
│   ├── model.pte                 # 8da4w / 8w quantized ExecuTorch model binary
│   ├── tokenizer.json            # Offline tokenizer vocabulary & merges
│   ├── tokenizer_config.json     # Offline tokenizer chat template config
│   └── special_tokens_map.json   # Special tokens map
├── phishing_detector/            # Pillar 3: Hybrid Phishing URL Detector (CompPhish + PhishTank)
│   ├── evaluate_url.py           # Standalone & importable URL phishing scanner
│   ├── build_hybrid_engine.py    # Training script (Bloom Filter + Random Forest)
│   ├── bloom_filter.bin          # 73,819-URL compressed PhishTank+CompPhish blacklist (225 KB)
│   ├── phishing_rf_model.joblib  # Trained 15-feature Random Forest model
│   ├── gib_model.pki             # CompPhish Markov-chain gibberish transition model
│   ├── shortUrls.txt             # CompPhish URL shortener domain list
│   ├── free_hosting_services.txt # CompPhish abused free-hosting domain list
│   ├── sample_brands_new.csv     # CompPhish target brand list
│   ├── phishtank_verified_online.csv # Raw PhishTank dataset (66,615 URLs)
│   ├── Mapping_File.xlsx         # CompPhish labeled dataset (15,358 URLs)
│   ├── Data_Dictionary.xlsx      # CompPhish feature dictionary
│   └── README.txt                # Phishing detector documentation
├── sms_detector/                 # Pillar 2: SMS Scam Ensemble Classifier (Unmodified)
│   ├── sms_scam.py               # Soft-voting TF-IDF + SVM/LR/NB SMS classifier
│   ├── scam_model.joblib         # Pre-trained SMS ensemble model artifact
│   ├── spam.csv                  # Training dataset
│   ├── Bharat SOC/spam.csv       # Default relative path expected by sms_scam.py
│   └── sms_test.txt              # 15 Indian banking/UPI/OTP/KYC test cases
└── traffic_monitor/              # Pillar 1: Network Intrusion Detection System (Unmodified)
    ├── main.py                   # Live packet capture / PCAP replay entry point
    ├── capture.py                # Scapy packet handler (SYN, ICMP, DNS, outbound)
    ├── features.py               # Network feature & DNS Shannon entropy extractor
    ├── detectors.py              # Baseline + rule-based network anomaly detector
    ├── reporting.py              # Periodic terminal report & benchmark logger
    ├── settings.py               # Thresholds and interface configuration
    ├── state.py                  # Sliding window and golden baseline store
    ├── test_dns.py               # Simulated DNS exfiltration / DGA attack script
    └── setup_guide.txt           # Network monitor setup guide

## Quick Start (`venv` is Optional!)

### Option 1: Without `venv` (If you already installed packages globally)
1. Install any missing packages and run:
   cd codebase
   pip install -r requirements.txt
   python llama_advisor.py

For exporting the `.pte` model locally, install the required export package:
   pip install coremltools

### Option 2: With `venv` (Optional — if you use a virtual environment)
1. Activate virtual environment and run:
   source venv/bin/activate      # Windows PowerShell: .\venv\Scripts\Activate.ps1
   cd codebase
   pip install -r requirements.txt
   python llama_advisor.py

### Run Individual Modules Standalone (from inside `codebase/`):
   - Phishing URL Scanner : cd phishing_detector && python evaluate_url.py
   - SMS Scam Detector    : cd sms_detector && python sms_scam.py
   - Network Monitor      : cd traffic_monitor && python main.py --ip <IP> --iface "<IFACE>" (run as Admin/sudo)

### Run the Desktop UI
   python aegis_ui.py

### Benchmark the 8-Bit Quantized Model
   python benchmark_aegis.py --model-dir ".\llama32_1b_instruct" --quant "8da4w / 8w (qembedding)"

The recorded Jetson benchmark shows sub-5-second Llama generation:
   Average LLM total time: 3.762 seconds
   End-to-end throughput: 13.08 tokens/sec
   Model/advisor load time: 6.79 seconds
   Model directory: 923.1 MB
