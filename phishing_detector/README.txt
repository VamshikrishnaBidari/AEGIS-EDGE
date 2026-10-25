# Hybrid Phishing URL Detector

## Overview
This module is a highly optimized, offline-capable Phishing URL Detector designed specifically for edge devices (Raspberry Pi, Arm-based smartphones, etc.) with strict memory and compute constraints. 

Instead of relying on cloud APIs or loading massive datasets into RAM, it uses a two-stage Hybrid Architecture:
1. **The Bloom Filter (Zero-Latency Blacklist):** Compresses over 66,000 known phishing URLs (from PhishTank) into a highly efficient probabilistic data structure (~187 KB). This allows `O(1)` instant lookups with almost zero memory footprint.
2. **The Machine Learning Engine (Zero-Day Detection):** A lightweight Random Forest classifier trained to evaluate the structural and lexical features of a URL (e.g., entropy, presence of IP addresses, suspicious keywords). It catches brand-new phishing links that aren't on any blacklist yet.

Crucially, the engine outputs **plain-English evidence sentences** alongside its verdict. This is formatted specifically to be fed into the Llama / ExecuTorch AI agent required by the competition.

## Files Included
* `evaluate_url.py` - The main inference script. Use this to test URLs.
* `build_hybrid_engine.py` - The training script. Use this to rebuild the models if the dataset updates.
* `bloom_filter.bin` - The compressed blacklist of 66k+ active phishing URLs.
* `phishing_rf_model.joblib` - The trained Random Forest machine learning model.
* `phishtank_verified_online.csv` - The raw training data (can be deleted from the edge device after building).

## Setup Instructions

1. **Prerequisites (Linux/Fedora):**
   Ensure Python 3 is installed on your system.

2. **Create a Virtual Environment:**
   It is highly recommended to run this inside an isolated environment.
   > python3 -m venv venv
   > source venv/bin/activate

3. **Install Required Libraries:**
   > pip install pandas scikit-learn tldextract bitarray mmh3 joblib

## How to Run (Testing)

You do not need to train the model; the pre-trained `.bin` and `.joblib` files are already included.

**Interactive Mode:**
Start the scanner and paste URLs into the prompt.
> source venv/bin/activate
> python evaluate_url.py

**Command-Line Mode:**
Pass a single URL directly for integration with other scripts.
> source venv/bin/activate
> python evaluate_url.py "http://secure-login-update.example.com"

## Architecture Breakdown

### 1. Feature Extraction (`tldextract`, `math`, `re`)
When a URL is scanned, it is broken down into 8 numerical features:
- Length of URL
- Number of dots
- Has IP Address (Boolean)
- Has '@' Symbol (Boolean)
- Number of hyphens
- Shannon Entropy (Mathematical randomness of the domain name)
- Suspicious Keyword Count (login, kyc, update, wallet, etc.)
- Length of the Subdomain

### 2. The Engine
- **Fast Path:** The URL is hashed (MurmurHash3) and checked against `bloom_filter.bin`. If there is a match, it returns `PHISHING` instantly.
- **Slow Path:** If not in the Bloom Filter, the 8 features are passed to `phishing_rf_model.joblib`. The Random Forest outputs a probability score.

### 3. The Explainability Hook
If an attack is detected, the features that triggered the alarm are converted into readable evidence (e.g., "The domain name appears to be randomly generated"). This readies the data for the PS3 Llama-based advisory agent.
