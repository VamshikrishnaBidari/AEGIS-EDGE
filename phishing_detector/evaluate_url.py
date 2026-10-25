"""
evaluate_url.py

AEGIS EDGE — Hybrid Phishing URL Scanner (Bloom Filter + CompPhish/PhishTank RF)
Uses the 73,819-URL Bloom Filter + 15-feature CompPhish Random Forest model
built by build_hybrid_engine.py.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List

from bitarray import bitarray
import joblib
import mmh3
import pandas as pd

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from build_hybrid_engine import extract_features  # noqa: E402

try:
    bloom_array = bitarray()
    with open(MODULE_DIR / "bloom_filter.bin", "rb") as fh:
        bloom_array.fromfile(fh)
    bloom_size = len(bloom_array)
    rf_model = joblib.load(MODULE_DIR / "phishing_rf_model.joblib")
except FileNotFoundError:
    print("Engine files not found. Run build_hybrid_engine.py first.")
    sys.exit(1)


def is_in_bloom(url: str) -> bool:
    s = url.strip().lower().rstrip("/")
    for seed in range(7):
        result = mmh3.hash(s, seed) % bloom_size
        if bloom_array[result] == 0:
            return False
    return True


def explain_prediction(features: Dict[str, Any], bloom_match: bool) -> List[str]:
    evidence = []
    if bloom_match:
        evidence.append("Exact match found in offline PhishTank + CompPhish blacklist (73,819 verified phishing URLs).")
    if features["has_ip"] == 1:
        evidence.append("The URL uses a raw IP address instead of a registered domain name.")
    if features["has_at"] == 1:
        evidence.append("The URL contains an '@' symbol to disguise the real destination host.")
    if features["brand_impersonation"] == 1:
        evidence.append("Brand impersonation detected: a protected brand name appears in the subdomain/domain/path of an unofficial domain.")
    if features["is_shortener"] == 1:
        evidence.append("Uses a URL shortening service (CompPhish shortUrls list) to hide the final destination.")
    if features["is_free_host"] == 1:
        evidence.append("Hosted on a high-abuse free web hosting platform (CompPhish free_hosting list).")
    if features["is_suspicious_tld"] == 1:
        evidence.append("Uses a high-risk top-level domain extension frequently abused in phishing.")
    if features["host_bait_count"] > 0 or features["path_bait_count"] > 0:
        total_kw = features["host_bait_count"] + features["path_bait_count"]
        evidence.append(f"Contains {total_kw} manipulative credential/KYC bait keyword(s) (e.g., login, kyc, update, verify, signin).")
    if features["subdomain_depth"] >= 2:
        evidence.append(f"Uses a deep multi-level subdomain chain ({features['subdomain_depth']} subdomain levels).")
    if features["is_gibberish"] == 1:
        evidence.append(f"CompPhish Markov model flagged random/gibberish domain characters (transition score: {features['markov_prob']:.4f}).")
    return evidence


def inspect_url(url: str) -> Dict[str, Any]:
    feats = extract_features(url)
    if is_in_bloom(url):
        return {
            "url": url,
            "verdict": "PHISHING",
            "confidence": 100,
            "method": "Instant Zero-Latency Bloom Filter Match (PhishTank+CompPhish)",
            "evidence": explain_prediction(feats, True),
            "features": feats,
        }

    X_input = pd.DataFrame([feats])
    proba = rf_model.predict_proba(X_input)[0]
    is_phishing = bool(proba[1] >= 0.5)
    verdict = "PHISHING" if is_phishing else "SAFE"
    confidence = int(round((proba[1] if is_phishing else proba[0]) * 100))
    evidence = explain_prediction(feats, False) if is_phishing else []
    if is_phishing and not evidence:
        evidence.append(f"Lexical URL structure matched phishing profile ({confidence}% ML confidence).")

    return {
        "url": url,
        "verdict": verdict,
        "confidence": confidence,
        "method": "CompPhish + PhishTank Random Forest Engine",
        "evidence": evidence,
        "features": feats,
    }


def evaluate(url: str):
    res = inspect_url(url)
    print(f"\n[+] Scanning URL: {url}")
    print(f"    Verdict: {res['verdict']} (Confidence: {res['confidence']}%)")
    print(f"    Method: {res['method']}")
    if res["evidence"]:
        print("    Evidence for AI:")
        for e in res["evidence"]:
            print(f"      - {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        evaluate(sys.argv[1])
    else:
        print("Hybrid Phishing Engine (CompPhish + PhishTank) - Interactive Mode")
        while True:
            try:
                u = input("\nURL> ").strip()
                if u.lower() in ["q", "quit", "exit"]:
                    break
                if u:
                    evaluate(u)
            except KeyboardInterrupt:
                break
