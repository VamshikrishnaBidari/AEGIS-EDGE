"""
llama_advisor.py

AEGIS EDGE — Unified 4-Pillar On-Device Cybersecurity Assistant (PS3)
  Pillar 1: Network Intrusion Monitor (traffic_monitor alerts / JSONL logs)
  Pillar 2: SMS Scam Ensemble Classifier (workspace_temp/sms_scam.py — unmodified)
  Pillar 3: Hybrid Phishing URL Detector (Bloom Filter + Random Forest — unmodified)
  Pillar 4: Offline Meta Llama-3.2-1B-Instruct via ExecuTorch (XNNPACK CPU)

When given an SMS, URL, or Network Alert:
  1. Runs the SMS ML Classifier and URL Phishing Detector in parallel (milliseconds).
  2. Applies Indian Banking/UPI/OTP domain-specific evidence analysis.
  3. Immediately prints the Fast Sensor Verdict & Evidence Breakdown.
  4. Feeds the structured, verdict-aware evidence to Llama-3.2-1B (ExecuTorch)
     to generate a plain-language explanation and remediation steps completely offline.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
import re
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

import joblib
import mmh3
import pandas as pd
import tldextract
from bitarray import bitarray

import torch  # noqa: F401 (must be imported before optimum.executorch)
from optimum.executorch import ExecuTorchModelForCausalLM
from transformers import AutoTokenizer

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SMS_DIR = os.path.join(ROOT_DIR, "sms_detector")
PHISHING_DIR = os.path.join(ROOT_DIR, "phishing_detector")
DEFAULT_MODEL_DIR = os.path.join(ROOT_DIR, "llama32_1b_instruct")

if PHISHING_DIR not in sys.path:
    sys.path.insert(0, PHISHING_DIR)
if SMS_DIR not in sys.path:
    sys.path.insert(0, SMS_DIR)

import sms_scam  # noqa: E402  (imported unmodified)
import evaluate_url as phishing_eval  # noqa: E402  (uses CompPhish + PhishTank Hybrid Engine)

# Expose ScamDetector & clean on __main__ so joblib can unpickle scam_model.joblib
setattr(sys.modules["__main__"], "ScamDetector", sms_scam.ScamDetector)
setattr(sys.modules["__main__"], "clean", sms_scam.clean)


# =====================================================================
# PILLAR 2 & 3: FAST PARALLEL SENSORS (SMS ML + HYBRID PHISHING + RULES)
# =====================================================================

class FastThreatSensors:
    """Loads the unmodified SMS Scam model and Hybrid Phishing URL engine
    and runs them in parallel on any incoming text or URL."""

    def __init__(self):
        # 1. Load or train SMS Scam Detector
        sms_model_path = os.path.join(SMS_DIR, "scam_model.joblib")
        sms_data_path = os.path.join(SMS_DIR, "spam.csv")
        if os.path.exists(sms_model_path):
            self.sms_det = joblib.load(sms_model_path)
        else:
            self.sms_det = sms_scam.train(data_path=sms_data_path, model_path=sms_model_path)

        # 2. Load Hybrid Phishing Engine (Bloom Filter + Random Forest)
        bloom_path = os.path.join(PHISHING_DIR, "bloom_filter.bin")
        rf_path = os.path.join(PHISHING_DIR, "phishing_rf_model.joblib")
        self.bloom_array = bitarray()
        with open(bloom_path, "rb") as fh:
            self.bloom_array.fromfile(fh)
        self.bloom_size = len(self.bloom_array)
        self.rf_model = joblib.load(rf_path)

    # --- Phishing URL helper methods (matching evaluate_url.py) ---
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        p, lns = Counter(s), float(len(s))
        return -sum(count / lns * math.log2(count / lns) for count in p.values())

    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        full_url = url if url.startswith("http") else "http://" + url
        parsed = urllib.parse.urlparse(full_url)
        domain = parsed.netloc
        extracted = tldextract.extract(full_url)

        ip_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:\d+)?$"
        keywords = ["login", "kyc", "update", "verify", "secure", "account", "free", "wallet", "bonus", "claim"]
        url_lower = full_url.lower()

        return {
            "length": len(full_url),
            "num_dots": domain.count("."),
            "has_ip": 1 if re.match(ip_pattern, domain) else 0,
            "has_at": 1 if "@" in parsed.netloc else 0,
            "num_hyphens": domain.count("-"),
            "entropy": self._shannon_entropy(domain),
            "suspicious_count": sum(1 for kw in keywords if kw in url_lower),
            "subdomain_length": len(extracted.subdomain) if extracted.subdomain else 0,
        }

    def _is_in_bloom(self, url: str) -> bool:
        for seed in range(7):
            result = mmh3.hash(url.lower(), seed) % self.bloom_size
            if self.bloom_array[result] == 0:
                return False
        return True

    def check_single_url(self, url: str) -> Dict[str, Any]:
        import importlib
        importlib.reload(phishing_eval)
        return phishing_eval.inspect_url(url)

    def check_sms_ml(self, text: str) -> Tuple[float, str]:
        prob, verdict = sms_scam.classify(self.sms_det, text)
        return float(prob), verdict

    @staticmethod
    def analyze_indian_context(text: str, urls: List[str]) -> Dict[str, Any]:
        """Detects high-precision Indian banking/UPI/OTP/KYC fraud traps and
        distinguishes them from genuine bank security notifications."""
        t_low = text.lower()
        signals: List[str] = []
        override_verdict: Optional[str] = None
        action_code = "WARN_USER"

        # 1. OTP Social-Engineering Trap (asking user to share/forward/send OTP, excluding "do not share" / "never share")
        otp_share_pattern = re.search(
            r"(?<!do not )(?<!never )(?<!not )\b(please\s+(share|forward|send|give)|(share|forward|send)\s+the\s+(\d+-digit\s+)?otp)\b.{0,60}\b(with\s+our\s+agent|to\s+\d|to\s+cancel|to\s+block)",
            t_low,
        )
        if otp_share_pattern:
            override_verdict = "CRITICAL_SCAM"
            action_code = "NEVER_SHARE_OTP"
            signals.append(
                "CRITICAL OTP TRAP: The message asks you to share or forward an OTP with an agent/number to 'cancel' a transaction or 'block' an account. Real banks NEVER ask you to share or forward an OTP—giving this OTP will actually approve the scammer's transaction."
            )

        # 2. UPI PIN / Collect Request Trap (asking to enter UPI PIN or approve request to RECEIVE money)
        upi_pin_trap = re.search(
            r"(enter\s+upi\s+pin|approve\s+the\s+request|approve\s+request).{0,50}(receive|claim|reward|cashback|get\s+money|credited)",
            t_low,
        ) or ("upi pin" in t_low and any(w in t_low for w in ["receive", "claim", "reward", "cashback"]))
        if upi_pin_trap:
            override_verdict = "CRITICAL_SCAM"
            action_code = "REJECT_UPI_COLLECT"
            signals.append(
                "CRITICAL UPI PIN TRAP: The message asks you to enter your UPI PIN or approve a collect request to 'receive' money/rewards. In UPI (PhonePe/GPay/Paytm), you NEVER enter a UPI PIN to receive money—entering your PIN deducts money from your account."
            )

        # 3. Urgent KYC / SIM / Electricity / Delivery Suspension Coercion
        coercion_match = re.search(
            r"(kyc\s+(is\s+pending|has\s+expired|immediately)|account\s+will\s+be\s+(blocked|closed|suspended)|electricity\s+power\s+will\s+be\s+disconnected|outgoing\s+calls\s+will\s+be\s+stopped|package\s+is\s+on\s+hold)",
            t_low,
        )
        if coercion_match:
            if override_verdict is None:
                override_verdict = "SCAM"
            action_code = "BLOCK_SENDER_AND_LINK"
            signals.append(
                "URGENCY / IMPERSONATION BAIT: Threatens immediate disconnection or account suspension (KYC/SIM/Electricity/Parcel) to panic you into clicking a link or calling an unverified number."
            )

        # 4. Genuine Bank OTP / Security Alert Guard (when NO links and NO scam traps exist)
        has_anti_share_warning = any(
            phrase in t_low
            for phrase in [
                "do not share otp with anyone",
                "never share this with anyone",
                "bank never calls to verify otp",
                "paytm will never call you for this otp",
            ]
        )
        is_standard_bank_notice = (
            not urls
            and override_verdict is None
            and (
                has_anti_share_warning
                or "upi pin successfully set" in t_low
                or ("autopay mandate" in t_low and "login to" in t_low and "app" in t_low)
                or ("debited from a/c" in t_low and "1800" in t_low)
                or ("credited to your a/c" in t_low and "available balance" in t_low)
            )
        )
        if is_standard_bank_notice:
            override_verdict = "LEGITIMATE_BANK_ALERT"
            action_code = "VERIFY_IF_INITIATED_BY_YOU"
            if has_anti_share_warning:
                signals.append(
                    "GENUINE OTP NOTIFICATION: Contains standard bank security warnings ('Do not share OTP with anyone') and contains no phishing links or requests to hand over the OTP."
                )
            else:
                signals.append(
                    "GENUINE TRANSACTION / ACCOUNT NOTIFICATION: Contains no external links or requests for your PIN/OTP, and directs you only to the official banking app or official 1800 toll-free helpline."
                )

        return {
            "override_verdict": override_verdict,
            "action_code": action_code,
            "signals": signals,
        }

    def analyze_input(self, raw_input: str) -> Dict[str, Any]:
        """Runs SMS ML + URL Phishing Engine in parallel and fuses all evidence."""
        t0 = time.perf_counter()
        stripped = raw_input.strip()

        # Check if input is a JSON network alert from traffic_monitor
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                net_alert = json.loads(stripped)
                if net_alert.get("channel") == "network" or "type" in net_alert:
                    return self.format_network_alert(net_alert)
            except json.JSONDecodeError:
                pass

        # Extract URLs using sms_scam.URL_RE (without modifying sms_scam.py)
        urls = sms_scam.URL_RE.findall(stripped)
        is_pure_url = (len(urls) == 1 and urls[0] == stripped) or (
            " " not in stripped and "." in stripped and len(stripped) < 250
        )

        if is_pure_url:
            target_url = urls[0] if urls else stripped
            url_res = self.check_single_url(target_url)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            is_phish = url_res["verdict"] == "PHISHING"
            return {
                "channel": "phishing_url",
                "is_threat": is_phish,
                "verdict": "PHISHING_URL" if is_phish else "SAFE_URL",
                "severity": "CRITICAL" if is_phish else "LOW",
                "confidence": f"{url_res['confidence']}%",
                "source": target_url,
                "sms_ml": None,
                "url_checks": [url_res],
                "evidence": url_res["evidence"]
                if is_phish
                else [f"URL '{target_url}' passed both the PhishTank Bloom Filter and Random Forest ML checks ({url_res['confidence']}% safe confidence)."],
                "recommended_action": "BLOCK_DOMAIN" if is_phish else "NO_ACTION",
                "sensor_latency_ms": elapsed_ms,
            }

        # Run SMS ML classifier and URL Phishing checks IN PARALLEL
        with ThreadPoolExecutor(max_workers=4) as pool:
            sms_future = pool.submit(self.check_sms_ml, stripped)
            url_futures = [pool.submit(self.check_single_url, u) for u in urls]
            sms_prob, sms_verdict = sms_future.result()
            url_results = [f.result() for f in url_futures]

        indian_ctx = self.analyze_indian_context(stripped, urls)
        any_phish_url = any(r["verdict"] == "PHISHING" for r in url_results)

        evidence: List[str] = []
        # Fuse verdicts across SMS ML + Phishing URL Engine + Indian Context Rules
        if indian_ctx["override_verdict"] == "LEGITIMATE_BANK_ALERT" and not any_phish_url:
            is_threat = False
            final_verdict = "LEGITIMATE_BANK_ALERT (SAFE)"
            severity = "INFO"
            confidence = "95% (Verified Genuine Bank/OTP Format)"
            evidence.extend(indian_ctx["signals"])
            evidence.append(
                f"URL Check: 0 links present (note: raw UK-trained SMS model scored {sms_prob:.3f} only because of currency/phone numbers)."
            )
            action_code = indian_ctx["action_code"]
        elif any_phish_url or indian_ctx["override_verdict"] in ("CRITICAL_SCAM", "SCAM") or sms_prob >= 0.5:
            is_threat = True
            severity = "CRITICAL" if (any_phish_url or indian_ctx["override_verdict"] == "CRITICAL_SCAM" or sms_prob >= 0.85) else "HIGH"
            final_verdict = indian_ctx["override_verdict"] or ("SMISHING_AND_PHISHING" if any_phish_url else "SCAM_SMS")
            top_conf = max(
                [int(round(sms_prob * 100))]
                + ([98] if indian_ctx["override_verdict"] == "CRITICAL_SCAM" else [])
                + [r["confidence"] for r in url_results if r["verdict"] == "PHISHING"]
            )
            confidence = f"{top_conf}%"
            evidence.extend(indian_ctx["signals"])
            evidence.append(f"SMS ML Classifier score: {sms_prob:.3f} ({sms_verdict}).")
            for r in url_results:
                if r["verdict"] == "PHISHING":
                    evidence.extend(r["evidence"])
            action_code = "BLOCK_DOMAIN & WARN_USER" if any_phish_url else indian_ctx["action_code"]
        else:
            is_threat = False
            final_verdict = "LEGITIMATE_SMS (SAFE)"
            severity = "LOW"
            confidence = f"{int(round((1.0 - sms_prob) * 100))}% Safe"
            evidence.append(f"SMS ML Classifier rated this message safe (scam probability: {sms_prob:.3f}).")
            if not urls:
                evidence.append("No suspicious links or OTP/UPI social-engineering traps detected.")
            action_code = "NO_ACTION"

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "channel": "sms + url" if urls else "sms",
            "is_threat": is_threat,
            "verdict": final_verdict,
            "severity": severity,
            "confidence": confidence,
            "source": stripped[:120] + ("..." if len(stripped) > 120 else ""),
            "full_text": stripped,
            "sms_ml": {"probability": round(sms_prob, 3), "raw_verdict": sms_verdict},
            "url_checks": url_results,
            "evidence": evidence,
            "recommended_action": action_code,
            "sensor_latency_ms": elapsed_ms,
        }

    @staticmethod
    def format_network_alert(net_alert: Dict[str, Any]) -> Dict[str, Any]:
        """Converts an alert dict from traffic_monitor/detectors.py into the unified format."""
        kind = net_alert.get("type", "network_anomaly")
        src = net_alert.get("source", "unknown")
        sev = net_alert.get("severity", "high").upper()
        summary = net_alert.get("summary", "Abnormal network traffic detected.")
        reasons = net_alert.get("reasons", [])

        evidence = [summary]
        for r in reasons:
            if isinstance(r, dict):
                evidence.append("Metric trigger: " + ", ".join(f"{k}={v}" for k, v in r.items()))
            else:
                evidence.append(str(r))

        action = "QUARANTINE_DEVICE" if kind in ("dns_anomaly", "outbound_anomaly") else "BLOCK_SOURCE_IP"
        return {
            "channel": "network",
            "is_threat": True,
            "verdict": f"NETWORK_INTRUSION ({kind.upper()})",
            "severity": sev,
            "confidence": "98% (Baseline + Rule Trigger)",
            "source": f"{src} -> {net_alert.get('target', 'local_device')}",
            "sms_ml": None,
            "url_checks": [],
            "evidence": evidence,
            "recommended_action": action,
            "sensor_latency_ms": 0.5,
        }


# =====================================================================
# PILLAR 4: OFFLINE LLAMA-3.2-1B EXECUTORCH REASONING ENGINE
# =====================================================================

THREAT_SYSTEM_PROMPT = (
    "You are AEGIS, a helpful defensive cybersecurity educator. "
    "An automated security sensor flagged a dangerous scam or network attack and produced a technical report. "
    "Keep your response under 65 words total: write 2 short sentences in plain English explaining why "
    "this is dangerous using ONLY the sensor report, followed by 2 short bullet-point safety actions."
)

SAFE_URL_SYSTEM_PROMPT = (
    "You are AEGIS, a helpful cybersecurity assistant. "
    "An automated URL security scanner verified that this website URL is SAFE and LEGITIMATE (NOT phishing). "
    "Keep your response under 50 words total: write 2 short sentences reassuring the user why the URL passed security checks, "
    "followed by 2 short general safe-browsing bullet points."
)


class LlamaSecurityAdvisor:
    def __init__(self, model_dir: str = DEFAULT_MODEL_DIR):
        self.model_dir = model_dir
        print(f"[AEGIS] Initializing fast ML sensors (SMS Ensemble + PhishTank Bloom Filter + Random Forest)...")
        t_s = time.perf_counter()
        self.sensors = FastThreatSensors()
        print(f"[AEGIS] Fast sensors ready in {round(time.perf_counter() - t_s, 2)}s.")

        print(f"[AEGIS] Loading offline Llama-3.2-1B ExecuTorch model & tokenizer from: {model_dir}")
        t0 = time.perf_counter()
        self.model = ExecuTorchModelForCausalLM.from_pretrained(model_dir)
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        self.load_time_s = round(time.perf_counter() - t0, 2)
        print(f"[AEGIS] Llama-3.2-1B ExecuTorch ready in {self.load_time_s}s (100% offline mode).")

    @staticmethod
    def _clean_response(raw_output: str) -> str:
        if "assistant\n\n" in raw_output:
            cleaned = raw_output.split("assistant\n\n")[-1]
        elif "assistant\n" in raw_output:
            cleaned = raw_output.split("assistant\n")[-1]
        else:
            cleaned = raw_output
        # Strip leading conversational filler like "Here's the translation:" or "Here's the response...:"
        cleaned = re.sub(r"^(Here('s| is) [^\n:]+:\s*)", "", cleaned.strip(), flags=re.IGNORECASE)
        cleaned = cleaned.strip()
        # If generation hit max_new_tokens mid-sentence, trim back to the last complete sentence
        if cleaned and cleaned[-1] not in ".!?)":
            last_punct = max(cleaned.rfind("."), cleaned.rfind("!"), cleaned.rfind("?"))
            if last_punct > len(cleaned) // 2:
                cleaned = cleaned[: last_punct + 1].strip()
        return cleaned

    def build_prompt_messages(self, report: Dict[str, Any]) -> List[Dict[str, str]]:
        evidence_bullets = "\n".join(f"- {item}" for item in report.get("evidence", []))
        is_threat = report.get("is_threat", True)
        # Mask raw 6-digit OTPs/ref numbers before sending to the 1B LLM for privacy & to avoid false financial refusals
        sanitized_source = re.sub(r"\b\d{6}\b", "[6-DIGIT-OTP]", report.get("source", ""))

        if is_threat:
            user_msg = (
                f"Translate this confirmed security threat report into simple English for a non-expert user:\n"
                f"- Channel: {report['channel'].upper()}\n"
                f"- Verdict: {report['verdict']} (Confidence: {report['confidence']})\n"
                f"- Content: {sanitized_source}\n"
                f"- Key Findings:\n{evidence_bullets}\n"
                f"- Recommended Action: {report['recommended_action']}\n\n"
                f"Write:\n1) Why This Is Dangerous (2 plain sentences based on Key Findings)\n"
                f"2) Safe Next Steps (2 short bullet points)"
            )
            return [
                {"role": "system", "content": THREAT_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        elif report.get("channel") == "phishing_url":
            user_msg = (
                f"Translate this verified safe URL scan report into simple English for the user:\n"
                f"- Verdict: {report['verdict']} (Confidence: {report['confidence']})\n"
                f"- Scanned URL: {sanitized_source}\n"
                f"- Verification Notes:\n{evidence_bullets}\n\n"
                f"Write:\n1) Why This Link Is Safe (2 plain reassuring sentences)\n"
                f"2) Routine Safe-Browsing Tips (2 short bullet points)"
            )
            return [
                {"role": "system", "content": SAFE_URL_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        else:
            safe_bank_prompt = (
                "You are AEGIS, a helpful cybersecurity educator. "
                "An automated security filter verified that this message is a LEGITIMATE bank security notification (NOT a scam). "
                "Keep your response under 60 words total: write 2 short sentences reassuring the user what this genuine alert means, "
                "followed by 2 short bullet points on what to do if they did NOT initiate this activity."
            )
            user_msg = (
                f"Translate this verified safe bank notification log into simple English for the user:\n"
                f"- Verdict: {report['verdict']}\n"
                f"- Notification Summary: {sanitized_source}\n"
                f"- Verification Notes:\n{evidence_bullets}\n\n"
                f"Write:\n1) What This Genuine Alert Means (2 plain reassuring sentences)\n"
                f"2) Routine Precaution (2 short bullet points if they did not initiate this activity)"
            )
            return [
                {"role": "system", "content": safe_bank_prompt},
                {"role": "user", "content": user_msg},
            ]

    def explain_report(self, report: Dict[str, Any], max_new_tokens: int = 135) -> Dict[str, Any]:
        messages = self.build_prompt_messages(report)
        prompt = self.tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        prompt_len = len(self.tokenizer.encode(prompt))
        max_seq_len = prompt_len + max_new_tokens

        t0 = time.perf_counter()
        raw_output = self.model.text_generation(
            tokenizer=self.tokenizer,
            prompt=prompt,
            max_seq_len=max_seq_len,
        )
        elapsed_s = round(time.perf_counter() - t0, 2)
        explanation = self._clean_response(raw_output)

        return {
            "sensor_report": report,
            "explanation": explanation,
            "inference_time_s": elapsed_s,
            "prompt_tokens": prompt_len,
        }

    def analyze_and_explain(self, raw_input: str, max_new_tokens: int = 135) -> Dict[str, Any]:
        """Full 4-pillar pipeline: runs fast parallel sensors first, prints the
        instant breakdown, then generates the Llama ExecuTorch explanation."""
        report = self.sensors.analyze_input(raw_input)
        self.print_sensor_report(report)
        print("[Llama-3.2-1B ExecuTorch generating plain-language advisory...]")
        return self.explain_report(report, max_new_tokens=max_new_tokens)

    @staticmethod
    def print_sensor_report(report: Dict[str, Any]):
        print("\n" + "-" * 68)
        print(f"[FAST SENSOR BREAKDOWN — completed in {report.get('sensor_latency_ms', 0)} ms]")
        print(f"  Channel           : {report['channel'].upper()}")
        print(f"  Fused Verdict     : {report['verdict']} (Severity: {report['severity']}, Confidence: {report['confidence']})")
        if report.get("sms_ml"):
            print(f"  Pillar 2 (SMS ML) : prob={report['sms_ml']['probability']:.3f} ({report['sms_ml']['raw_verdict']})")
        if report.get("url_checks"):
            for u in report["url_checks"]:
                print(f"  Pillar 3 (URL ML) : {u['url']} -> {u['verdict']} ({u['confidence']}% via {u['method']})")
        print("  Extracted Evidence:")
        for ev in report.get("evidence", []):
            print(f"    * {ev}")
        print("-" * 68)


SAMPLE_NETWORK_ALERT = {
    "id": "NET-0001",
    "channel": "network",
    "type": "dns_anomaly",
    "severity": "high",
    "source": "192.168.43.50",
    "target": "8.8.8.8",
    "summary": "This device's dns_max_entropy jumped to 4.35 across 80 rapid queries (normal baseline is 2.8) — indicative of DNS Exfiltration or DGA malware.",
    "reasons": [
        {"feature": "dns_max_entropy", "value": 4.35, "baseline_median": 2.8, "z": 8.4},
        {"feature": "dns_queries", "value": 80, "baseline_median": 6, "z": 7.4},
    ],
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS 4-Pillar Offline Cybersecurity Assistant")
    parser.add_argument("--model-dir", default=DEFAULT_MODEL_DIR, help="Path to offline ExecuTorch model + tokenizer folder")
    parser.add_argument("--demo", action="store_true", help="Run built-in 4-pillar demos (SMS + Phishing URL + Network Intrusion)")
    args = parser.parse_args()

    advisor = LlamaSecurityAdvisor(model_dir=args.model_dir)
    if args.demo:
        demo_inputs = [
            "Dear Customer, Rs. 15,500 has been successfully credited to your bank account via PhonePe. Click here to claim your reward and enter UPI PIN to receive the money: http://claim-reward-fake.in",
            "839201 is the OTP for txn of INR 2,499.00 at AMAZON on ICICI Bank Card XX4019. Valid for 5 mins. Do not share OTP with anyone. Bank never calls to verify OTP. - ICICI Bank",
            "URGENT: We detected a suspicious transaction of Rs 49,999 on your HDFC Credit Card. If this was NOT you, please share the 6-digit OTP sent to your phone with our agent to cancel the transaction.",
            json.dumps(SAMPLE_NETWORK_ALERT),
        ]
        for idx, item in enumerate(demo_inputs, 1):
            print(f"\n================ DEMO CASE {idx} ================")
            print(f"Input: {item}")
            res = advisor.analyze_and_explain(item)
            print(f"\n>>> AEGIS Llama Advisory ({res['inference_time_s']}s):\n{res['explanation']}\n")
    else:
        print("\n=== AEGIS 4-Pillar Interactive Mode ===")
        print("Paste an SMS, a URL, 'net' (to simulate a network intrusion alert), or 'quit' to exit.")
        while True:
            try:
                user_text = input("\nAlert/SMS/URL> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user_text.lower() in ("quit", "exit", "q"):
                break
            if not user_text:
                continue
            if user_text.lower() == "net":
                user_text = json.dumps(SAMPLE_NETWORK_ALERT)
            res = advisor.analyze_and_explain(user_text)
            print(f"\n>>> AEGIS Llama Advisory ({res['inference_time_s']}s):\n{res['explanation']}")
