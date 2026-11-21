#!/usr/bin/env python3
r"""
Simple AEGIS Benchmark — writes a single Notepad-friendly .txt report covering all slide requirements.
Run:
    python benchmark_aegis.py --model-dir ".\llama32_1b_instruct" --quant "8da4w / 8w (qembedding)" --skip sustained
    python benchmark_aegis.py --model-dir ".\llama32_1b_instruct" --quant "8da4w / 8w (qembedding)"
    python benchmark_aegis.py --model-dir ".\llama32_1b_instruct" --quant "8da4w / 8w (qembedding)" --offline
"""
import argparse
import datetime
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from importlib import metadata

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import numpy as np
import psutil

MB = 1024 * 1024


def build_cases(la):
    sample_net = getattr(la, "SAMPLE_NETWORK_ALERT", {"type": "network_alert", "detail": "suspicious connection"})
    return [
        {
            "name": "otp_trap_short",
            "expected_threat": True,
            "text": "URGENT: Suspicious txn of Rs 49,999 on HDFC Card. Share 6-digit OTP to cancel.",
        },
        {
            "name": "otp_trap_long",
            "expected_threat": True,
            "text": "URGENT: We detected a suspicious transaction of Rs 49,999 on your HDFC Credit Card. If this was NOT you, "
                    "please share the 6-digit OTP sent to your phone with our agent to cancel the transaction.",
        },
        {
            "name": "upi_pin_trap_with_url",
            "expected_threat": True,
            "text": "Dear Customer, Rs. 15,500 has been successfully credited to your bank account via PhonePe. Click here to "
                    "claim your reward and enter UPI PIN to receive the money: http://claim-reward-fake.in",
        },
        {
            "name": "legit_bank_otp",
            "expected_threat": False,
            "text": "839201 is the OTP for txn of INR 2,499.00 at AMAZON on ICICI Bank Card XX4019. Valid for 5 mins. "
                    "Do not share OTP with anyone. Bank never calls to verify OTP. - ICICI Bank",
        },
        {
            "name": "pure_url",
            "expected_threat": None,
            "text": "http://secure-login.verify-account-update.xyz/kyc",
        },
        {
            "name": "network_alert",
            "expected_threat": True,
            "text": json.dumps(sample_net),
        },
    ]


class NetworkGuard:
    def __init__(self):
        self.attempts = []
        self.active = False
        self._orig_connect = None
        self._orig_gai = None

    @staticmethod
    def _is_local(addr):
        if isinstance(addr, (tuple, list)) and addr:
            host = str(addr[0])
            return host in ("localhost", "", "::1") or host.startswith("127.")
        return True

    def install(self):
        if self.active:
            return
        self._orig_connect = socket.socket.connect
        self._orig_gai = socket.getaddrinfo
        guard = self

        def blocked_connect(sock, addr, *args, **kwargs):
            if not guard._is_local(addr):
                guard.attempts.append(f"connect {addr}")
                raise OSError("Blocked non-loopback network connection")
            return guard._orig_connect(sock, addr, *args, **kwargs)

        def blocked_gai(host, *args, **kwargs):
            if host not in (None, "localhost", "127.0.0.1", "::1"):
                guard.attempts.append(f"dns {host}")
                raise socket.gaierror("Blocked non-loopback DNS lookup")
            return guard._orig_gai(host, *args, **kwargs)

        socket.socket.connect = blocked_connect
        socket.getaddrinfo = blocked_gai
        self.active = True

    def uninstall(self):
        if not self.active:
            return
        socket.socket.connect = self._orig_connect
        socket.getaddrinfo = self._orig_gai
        self.active = False


def rss_mb():
    return round(psutil.Process().memory_info().rss / MB, 1)


def os_peak_rss_mb():
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        return round(int(line.split()[1]) / 1024, 1)
        mi = psutil.Process().memory_info()
        if hasattr(mi, "peak_wset"):
            return round(mi.peak_wset / MB, 1)
    except Exception:
        pass
    return None


def dir_size_mb(path):
    if not os.path.exists(path):
        return 0.0
    total = 0
    for root, _, files in os.walk(path):
        for fname in files:
            try:
                total += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass
    return round(total / MB, 1)


def get_cpu_name():
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/cpuinfo") as f:
                txt = f.read()
            for key in ("model name", "Model", "Hardware"):
                m = re.search(rf"^{key}\s*:\s*(.+)$", txt, re.M)
                if m:
                    return m.group(1).strip()
        elif os.name == "nt":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
                capture_output=True, text=True, timeout=5, creationflags=0x08000000
            ).stdout.strip()
            if out:
                return out
    except Exception:
        pass
    return platform.processor() or "unknown"


def read_temp_c():
    try:
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            for key in ("cpu_thermal", "cpu-thermal", "coretemp", "k10temp", "soc_thermal"):
                if temps.get(key):
                    return round(float(temps[key][0].current), 1)
            for entries in temps.values():
                if entries:
                    return round(float(entries[0].current), 1)
    except Exception:
        pass
    if os.path.exists("/sys/class/thermal/thermal_zone0/temp"):
        try:
            return round(int(open("/sys/class/thermal/thermal_zone0/temp").read().strip()) / 1000.0, 1)
        except Exception:
            pass
    if os.name == "nt":
        try:
            cmd = ("(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature "
                   "| Select-Object -First 1 -ExpandProperty CurrentTemperature)")
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, timeout=5, creationflags=0x08000000
            ).stdout.strip()
            if out:
                return round(float(out) / 10.0 - 273.15, 1)
        except Exception:
            pass
    return None


def check_throttling():
    vcg = shutil.which("vcgencmd")
    if vcg:
        try:
            out = subprocess.run([vcg, "get_throttled"], capture_output=True, text=True, timeout=3).stdout
            val = int(out.strip().split("=")[1], 16)
            return f"{hex(val)} (throttled={bool(val & 0xF)})"
        except Exception:
            pass
    freq = psutil.cpu_freq()
    if freq and freq.current and freq.max and freq.max > 0:
        ratio = round(freq.current / freq.max, 2)
        return f"freq_ratio={ratio} ({round(freq.current)}/{round(freq.max)} MHz)"
    return "n/a (no sensor/freq access)"


def run_llm(adv, report, max_new_tokens, ttft_only=False):
    messages = adv.build_prompt_messages(report)
    prompt = adv.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    prompt_len = len(adv.tokenizer.encode(prompt))
    steps = 1 if ttft_only else max_new_tokens

    t0 = time.perf_counter()
    raw = adv.model.text_generation(tokenizer=adv.tokenizer, prompt=prompt, max_seq_len=prompt_len + steps)
    elapsed = time.perf_counter() - t0

    if "assistant\n\n" in raw:
        gen = raw.split("assistant\n\n")[-1]
    elif "assistant\n" in raw:
        gen = raw.split("assistant\n")[-1]
    else:
        gen = raw

    gen_tokens = len(adv.tokenizer.encode(gen, add_special_tokens=False)) if gen.strip() else 0
    return {
        "seconds": elapsed,
        "gen_tokens": gen_tokens,
        "text": adv._clean_response(raw),
    }


def make_table(rows, headers):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(r):
        return "| " + " | ".join(str(r[i]).ljust(widths[i]) for i in range(len(headers))) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out = [sep, fmt_row(headers), sep]
    for r in rows:
        out.append(fmt_row(r))
    out.append(sep)
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Simple AEGIS benchmark (.txt report)")
    ap.add_argument("--model-dir", default=os.path.join(ROOT_DIR, "llama32_1b_instruct"))
    ap.add_argument("--quant", default="unknown")
    ap.add_argument("--backend", default="ExecuTorch XNNPACK (CPU)")
    ap.add_argument("--det-iters", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--llm-reps", type=int, default=2)
    ap.add_argument("--max-new-tokens", type=int, default=135)
    ap.add_argument("--sustained-minutes", type=float, default=2.0)
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--skip", nargs="*", default=[], choices=["detection", "llm", "sustained", "offline"])
    ap.add_argument("--out-file", default=None)
    args = ap.parse_args()

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = args.out_file or os.path.join(HERE, f"benchmark_summary_{ts}.txt")

    guard = NetworkGuard()
    if args.offline:
        guard.install()

    rss_before_import = rss_mb()
    import llama_advisor as la
    rss_after_import = rss_mb()

    t_load0 = time.perf_counter()
    adv = la.LlamaSecurityAdvisor(model_dir=args.model_dir)
    load_sec = round(time.perf_counter() - t_load0, 2)
    rss_after_load = rss_mb()
    peak_rss = rss_after_load

    model_size_mb = dir_size_mb(args.model_dir)
    pte_files = [f for f in os.listdir(args.model_dir) if f.endswith(".pte")] if os.path.isdir(args.model_dir) else []
    artefact_sizes = {}
    for label, d, names in (("sms", getattr(la, "SMS_DIR", ""), ["scam_model.joblib"]),
                            ("phishing", getattr(la, "PHISHING_DIR", ""), ["bloom_filter.bin", "phishing_rf_model.joblib"])):
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                artefact_sizes[f"{label}/{n}"] = f"{round(os.path.getsize(p) / MB, 2)} MB"

    cases = build_cases(la)
    per_case_summary = {}
    for c in cases:
        per_case_summary[c["name"]] = {
            "expected": c["expected_threat"],
            "verdict": "skipped",
            "det_med_ms": "-",
            "ttft_ms": "-",
            "llm_total_ms": "-",
            "gen_tokens": "-",
            "tok_per_sec": "-",
            "offline_ok": "-",
        }

    # 1. Detection
    det_notes = ["Skipped"]
    det_case_meds = []
    if "detection" not in args.skip:
        det_notes = []
        for c in cases:
            for _ in range(args.warmup):
                adv.sensors.analyze_input(c["text"])
            ms_list = []
            last = None
            for _ in range(args.det_iters):
                t0 = time.perf_counter_ns()
                last = adv.sensors.analyze_input(c["text"])
                ms_list.append((time.perf_counter_ns() - t0) / 1e6)
            peak_rss = max(peak_rss, rss_mb())
            med_ms = round(float(np.median(ms_list)), 2)
            p95_ms = round(float(np.percentile(ms_list, 95)), 2)
            det_case_meds.append(med_ms)
            per_case_summary[c["name"]]["det_med_ms"] = med_ms
            per_case_summary[c["name"]]["verdict"] = last.get("verdict", "unknown")
            det_notes.append(f"{c['name']}: median={med_ms} ms, p95={p95_ms} ms, verdict={last.get('verdict')}")

    # 2. LLM
    llm_notes = ["Skipped"]
    llm_case_ttfts = []
    llm_case_totals = []
    llm_case_tps = []
    llm_case_decode_tps = []
    if "llm" not in args.skip:
        llm_notes = []
        run_llm(adv, adv.sensors.analyze_input(cases[0]["text"]), args.max_new_tokens)
        peak_rss = max(peak_rss, rss_mb())
        for c in cases:
            rep = adv.sensors.analyze_input(c["text"])
            ttfts = []
            for _ in range(args.llm_reps):
                r1 = run_llm(adv, rep, args.max_new_tokens, ttft_only=True)
                ttfts.append(r1["seconds"] * 1000.0)

            tps_list = []
            decode_tps_list = []
            total_ms_list = []
            tok_list = []
            mean_ttft = round(float(np.mean(ttfts)), 1)
            for _ in range(args.llm_reps):
                r = run_llm(adv, rep, args.max_new_tokens, ttft_only=False)
                total_ms_list.append(r["seconds"] * 1000.0)
                tok_list.append(r["gen_tokens"])
                if r["seconds"] > 0 and r["gen_tokens"] > 0:
                    tps_list.append(r["gen_tokens"] / r["seconds"])
                    # Pure decode rate: exclude prefill time (approximated by TTFT)
                    decode_sec = r["seconds"] - (mean_ttft / 1000.0)
                    if decode_sec > 0:
                        decode_tps_list.append(r["gen_tokens"] / decode_sec)
            peak_rss = max(peak_rss, rss_mb())

            mean_total = round(float(np.mean(total_ms_list)), 1)
            mean_toks = round(float(np.mean(tok_list)), 1)
            mean_tps = round(float(np.mean(tps_list)), 2) if tps_list else 0.0
            mean_decode_tps = round(float(np.mean(decode_tps_list)), 2) if decode_tps_list else 0.0

            llm_case_ttfts.append(mean_ttft)
            llm_case_totals.append(mean_total)
            llm_case_tps.append(mean_tps)
            llm_case_decode_tps.append(mean_decode_tps)

            per_case_summary[c["name"]]["ttft_ms"] = mean_ttft
            per_case_summary[c["name"]]["llm_total_ms"] = mean_total
            per_case_summary[c["name"]]["gen_tokens"] = mean_toks
            per_case_summary[c["name"]]["tok_per_sec"] = mean_tps
            llm_notes.append(
                f"{c['name']}: TTFT={mean_ttft} ms, total={mean_total} ms, tokens={mean_toks}, "
                f"speed={mean_tps} tok/s (end-to-end), decode-only={mean_decode_tps} tok/s"
            )

    # 3. Offline check
    offline_notes = ["Skipped"]
    offline_pass_count = 0
    if "offline" not in args.skip:
        installed_here = not guard.active
        if installed_here:
            guard.install()
        try:
            all_ok = True
            for c in cases:
                try:
                    rep = adv.sensors.analyze_input(c["text"])
                    r = run_llm(adv, rep, args.max_new_tokens, ttft_only=False)
                    ok = bool(r["text"].strip())
                    if ok:
                        offline_pass_count += 1
                    per_case_summary[c["name"]]["offline_ok"] = "PASS" if ok else "FAIL"
                    all_ok = all_ok and ok
                except Exception as exc:
                    per_case_summary[c["name"]]["offline_ok"] = f"ERR({exc})"
                    all_ok = False
            offline_notes = [
                f"All cases passed offline: {all_ok} ({offline_pass_count}/{len(cases)})",
                f"Blocked network attempts: {len(guard.attempts)} -> {guard.attempts[:5]}",
            ]
        finally:
            if installed_here:
                guard.uninstall()

    # 4. Sustained check
    sustained_notes = ["Skipped"]
    if "sustained" not in args.skip and args.sustained_minutes > 0:
        t_start = time.perf_counter()
        t_end = t_start + args.sustained_minutes * 60.0
        iters = 0
        errors = 0
        tps_series = []
        cpu_series = []
        temps = []
        temp_start = read_temp_c()
        if temp_start is not None:
            temps.append(temp_start)
        psutil.cpu_percent(None)

        while time.perf_counter() < t_end:
            c = cases[iters % len(cases)]
            try:
                rep = adv.sensors.analyze_input(c["text"])
                r = run_llm(adv, rep, args.max_new_tokens, ttft_only=False)
                if r["seconds"] > 0 and r["gen_tokens"] > 0:
                    tps_series.append(r["gen_tokens"] / r["seconds"])
                cpu_series.append(psutil.cpu_percent(None))
                t_now = read_temp_c()
                if t_now is not None:
                    temps.append(t_now)
                peak_rss = max(peak_rss, rss_mb())
            except Exception as exc:
                errors += 1
                sustained_notes.append(f"Error on iter {iters}: {exc}")
            iters += 1

        dur = round(time.perf_counter() - t_start, 1)
        avg_tps = round(float(np.mean(tps_series)), 2) if tps_series else 0.0
        avg_cpu = round(float(np.mean(cpu_series)), 1) if cpu_series else 0.0
        drift_str = "n/a"
        if len(tps_series) >= 4:
            k = max(1, len(tps_series) // 4)
            first_avg = float(np.mean(tps_series[:k]))
            last_avg = float(np.mean(tps_series[-k:]))
            drift_pct = round((last_avg - first_avg) / first_avg * 100, 1)
            drift_str = f"{round(first_avg, 2)} -> {round(last_avg, 2)} tok/s ({drift_pct:+.1f}%)"
        temp_str = f"start={temps[0]} C, max={max(temps)} C" if temps else "n/a (not exposed by OS/sensor)"

        sustained_notes = [
            f"Duration: {dur}s | Iterations: {iters} | Errors: {errors}",
            f"Avg throughput: {avg_tps} tok/s | Throughput drift: {drift_str}",
            f"Avg system CPU: {avg_cpu}% | End RSS: {rss_mb()} MB",
            f"Temperature: {temp_str} | Throttling status: {check_throttling()}",
        ]

    if guard.active:
        guard.uninstall()

    avg_det_ms = f"{round(float(np.mean(det_case_meds)), 2)} ms" if det_case_meds else "skipped"
    avg_ttft_ms = f"{round(float(np.mean(llm_case_ttfts)), 1)} ms" if llm_case_ttfts else "skipped"
    avg_total_ms = f"{round(float(np.mean(llm_case_totals)), 1)} ms" if llm_case_totals else "skipped"
    avg_tok_s = f"{round(float(np.mean(llm_case_tps)), 2)} tok/s" if llm_case_tps else "skipped"
    avg_decode_tok_s = f"{round(float(np.mean(llm_case_decode_tps)), 2)} tok/s" if llm_case_decode_tps else "skipped"
    offline_summary = "skipped" if "offline" in args.skip else f"{offline_pass_count}/{len(cases)} passed"

    pkg_ver = {}
    for pkg in ("torch", "executorch", "optimum-executorch", "transformers", "scikit-learn", "psutil"):
        try:
            pkg_ver[pkg] = metadata.version(pkg)
        except Exception:
            pkg_ver[pkg] = "n/a"

    table_rows = []
    for name, d in per_case_summary.items():
        table_rows.append([
            name,
            str(d["expected"]),
            str(d["verdict"]),
            str(d["det_med_ms"]),
            str(d["ttft_ms"]),
            str(d["llm_total_ms"]),
            str(d["gen_tokens"]),
            str(d["tok_per_sec"]),
            str(d["offline_ok"]),
        ])

    summary_table = make_table(
        table_rows,
        ["Test Case", "Expected", "Verdict", "Det Med (ms)", "TTFT (ms)",
         "LLM Total (ms)", "Gen Tokens", "Tok/s", "Offline"],
    )

    os_peak = os_peak_rss_mb()
    lines = [
        "============================================================",
        "AEGIS BENCHMARK SUMMARY (COMPLETE PRODUCT REPORT)",
        "============================================================",
        f"Timestamp      : {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"Device / CPU   : {get_cpu_name()} ({psutil.cpu_count(logical=False)}P/{psutil.cpu_count(logical=True)}L cores)",
        f"OS / Arch      : {platform.platform()} ({platform.machine()})",
        f"Python         : {sys.version.split()[0]}",
        f"RAM Total      : {round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        f"Backend / Quant: {args.backend} | {args.quant}",
        f"Model Dir / PTE: {args.model_dir} | {pte_files or 'none found'}",
        f"Packages       : {pkg_ver}",
        "",
        "--- OVERALL AVERAGES (ACROSS ALL 6 TEST CASES) ---",
        f"Avg detection latency  : {avg_det_ms}",
        f"Avg LLM TTFT           : {avg_ttft_ms}",
        f"Avg LLM total time     : {avg_total_ms}",
        f"Avg LLM throughput     : {avg_tok_s} (end-to-end, includes prefill)",
        f"Avg LLM decode speed   : {avg_decode_tok_s} (excludes prefill/TTFT)",
        f"Offline pass rate      : {offline_summary}",
        "",
        "--- MEMORY & MODEL SIZE ---",
        f"Advisor load time      : {load_sec} s",
        f"LLM directory size     : {model_size_mb} MB",
        f"Detector artefacts     : {artefact_sizes or 'n/a'}",
        f"RSS before import      : {rss_before_import} MB",
        f"RSS after import       : {rss_after_import} MB",
        f"RSS after model load   : {rss_after_load} MB",
        f"Observed peak RSS      : {peak_rss} MB (OS lifetime peak: {os_peak if os_peak else 'n/a'} MB)",
        "",
        "--- PER-CASE SUMMARY TABLE ---",
        summary_table,
        "",
        "--- 1. DETECTION LATENCY DETAILS ---",
        *[f"* {x}" for x in det_notes],
        "",
        "--- 2. LLM RESPONSE DETAILS ---",
        *[f"* {x}" for x in llm_notes],
        "",
        "--- 3. SUSTAINED OPERATION ---",
        *[f"* {x}" for x in sustained_notes],
        "",
        "--- 4. OFFLINE TEST ---",
        *[f"* {x}" for x in offline_notes],
        "",
        "--- 5. MEASUREMENT METHOD ---",
        "* Detection latency: Wall-clock time of FastThreatSensors.analyze_input() via perf_counter_ns (warm-up excluded).",
        "* LLM response: Wall-clock time of model.text_generation(); TTFT = 1-token generation.",
        "* LLM total time: Full wall-clock time of text_generation() for up to max-new-tokens (prefill + decode), averaged over reps.",
        "* Tok/s (end-to-end): generated tokens / total seconds. Decode-only tok/s: generated tokens / (total seconds - TTFT).",
        "* Memory & size: Process VmRSS/working set via psutil plus OS lifetime peak (peak_wset/VmHWM) and on-disk model folder size.",
        "* Sustained operation: Continuous detection + LLM loop over configured duration while sampling CPU %, temp, frequency/throttling, and throughput drift.",
        "* Offline reliability: Socket connect() and DNS getaddrinfo() patched to block all non-loopback network traffic during execution.",
        "",
        "--- 6. TEST INPUTS USED ---",
        *[f"* {c['name']}: {c['text']}" for c in cases],
        "",
    ]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print("\n" + summary_table)
    print(f"\nSaved single summary file: {out_path}")


if __name__ == "__main__":
    main()