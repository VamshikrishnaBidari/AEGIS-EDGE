"""
state.py

The shared, mutable state of the monitor: the in-memory stores capture.py
writes to and detectors.py / reporting.py read from, the alert bookkeeping,
the benchmarking counters, and the per-device Baseline.

This gets its own file because it's the one thing every other module needs
to reach: capture writes to it, detectors read and write it (baseline,
cooldowns), reporting reads it to print and to build the benchmark file.
Putting it in, say, capture.py or detectors.py would make the other modules
import "the wrong file just to get at the state," which defeats the point
of splitting them up.
"""
import itertools
import statistics
import threading
from collections import Counter, defaultdict, deque
import json
import os
import settings

# ---------------------------------------------------------------------
# inbound / outbound / DNS stores -- written by capture.py
# ---------------------------------------------------------------------
store_lock = threading.Lock()

# src ip -> deque of (time, dport); kept for LONG_WINDOW_SIZE, sliced down to
# WINDOW_SIZE at feature time (see features.inbound_features)
inbound = defaultdict(lambda: deque(maxlen=settings.MAX_RECORDS))

# src ip -> deque of plain timestamps; echo requests aimed at this device
icmp_inbound = defaultdict(lambda: deque(maxlen=settings.MAX_RECORDS))

outbound = deque(maxlen=settings.MAX_RECORDS)       # (time, dst ip, dport)
dns_queries = deque(maxlen=settings.MAX_RECORDS)    # (time, name)
dns_responses = deque(maxlen=settings.MAX_RECORDS)  # (time, rcode)

# ---------------------------------------------------------------------
# alerts -- written by detectors.py, read by reporting.py (benchmark file)
# ---------------------------------------------------------------------
recent_alerts = deque(maxlen=100)    # for the dashboard / Llama step later
last_alert = {}                      # (type, source) -> time, for cooldowns
alert_ids = itertools.count(1)
alert_counts = Counter()
detect_delays = []                   # seconds from first packet to alert

# ---------------------------------------------------------------------
# benchmarking counters -- written by capture.py and reporting.py
# ---------------------------------------------------------------------
stats = {"packets": 0, "dropped_sources": 0, "reports": 0}
handler_times = deque(maxlen=50000)  # seconds per packet, for p50/p95
cycle_times = deque(maxlen=5000)     # seconds per report cycle
resource_samples = []                # (cpu %, rss MB)


# ---------------------------------------------------------------------
# per-device baseline
# ---------------------------------------------------------------------
class Baseline:
    """Dual-tiered baseline with instant Golden Baseline loading for demos."""

    def __init__(self):
        self.hist = {f: deque(maxlen=settings.BASELINE_HISTORY) for f in settings.DEVICE_FEATURES}
        self.long_hist = {f: deque(maxlen=settings.LONG_BASELINE_HISTORY) for f in settings.DEVICE_FEATURES}
        self.update_counter = 0
        self.static_profile = None
        self._load_from_disk()

    def _load_from_disk(self):
        if os.path.exists("golden_baseline.json"):
            with open("golden_baseline.json", "r", encoding="utf-8") as fh:
                self.static_profile = json.load(fh)
            print("[BASELINE] Loaded static golden profile from disk. Cold start bypassed.")

    def save_to_disk(self):
        if not self.ready():
            print("[BASELINE] Not enough samples collected to save golden baseline.")
            return

        profile = {}
        for f in settings.DEVICE_FEATURES:
            # Blend short window and long window samples for complete profile
            combined_samples = list(self.hist[f]) + list(self.long_hist[f])
            med = statistics.median(combined_samples)
            mad = statistics.median(abs(x - med) for x in combined_samples)
            scale = max(1.4826 * mad, settings.SCALE_FLOOR[f])
            profile[f] = {"median": round(med, 2), "scale": round(scale, 2)}

        with open("golden_baseline.json", "w", encoding="utf-8") as fh:
            json.dump(profile, fh, indent=2)
        print("[BASELINE] Saved blended dual-tier profile to golden_baseline.json")

    def samples(self):
        return len(self.hist[settings.DEVICE_FEATURES[0]])

    def ready(self):
        if self.static_profile:
            return True
        return self.samples() >= settings.BASELINE_MIN_SAMPLES

    def update(self, feats):
        self.update_counter += 1
        for f in settings.DEVICE_FEATURES:
            self.hist[f].append(feats[f])

            # Every 30 updates (5 minutes), push median of short window to long window
            if self.update_counter % 30 == 0:
                med = statistics.median(self.hist[f])
                self.long_hist[f].append(med)

    def deviations(self, feats):
        out = []
        for f in settings.DEVICE_FEATURES:
            if self.static_profile:
                # Demo Mode: Use loaded golden profile
                med = self.static_profile[f]["median"]
                scale = self.static_profile[f]["scale"]
            else:
                # Learning Mode: Use combined short + long rolling windows
                combined = list(self.hist[f]) + list(self.long_hist[f])
                med = statistics.median(combined)
                mad = statistics.median(abs(x - med) for x in combined)
                scale = max(1.4826 * mad, settings.SCALE_FLOOR[f])

            z_score = (feats[f] - med) / scale if scale > 0 else 0.0
            out.append({
                "feature": f,
                "value": round(feats[f], 2),
                "baseline_median": round(med, 2),
                "z": round(z_score, 1)
            })

        out.sort(key=lambda d: -d["z"])
        return out


baseline = Baseline()