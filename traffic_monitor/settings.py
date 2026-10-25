"""
settings.py

All constants and thresholds for the network monitor, in one place. Nothing
in here does anything by itself -- every other module imports this one and
reads from it.

INTERFACE and DEVICE_IP are the two values main.py may override from the
command line (--iface / --ip). Every other module reads them as
`settings.INTERFACE` / `settings.DEVICE_IP` (not `from settings import ...`)
specifically so that an override made in main.py, before capture starts, is
seen by every module -- a `from settings import DEVICE_IP` elsewhere would
freeze in the old value at import time and silently ignore the override.
"""

INTERFACE = "Realtek PCIe FE Family Controller"
DEVICE_IP = "192.168.1.5"
WINDOW_SIZE = 60            # seconds of history used for features
REPORT_INTERVAL = 10        # seconds between reports

# --- rule thresholds for INBOUND sources (placeholders: tune from your own data) ---
RULE_SCAN_PORTS = 50        # this many distinct ports in one short window = port scan
RULE_REPEAT_SYNS = 30       # this many SYNs to one port (<= 3 ports total) = repeated attempts
RULE_FLOOD_RATE = 100       # SYNs per second to <= 5 ports = flood
RULE_FLOOD_MIN_SYNS = 200

# --- slow-scan detection: a second, longer window with a lower bar ---
LONG_WINDOW_SIZE = 600      # seconds of inbound history kept for the slow-scan check (10 min)
RULE_SLOW_SCAN_PORTS = 30   # distinct ports over the LONG window = slow scan

# --- ICMP ping probing (inbound echo requests to this device) ---
RULE_ICMP_COUNT = 20        # echo requests from one source within WINDOW_SIZE = probe/flood

# --- per-device baseline (this device's outbound + DNS behaviour) ---
BASELINE_HISTORY = 90       # samples kept (90 x 10 s = 15 minutes)
BASELINE_MIN_SAMPLES = 12   # samples needed before alerts are allowed (2 minutes)
LONG_BASELINE_HISTORY = 288     # long-window downsampled samples (288 x 5m = 24 hours)
Z_THRESHOLD = 6.0           # robust z-score needed to count as abnormal
# feature must ALSO exceed this absolute value (stops tiny changes alerting)
ABS_MIN = {
    "out_conns": 50, "out_unique_dsts": 25, "out_unique_ports": 25,
    "dns_queries": 60, "dns_unique_names": 40, "dns_nx_ratio": 0.5,
    "dns_max_entropy": 3.5,
}
# smallest "spread" allowed when the baseline is perfectly flat
SCALE_FLOOR = {
    "out_conns": 10, "out_unique_dsts": 5, "out_unique_ports": 5,
    "dns_queries": 10, "dns_unique_names": 5, "dns_nx_ratio": 0.1,
    "dns_max_entropy": 0.5,
}
DEVICE_FEATURES = list(ABS_MIN.keys())

ALERT_COOLDOWN = 60         # seconds before the same (type, source) can alert again
ALERT_LOG = "alerts.jsonl"  # set to None to disable the log file
BENCH_DIR = "benchmarks"    # set to None to disable the benchmark file

MAX_RECORDS = 20000         # per deque, so a flood cannot exhaust memory
MAX_SOURCES = 5000          # distinct inbound sources tracked at once
