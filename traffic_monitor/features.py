"""
features.py

Pure feature-extraction functions: turn raw (time, ...) records into the
small set of numbers the detectors and the baseline work with.

Nothing here touches settings.py or state.py -- every function takes
exactly the data it needs as arguments and returns a plain dict. That's
deliberate: this is the one file that has to produce identical output
whether it's fed live packets (via capture.py's stores) or recorded/replayed
data used later to train a classifier. If a function here ever needs a
global or a setting, that's a sign it's drifting out of this file and
risking a live/training mismatch.
"""
import math
import statistics
from collections import Counter


def shannon_entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def inbound_features(records, now=None, window=None):
    """records: (time, dport) history from ONE source.
    If `window` is given, only the slice of records within that many seconds of `now`
    is used -- this lets the same stored history serve both the short (fast-scan /
    flood / brute-force) and long (slow-scan) checks without duplicating storage."""
    if window is not None:
        cutoff = now - window
        records = [r for r in records if r[0] >= cutoff]
    if not records:
        return None

    times = sorted(r[0] for r in records)
    ports = [r[1] for r in records]
    n = len(records)
    duration = times[-1] - times[0]
    gaps = [b - a for a, b in zip(times, times[1:])]
    gap_mean = statistics.fmean(gaps) if gaps else 0.0
    gap_cv = (statistics.pstdev(gaps) / gap_mean) if gaps and gap_mean > 0 else 0.0
    return {
        "syn_count": n,
        "unique_ports": len(set(ports)),
        "duration": duration,
        "rate": n / max(duration, 1.0),
        "port_diversity": len(set(ports)) / n,
        "max_port_syns": max(Counter(ports).values()),
        "iat_mean": gap_mean,          # mean seconds between attempts
        "iat_cv": gap_cv,              # burstiness: ~0 = metronome, >1 = bursty
    }


def icmp_features(times):
    """times: echo-request timestamps from ONE source, already pruned to WINDOW_SIZE."""
    if not times:
        return None
    times = sorted(times)
    duration = times[-1] - times[0]
    return {
        "echo_count": len(times),
        "duration": duration,
        "rate": len(times) / max(duration, 1.0),
    }


def device_features(out_records, q_records, r_records):
    """This device's outbound connections and DNS behaviour in the window."""
    names = [name for _, name in q_records]
    rcodes = [rc for _, rc in r_records]
    nx_ratio = (rcodes.count(3) / len(rcodes)) if len(rcodes) >= 10 else 0.0   # rcode 3 = NXDOMAIN
    return {
        "out_conns": len(out_records),
        "out_unique_dsts": len({d for _, d, _ in out_records}),
        "out_unique_ports": len({p for _, _, p in out_records}),
        "dns_queries": len(names),
        "dns_unique_names": len(set(names)),
        "dns_nx_ratio": nx_ratio,
        "dns_max_entropy": max((shannon_entropy(n.split(".")[0]) for n in names), default=0.0),
    }
