"""
reporting.py

Everything observability-related: the periodic on-screen report (prune the
stores, compute features for every tracked source and this device, print a
status line, hand off to detectors.py), plus the benchmark file written on
exit. Kept together because both just read from state.py and write to the
screen or disk, rather than holding any detection logic of their own.
"""
import json
import os
import statistics
import time
from datetime import datetime

import psutil

import capture
import detectors
import features
import settings
import state


def report(now):
    t0 = time.perf_counter()
    with state.store_lock:                     # hold the lock only long enough to copy
        capture.prune(now)
        in_snap = {src: list(rec) for src, rec in state.inbound.items()}       # up to LONG_WINDOW_SIZE each
        icmp_snap = {src: list(times) for src, times in state.icmp_inbound.items()}  # up to WINDOW_SIZE each
        out_snap = list(state.outbound)
        q_snap = list(state.dns_queries)
        r_snap = list(state.dns_responses)

    print("%s  inbound sources: %d" % (time.strftime("%H:%M:%S", time.localtime(now)), len(in_snap)))
    for src, recs in in_snap.items():
        f = features.inbound_features(recs, now, settings.WINDOW_SIZE)       # last WINDOW_SIZE seconds only
        f_long = features.inbound_features(recs, now, settings.LONG_WINDOW_SIZE)  # the full stored history
        first_seen = min(r[0] for r in recs)
        if f:
            print("  %-15s syns=%-5d ports=%-5d rate=%.1f/s diversity=%.2f maxport=%-4d iat_cv=%.2f"
                  % (src, f["syn_count"], f["unique_ports"], f["rate"], f["port_diversity"],
                     f["max_port_syns"], f["iat_cv"]))
            detectors.check_inbound(now, src, f, first_seen=first_seen, f_long=f_long)
        elif f_long:
            # nothing in the short window, but the long-window history (e.g. a slow
            # scan paced slower than REPORT_INTERVAL) still needs checking
            print("  %-15s ports(%dm)=%-5d (quiet in the last %ds)"
                  % (src, settings.LONG_WINDOW_SIZE // 60, f_long["unique_ports"], settings.WINDOW_SIZE))
            detectors.check_inbound(now, src, {"rate": 0, "unique_ports": 0, "max_port_syns": 0},
                                     first_seen=first_seen, f_long=f_long)

    for src, times in icmp_snap.items():
        fi = features.icmp_features(times)
        if fi:
            print("  %-15s icmp echoes=%-4d rate=%.1f/s" % (src, fi["echo_count"], fi["rate"]))
            detectors.check_icmp(now, src, fi, first_seen=min(times))

    d = features.device_features(out_snap, q_snap, r_snap)
    bl_state = ("ready" if state.baseline.ready()
                else "learning %d/%d" % (state.baseline.samples(), settings.BASELINE_MIN_SAMPLES))
    print("  device: conns=%d dsts=%d ports=%d | dns q=%d uniq=%d nx=%.2f ent=%.2f | baseline %s"
          % (d["out_conns"], d["out_unique_dsts"], d["out_unique_ports"], d["dns_queries"],
             d["dns_unique_names"], d["dns_nx_ratio"], d["dns_max_entropy"], bl_state))
    detectors.check_device(now, d)

    state.stats["reports"] += 1
    state.cycle_times.append(time.perf_counter() - t0)
    proc = psutil.Process()
    state.resource_samples.append((proc.cpu_percent(interval=None), proc.memory_info().rss / 1e6))


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    return s[int(round((p / 100) * (len(s) - 1)))]


def write_benchmark(mode):
    if not settings.BENCH_DIR:
        return
    os.makedirs(settings.BENCH_DIR, exist_ok=True)
    h = [x * 1e6 for x in state.handler_times]       # microseconds
    c = [x * 1e3 for x in state.cycle_times]         # milliseconds
    cpu = [s[0] for s in state.resource_samples]
    ram = [s[1] for s in state.resource_samples]
    result = {
        "mode": mode,
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "packets_seen": state.stats["packets"],
        "reports": state.stats["reports"],
        "dropped_sources": state.stats["dropped_sources"],
        "alerts": dict(state.alert_counts),
        "handler_us_p50": pct(h, 50), "handler_us_p95": pct(h, 95), "handler_us_max": max(h) if h else None,
        "report_cycle_ms_p50": pct(c, 50), "report_cycle_ms_p95": pct(c, 95),
        "seconds_to_detect_p50": pct(state.detect_delays, 50), "seconds_to_detect_p95": pct(state.detect_delays, 95),
        "cpu_percent_avg": round(statistics.fmean(cpu), 1) if cpu else None,
        "ram_mb_max": round(max(ram), 1) if ram else None,
    }
    path = os.path.join(settings.BENCH_DIR, "net_run_%s.json" % datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print("Benchmark saved to", path)
