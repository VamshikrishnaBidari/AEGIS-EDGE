"""
detectors.py

Turns features into alerts. This is the file with the actual detection
logic: the rule thresholds (all from settings.py), the per-device baseline
comparison, and the alert lifecycle (build one, decide if it's a repeat of
an ongoing incident, apply cooldowns, print and log it).

This is also the file most likely to change as the project goes on: tuning
thresholds, adding new rule types, or eventually calling a trained
classifier instead of (or alongside) one of these rules. Keeping it apart
from capture.py and features.py means those two don't need to change at all
when the detection logic does.
"""
import json
from datetime import datetime

import settings
import state


def make_alert(now, kind, source, severity, summary, evidence, reasons, first_seen=None):
    delay = round(now - first_seen, 1) if first_seen else None
    return {
        "id": None,                      # assigned in emit_alert, after the cooldown check
        "timestamp": datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds"),
        "channel": "network",
        "type": kind,
        "severity": severity,
        "source": source,
        "target": settings.DEVICE_IP,
        "summary": summary,
        "evidence": {k: (round(v, 2) if isinstance(v, float) else v) for k, v in evidence.items()},
        "reasons": reasons,
        "detector": "rules+baseline",
        "seconds_to_detect": delay,
        "window_seconds": settings.WINDOW_SIZE,
    }


def emit_alert(now, alert):
    key = (alert["type"], alert["source"])
    gap = now - state.last_alert.get(key, -1e18)
    if gap < settings.ALERT_COOLDOWN:
        return
    # still the same incident if the previous alert is recent (window + one report)
    continuing = gap <= settings.WINDOW_SIZE + settings.REPORT_INTERVAL
    state.last_alert[key] = now
    alert["id"] = "NET-%04d" % next(state.alert_ids)
    alert["continuing"] = continuing
    if continuing:
        alert["seconds_to_detect"] = None      # only a new incident has a meaningful delay
    state.recent_alerts.append(alert)
    state.alert_counts[alert["type"]] += 1
    if alert["seconds_to_detect"] is not None:
        state.detect_delays.append(alert["seconds_to_detect"])

    print("\n[ALERT %s] %s  %s  source=%s" %
          (alert["id"], alert["severity"].upper(), alert["type"], alert["source"]))
    print("   " + alert["summary"])
    for r in alert["reasons"][:3]:
        print("   - " + ", ".join("%s=%s" % (k, v) for k, v in r.items()))
    if continuing:
        print("   (ongoing: repeat of an earlier alert)")
    elif alert["seconds_to_detect"] is not None:
        print("   detected %.1fs after the first packet in the window" % alert["seconds_to_detect"])
    print()
    if settings.ALERT_LOG:
        with open(settings.ALERT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert) + "\n")


def _recently_alerted(now, src, kinds):
    return any(now - state.last_alert.get((k, src), -1e18) < settings.LONG_WINDOW_SIZE for k in kinds)


def check_inbound(now, src, f, first_seen, f_long=None):
    """Rule-based detectors for one inbound source. `f` is the short-window
    (WINDOW_SIZE) feature set; `f_long` is the same source over LONG_WINDOW_SIZE,
    used only for the slow-scan check below. Replace/augment with a trained
    model later."""
    if f["rate"] >= settings.RULE_FLOOD_RATE and f["unique_ports"] <= 5 and f["syn_count"] >= settings.RULE_FLOOD_MIN_SYNS:
        kind, sev = "syn_flood", "high"
        summary = "%s sent %d connection attempts at %.0f per second to %d port(s)." % (
            src, f["syn_count"], f["rate"], f["unique_ports"])
        reasons = [{"feature": "rate", "value": round(f["rate"], 1), "threshold": settings.RULE_FLOOD_RATE}]
    elif f["unique_ports"] >= settings.RULE_SCAN_PORTS:
        kind = "port_scan"
        sev = "high" if f["unique_ports"] >= 200 else "medium"
        summary = "%s tried %d different ports in the last %ds (%d attempts)." % (
            src, f["unique_ports"], settings.WINDOW_SIZE, f["syn_count"])
        reasons = [{"feature": "unique_ports", "value": f["unique_ports"], "threshold": settings.RULE_SCAN_PORTS},
                   {"feature": "port_diversity", "value": round(f["port_diversity"], 2)}]
    elif f["unique_ports"] <= 3 and f["max_port_syns"] >= settings.RULE_REPEAT_SYNS:
        kind, sev = "repeated_connection_attempts", "medium"
        summary = "%s made %d connection attempts to the same port(s) in %ds (possible brute force)." % (
            src, f["max_port_syns"], settings.WINDOW_SIZE)
        reasons = [{"feature": "max_port_syns", "value": f["max_port_syns"], "threshold": settings.RULE_REPEAT_SYNS}]
    elif (f_long is not None and f_long["unique_ports"] >= settings.RULE_SLOW_SCAN_PORTS
          and f_long["duration"] > settings.WINDOW_SIZE   # genuinely spread out, not just an early fast scan
          and not _recently_alerted(now, src, ("port_scan", "syn_flood", "repeated_connection_attempts"))):
        # none of the fast-window rules fired (or fired recently for this source),
        # but spread over the long window this source has still touched an
        # abnormal number of distinct ports
        kind, sev = "slow_port_scan", "medium"
        summary = "%s tried %d different ports over the last %d minutes (%d attempts) -- too slow for the short-window scan rule, but still a scan pattern." % (
            src, f_long["unique_ports"], settings.LONG_WINDOW_SIZE // 60, f_long["syn_count"])
        reasons = [{"feature": "unique_ports_long", "value": f_long["unique_ports"], "threshold": settings.RULE_SLOW_SCAN_PORTS},
                   {"feature": "window_minutes", "value": settings.LONG_WINDOW_SIZE // 60}]
        emit_alert(now, make_alert(now, kind, src, sev, summary, f_long, reasons, first_seen))
        return
    else:
        return
    emit_alert(now, make_alert(now, kind, src, sev, summary, f, reasons, first_seen))


def check_icmp(now, src, f, first_seen):
    """Repeated inbound ICMP echo requests from one source (ping probing/flooding us)."""
    if f["echo_count"] < settings.RULE_ICMP_COUNT:
        return
    sev = "high" if f["rate"] >= 20 else "low"
    summary = "%s sent %d ICMP echo requests (pings) in the last %ds -- possible ping probe or flood." % (
        src, f["echo_count"], settings.WINDOW_SIZE)
    reasons = [{"feature": "echo_count", "value": f["echo_count"], "threshold": settings.RULE_ICMP_COUNT},
               {"feature": "rate", "value": round(f["rate"], 1)}]
    emit_alert(now, make_alert(now, "icmp_probe", src, sev, summary, f, reasons, first_seen))


def check_device(now, feats):
    """Compare this device's outbound/DNS behaviour with its own baseline."""
    if not state.baseline.ready():
        state.baseline.update(feats)
        return
    devs = state.baseline.deviations(feats)
    hot = [d for d in devs if d["z"] >= settings.Z_THRESHOLD and d["value"] >= settings.ABS_MIN[d["feature"]]]
    if not hot:
        state.baseline.update(feats)       # only learn from samples that looked normal
        return
    kind = "dns_anomaly" if hot[0]["feature"].startswith("dns_") else "outbound_anomaly"
    sev = "high" if len(hot) >= 3 else "medium"
    top = hot[0]
    summary = ("This device's %s jumped to %s (its normal is about %s)."
               % (top["feature"], top["value"], top["baseline_median"]))
    emit_alert(now, make_alert(now, kind, settings.DEVICE_IP, sev, summary, feats, hot))
