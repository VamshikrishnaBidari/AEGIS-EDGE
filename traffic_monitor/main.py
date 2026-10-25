"""
main.py

Entry point. Parses command-line arguments, applies any --iface/--ip
overrides directly onto the settings module (so every other module, which
always reads settings.INTERFACE / settings.DEVICE_IP fresh rather than
caching them at import time, sees the override), then runs either live
capture or a pcap replay, and writes the benchmark file on the way out.

Run live (administrator PowerShell):   python main.py
Replay a saved capture (any shell):    python main.py --pcap scan.pcapng
To create your device baseline:        python main.py --save-baseline
"""
import argparse
import time

from scapy.all import AsyncSniffer, PcapReader
import psutil

import capture
import reporting
import settings
import state

def run_live():
    sniffer = AsyncSniffer(iface=settings.INTERFACE, prn=capture.handle_packet, store=False)
    sniffer.start()
    time.sleep(1)
    if not sniffer.running:
        print("Sniffer did not start. Run as Administrator and check INTERFACE.")
        return
    print("Capturing on", settings.INTERFACE, "- press Ctrl+C to stop")
    psutil.Process().cpu_percent(interval=None)    # prime the CPU counter
    try:
        while True:
            time.sleep(settings.REPORT_INTERVAL)
            reporting.report(time.time())
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        if sniffer.running:
            sniffer.stop()


def run_replay(path):
    """Feed a saved capture through the same handlers, using packet time as the clock."""
    print("Replaying", path)
    next_report = None
    last_t = None
    with PcapReader(path) as reader:
        for pkt in reader:
            t = float(pkt.time)
            if next_report is None:
                next_report = t + settings.REPORT_INTERVAL
            while t >= next_report:
                reporting.report(next_report)
                next_report += settings.REPORT_INTERVAL
            capture.handle_packet(pkt)
            last_t = t
    if last_t is not None:
        reporting.report(last_t)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", help="replay a saved capture instead of sniffing live")
    ap.add_argument("--iface", help="override settings.INTERFACE")
    ap.add_argument("--ip", help="override settings.DEVICE_IP")
    ap.add_argument("--save-baseline", action="store_true", help="Save the dual-tier baseline to golden_baseline.json on exit")
    args = ap.parse_args()

    if args.iface:
        settings.INTERFACE = args.iface
    if args.ip:
        settings.DEVICE_IP = args.ip

    mode = "replay" if args.pcap else "live"
    try:
        run_replay(args.pcap) if args.pcap else run_live()
    finally:
        if args.save_baseline:
            state.baseline.save_to_disk()
        reporting.write_benchmark(mode)


if __name__ == "__main__":
    main()
