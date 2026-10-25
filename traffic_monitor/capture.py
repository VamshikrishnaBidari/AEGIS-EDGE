"""
capture.py

Turns raw packets into the stored history in state.py: which source IPs are
knocking on which ports (inbound TCP SYNs), this device's own outbound
connections, ICMP echo requests aimed at this device, and this device's DNS
queries/responses. Also prunes that history down to the configured window
lengths.

handle_packet() is called once per packet -- by Scapy's AsyncSniffer in live
mode, or once per packet read from a saved file in replay mode (see
main.py). Nothing in this file decides whether something is an attack; that
judgement happens in detectors.py, downstream of features.py.
"""
import time

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP

import settings
import state

SYN = 0x02
ACK = 0x10


def handle_packet(packet):
    t0 = time.perf_counter()
    try:
        _process(packet)
    finally:
        state.stats["packets"] += 1
        state.handler_times.append(time.perf_counter() - t0)


def _process(packet):
    if IP not in packet:          # IPv6 is ignored for now
        return
    ip = packet[IP]
    t = float(packet.time)
    device_ip = settings.DEVICE_IP   # read fresh each call so a CLI --ip override is honoured

    if TCP in packet:
        tcp = packet[TCP]
        flags = int(tcp.flags)
        if not (flags & SYN) or (flags & ACK):   # keep new connection attempts only
            return
        if ip.dst == device_ip and ip.src != device_ip:
            with state.store_lock:
                if ip.src not in state.inbound and len(state.inbound) >= settings.MAX_SOURCES:
                    state.stats["dropped_sources"] += 1
                    return
                state.inbound[ip.src].append((t, tcp.dport))
        elif ip.src == device_ip and ip.dst != device_ip:
            with state.store_lock:
                state.outbound.append((t, ip.dst, tcp.dport))

    elif ICMP in packet:
        icmp = packet[ICMP]
        if icmp.type == 8 and ip.dst == device_ip and ip.src != device_ip:   # type 8 = echo request
            with state.store_lock:
                state.icmp_inbound[ip.src].append(t)

    elif UDP in packet and DNS in packet:
        dns = packet[DNS]
        if dns.qr == 0 and ip.src == device_ip and DNSQR in packet:
            name = qname_to_str(packet[DNSQR].qname)
            with state.store_lock:
                state.dns_queries.append((t, name))
        elif dns.qr == 1 and ip.dst == device_ip:
            with state.store_lock:
                state.dns_responses.append((t, int(dns.rcode)))


def qname_to_str(q):
    if isinstance(q, bytes):
        q = q.decode("utf-8", "ignore")
    return str(q).rstrip(".").lower()


def _trim(dq, cutoff):
    """For deques of (time, ...) tuples -- inbound, outbound, dns_queries, dns_responses."""
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _trim_flat(dq, cutoff):
    """For deques of plain timestamps -- icmp_inbound."""
    while dq and dq[0] < cutoff:
        dq.popleft()


def prune(now):
    """Call only while holding state.store_lock."""
    cutoff = now - settings.WINDOW_SIZE
    long_cutoff = now - settings.LONG_WINDOW_SIZE
    # inbound TCP records are kept for the LONG window; the short window is
    # applied later, at feature time, by slicing this same history (see
    # features.inbound_features).
    for src in list(state.inbound.keys()):
        _trim(state.inbound[src], long_cutoff)
        if not state.inbound[src]:
            del state.inbound[src]
    for src in list(state.icmp_inbound.keys()):
        _trim_flat(state.icmp_inbound[src], cutoff)
        if not state.icmp_inbound[src]:
            del state.icmp_inbound[src]
    _trim(state.outbound, cutoff)
    _trim(state.dns_queries, cutoff)
    _trim(state.dns_responses, cutoff)
