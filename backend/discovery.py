"""Device discovery engine: ARP, ICMP and TCP techniques merged into one device list.

Layer view (good to remember for the viva)
  ARP   -> Layer 2/3 boundary. Broadcast frame, cannot be firewalled on a LAN without breaking it.
  ICMP  -> Layer 3 (network). Many hosts' firewalls drop echo requests.
  TCP   -> Layer 4 (transport). A completed three-way handshake proves a service is listening.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed

import analysis
import demo as demo_module
import netutils
import vendor

try:
    from scapy.all import ARP, Ether, conf, srp  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # Scapy missing or no packet-capture driver
    SCAPY_AVAILABLE = False

VALID_METHODS = ("arp", "icmp", "tcp")


def arp_scan(network, timeout=2, retry=1):
    """Broadcast 'who has <ip>?' for every address in the subnet.

    Returns (devices, conflicts). `conflicts` lists IPs for which more than one MAC replied.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed (pip install -r requirements.txt). "
                           "On Windows also install Npcap.")
    try:
        conf.verb = 0
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                          timeout=timeout, retry=retry, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("Permission denied: run the terminal as Administrator (Windows) "
                           "or with sudo (Linux/macOS).") from exc
    except Exception as exc:
        raise RuntimeError(f"Packet capture failed: {exc}. On Windows make sure Npcap is installed "
                           "in WinPcap-compatible mode.") from exc

    seen = {}
    for sent, received in answered:
        ip, mac = received.psrc, received.hwsrc.lower()
        entry = seen.setdefault(ip, {"macs": [], "rtt_ms": _rtt_ms(sent, received)})
        if mac not in entry["macs"]:
            entry["macs"].append(mac)
    devices = [{"ip": ip, "mac": e["macs"][0], "rtt_ms": e["rtt_ms"]} for ip, e in seen.items()]
    conflicts = [{"ip": ip, "macs": e["macs"]} for ip, e in seen.items() if len(e["macs"]) > 1]
    return devices, conflicts


def _rtt_ms(sent, received):
    """Round-trip time = reply arrival time - request send time (None if unavailable)."""
    try:
        return round(float(received.time - sent.sent_time) * 1000, 2)
    except Exception:
        return None


def _resolve(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def resolve_hostnames(ips, timeout_s=4):
    """Reverse DNS (PTR lookups) in parallel; slow lookups are abandoned after timeout_s."""
    names = {}
    if not ips:
        return names
    pool = ThreadPoolExecutor(max_workers=32)
    futures = {pool.submit(_resolve, ip): ip for ip in ips}
    try:
        for future in as_completed(futures, timeout=timeout_s):
            names[futures[future]] = future.result()
    except FuturesTimeout:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return names


def _ip_key(ip):
    return tuple(int(part) for part in ip.split("."))


def run_discovery(network, methods, ports=None, demo_variant=None):
    """Run the selected techniques and return a merged result dictionary."""
    methods = [m for m in VALID_METHODS if m in methods]
    if not any(m in methods for m in ("arp", "icmp")):
        raise ValueError("Select ARP and/or ICMP discovery. TCP port scanning only probes hosts "
                         "that were discovered first.")
    ports = ports or netutils.DEFAULT_PORTS
    notes = []
    arp_ips, icmp_ips = set(), set()

    if demo_variant:
        devices, conflicts = demo_module.demo_scan(network, methods, ports, demo_variant)
        gateway = demo_module.demo_gateway(network)
        notes.append("SIMULATED DATA: no packets were sent on any network.")
    else:
        gateway = netutils.get_default_gateway()
        merged, conflicts = {}, []

        if "arp" in methods:
            arp_devices, conflicts = arp_scan(network)
            for d in arp_devices:
                arp_ips.add(d["ip"])
                merged[d["ip"]] = {"ip": d["ip"], "mac": d["mac"], "methods": ["ARP"],
                                   "rtt_ms": d["rtt_ms"], "ttl": None}
        if "icmp" in methods:
            for ip, info in netutils.ping_sweep(network).items():
                icmp_ips.add(ip)
                dev = merged.setdefault(ip, {"ip": ip, "mac": None, "methods": [], "rtt_ms": None, "ttl": None})
                dev["methods"].append("ICMP")
                dev["ttl"] = info["ttl"]
                if info["rtt_ms"] is not None:
                    dev["rtt_ms"] = info["rtt_ms"]
        devices = sorted(merged.values(), key=lambda d: _ip_key(d["ip"]))

        for d in devices:
            d["vendor"] = vendor.lookup_vendor(d["mac"])
        names = resolve_hostnames([d["ip"] for d in devices])
        for d in devices:
            d["hostname"] = names.get(d["ip"])

        if "tcp" in methods and devices:
            open_ports = netutils.scan_ports([d["ip"] for d in devices], ports)
            for d in devices:
                d["open_ports"] = open_ports.get(d["ip"], [])
        else:
            for d in devices:
                d["open_ports"] = []
        if "arp" in methods and "icmp" in methods:
            notes.append("Both ARP and ICMP ran; see the method comparison for the differences.")
        elif "icmp" in methods and "arp" not in methods:
            notes.append("ICMP-only scan: MAC addresses and vendors are unavailable because ICMP "
                         "works at layer 3 and does not reveal layer-2 addresses.")

    for d in devices:
        d["os_hint"] = netutils.os_hint_from_ttl(d.get("ttl"))
        d["is_gateway"] = d["ip"] == gateway
        d.setdefault("open_ports", [])

    comparison = None
    if "arp" in methods and "icmp" in methods:
        if demo_variant:
            arp_ips = {d["ip"] for d in devices if "ARP" in d["methods"]}
            icmp_ips = {d["ip"] for d in devices if "ICMP" in d["methods"]}
        comparison = analysis.method_comparison(arp_ips, icmp_ips)

    return {
        "devices": devices,
        "conflicts": conflicts,
        "gateway_ip": gateway,
        "method_comparison": comparison,
        "notes": notes,
        "anomalies": analysis.intra_scan_anomalies(devices, conflicts, gateway),
    }
