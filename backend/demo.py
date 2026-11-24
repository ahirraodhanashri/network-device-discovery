"""Simulated network used for rehearsals and as a fallback when real scanning is not possible
(no admin rights, no Npcap, client-isolated Wi-Fi...).

EVERYTHING returned here is fake and every scan made from it is stored and displayed as
"DEMO (simulated)". It exists so the analysis features (comparison, spoofing indicators,
ARP-vs-ICMP) can be shown reliably. It must never be presented as a real scan.
"""
import ipaddress

# (host offset in the subnet, hostname, MAC, vendor, answers ping, TTL, RTT ms, open ports)
_BASE = [
    (1,   "router.lan",     "02:de:00:00:00:01", "ExampleNet Router (demo)", True,  255, 1.1, [53, 80, 443]),
    (5,   "laptop-ravi",    "02:de:00:00:00:05", "Demo Laptop Co.",          False, 128, 3.4, [135, 445, 3389]),
    (12,  "office-printer", "02:de:00:00:00:0c", "Demo Printers Inc.",       True,  64,  5.0, [80, 443]),
    (23,  "phone-android",  "02:de:00:00:00:17", "Demo Mobile Ltd.",         False, 64,  9.8, []),
    (42,  "smart-tv",       "02:de:00:00:00:2a", "Demo Display Corp.",       True,  64,  6.2, [8080]),
    (57,  "pi-server",      "02:de:00:00:00:39", "Demo Single-Board Co.",    True,  64,  2.3, [22, 80]),
    (88,  "lab-desktop",    "02:de:00:00:00:58", "Demo PC Works",            True,  128, 1.9, [135, 445, 3389]),
    (101, "ip-camera",      "02:de:00:00:00:65", "Demo Vision Ltd.",         True,  64,  7.7, [80, 554]),
]
ATTACKER_MAC = "02:de:00:00:00:66"

VARIANTS = {
    "baseline": "Normal network: 8 devices.",
    "changed": "Later scan: pi-server left, a new guest-tablet joined.",
    "spoofed": "ARP-spoofing scenario: lab-desktop's MAC also claims the gateway IP.",
}


def demo_gateway(network):
    return str(network.network_address + 1)


def demo_scan(network, methods, ports, variant="baseline"):
    """Return (devices, conflicts) shaped exactly like a real scan, filtered by chosen methods."""
    if variant not in VARIANTS:
        raise ValueError(f"Unknown demo variant '{variant}'. Use one of: {', '.join(VARIANTS)}")
    rows = list(_BASE)
    if variant == "changed":
        rows = [r for r in rows if r[1] != "pi-server"]
        rows.append((130, "guest-tablet", "02:de:00:00:00:82", "Demo Tablets Ltd.", True, 64, 11.4, [80]))

    size = network.num_addresses
    devices, conflicts = [], []
    for offset, host, mac, vendor, pings, ttl, rtt, open_ports in rows:
        if offset >= size - 1:
            continue  # host would fall outside a small subnet
        ip = str(network.network_address + offset)
        if variant == "spoofed" and offset == 1:
            conflicts.append({"ip": ip, "macs": [mac, ATTACKER_MAC]})
        found_by = []
        if "arp" in methods:
            found_by.append("ARP")
        if "icmp" in methods and pings:
            found_by.append("ICMP")
        if not found_by:
            continue
        shown_mac, shown_vendor = mac, vendor
        if variant == "spoofed" and offset in (1, 88):
            # The attacker's NIC (lab-desktop) answers for its own IP *and* for the gateway IP.
            shown_mac, shown_vendor = ATTACKER_MAC, "Demo PC Works"
        dev = {
            "ip": ip,
            "mac": shown_mac if "ARP" in found_by else None,
            "hostname": host, "vendor": shown_vendor if "ARP" in found_by else None,
            "methods": found_by,
            "rtt_ms": rtt, "ttl": ttl if "ICMP" in found_by else None,
            "open_ports": [{"port": p, "service": _service(p)} for p in open_ports if p in ports]
            if "tcp" in methods else [],
        }
        devices.append(dev)
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return devices, conflicts


def _service(port):
    from netutils import service_name
    return service_name(port)
