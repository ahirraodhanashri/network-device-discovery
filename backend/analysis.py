"""Scan analysis: change detection and ARP-spoofing indicators.

ARP has no authentication: any host on the LAN can claim any IP address. An attacker who
answers "192.168.1.1 is at <my MAC>" can sit between victims and the gateway
(man-in-the-middle). We cannot *prove* an attack from scans alone, but these patterns are
the classic indicators, so we report them as indicators with the harmless explanations too.
"""


def _norm_mac(mac):
    return mac.lower() if mac else None


def anomaly(kind, severity, ip, message, **details):
    return {"type": kind, "severity": severity, "ip": ip, "message": message, "details": details}


def intra_scan_anomalies(devices, conflicts=None, gateway_ip=None):
    """Indicators visible inside one scan."""
    found = []

    # 1. Two different MACs answered for the same IP in the same scan.
    for conflict in conflicts or []:
        is_gw = conflict["ip"] == gateway_ip
        found.append(anomaly(
            "ip_conflict", "high" if is_gw else "medium", conflict["ip"],
            f"{len(conflict['macs'])} different MAC addresses answered for {conflict['ip']}"
            + (" (the default gateway)" if is_gw else "")
            + ". Possible ARP spoofing, or two devices configured with the same IP.",
            macs=conflict["macs"]))

    # 2. One MAC claiming several IPs.
    by_mac = {}
    for dev in devices:
        mac = _norm_mac(dev.get("mac"))
        if mac:
            by_mac.setdefault(mac, []).append(dev["ip"])
    for mac, ips in sorted(by_mac.items()):
        if len(ips) > 1:
            gw_involved = gateway_ip in ips
            found.append(anomaly(
                "mac_multiple_ips", "high" if gw_involved else "info", ", ".join(sorted(ips)),
                f"MAC {mac} answered for {len(ips)} IP addresses ({', '.join(sorted(ips))})."
                + (" One of them is the gateway, a typical man-in-the-middle pattern." if gw_involved else "")
                + " Can also be harmless: a router with several interfaces, a VM host or proxy ARP.",
                mac=mac, ips=sorted(ips)))
    return found


def compare_scans(old_devices, new_devices, gateway_ip=None):
    """Differences between two scans, keyed by IP address."""
    old = {d["ip"]: d for d in old_devices}
    new = {d["ip"]: d for d in new_devices}

    def pick(d):
        return {"ip": d["ip"], "mac": d.get("mac"), "hostname": d.get("hostname"), "vendor": d.get("vendor")}

    mac_changed = []
    for ip in sorted(old.keys() & new.keys(), key=lambda s: tuple(int(x) for x in s.split("."))):
        old_mac, new_mac = _norm_mac(old[ip].get("mac")), _norm_mac(new[ip].get("mac"))
        if old_mac and new_mac and old_mac != new_mac:
            is_gw = ip == gateway_ip or old[ip].get("is_gateway") or new[ip].get("is_gateway")
            mac_changed.append({
                "ip": ip, "old_mac": old_mac, "new_mac": new_mac, "is_gateway": bool(is_gw),
                "severity": "high" if is_gw else "medium",
                "message": f"{ip} moved from {old_mac} to {new_mac}."
                           + (" This is the gateway: investigate for ARP spoofing." if is_gw else "")
                           + " Benign causes: DHCP lease given to a different device, replaced network card.",
            })

    def ip_key(ip):
        return tuple(int(x) for x in ip.split("."))

    return {
        "newly_observed": [pick(new[ip]) for ip in sorted(new.keys() - old.keys(), key=ip_key)],
        "not_observed_in_new_scan": [pick(old[ip]) for ip in sorted(old.keys() - new.keys(), key=ip_key)],
        "mac_changed": mac_changed,
        "unchanged_count": len([ip for ip in old.keys() & new.keys()
                                if _norm_mac(old[ip].get("mac")) == _norm_mac(new[ip].get("mac"))
                                or not old[ip].get("mac") or not new[ip].get("mac")]),
        "note": "A device missing from a scan is not necessarily offline or malicious: it may be asleep, "
                "out of range or blocking probes.",
    }


def method_comparison(arp_ips, icmp_ips):
    """Why do ARP and ICMP find different hosts? (a classic data-communication talking point)."""
    arp_ips, icmp_ips = set(arp_ips), set(icmp_ips)
    key = lambda s: tuple(int(x) for x in s.split("."))  # noqa: E731
    return {
        "both": sorted(arp_ips & icmp_ips, key=key),
        "arp_only": sorted(arp_ips - icmp_ips, key=key),
        "icmp_only": sorted(icmp_ips - arp_ips, key=key),
        "explanation": (
            "ARP-only hosts are alive but ignore ping: a firewall (e.g. Windows Defender Firewall) or "
            "phone power-saving drops ICMP echo requests, yet the host must still answer ARP or it could "
            "not use the network. ICMP-only hosts are unusual on one LAN; they can be reached through "
            "proxy ARP or answered by a router on behalf of another subnet."),
    }
