"""Networking helpers: subnet maths, local/gateway detection, ICMP ping, TCP probing.

Data-communication concepts used here
-------------------------------------
* IPv4 addressing and CIDR (network address, broadcast address, netmask, usable hosts)
* ICMP echo request/reply ("ping") and the IP TTL field
* TCP three-way handshake (a successful connect() means the port is open)
"""
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor

MAX_ADDRESSES = 1024  # keep scans small and polite (a /22)

# Small, well-known port list. Students can extend it from the UI.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "MS-RPC",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB", 554: "RTSP", 3389: "RDP",
    5000: "UPnP/Flask", 8080: "HTTP-alt",
}
DEFAULT_PORTS = [22, 53, 80, 135, 139, 443, 445, 3389, 8080]


# --------------------------------------------------------------------------- #
# Subnet maths
# --------------------------------------------------------------------------- #
def parse_cidr(text):
    """Parse any IPv4 CIDR string (used by the subnet calculator)."""
    try:
        network = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"'{text}' is not a valid CIDR range (example: 192.168.1.0/24)") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 CIDR ranges are supported.")
    return network


def parse_scan_subnet(text):
    """Parse a CIDR range and apply the safety rules for *scanning*."""
    network = parse_cidr(text)
    if network.num_addresses > MAX_ADDRESSES:
        raise ValueError(f"Range too large for this tool (max {MAX_ADDRESSES} addresses, i.e. /22).")
    if network.is_loopback or network.is_link_local or not network.is_private:
        raise ValueError("Only private LAN ranges are allowed (10/8, 172.16/12, 192.168/16).")
    return network


def _private_block(network):
    for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        if network.subnet_of(ipaddress.ip_network(block)):
            return block
    return None


def subnet_info(network):
    """Everything a student would calculate by hand for a CIDR block."""
    total = network.num_addresses
    if network.prefixlen == 32:
        first = last = network.network_address
        usable = 1
    elif network.prefixlen == 31:  # point-to-point link, RFC 3021
        first, last, usable = network.network_address, network.broadcast_address, 2
    else:
        first = network.network_address + 1
        last = network.broadcast_address - 1
        usable = total - 2
    first_octet = int(network.network_address) >> 24
    if first_octet < 128:
        klass = "A"
    elif first_octet < 192:
        klass = "B"
    elif first_octet < 224:
        klass = "C"
    elif first_octet < 240:
        klass = "D (multicast)"
    else:
        klass = "E (reserved)"
    mask_bits = f"{int(network.netmask):032b}"
    return {
        "cidr": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "netmask": str(network.netmask),
        "wildcard_mask": str(network.hostmask),
        "prefix_length": network.prefixlen,
        "netmask_binary": ".".join(mask_bits[i:i + 8] for i in range(0, 32, 8)),
        "total_addresses": total,
        "usable_hosts": usable,
        "first_host": str(first),
        "last_host": str(last),
        "address_class": klass,
        "is_private": network.is_private,
        "private_block": _private_block(network),
        "scannable": (network.is_private and not network.is_loopback
                      and not network.is_link_local and total <= MAX_ADDRESSES),
    }


# --------------------------------------------------------------------------- #
# Local machine information
# --------------------------------------------------------------------------- #
def get_local_ip():
    """IP of the interface used for the default route (no packet is actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1 address; UDP connect only picks a route
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_local_mac():
    """MAC from uuid.getnode(); returns None if Python had to invent a random one."""
    node = uuid.getnode()
    if (node >> 40) & 1:  # multicast bit set => not a real MAC
        return None
    return ":".join(f"{(node >> shift) & 0xff:02x}" for shift in range(40, -8, -8))


def get_default_gateway():
    """Best-effort default gateway lookup (None if it cannot be determined)."""
    try:
        from scapy.all import conf  # type: ignore
        gateway = conf.route.route("0.0.0.0")[2]
        if gateway and gateway != "0.0.0.0":
            return gateway
    except Exception:
        pass
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 text=True, timeout=5).stdout
            match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        elif system == "Darwin":
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True,
                                 text=True, timeout=5).stdout
            match = re.search(r"gateway:\s*(\S+)", out)
        else:
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True,
                                 text=True, timeout=5).stdout
            match = re.search(r"default via (\S+)", out)
        return match.group(1) if match else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# ICMP ping
# --------------------------------------------------------------------------- #
def ping_available():
    return shutil.which("ping") is not None


def _ping_command(ip, timeout_s):
    system = platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    if system == "Darwin":
        return ["ping", "-c", "1", "-W", str(int(timeout_s * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip]


def parse_ping_output(text):
    """Return (rtt_ms, ttl) from the system ping output, or None if the host did not reply."""
    ttl_match = re.search(r"ttl[=:]\s*(\d+)", text, re.I)
    if not ttl_match:  # Windows can print 'Destination host unreachable' with exit code 0
        return None
    rtt_match = re.search(r"time\s*[=<]\s*([\d.]+)\s*ms", text, re.I)
    rtt = float(rtt_match.group(1)) if rtt_match else None
    return rtt, int(ttl_match.group(1))


def ping_host(ip, timeout_s=1):
    """Send one ICMP echo request using the OS ping tool (works without admin rights)."""
    try:
        done = subprocess.run(_ping_command(ip, timeout_s), capture_output=True, text=True,
                              timeout=timeout_s + 3)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return parse_ping_output(done.stdout + done.stderr)


def ping_sweep(network, workers=64, timeout_s=1):
    """ICMP echo to every usable host. Returns {ip: {"rtt_ms": float|None, "ttl": int}}."""
    if not ping_available():
        raise RuntimeError("The 'ping' command was not found on this machine.")
    hosts = [str(h) for h in network.hosts()] or [str(network.network_address)]
    alive = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, result in zip(hosts, pool.map(lambda h: ping_host(h, timeout_s), hosts)):
            if result:
                alive[ip] = {"rtt_ms": result[0], "ttl": result[1]}
    return alive


def os_hint_from_ttl(ttl):
    """Rough OS family guess from the initial TTL. A heuristic, not proof."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux/Android/iOS/macOS (TTL≈64)"
    if ttl <= 128:
        return "Windows (TTL≈128)"
    return "Router/network device (TTL≈255)"


# --------------------------------------------------------------------------- #
# TCP connect scan
# --------------------------------------------------------------------------- #
def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def tcp_probe(ip, port, timeout_s=0.6):
    """True if the TCP three-way handshake completes (port open)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def scan_ports(ips, ports, timeout_s=0.6, workers=100):
    """TCP connect scan. Returns {ip: [{"port": 80, "service": "HTTP"}, ...]}."""
    jobs = [(ip, port) for ip in ips for port in ports]
    results = {ip: [] for ip in ips}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for (ip, port), is_open in zip(jobs, pool.map(lambda j: tcp_probe(j[0], j[1], timeout_s), jobs)):
            if is_open:
                results[ip].append({"port": port, "service": service_name(port)})
    for ip in results:
        results[ip].sort(key=lambda p: p["port"])
    return results


def parse_ports(value, limit=20):
    """Turn user input (list or '22,80,443') into a validated list of ports."""
    if value in (None, "", []):
        return list(DEFAULT_PORTS)
    if isinstance(value, str):
        value = [p for p in re.split(r"[,\s]+", value) if p]
    try:
        ports = sorted({int(p) for p in value})
    except (TypeError, ValueError) as exc:
        raise ValueError("Ports must be numbers, e.g. 22,80,443.") from exc
    if not ports or len(ports) > limit or ports[0] < 1 or ports[-1] > 65535:
        raise ValueError(f"Provide 1-{limit} ports between 1 and 65535.")
    return ports
