"""Hand-built Ethernet + ARP frames (no Scapy needed).

This module shows *exactly* what goes on the wire when we ask "who has 192.168.1.1?".
Everything is packed with struct so each byte can be explained in the viva.

Ethernet II header (14 bytes)           ARP payload for IPv4 over Ethernet (28 bytes)
  dst MAC   6   ff:ff:ff:ff:ff:ff         hardware type   2   1 = Ethernet
  src MAC   6   our NIC                   protocol type   2   0x0800 = IPv4
  EtherType 2   0x0806 = ARP              hw addr length  1   6
                                          proto addr len  1   4
                                          opcode          2   1 = request, 2 = reply
                                          sender MAC      6
                                          sender IP       4
                                          target MAC      6   all zero in a request
                                          target IP       4
"""
import ipaddress
import re
import struct

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
ETHERTYPE_ARP = 0x0806
OP_REQUEST, OP_REPLY = 1, 2
ARP_FORMAT = "!6s6sH HHBBH 6s4s6s4s"  # Ethernet header + ARP payload, network byte order
FRAME_LENGTH = struct.calcsize(ARP_FORMAT)  # 42 bytes (NIC pads to 60 on the wire)

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def mac_to_bytes(mac):
    if not _MAC_RE.match(str(mac)):
        raise ValueError(f"Invalid MAC address: {mac}")
    return bytes(int(part, 16) for part in re.split(r"[:-]", mac))


def bytes_to_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def build_arp_frame(op, sender_mac, sender_ip, target_mac, target_ip, eth_dst, eth_src=None):
    """Pack a complete Ethernet+ARP frame."""
    eth_src = eth_src or sender_mac
    return struct.pack(
        ARP_FORMAT,
        mac_to_bytes(eth_dst), mac_to_bytes(eth_src), ETHERTYPE_ARP,
        1, 0x0800, 6, 4, op,
        mac_to_bytes(sender_mac), ipaddress.IPv4Address(sender_ip).packed,
        mac_to_bytes(target_mac), ipaddress.IPv4Address(target_ip).packed,
    )


def build_arp_request(sender_mac, sender_ip, target_ip):
    """'Who has target_ip? Tell sender_ip.' - broadcast at layer 2."""
    return build_arp_frame(OP_REQUEST, sender_mac, sender_ip, ZERO_MAC, target_ip, BROADCAST_MAC)


def build_arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    """'sender_ip is at sender_mac.' - unicast back to the asker."""
    return build_arp_frame(OP_REPLY, sender_mac, sender_ip, target_mac, target_ip, target_mac)


def parse_arp_frame(frame):
    """Unpack a frame produced by build_arp_frame (or captured on the wire)."""
    if len(frame) < FRAME_LENGTH:
        raise ValueError("Frame too short to be Ethernet + ARP")
    (dst, src, ethertype, htype, ptype, hlen, plen, op,
     sha, spa, tha, tpa) = struct.unpack(ARP_FORMAT, frame[:FRAME_LENGTH])
    return {
        "eth_dst": bytes_to_mac(dst), "eth_src": bytes_to_mac(src), "ethertype": ethertype,
        "htype": htype, "ptype": ptype, "hlen": hlen, "plen": plen, "opcode": op,
        "sender_mac": bytes_to_mac(sha), "sender_ip": str(ipaddress.IPv4Address(spa)),
        "target_mac": bytes_to_mac(tha), "target_ip": str(ipaddress.IPv4Address(tpa)),
    }


def hexdump(frame, width=16):
    lines = []
    for offset in range(0, len(frame), width):
        chunk = frame[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def explain_frame(frame):
    """Field-by-field breakdown used by the 'Packet anatomy' panel."""
    p = parse_arp_frame(frame)
    op_name = {OP_REQUEST: "request (who has?)", OP_REPLY: "reply (is at)"}.get(p["opcode"], "other")
    rows = [
        ("Ethernet", "Destination MAC", 0, 6, p["eth_dst"],
         "Layer-2 broadcast: every host on the LAN receives it" if p["eth_dst"] == BROADCAST_MAC
         else "Unicast to the host that asked"),
        ("Ethernet", "Source MAC", 6, 6, p["eth_src"], "MAC address of the sender's network card"),
        ("Ethernet", "EtherType", 12, 2, f"0x{p['ethertype']:04x}", "0x0806 means the payload is ARP"),
        ("ARP", "Hardware type", 14, 2, str(p["htype"]), "1 = Ethernet"),
        ("ARP", "Protocol type", 16, 2, f"0x{p['ptype']:04x}", "0x0800 = IPv4 addresses are being resolved"),
        ("ARP", "Hardware size", 18, 1, str(p["hlen"]), "MAC addresses are 6 bytes"),
        ("ARP", "Protocol size", 19, 1, str(p["plen"]), "IPv4 addresses are 4 bytes"),
        ("ARP", "Opcode", 20, 2, str(p["opcode"]), f"1 = request, 2 = reply. This frame is a {op_name}"),
        ("ARP", "Sender MAC", 22, 6, p["sender_mac"], "Who is asking / answering (hardware address)"),
        ("ARP", "Sender IP", 28, 4, p["sender_ip"], "Who is asking / answering (IP address)"),
        ("ARP", "Target MAC", 32, 6, p["target_mac"],
         "Unknown yet, so all zeros in a request" if p["target_mac"] == ZERO_MAC else "Intended receiver"),
        ("ARP", "Target IP", 38, 4, p["target_ip"], "The IP address whose MAC we want to learn"),
    ]
    return [{
        "layer": layer, "field": field, "offset": offset, "length": length,
        "hex": " ".join(f"{b:02x}" for b in frame[offset:offset + length]),
        "value": value, "meaning": meaning,
    } for layer, field, offset, length, value, meaning in rows]
