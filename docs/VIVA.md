# Viva preparation: likely questions and answers

Learn these in your own words. Examiners usually point at a feature and ask "how does this work?".

## Core concepts
**1. What does your project do?**
It discovers devices on a local network using ARP, ICMP and TCP, shows each device's IP, MAC, vendor,
hostname, latency and open ports, stores scan history, and flags patterns that suggest ARP spoofing.

**2. What is ARP and why do we need it?**
Applications use IP addresses, but Ethernet delivers frames by MAC address. ARP resolves "which MAC owns this IP?".
The asker broadcasts the question and the owner replies with its MAC.

**3. Why is the ARP request sent to `ff:ff:ff:ff:ff:ff`?**
The sender does not yet know the target's MAC, so it uses the Layer-2 broadcast address. Every host in the
broadcast domain receives the frame, but only the owner of the target IP replies (unicast).

**4. Why does ARP only work inside the local subnet?**
Routers do not forward Layer-2 broadcasts, so ARP is limited to one broadcast domain. For other subnets a host
ARPs for its *gateway* and sends the packet there.

**5. Walk me through the ARP frame.** (*Packet anatomy* panel)
Ethernet header: destination MAC, source MAC, EtherType `0x0806`. ARP payload: hardware type 1 (Ethernet),
protocol type `0x0800` (IPv4), sizes 6 and 4, opcode 1 (request) or 2 (reply), then sender MAC/IP and
target MAC/IP. In a request the target MAC is all zeros because it is the unknown. Total 42 bytes; the NIC
pads to 60.

**6. Explain `192.168.1.0/24`.**
24 network bits, 8 host bits. Mask `255.255.255.0`. 256 addresses; the first (`.0`) is the network address and the
last (`.255`) the broadcast, so 254 usable hosts. (The subnet calculator shows this in binary.)

**7. Why only private ranges?**
Safety and ethics: ARP can't leave the LAN anyway, and scanning other people's networks without permission can
be illegal. The tool allows 10/8, 172.16/12, 192.168/16 only, caps the size at 1024 addresses, and asks for confirmation.

## The three techniques
**8. Why did ARP find hosts that ICMP did not?**
Many hosts (e.g. Windows with the default firewall, phones in power-save) drop ICMP echo requests. But a
host *must* answer ARP, or nobody could send it traffic. So ARP is more reliable on a LAN. (The *ARP vs ICMP* panel shows this.)

**9. What is TTL and how does it hint at the OS?**
TTL is a hop counter in the IP header, decremented by each router. Operating systems start with different values:
about 64 (Linux/macOS/Android/iOS), 128 (Windows), 255 (many routers). On a LAN there are no hops in between, so the
reply TTL is the starting value. It's a heuristic: it can be changed.

**10. How does the TCP scan work?**
It calls `connect()` on each port. If the three-way handshake (SYN, SYN-ACK, ACK) completes, the port is open.
A refused connection (RST) or timeout means closed or filtered. It is a "connect scan", the simplest type, and
unlike Nmap's SYN scan it needs no special privileges but is more visible in logs.

**11. What is reverse DNS?**
A PTR lookup (`gethostbyaddr`) maps IP -> name. Many home devices have no PTR record, so hostnames are often blank.

**12. What is an OUI?**
The first 3 bytes of a MAC identify the manufacturer (assigned by the IEEE). Phones often use randomized "private"
MACs (the locally-administered bit, 0x02 of the first byte, is set), so no vendor can be shown.

## Security
**13. What is ARP spoofing and how do you detect it?**
ARP has no authentication. An attacker answers "the gateway's IP is at *my* MAC", so victims send traffic through the
attacker (man-in-the-middle). Indicators: (a) two different MACs answer for one IP; (b) one MAC claims several IPs,
especially including the gateway; (c) an IP's MAC changes between scans. The demo scenario *spoofed* reproduces this.

**14. Can you prove an attack?**
No. DHCP can hand an IP to a new device, a VM host may legitimately own several IPs, and proxy ARP exists. The tool
reports *indicators* and lists the harmless explanations. Proof needs packet captures or switch logs.

**15. How would you defend against ARP spoofing?**
Dynamic ARP Inspection on managed switches, static ARP entries for the gateway, port security, and encrypted
protocols (HTTPS, SSH) so intercepted traffic is useless.

**16. Is your tool safe to run?**
It binds to `127.0.0.1` only, validates all input, rejects public ranges, allows one scan at a time, escapes all
network-supplied text in the browser (no `innerHTML`) and neutralises spreadsheet formulas in CSV export.

## Design questions
**17. Why Scapy for ARP but plain sockets for TCP and `ping` for ICMP?**
Sending raw Layer-2 frames needs a packet library and admin rights; TCP connects are ordinary socket calls; ICMP
via the system `ping` avoids raw-socket privileges. `packets.py` shows I understand the frame by building it myself with `struct`.

**18. Why does the hand-built packet exist if Scapy sends the real one?**
To make the protocol visible and testable. It is displayed, never transmitted, and the unit tests check every byte offset.

**19. What does the demo mode do? Is it real?**
No: it is simulated data, labelled everywhere (*DEMO* banner and tag, not stored with real scans for comparison). I use
it to demonstrate the analysis features reproducibly and as a fallback. Real scanning is the default.

**20. Limitations and future work?**
Switch-port/topology discovery via SNMP or LLDP, IPv6 (NDP instead of ARP), live detection by sniffing ARP packets
continuously, scheduled scans with alerts, authentication for a multi-user deployment.

## Be ready to demonstrate
- Open Wireshark with filter `arp`, run a scan, and point out the requests/replies that match the hexdump in the app.
- Change the subnet to `/26` and explain the calculator output by hand.
- Run the *spoofed* demo after the *baseline* one and walk through the alerts.
