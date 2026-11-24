# NetDiscover: Network Device Discovery Tool

A Data Communication project that discovers devices on a **private LAN you are authorised to scan**,
using three techniques from different layers of the network stack, and then analyses the results.

| Layer | Technique | What it proves | Implemented in |
|---|---|---|---|
| 2 (link) | **ARP** broadcast sweep | The host is alive and tells us its MAC | `discovery.arp_scan` (Scapy) |
| 3 (network) | **ICMP** echo (ping) sweep | Host answers ping; gives RTT and TTL (OS hint) | `netutils.ping_sweep` |
| 4 (transport) | **TCP connect** scan | A service is listening (3-way handshake completes) | `netutils.scan_ports` (plain sockets) |

## Features
- **Subnet calculator**: network, broadcast, mask (decimal and binary), wildcard, usable hosts, class, private block
- **ARP / ICMP / TCP discovery**, selectable and combinable
- **Vendor lookup (OUI)** from the MAC; detects randomized/private MACs (phones)
- **Reverse-DNS hostnames**, **RTT**, **TTL-based OS hint**, **open ports with service names**
- **ARP vs ICMP comparison**: shows which hosts hide from ping and explains why
- **ARP-spoofing indicators**: duplicate MAC for one IP, one MAC claiming several IPs, MAC changes between scans (gateway changes rated *high*)
- **Automatic comparison** with the previous scan of the same subnet, plus a manual compare tool
- **Packet anatomy**: the exact ARP request, hand-built with `struct`, byte by byte with a hexdump (it is displayed, never sent)
- **Logical topology map** (SVG) centred on the gateway
- **Scan history** in SQLite, **CSV export** (formula-injection safe), delete scans
- **Demo mode**: clearly labelled *simulated* data for rehearsals or when the real network will not cooperate
- Safety: private ranges only, max 1024 addresses, authorisation tick-box, one scan at a time

## Project layout
```
backend/
  app.py         Flask API + serves the frontend
  discovery.py   Runs ARP/ICMP/TCP and merges results
  netutils.py    Subnet maths, ping, TCP probe, gateway/local-IP detection
  packets.py     Hand-built Ethernet+ARP frames (struct), parser, hexdump
  analysis.py    Spoofing indicators, scan comparison, ARP-vs-ICMP logic
  vendor.py      MAC -> manufacturer (OUI) lookup
  demo.py        Simulated network (always labelled DEMO)
  db.py          SQLite storage
frontend/        index.html, style.css, app.js (plain JavaScript, no build step)
tests/           36 unit/API tests (python -m unittest discover -s tests)
docs/            VIVA.md (likely questions + answers), DEMO_SCRIPT.md
```

## Run (Windows)
1. Install Python 3.11+ and **[Npcap](https://npcap.com)** (tick "WinPcap API-compatible mode").
2. Open a terminal **as Administrator** in the `backend` folder:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   py app.py
   ```
3. Open **http://127.0.0.1:5000** (Flask serves the page, so there is no CORS setup).

Linux/macOS: same steps with `python3`, and run `sudo .venv/bin/python app.py` (raw packets need root).

Real ARP scanning needs admin rights. Without Scapy or admin rights the page still works in
**demo mode** (choose a *DEMO* data source).

## Optional: full vendor database
The first lookup uses Scapy's bundled manufacturer list. To use IEEE's complete list instead, put a
CSV named `backend/data/oui.csv` with lines like `B8:27:EB,Raspberry Pi Foundation`.

## Tests
```
python -m unittest discover -s tests -v
```

## API
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Capabilities, local IP, gateway |
| GET | `/api/subnet-info?cidr=192.168.1.0/24` | Subnet calculator |
| GET | `/api/packet/arp?target=192.168.1.1` | Build and explain an ARP request |
| POST | `/api/scans` | `{"subnet":"192.168.1.0/24","methods":["arp","icmp","tcp"],"ports":"22,80","authorized":true}` (add `"demo":"baseline"\|"changed"\|"spoofed"` for simulated data) |
| GET | `/api/scans`, `/api/scans/<id>` | History / one scan with devices and alerts |
| GET | `/api/scans/compare?old=1&new=2` | Differences between two scans |
| GET | `/api/scans/<id>/export.csv` | CSV export |
| DELETE | `/api/scans/<id>` | Delete a scan |

## Limitations (be upfront about these)
- ARP works only inside the **local broadcast domain**; this is not an internet scanner.
- Your own machine does not answer its own ARP request, so it is not listed.
- Wi-Fi with *client isolation* (many college networks) blocks ARP replies from other devices. Use your own hotspot or home router.
- A device missing from a scan may be asleep, out of range or firewalled; it is not proof of anything.
- **Spoofing indicators are hints, not proof.** Each alert lists harmless explanations too (DHCP re-lease, VM host, proxy ARP).
- TTL-based OS detection is a rough heuristic. Vendor names are unavailable for randomized MACs.
- The topology is logical (one hop from the gateway); it does not discover switch ports or physical cabling.
- Scans run synchronously; a /24 with ICMP + TCP can take up to a minute.
- No authentication: it binds to `127.0.0.1` only. Do not expose it publicly.

Use only on networks you own or have explicit written permission to scan.
