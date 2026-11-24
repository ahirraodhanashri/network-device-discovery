# Presentation script (about 8 minutes)

## Before you walk in (do this the day before, on the actual laptop)
- [ ] Npcap installed; terminal **opened as Administrator**; `py app.py` runs; page opens at http://127.0.0.1:5000
- [ ] Both chips at the top are green: **Scapy ready** and **ping ready**
- [ ] Use **your own phone hotspot or home router**. College Wi-Fi often isolates clients and shows zero devices.
- [ ] Do one real scan *at home first* so there are real scans in the history
- [ ] Wireshark installed, filter set to `arp`
- [ ] Have 2 phones/laptops on the same network; turn one phone's Wi-Fi off and on to show a change
- [ ] Backup plan: if real scanning fails in the room, say so and switch to the **DEMO** source. Never present demo data as real.

## Flow
1. **Problem (30 s):** "How do you find out what is connected to a network? Each protocol layer gives a different answer."
2. **Subnet calculator (45 s):** type `192.168.1.0/26`; read out network, broadcast, 62 usable hosts, binary mask.
3. **Packet anatomy (1 min):** scroll to the ARP frame; explain broadcast MAC, EtherType, opcode, zero target MAC.
4. **Live ARP scan (1.5 min):** start Wireshark capture, run an ARP scan. Show requests going out and replies coming back, and the same devices in the table: vendor, hostname, RTT.
5. **ICMP + TCP (1.5 min):** tick ICMP and TCP, rescan. Show TTL / OS hint, open ports, and the **ARP vs ICMP** panel (which device hides from ping and why).
6. **Change detection (1 min):** toggle a phone's Wi-Fi, rescan; show *Newly observed / Not observed* and the automatic comparison with the previous scan.
7. **Security (1.5 min):** choose *DEMO: ARP-spoofing scenario*, run *baseline* then *spoofed*; walk through the red alerts and the red node on the topology map. State clearly: "this is simulated, but it is exactly the pattern a real ARP spoof produces."
8. **Close (30 s):** limitations (local broadcast domain only, indicators are not proof) and future work (IPv6/NDP, SNMP/LLDP topology, continuous ARP monitoring).

## If something goes wrong
| Symptom | Fix |
|---|---|
| "Scapy is not installed" / "Packet capture failed" | Install Npcap in WinPcap-compatible mode and restart the terminal |
| "Permission denied" | Reopen the terminal as Administrator |
| 0 devices found | Wrong subnet (check your IP with `ipconfig`) or Wi-Fi client isolation: use a hotspot |
| Gateway not marked | Gateway detection failed; harmless, the topology centre shows "LAN" |
| "Another scan is already running" | Wait; one scan at a time |
