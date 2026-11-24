import os
import tempfile
import unittest

import conftest_path  # noqa: F401

_tmp = tempfile.mkdtemp()
os.environ["NETDISCOVERY_DB"] = os.path.join(_tmp, "test.db")
import app as backend  # noqa: E402


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = backend.app.test_client()

    def scan(self, **body):
        body.setdefault("subnet", "192.168.50.0/24")
        return self.client.post("/api/scans", json=body)

    def test_01_health_and_frontend(self):
        self.assertEqual(self.client.get("/api/health").json["status"], "ok")
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Network Device Discovery", page.data)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)
        self.assertEqual(self.client.get("/static/../backend/app.py").status_code, 404)

    def test_02_validation(self):
        self.assertEqual(self.scan(subnet="8.8.8.0/24").status_code, 400)
        self.assertEqual(self.scan(subnet="nonsense").status_code, 400)
        self.assertEqual(self.scan(methods=["nmap"], demo="baseline").status_code, 400)
        self.assertEqual(self.scan(methods=["tcp"], demo="baseline").status_code, 400)
        self.assertEqual(self.scan(ports="99999", demo="baseline").status_code, 400)
        self.assertEqual(self.scan(demo="nope").status_code, 400)
        self.assertEqual(self.scan().status_code, 403)                       # real scan, no authorization
        self.assertEqual(self.scan(authorized="yes").status_code, 403)       # must be literal true

    def test_03_demo_scan_flow_and_spoof_detection(self):
        first = self.scan(demo="baseline", methods=["arp", "icmp", "tcp"]).json
        self.assertEqual(first["device_count"], 8)
        self.assertTrue(first["is_demo"])
        self.assertEqual(first["anomalies"], [])
        self.assertIsNone(first["changes_since_previous"])
        self.assertEqual(first["method_comparison"]["arp_only"], ["192.168.50.5", "192.168.50.23"])

        second = self.scan(demo="spoofed", methods=["arp", "icmp", "tcp"]).json
        kinds = {a["type"] for a in second["anomalies"]}
        self.assertEqual(kinds, {"ip_conflict", "mac_multiple_ips"})
        change = second["changes_since_previous"]
        self.assertEqual(change["previous_scan_id"], first["scan_id"])
        self.assertTrue(any(c["is_gateway"] and c["severity"] == "high" for c in change["mac_changed"]))

        stored = self.client.get(f"/api/scans/{second['scan_id']}").json
        self.assertEqual(len(stored["devices"]), 8)
        self.assertEqual(len(stored["anomalies"]), 2)
        self.assertTrue(stored["is_demo"])

        cmp_ = self.client.get(f"/api/scans/compare?old={first['scan_id']}&new={second['scan_id']}").json
        self.assertEqual(len(cmp_["mac_changed"]), 2)
        self.assertFalse(cmp_["mixed_sources"])

    def test_04_demo_methods_respected(self):
        arp_only = self.scan(demo="baseline", subnet="192.168.60.0/24", methods=["arp"]).json
        self.assertIsNone(arp_only["method_comparison"])
        self.assertTrue(all(d["methods"] == ["ARP"] and d["ttl"] is None for d in arp_only["devices"]))
        icmp_only = self.scan(demo="baseline", subnet="192.168.61.0/24", methods=["icmp"]).json
        self.assertTrue(all(d["mac"] is None for d in icmp_only["devices"]))   # ICMP cannot see MACs
        self.assertLess(icmp_only["device_count"], 8)                            # ping-blockers missing

    def test_05_demo_never_mixed_with_real_history(self):
        a = self.scan(demo="baseline", subnet="192.168.70.0/24").json
        self.assertIsNone(a["changes_since_previous"])
        b = self.scan(demo="changed", subnet="192.168.70.0/24").json
        names = {d["ip"] for d in b["changes_since_previous"]["newly_observed"]}
        self.assertEqual(names, {"192.168.70.130"})

    def test_06_csv_export_is_injection_safe(self):
        import db
        scan_id = db.save_scan("192.168.80.0/24", "ARP", "completed", {
            "devices": [{"ip": "192.168.80.2", "mac": "aa:bb:cc:dd:ee:01", "hostname": "=HYPERLINK(\"http://x\")",
                         "vendor": None, "methods": ["ARP"], "open_ports": []}],
            "anomalies": [], "gateway_ip": None})
        text = self.client.get(f"/api/scans/{scan_id}/export.csv").data.decode()
        self.assertIn("'=HYPERLINK", text)
        self.assertNotIn(",=HYPERLINK", text)

    def test_07_subnet_info_and_packet_endpoints(self):
        info = self.client.get("/api/subnet-info?cidr=172.16.0.0/20").json
        self.assertEqual(info["usable_hosts"], 4094)
        self.assertEqual(self.client.get("/api/subnet-info?cidr=zzz").status_code, 400)
        pkt = self.client.get("/api/packet/arp?target=192.168.1.1&src_ip=192.168.1.50&src_mac=aa:bb:cc:dd:ee:ff").json
        self.assertEqual(pkt["length_bytes"], 42)
        self.assertEqual(self.client.get("/api/packet/arp?target=bad").status_code, 400)

    def test_08_delete_and_missing(self):
        self.assertEqual(self.client.get("/api/scans/99999").status_code, 404)
        self.assertEqual(self.client.get("/api/scans/compare?old=1").status_code, 400)
        self.assertEqual(self.client.get("/api/scans/compare?old=1&new=99999").status_code, 404)
        sid = self.scan(demo="baseline", subnet="192.168.90.0/24").json["scan_id"]
        self.assertEqual(self.client.delete(f"/api/scans/{sid}").status_code, 200)
        self.assertEqual(self.client.get(f"/api/scans/{sid}").status_code, 404)

    def test_09_real_scan_failure_is_recorded(self):
        # Scapy / ping are unavailable in some environments; the failure must be stored, not crash.
        r = self.scan(authorized=True, methods=["arp"], subnet="192.168.99.0/24")
        if r.status_code == 500:
            self.assertEqual(r.json["status"], "failed")
            failed = self.client.get(f"/api/scans/{r.json['scan_id']}").json
            self.assertEqual(failed["status"], "failed")


if __name__ == "__main__":
    unittest.main()
