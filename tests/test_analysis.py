import unittest

import conftest_path  # noqa: F401
import analysis
import vendor


def dev(ip, mac, **extra):
    return {"ip": ip, "mac": mac, **extra}


class AnomalyTests(unittest.TestCase):
    def test_clean_scan_has_no_anomalies(self):
        devices = [dev("10.0.0.1", "aa:aa:aa:aa:aa:01"), dev("10.0.0.2", "aa:aa:aa:aa:aa:02")]
        self.assertEqual(analysis.intra_scan_anomalies(devices, [], "10.0.0.1"), [])

    def test_ip_conflict_on_gateway_is_high(self):
        found = analysis.intra_scan_anomalies([], [{"ip": "10.0.0.1", "macs": ["aa", "bb"]}], "10.0.0.1")
        self.assertEqual(found[0]["type"], "ip_conflict")
        self.assertEqual(found[0]["severity"], "high")

    def test_one_mac_many_ips(self):
        devices = [dev("10.0.0.1", "AA:AA:AA:AA:AA:01"), dev("10.0.0.9", "aa:aa:aa:aa:aa:01")]
        found = analysis.intra_scan_anomalies(devices, [], "10.0.0.1")
        self.assertEqual(found[0]["type"], "mac_multiple_ips")   # case-insensitive match
        self.assertEqual(found[0]["severity"], "high")           # gateway involved
        found = analysis.intra_scan_anomalies(devices, [], "10.0.0.200")
        self.assertEqual(found[0]["severity"], "info")           # no gateway involved

    def test_missing_mac_is_ignored(self):
        devices = [dev("10.0.0.1", None), dev("10.0.0.2", None)]
        self.assertEqual(analysis.intra_scan_anomalies(devices), [])


class CompareTests(unittest.TestCase):
    def test_new_missing_and_changed(self):
        old = [dev("10.0.0.1", "aa:01", is_gateway=True), dev("10.0.0.2", "aa:02"), dev("10.0.0.3", "aa:03")]
        new = [dev("10.0.0.1", "ff:99"), dev("10.0.0.2", "aa:02"), dev("10.0.0.10", "aa:10")]
        result = analysis.compare_scans(old, new, gateway_ip="10.0.0.1")
        self.assertEqual([d["ip"] for d in result["newly_observed"]], ["10.0.0.10"])
        self.assertEqual([d["ip"] for d in result["not_observed_in_new_scan"]], ["10.0.0.3"])
        self.assertEqual(len(result["mac_changed"]), 1)
        self.assertEqual(result["mac_changed"][0]["severity"], "high")
        self.assertEqual(result["unchanged_count"], 1)

    def test_numeric_ip_sorting(self):
        new = [dev("10.0.0.100", "a"), dev("10.0.0.20", "b"), dev("10.0.0.3", "c")]
        result = analysis.compare_scans([], new)
        self.assertEqual([d["ip"] for d in result["newly_observed"]], ["10.0.0.3", "10.0.0.20", "10.0.0.100"])

    def test_icmp_only_scan_vs_arp_scan_is_not_a_mac_change(self):
        result = analysis.compare_scans([dev("10.0.0.2", "aa:02")], [dev("10.0.0.2", None)])
        self.assertEqual(result["mac_changed"], [])

    def test_method_comparison(self):
        cmp_ = analysis.method_comparison({"10.0.0.1", "10.0.0.2"}, {"10.0.0.1", "10.0.0.9"})
        self.assertEqual(cmp_["both"], ["10.0.0.1"])
        self.assertEqual(cmp_["arp_only"], ["10.0.0.2"])
        self.assertEqual(cmp_["icmp_only"], ["10.0.0.9"])


class VendorTests(unittest.TestCase):
    def test_randomized_mac_detected(self):
        self.assertTrue(vendor.is_locally_administered("02:de:00:00:00:01"))
        self.assertFalse(vendor.is_locally_administered("b8:27:eb:00:00:01"))
        self.assertEqual(vendor.lookup_vendor("da:a1:19:00:00:01"), "Randomized / private MAC")

    def test_known_and_unknown(self):
        self.assertEqual(vendor.lookup_vendor("B8-27-EB-12-34-56"), "Raspberry Pi Foundation")
        self.assertIsNone(vendor.lookup_vendor("garbage"))
        self.assertIsNone(vendor.lookup_vendor(None))


if __name__ == "__main__":
    unittest.main()
