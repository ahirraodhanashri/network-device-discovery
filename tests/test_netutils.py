import ipaddress
import unittest

import conftest_path  # noqa: F401
import netutils


class SubnetTests(unittest.TestCase):
    def test_slash24(self):
        info = netutils.subnet_info(netutils.parse_cidr("192.168.1.77/24"))  # host bits ignored
        self.assertEqual(info["network_address"], "192.168.1.0")
        self.assertEqual(info["broadcast_address"], "192.168.1.255")
        self.assertEqual(info["netmask"], "255.255.255.0")
        self.assertEqual(info["wildcard_mask"], "0.0.0.255")
        self.assertEqual(info["usable_hosts"], 254)
        self.assertEqual((info["first_host"], info["last_host"]), ("192.168.1.1", "192.168.1.254"))
        self.assertEqual(info["address_class"], "C")
        self.assertEqual(info["private_block"], "192.168.0.0/16")

    def test_slash26_by_hand(self):
        info = netutils.subnet_info(netutils.parse_cidr("10.1.2.0/26"))
        self.assertEqual(info["netmask"], "255.255.255.192")
        self.assertEqual(info["netmask_binary"], "11111111.11111111.11111111.11000000")
        self.assertEqual(info["usable_hosts"], 62)
        self.assertEqual(info["address_class"], "A")

    def test_tiny_networks(self):
        self.assertEqual(netutils.subnet_info(netutils.parse_cidr("192.168.1.5/32"))["usable_hosts"], 1)
        self.assertEqual(netutils.subnet_info(netutils.parse_cidr("192.168.1.4/31"))["usable_hosts"], 2)

    def test_invalid_input(self):
        for bad in ("", "hello", "300.1.1.0/24", "fe80::/64"):
            with self.assertRaises(ValueError):
                netutils.parse_cidr(bad)

    def test_scan_safety_rules(self):
        netutils.parse_scan_subnet("192.168.0.0/24")
        netutils.parse_scan_subnet("172.20.0.0/22")
        for bad in ("8.8.8.0/24", "127.0.0.0/24", "169.254.0.0/16", "10.0.0.0/8", "192.168.0.0/16"):
            with self.assertRaises(ValueError, msg=bad):
                netutils.parse_scan_subnet(bad)


class PingParsingTests(unittest.TestCase):
    def test_linux(self):
        out = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms"
        self.assertEqual(netutils.parse_ping_output(out), (1.23, 64))

    def test_windows_reply(self):
        out = "Reply from 192.168.1.1: bytes=32 time=3ms TTL=128"
        self.assertEqual(netutils.parse_ping_output(out), (3.0, 128))

    def test_windows_fast_reply(self):
        self.assertEqual(netutils.parse_ping_output("Reply from 10.0.0.2: bytes=32 time<1ms TTL=64"), (1.0, 64))

    def test_no_reply(self):
        self.assertIsNone(netutils.parse_ping_output("Request timed out."))
        # Windows prints this with exit code 0, but it is NOT a live host
        self.assertIsNone(netutils.parse_ping_output("Reply from 192.168.1.9: Destination host unreachable."))


class MiscTests(unittest.TestCase):
    def test_os_hint(self):
        self.assertIn("Linux", netutils.os_hint_from_ttl(64))
        self.assertIn("Windows", netutils.os_hint_from_ttl(128))
        self.assertIn("Router", netutils.os_hint_from_ttl(255))
        self.assertIsNone(netutils.os_hint_from_ttl(None))

    def test_parse_ports(self):
        self.assertEqual(netutils.parse_ports("80, 22 443,80"), [22, 80, 443])
        self.assertEqual(netutils.parse_ports(None), netutils.DEFAULT_PORTS)
        for bad in ("0", "70000", "abc", ",".join(str(p) for p in range(1, 40))):
            with self.assertRaises(ValueError, msg=bad):
                netutils.parse_ports(bad)

    def test_tcp_probe_on_local_listener(self):
        import socket
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            self.assertTrue(netutils.tcp_probe("127.0.0.1", port))
            found = netutils.scan_ports(["127.0.0.1"], [port])["127.0.0.1"]
            self.assertEqual([p["port"] for p in found], [port])
        finally:
            server.close()
        self.assertFalse(netutils.tcp_probe("127.0.0.1", port))  # closed now


if __name__ == "__main__":
    unittest.main()
