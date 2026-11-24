import unittest

import conftest_path  # noqa: F401
import packets


class ArpFrameTests(unittest.TestCase):
    def setUp(self):
        self.frame = packets.build_arp_request("aa:bb:cc:dd:ee:ff", "192.168.1.50", "192.168.1.1")

    def test_length_and_known_bytes(self):
        self.assertEqual(len(self.frame), 42)
        self.assertEqual(self.frame[:6], b"\xff" * 6)          # broadcast destination
        self.assertEqual(self.frame[12:14], b"\x08\x06")        # EtherType ARP
        self.assertEqual(self.frame[20:22], b"\x00\x01")        # opcode 1 = request
        self.assertEqual(self.frame[28:32], bytes([192, 168, 1, 50]))
        self.assertEqual(self.frame[32:38], b"\x00" * 6)        # unknown target MAC
        self.assertEqual(self.frame[38:42], bytes([192, 168, 1, 1]))

    def test_round_trip(self):
        parsed = packets.parse_arp_frame(self.frame)
        self.assertEqual(parsed["opcode"], 1)
        self.assertEqual(parsed["sender_ip"], "192.168.1.50")
        self.assertEqual(parsed["target_ip"], "192.168.1.1")
        self.assertEqual(parsed["eth_dst"], packets.BROADCAST_MAC)

    def test_reply_is_unicast(self):
        reply = packets.build_arp_reply("11:22:33:44:55:66", "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.50")
        parsed = packets.parse_arp_frame(reply)
        self.assertEqual(parsed["opcode"], 2)
        self.assertEqual(parsed["eth_dst"], "aa:bb:cc:dd:ee:ff")

    def test_explain_covers_whole_frame_without_gaps(self):
        fields = packets.explain_frame(self.frame)
        position = 0
        for f in fields:
            self.assertEqual(f["offset"], position, f["field"])
            position += f["length"]
        self.assertEqual(position, len(self.frame))

    def test_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            packets.build_arp_request("not-a-mac", "192.168.1.1", "192.168.1.2")
        with self.assertRaises(ValueError):
            packets.build_arp_request("aa:bb:cc:dd:ee:ff", "999.1.1.1", "192.168.1.2")
        with self.assertRaises(ValueError):
            packets.parse_arp_frame(b"\x00" * 10)


if __name__ == "__main__":
    unittest.main()
