import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))
from port_sentinel import get_active_tcp_connections, decode_port

class TestPortSentinel(unittest.TestCase):
    def test_port_endianness_decode(self):
        # 80 (HTTP) -> htons(80) = 0x5000 in little endian = 20480
        self.assertEqual(decode_port(20480), 80)
        # 443 (HTTPS) -> htons(443) = 0xBB01 = 47873
        self.assertEqual(decode_port(47873), 443)

    def test_enumeration_returns_sockets(self):
        conns = get_active_tcp_connections()
        self.assertGreater(len(conns), 0, "System must have at least one active TCP socket")
        self.assertTrue(any(c["state"] in ["LISTEN", "ESTABLISHED"] for c in conns))

if __name__ == '__main__':
    unittest.main()
