"""
tests.test_tunnel — Unit tests for SOCKS5 and Port Forwarder
"""

import socket
import time
import unittest
from unittest.mock import MagicMock
from pwnrm.core.tunnel import Socks5Server, PortForwarder


class TestTunnel(unittest.TestCase):
    def test_socks5_lifecycle(self):
        server = Socks5Server(bind_host="127.0.0.1", bind_port=0)
        self.assertFalse(server.is_running)
        server.start()
        self.assertTrue(server.is_running)

        # Test connecting and handshake
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", server.bind_port))
        # Send SOCKS5 Greeting (VER=5, NMETHODS=1, METHOD=0)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        self.assertEqual(resp, b"\x05\x00")
        s.close()

        server.stop()
        self.assertFalse(server.is_running)

    def test_port_forwarder_lifecycle(self):
        fwd = PortForwarder()
        fid = fwd.start_local_forward(0, "127.0.0.1", 11082)
        forwards = fwd.list_forwards()
        self.assertEqual(len(forwards), 1)
        self.assertEqual(forwards[0]["id"], fid)
        self.assertTrue(fwd.stop_forward(fid))
        self.assertEqual(len(fwd.list_forwards()), 0)

    def test_port_forwarder_validation_and_stop_all(self):
        fwd = PortForwarder()
        with self.assertRaises(ValueError):
            fwd.start_local_forward(-1, "127.0.0.1", 80)
        with self.assertRaises(ValueError):
            fwd.start_local_forward(0, "127.0.0.1", 0)
        first = fwd.start_local_forward(0, "127.0.0.1", 11082)
        second = fwd.start_local_forward(0, "127.0.0.1", 11083)
        self.assertNotEqual(first, second)
        self.assertEqual(fwd.stop_all(), 2)
        self.assertEqual(fwd.list_forwards(), [])

    def test_socks_frame_reader_handles_partial_reads(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"a", b"bc", b"d"]
        self.assertEqual(Socks5Server._recv_exact(sock, 4), b"abcd")

    def test_socks_frame_reader_rejects_truncation(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"a", b""]
        with self.assertRaises(ConnectionError):
            Socks5Server._recv_exact(sock, 2)


if __name__ == "__main__":
    unittest.main()
