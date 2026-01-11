import socket
import threading
import unittest

from rsync_phoenix_rebuilt import (
    CF_VARINT_FLIST_FLAGS,
    ProtocolIO,
    RsyncOptions,
    setup_protocol_wire,
)


class TestCompatHandshake(unittest.TestCase):
    def _run_handshake(self, server_opts: RsyncOptions, client_opts: RsyncOptions, *, client_info: str = ""):
        s1, s2 = socket.socketpair()
        try:
            server_io = ProtocolIO()
            client_io = ProtocolIO()
            server_io.set_fd(s1.fileno(), s1.fileno())
            client_io.set_fd(s2.fileno(), s2.fileno())

            out = {}

            def _server():
                out["server"] = setup_protocol_wire(
                    server_io, server_opts, am_server=True, client_info=client_info, protocol_version=32
                )

            def _client():
                out["client"] = setup_protocol_wire(
                    client_io, client_opts, am_server=False, protocol_version=32
                )

            t1 = threading.Thread(target=_server)
            t2 = threading.Thread(target=_client)
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)
            self.assertFalse(t1.is_alive())
            self.assertFalse(t2.is_alive())
            return out["server"], out["client"]
        finally:
            s1.close()
            s2.close()

    def test_handshake_default_no_negotiated_strings(self) -> None:
        server_opts = RsyncOptions(compress=True)
        client_opts = RsyncOptions(compress=True)
        server, client = self._run_handshake(server_opts, client_opts, client_info="")

        self.assertEqual(server.negotiated_protocol, 32)
        self.assertEqual(client.negotiated_protocol, 32)
        self.assertFalse(server.do_negotiated_strings)
        self.assertFalse(client.do_negotiated_strings)
        self.assertFalse(server.xfer_flags_as_varint)
        self.assertFalse(client.xfer_flags_as_varint)
        self.assertEqual(server.checksum_choice, "md5")
        self.assertEqual(client.checksum_choice, "md5")
        self.assertEqual(server.compress_choice, "zlib")
        self.assertEqual(client.compress_choice, "zlib")

    def test_handshake_enables_varint_flist_for_crtimes(self) -> None:
        server_opts = RsyncOptions(compress=False, crtimes=True)
        client_opts = RsyncOptions(compress=False, crtimes=True)
        server, client = self._run_handshake(server_opts, client_opts, client_info="vC")

        self.assertTrue(server.compat_flags & CF_VARINT_FLIST_FLAGS)
        self.assertTrue(client.compat_flags & CF_VARINT_FLIST_FLAGS)
        self.assertTrue(server.do_negotiated_strings)
        self.assertTrue(client.do_negotiated_strings)
        self.assertTrue(server.xfer_flags_as_varint)
        self.assertTrue(client.xfer_flags_as_varint)
        self.assertEqual(server.compress_choice, "none")
        self.assertEqual(client.compress_choice, "none")
        self.assertEqual(server.checksum_choice, client.checksum_choice)


if __name__ == "__main__":
    unittest.main()

