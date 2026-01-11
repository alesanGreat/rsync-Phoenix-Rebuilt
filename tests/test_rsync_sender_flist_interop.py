#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interop test: rsync (C) sender -> python flist receiver.

This validates that our minimal wire-level `setup_protocol_wire()` + multiplex
framing + `recv_file_list_wire()` can decode a real rsync sender's file-list.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import unittest

import rsync_phoenix_rebuilt as impl


class TestRsyncSenderFlistInterop(unittest.TestCase):
    def test_rsync_sender_file_list_roundtrip(self) -> None:
        if shutil.which("rsync") is None:
            self.skipTest("rsync binary not available")

        with tempfile.TemporaryDirectory() as td:
            srcdir = os.path.join(td, "src")
            os.mkdir(srcdir)
            srcfile = os.path.join(srcdir, "hello.txt")
            with open(srcfile, "wb") as f:
                f.write(b"hello")

            # Mimic a remote-shell --server invocation. The packed option-string is
            # representative of a protocol>=30 run (it includes an -eFLAGS arg).
            cmd = ["rsync", "--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", srcfile]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert proc.stdin is not None
            assert proc.stdout is not None
            assert proc.stderr is not None

            io = impl.ProtocolIO()
            io.set_fd(proc.stdout.fileno(), proc.stdin.fileno())

            # These flags must match the sender's idea of what's enabled, or the
            # receiver will desync on optional fields (uid/gid, symlink data, etc).
            opts = impl.RsyncOptions()
            opts.compress = False
            opts.preserve_owner = True
            opts.preserve_group = True
            opts.preserve_links = True
            opts.preserve_devices = True
            opts.preserve_specials = True
            opts.preserve_times = True

            try:
                hs = impl.setup_protocol_wire(io, opts, am_server=False, protocol_version=impl.PROTOCOL_VERSION)
                # With protocol>=30, rsync expects multiplexing in both directions.
                io.io_start_multiplex_in()
                io.io_start_multiplex_out()

                # Sender-side start_server() calls recv_filter_list() before send_file_list().
                impl.send_filter_list_wire(io, rules=[])

                flist = impl.recv_file_list_wire(
                    io,
                    opts,
                    protocol_version=hs.negotiated_protocol,
                    xfer_flags_as_varint=hs.xfer_flags_as_varint,
                )
            finally:
                try:
                    proc.send_signal(signal.SIGTERM)
                except Exception:
                    pass
                try:
                    proc.communicate(timeout=5)
                except Exception:
                    proc.kill()
                    proc.communicate(timeout=5)

            self.assertGreaterEqual(len(flist), 1)
            self.assertEqual(flist[0].filename, "hello.txt")

