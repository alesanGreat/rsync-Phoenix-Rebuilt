import os
import tempfile
import unittest

from rsync_phoenix_rebuilt import FileEntry, RsyncOptions, file_list_roundtrip_over_wire


class TestFileListWireRoundtrip(unittest.TestCase):
    def test_roundtrip_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "alpha-0001.txt")
            p2 = os.path.join(td, "alpha-0002.txt")
            with open(p1, "wb") as f:
                f.write(b"one")
            with open(p2, "wb") as f:
                f.write(b"two-two")

            fixed_mtime = 1700000000
            os.utime(p1, (fixed_mtime, fixed_mtime))
            os.utime(p2, (fixed_mtime, fixed_mtime))

            entries = [FileEntry.from_stat(p1), FileEntry.from_stat(p2)]
            opts = RsyncOptions(preserve_owner=True, preserve_group=True, preserve_links=False)

            out = file_list_roundtrip_over_wire(entries, opts=opts, protocol_version=32, xfer_flags_as_varint=True)
            self.assertEqual(len(out), len(entries))
            self.assertEqual([e.filename for e in out], [e.filename for e in entries])
            self.assertEqual([e.size for e in out], [e.size for e in entries])
            self.assertEqual([e.mtime for e in out], [e.mtime for e in entries])
            self.assertEqual([e.uid for e in out], [e.uid for e in entries])
            self.assertEqual([e.gid for e in out], [e.gid for e in entries])

    def test_roundtrip_symlink_if_supported(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("os.symlink not available")

        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "target.txt")
            link = os.path.join(td, "link.txt")
            with open(target, "wb") as f:
                f.write(b"target")

            try:
                os.symlink("target.txt", link)
            except (OSError, NotImplementedError) as e:
                self.skipTest(f"symlinks not supported in this environment: {e}")

            entry = FileEntry.from_stat(link, follow_links=False)
            self.assertTrue(entry.is_link)

            opts = RsyncOptions(preserve_owner=False, preserve_group=False, preserve_links=True)
            out = file_list_roundtrip_over_wire([entry], opts=opts, protocol_version=32, xfer_flags_as_varint=True)
            self.assertEqual(len(out), 1)
            self.assertTrue(out[0].is_link)
            self.assertEqual(out[0].link_target, entry.link_target)

    def test_roundtrip_atimes_and_crtimes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "file.txt")
            with open(p1, "wb") as f:
                f.write(b"data")

            fixed_atime = 1700000100
            fixed_mtime = 1700000200
            os.utime(p1, (fixed_atime, fixed_mtime))

            entry = FileEntry.from_stat(p1)
            # On platforms without birthtime, rsync_phoenix_rebuilt falls back to mtime.
            self.assertEqual(entry.mtime, fixed_mtime)

            opts = RsyncOptions(
                preserve_owner=False,
                preserve_group=False,
                preserve_links=False,
                atimes=True,
                crtimes=True,
            )
            out = file_list_roundtrip_over_wire([entry], opts=opts, protocol_version=32, xfer_flags_as_varint=True)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0].mtime, entry.mtime)
            self.assertEqual(out[0].atime, entry.atime)
            self.assertEqual(out[0].crtime, entry.crtime)

    def test_roundtrip_mtime_nsec(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "nsec.txt")
            with open(p1, "wb") as f:
                f.write(b"data")

            entry = FileEntry.from_stat(p1)
            entry.mtime_nsec = 123456789

            opts = RsyncOptions(
                preserve_owner=False,
                preserve_group=False,
                preserve_links=False,
            )
            out = file_list_roundtrip_over_wire([entry], opts=opts, protocol_version=32, xfer_flags_as_varint=True)
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0].mtime, entry.mtime)
            self.assertEqual(out[0].mtime_nsec, entry.mtime_nsec)

    def test_roundtrip_device_rdev_encoding(self) -> None:
        # We cannot create real device nodes without privileges, but we can still
        # validate the wire encoding/decoding for a device-mode entry.
        entry = FileEntry(
            filename="dev/ttyS0",
            mode=0o020000 | 0o666,  # S_IFCHR | 0666
            size=0,
            mtime=1700000000,
            mtime_nsec=0,
            uid=0,
            gid=0,
            rdev=(123 << 8) | 45,
        )
        opts = RsyncOptions(preserve_devices=True)
        out = file_list_roundtrip_over_wire([entry], opts=opts, protocol_version=32, xfer_flags_as_varint=True)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].mode & 0o170000, entry.mode & 0o170000)
        self.assertEqual(out[0].rdev, entry.rdev)


if __name__ == "__main__":
    unittest.main()
