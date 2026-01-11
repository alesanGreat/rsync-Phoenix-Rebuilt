import os
import shutil
import subprocess
import sys
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    snapshot: dict[str, bytes] = {}
    if not root.exists():
        return snapshot
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        if p.is_dir():
            continue
        if p.is_symlink():
            snapshot[rel] = ("SYMLINK:" + os.readlink(p)).encode("utf-8", errors="replace")
        else:
            snapshot[rel] = p.read_bytes()
    return snapshot


def _snapshot_tree_modes(root: Path) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    if not root.exists():
        return snapshot
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = str(p.relative_to(root))
        snapshot[rel] = stat.S_IMODE(p.lstat().st_mode)
    return snapshot


def _snapshot_tree_mtimes(root: Path) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    if not root.exists():
        return snapshot
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = str(p.relative_to(root))
        snapshot[rel] = int(p.lstat().st_mtime)
    return snapshot


def _snapshot_tree_dir_modes(root: Path) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    if not root.exists():
        return snapshot
    for p in sorted(root.rglob("*")):
        if not p.is_dir():
            continue
        rel = str(p.relative_to(root))
        if rel == ".":
            continue
        snapshot[rel] = stat.S_IMODE(p.lstat().st_mode)
    return snapshot


def _snapshot_tree_dir_mtimes(root: Path) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    if not root.exists():
        return snapshot
    for p in sorted(root.rglob("*")):
        if not p.is_dir():
            continue
        rel = str(p.relative_to(root))
        if rel == ".":
            continue
        snapshot[rel] = int(p.lstat().st_mtime)
    return snapshot


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class TestCliLocalParity(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]
        self.script = self.repo_root / "rsync_phoenix_rebuilt.py"

    def _run_pair(self, args: list[str], src: Path, dest: Path) -> tuple[dict[str, bytes], dict[str, bytes]]:
        with TemporaryDirectory() as td:
            td_path = Path(td)
            rsync_dest = td_path / "rsync_dest"
            py_dest = td_path / "py_dest"
            shutil.copytree(dest, rsync_dest)
            shutil.copytree(dest, py_dest)

            rsync_cmd = ["rsync"] + args + [str(src) + "/", str(rsync_dest) + "/"]
            py_cmd = [sys.executable, str(self.script)] + args + [str(src) + "/", str(py_dest) + "/"]

            rsync_res = _run(rsync_cmd, cwd=self.repo_root)
            py_res = _run(py_cmd, cwd=self.repo_root)

            self.assertEqual(rsync_res.returncode, 0, msg=f"rsync failed: {rsync_res.stderr}")
            self.assertEqual(py_res.returncode, 0, msg=f"py failed: {py_res.stderr}")

            return _snapshot_tree(rsync_dest), _snapshot_tree(py_dest)

    def _run_pair_states(
        self, args: list[str], src: Path, dest: Path
    ) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
        with TemporaryDirectory() as td:
            td_path = Path(td)
            rsync_dest = td_path / "rsync_dest"
            py_dest = td_path / "py_dest"
            shutil.copytree(dest, rsync_dest)
            shutil.copytree(dest, py_dest)

            rsync_cmd = ["rsync"] + args + [str(src) + "/", str(rsync_dest) + "/"]
            py_cmd = [sys.executable, str(self.script)] + args + [str(src) + "/", str(py_dest) + "/"]

            rsync_res = _run(rsync_cmd, cwd=self.repo_root)
            py_res = _run(py_cmd, cwd=self.repo_root)

            self.assertEqual(rsync_res.returncode, 0, msg=f"rsync failed: {rsync_res.stderr}")
            self.assertEqual(py_res.returncode, 0, msg=f"py failed: {py_res.stderr}")

            return (
                _snapshot_tree(rsync_dest),
                _snapshot_tree(py_dest),
                _snapshot_tree_modes(rsync_dest),
                _snapshot_tree_modes(py_dest),
                _snapshot_tree_mtimes(rsync_dest),
                _snapshot_tree_mtimes(py_dest),
            )

    def _run_pair_states_with_dirs(
        self, args: list[str], sources: list[str], dest: Path
    ) -> tuple[
        dict[str, bytes],
        dict[str, bytes],
        dict[str, int],
        dict[str, int],
        dict[str, int],
        dict[str, int],
        dict[str, int],
        dict[str, int],
        dict[str, int],
        dict[str, int],
    ]:
        with TemporaryDirectory() as td:
            td_path = Path(td)
            rsync_dest = td_path / "rsync_dest"
            py_dest = td_path / "py_dest"
            shutil.copytree(dest, rsync_dest)
            shutil.copytree(dest, py_dest)

            rsync_cmd = ["rsync"] + args + sources + [str(rsync_dest) + "/"]
            py_cmd = [sys.executable, str(self.script)] + args + sources + [str(py_dest) + "/"]

            rsync_res = _run(rsync_cmd, cwd=self.repo_root)
            py_res = _run(py_cmd, cwd=self.repo_root)

            self.assertEqual(rsync_res.returncode, 0, msg=f"rsync failed: {rsync_res.stderr}")
            self.assertEqual(py_res.returncode, 0, msg=f"py failed: {py_res.stderr}")

            return (
                _snapshot_tree(rsync_dest),
                _snapshot_tree(py_dest),
                _snapshot_tree_modes(rsync_dest),
                _snapshot_tree_modes(py_dest),
                _snapshot_tree_mtimes(rsync_dest),
                _snapshot_tree_mtimes(py_dest),
                _snapshot_tree_dir_modes(rsync_dest),
                _snapshot_tree_dir_modes(py_dest),
                _snapshot_tree_dir_mtimes(rsync_dest),
                _snapshot_tree_dir_mtimes(py_dest),
            )

    def test_ignore_existing(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            _write_file(src / "a.txt", b"NEW")
            _write_file(dest / "a.txt", b"OLD")

            rsync_snap, py_snap = self._run_pair(["-r", "--ignore-existing"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(py_snap.get("a.txt"), b"OLD")

    def test_existing(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            dest.mkdir(parents=True, exist_ok=True)
            _write_file(src / "new.txt", b"DATA")

            rsync_snap, py_snap = self._run_pair(["-r", "--existing"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertNotIn("new.txt", py_snap)

    def test_delete(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            _write_file(src / "keep.txt", b"KEEP")
            _write_file(dest / "keep.txt", b"OLDKEEP")
            _write_file(dest / "extra.txt", b"EXTRA")

            rsync_snap, py_snap = self._run_pair(["-r", "--delete"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertNotIn("extra.txt", py_snap)

    def test_delete_respects_exclude(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            _write_file(src / "keep.txt", b"KEEP")
            _write_file(dest / "keep.txt", b"OLDKEEP")
            _write_file(dest / "excluded.tmp", b"EXTRA")

            rsync_snap, py_snap = self._run_pair(["-r", "--delete", "--exclude=*.tmp"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertIn("excluded.tmp", py_snap)

    def test_symlink_default_skips(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "target.txt", b"HELLO")
            os.symlink("target.txt", src / "link.txt")

            rsync_snap, py_snap = self._run_pair(["-r"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertNotIn("link.txt", py_snap)

    def test_symlink_links_copies(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "target.txt", b"HELLO")
            os.symlink("target.txt", src / "link.txt")

            rsync_snap, py_snap = self._run_pair(["-rl"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertIn("link.txt", py_snap)
            self.assertTrue(py_snap["link.txt"].startswith(b"SYMLINK:"))

    def test_symlink_copy_links_transforms(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "target.txt", b"HELLO")
            os.symlink("target.txt", src / "link.txt")

            rsync_snap, py_snap = self._run_pair(["-rL"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertIn("link.txt", py_snap)
            self.assertEqual(py_snap["link.txt"], b"HELLO")

    def test_new_file_preserves_mode_without_p(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "a.sh", b"echo hi\n")
            os.chmod(src / "a.sh", 0o750)

            rsync_snap, py_snap, rsync_modes, py_modes, _, _ = self._run_pair_states(["-r"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_modes, py_modes)
            self.assertEqual(py_modes.get("a.sh"), 0o750)

    def test_existing_file_keeps_mode_without_p(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "a.txt", b"NEW")
            os.chmod(src / "a.txt", 0o644)
            _write_file(dest / "a.txt", b"OLD")
            os.chmod(dest / "a.txt", 0o600)

            rsync_snap, py_snap, rsync_modes, py_modes, _, _ = self._run_pair_states(["-r"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_modes, py_modes)
            self.assertEqual(py_modes.get("a.txt"), 0o600)

    def test_existing_file_updates_mode_with_p(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "a.txt", b"NEW")
            os.chmod(src / "a.txt", 0o644)
            _write_file(dest / "a.txt", b"OLD")
            os.chmod(dest / "a.txt", 0o600)

            rsync_snap, py_snap, rsync_modes, py_modes, _, _ = self._run_pair_states(["-rp"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_modes, py_modes)
            self.assertEqual(py_modes.get("a.txt"), 0o644)

    def test_executability_updates_exec_bits(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()

            _write_file(src / "x", b"NEW")
            os.chmod(src / "x", 0o755)
            _write_file(dest / "x", b"OLD")
            os.chmod(dest / "x", 0o644)

            _write_file(src / "y", b"NEW")
            os.chmod(src / "y", 0o644)
            _write_file(dest / "y", b"OLD")
            os.chmod(dest / "y", 0o755)

            rsync_snap, py_snap, rsync_modes, py_modes, _, _ = self._run_pair_states(["-rE"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_modes, py_modes)
            self.assertEqual(py_modes.get("x"), 0o755)
            self.assertEqual(py_modes.get("y"), 0o644)

    def test_times_preserved_with_t(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()

            _write_file(src / "a.txt", b"NEW")
            fixed = 946684800  # 2000-01-01T00:00:00Z
            os.utime(src / "a.txt", (fixed, fixed))
            _write_file(dest / "a.txt", b"OLD")

            rsync_snap, py_snap, _, _, rsync_mtimes, py_mtimes = self._run_pair_states(["-rt"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_mtimes, py_mtimes)
            self.assertEqual(py_mtimes.get("a.txt"), fixed)

    def test_archive_no_perms_keeps_existing_mode(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "a.txt", b"NEW")
            os.chmod(src / "a.txt", 0o644)
            _write_file(dest / "a.txt", b"OLD")
            os.chmod(dest / "a.txt", 0o600)

            rsync_snap, py_snap, rsync_modes, py_modes, _, _ = self._run_pair_states(["-a", "--no-perms"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_modes, py_modes)
            self.assertEqual(py_modes.get("a.txt"), 0o600)

    def test_archive_no_times_does_not_preserve_mtime(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            src.mkdir()
            dest.mkdir()
            _write_file(src / "a.txt", b"NEW")
            fixed = 946684800  # 2000-01-01T00:00:00Z
            os.utime(src / "a.txt", (fixed, fixed))
            _write_file(dest / "a.txt", b"OLD")
            os.utime(dest / "a.txt", (fixed + 10, fixed + 10))

            rsync_snap, py_snap, _, _, rsync_mtimes, py_mtimes = self._run_pair_states(["-a", "--no-times"], src, dest)
            self.assertEqual(rsync_snap, py_snap)
            self.assertNotEqual(rsync_mtimes.get("a.txt"), fixed)
            self.assertNotEqual(py_mtimes.get("a.txt"), fixed)

    def test_relative_preserves_full_path(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            _write_file(src / "dir" / "f.txt", b"DATA")
            dest.mkdir(parents=True, exist_ok=True)

            rsync_snap, py_snap = self._run_pair(["-rR"], src, dest)
            self.assertEqual(rsync_snap, py_snap)

    def test_relative_dotdir_marker_strips_prefix(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            (root / "top" / "sub").mkdir(parents=True)
            _write_file(root / "top" / "sub" / "f.txt", b"DATA")
            dest = root / "dest"
            dest.mkdir()

            src_arg = f"{root}/top/./sub/"
            rsync_snap, py_snap, *_rest = self._run_pair_states_with_dirs(["-rR"], [src_arg], dest)
            self.assertEqual(rsync_snap, py_snap)

    def test_relative_implied_dirs_modes(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            _write_file(src / "dir" / "f.txt", b"DATA")
            dest.mkdir()

            res = self._run_pair_states_with_dirs(["-rR"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)

            res = self._run_pair_states_with_dirs(["-rRp"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)

            res = self._run_pair_states_with_dirs(["-rR", "--no-implied-dirs"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)

    def test_directory_mode_new_and_existing(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            (src / "d").mkdir(parents=True)
            os.chmod(src / "d", 0o755)
            _write_file(src / "d" / "f.txt", b"DATA")
            (dest / "d").mkdir(parents=True)
            os.chmod(dest / "d", 0o700)

            res = self._run_pair_states_with_dirs(["-r"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)
            self.assertEqual(py_dir_modes.get("d"), 0o700)

            res = self._run_pair_states_with_dirs(["-rp"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)
            self.assertEqual(py_dir_modes.get("d"), 0o755)

    def test_directory_times_preserved_and_omit_dir_times(self) -> None:
        with TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dest = root / "dest"
            (src / "d").mkdir(parents=True)
            fixed = 946684800  # 2000-01-01T00:00:00Z
            _write_file(src / "d" / "f.txt", b"DATA")
            os.utime(src / "d", (fixed, fixed))
            dest.mkdir()

            res = self._run_pair_states_with_dirs(["-rt"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            rsync_dir_mtimes, py_dir_mtimes = res[8], res[9]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)
            self.assertEqual(rsync_dir_mtimes, py_dir_mtimes)
            self.assertEqual(py_dir_mtimes.get("d"), fixed)

            res = self._run_pair_states_with_dirs(["-rtO"], [str(src) + "/"], dest)
            rsync_snap, py_snap = res[0], res[1]
            rsync_dir_modes, py_dir_modes = res[6], res[7]
            rsync_dir_mtimes, py_dir_mtimes = res[8], res[9]
            self.assertEqual(rsync_snap, py_snap)
            self.assertEqual(rsync_dir_modes, py_dir_modes)
            # With -O, directory times are not preserved, so the resulting mtimes
            # are based on the local filesystem operations and may differ slightly.
            self.assertNotEqual(py_dir_mtimes.get("d"), fixed)
