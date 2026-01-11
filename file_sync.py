#!/usr/bin/env python3
"""
File Synchronization - Directory and Recursive Sync
Will be integrated into rsync_phoenix_rebuilt.py
"""

import os
import sys
import time
import fnmatch
from pathlib import Path
from typing import List, Optional, Set, Dict
from dataclasses import dataclass, field

# This will use imports from rsync_phoenix_rebuilt when integrated
# For now, standalone implementation


@dataclass
class FileEntry:
    """File entry matching rsync's file_struct"""
    path: str
    size: int
    mtime: float
    mode: int = 0
    is_dir: bool = False
    is_link: bool = False
    link_target: Optional[str] = None

    def __hash__(self):
        return hash(self.path)


@dataclass
class TransferStats:
    """Transfer statistics matching rsync --stats output"""
    num_files: int = 0
    num_created: int = 0
    num_deleted: int = 0
    num_transferred: int = 0
    total_size: int = 0
    matched_data: int = 0
    literal_data: int = 0
    total_written: int = 0
    total_read: int = 0

    def format_size(self, size: int) -> str:
        """Format size in human-readable format"""
        for unit in ['', 'K', 'M', 'G', 'T']:
            if size < 1024:
                if unit:
                    return f"{size:.2f}{unit}"
                return f"{size}"
            size /= 1024
        return f"{size:.2f}P"

    def print_stats(self) -> None:
        """Print statistics in rsync format"""
        print(f"\nNumber of files: {self.num_files:,}")
        print(f"Number of created files: {self.num_created:,}")
        print(f"Number of deleted files: {self.num_deleted:,}")
        print(f"Number of regular files transferred: {self.num_transferred:,}")
        print(f"Total file size: {self.format_size(self.total_size)} bytes")
        print(f"Total transferred file size: {self.format_size(self.total_written)}")
        print(f"Literal data: {self.format_size(self.literal_data)}")
        print(f"Matched data: {self.format_size(self.matched_data)}")
        print()


class PatternMatcher:
    """Pattern matching for --exclude and --include"""

    def __init__(self, exclude_patterns: List[str] = None, include_patterns: List[str] = None):
        self.exclude_patterns = exclude_patterns or []
        self.include_patterns = include_patterns or []

    def should_exclude(self, filepath: str) -> bool:
        """Check if file should be excluded"""
        # Include patterns take precedence
        for pattern in self.include_patterns:
            if fnmatch.fnmatch(filepath, pattern):
                return False

        # Then check exclude patterns
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(filepath, pattern):
                return True

        return False


class FileListBuilder:
    """Build file list with directory recursion"""

    def __init__(self, pattern_matcher: Optional[PatternMatcher] = None):
        self.files: List[FileEntry] = []
        self.pattern_matcher = pattern_matcher or PatternMatcher()

    def build_file_list(self, paths: List[str], recursive: bool = False) -> List[FileEntry]:
        """Build file list from source paths"""
        self.files = []

        for path in paths:
            path_obj = Path(path)

            if not path_obj.exists():
                print(f"rsync: link_stat \"{path}\" failed: No such file or directory (2)", file=sys.stderr)
                continue

            if path_obj.is_dir():
                if recursive:
                    self._add_dir_recursive(path_obj)
                else:
                    # Non-recursive: just add directory entry
                    self._add_file(path_obj)
            else:
                self._add_file(path_obj)

        # Sort for deterministic ordering (rsync does this)
        self.files.sort(key=lambda f: f.path)

        return self.files

    def _add_dir_recursive(self, dirpath: Path) -> None:
        """Recursively add directory contents"""
        try:
            # Add directory itself
            self._add_file(dirpath)

            # Walk directory
            for entry in sorted(dirpath.iterdir()):
                # Check if excluded
                if self.pattern_matcher.should_exclude(str(entry)):
                    continue

                if entry.is_dir():
                    self._add_dir_recursive(entry)
                else:
                    self._add_file(entry)

        except PermissionError as e:
            print(f"rsync: opendir \"{dirpath}\" failed: Permission denied (13)", file=sys.stderr)

    def _add_file(self, path: Path) -> None:
        """Add single file to list"""
        try:
            stat = path.lstat()  # lstat to handle symlinks

            entry = FileEntry(
                path=str(path),
                size=stat.st_size if not path.is_dir() else 0,
                mtime=stat.st_mtime,
                mode=stat.st_mode,
                is_dir=path.is_dir(),
                is_link=path.is_symlink(),
                link_target=str(path.readlink()) if path.is_symlink() else None
            )

            self.files.append(entry)

        except (OSError, PermissionError) as e:
            print(f"rsync: stat \"{path}\" failed: {e}", file=sys.stderr)


class FileSynchronizer:
    """Orchestrate file synchronization"""

    def __init__(self, options):
        self.options = options
        self.stats = TransferStats()

    def sync(self, sources: List[str], dest: str) -> TransferStats:
        """Synchronize files from sources to destination"""
        # Build source file list
        pattern_matcher = PatternMatcher(
            exclude_patterns=self.options.exclude,
            include_patterns=self.options.include
        )

        builder = FileListBuilder(pattern_matcher)
        src_files = builder.build_file_list(sources, recursive=self.options.recursive)

        if self.options.verbose >= 1:
            print(f"building file list ... done")

        # Update stats
        self.stats.num_files = len(src_files)
        self.stats.total_size = sum(f.size for f in src_files if not f.is_dir)

        # Create destination directory if needed
        dest_path = Path(dest)
        if not dest_path.exists():
            if not self.options.dry_run:
                dest_path.mkdir(parents=True, exist_ok=True)
                if self.options.verbose >= 2:
                    print(f"cd++++++++++ {dest}")

        # Transfer files
        for src_file in src_files:
            self._transfer_file(src_file, sources[0], dest)

        # Print final newline if progress was shown
        if self.options.progress:
            print()

        return self.stats

    def _transfer_file(self, src_file: FileEntry, src_base: str, dest_base: str) -> None:
        """Transfer a single file"""
        # Calculate relative path
        src_path = Path(src_file.path)
        src_base_path = Path(src_base)

        try:
            rel_path = src_path.relative_to(src_base_path.parent if src_base_path.is_file() else src_base_path)
        except ValueError:
            rel_path = src_path.name

        dest_path = Path(dest_base) / rel_path

        # Check if file exists at destination
        file_exists = dest_path.exists()

        # Determine if transfer is needed
        needs_transfer = True
        if file_exists:
            if self.options.update:
                # Only transfer if source is newer
                dest_mtime = dest_path.stat().st_mtime
                if src_file.mtime <= dest_mtime:
                    needs_transfer = False
            elif self.options.ignore_existing:
                needs_transfer = False
        else:
            if self.options.existing:
                # Skip creating new files
                needs_transfer = False

        # Skip if not needed
        if not needs_transfer:
            return

        # Verbose output
        if self.options.verbose >= 1:
            if self.options.itemize_changes:
                itemize = self._generate_itemize(src_file, dest_path, file_exists)
                print(f"{itemize} {rel_path}")
            else:
                print(rel_path)

        # Dry run - just print, don't copy
        if self.options.dry_run:
            return

        # Handle directories
        if src_file.is_dir:
            if not dest_path.exists():
                dest_path.mkdir(parents=True, exist_ok=True)
                self.stats.num_created += 1
            return

        # Handle symlinks
        if src_file.is_link:
            if self.options.preserve_links:
                if dest_path.exists() or dest_path.is_symlink():
                    dest_path.unlink()
                dest_path.symlink_to(src_file.link_target)
                self.stats.num_created += 1
                return
            # If not preserving links, fall through to copy the target

        # Regular file transfer
        # TODO: Integrate with ChecksumEngine for rsync algorithm
        # For now, simple copy
        try:
            import shutil
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_path, dest_path)

            self.stats.num_transferred += 1
            if not file_exists:
                self.stats.num_created += 1
            self.stats.total_written += src_file.size
            self.stats.literal_data += src_file.size  # TODO: use actual rsync delta

            # Preserve permissions
            if self.options.preserve_perms:
                dest_path.chmod(src_file.mode & 0o777)

            # Preserve times
            if self.options.preserve_times:
                os.utime(dest_path, (src_file.mtime, src_file.mtime))

        except (OSError, PermissionError) as e:
            print(f"rsync: send_files failed to open \"{src_file.path}\": {e}", file=sys.stderr)

    def _generate_itemize(self, src_file: FileEntry, dest_path: Path, exists: bool) -> str:
        """Generate itemize-changes string"""
        if not exists:
            return ">f+++++++++"

        # Compare file attributes
        changes = "."

        if src_file.is_dir:
            return f"cd{changes}+++++++"
        if src_file.is_link:
            return f"cL{changes}+++++++"

        return f">f{changes}+++++++"


def test_sync():
    """Test file synchronization"""
    from rsync_cli_new import RsyncOptions

    # Create test options
    opts = RsyncOptions(
        recursive=True,
        verbose=2,
        archive=True,
        preserve_links=True,
        preserve_perms=True,
        preserve_times=True,
        dry_run=False,
        stats=True,
        sources=['/tmp/test_sync_source'],
        dest='/tmp/test_sync_dest'
    )

    # Sync
    syncer = FileSynchronizer(opts)
    stats = syncer.sync(opts.sources, opts.dest)

    # Print stats
    if opts.stats:
        stats.print_stats()


if __name__ == '__main__':
    test_sync()
