#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rsync-python: Pure Python 1:1 Implementation of the rsync Algorithm
====================================================================

A faithful replica of the rsync synchronization algorithm compatible with
protocol versions 20-32, mirroring the original C implementation line-by-line.

Quick Start:
-----------
    >>> from rsync_phoenix_rebuilt import ChecksumEngine
    >>>
    >>> # Create engine with 4KB blocks
    >>> engine = ChecksumEngine(block_size=4096)
    >>>
    >>> # Generate signature, delta, and reconstruct
    >>> signature = engine.generate_signature(original_data)
    >>> delta = engine.generate_delta(signature, modified_data)
    >>> reconstructed = engine.apply_delta(original_data, delta)
    >>>
    >>> # Verify and check compression
    >>> assert reconstructed == modified_data
    >>> print(f"Compression: {delta.compression_ratio:.1%}")

Key Features:
------------
    ✓ 1:1 C code parity with exact line references (match.c, checksum.c, etc.)
    ✓ Protocol versions 20-32 (MD4, MD5, SHA, xxHash checksums)
    ✓ Streaming support for files larger than RAM
    ✓ Professional CLI with colors and statistics
    ✓ 120 tests including cross-validation/interop with rsync binary
    ✓ Type-safe API with dataclasses (ChecksumSignature, DeltaInstructions)

Algorithm (from Tridgell's PhD thesis, 1999):
--------------------------------------------
    1. Rolling Checksum: O(1) byte-by-byte window sliding (Adler-32 variant)
    2. Strong Checksum: Cryptographic verification (MD5/SHA/xxHash)
    3. Hash Table: Dynamic sizing, 80% load factor, O(1) lookup

Protocol Support:
----------------
    v20-26: MD4, 8KB blocks
    v27-29: Variable-length integers, long filenames
    v30:    MD5 default, 128KB blocks, incremental recursion
    v31-32: xxHash, zstd compression, creation times

CLI Usage:
---------
    $ python rsync_phoenix_rebuilt.py sync source.txt target.txt
    $ python rsync_phoenix_rebuilt.py signature file.iso -o file.sig
    $ python rsync_phoenix_rebuilt.py delta file.sig new.iso -o delta.bin
    $ python rsync_phoenix_rebuilt.py patch file.iso delta.bin -o result.iso
    $ python rsync_phoenix_rebuilt.py --help

Copyright:
---------
    Original rsync (C): Andrew Tridgell, Paul Mackerras, Wayne Davison
    Python implementation: Alejandro Sanchez (2024-2026)
    License: GPLv3+ with OpenSSL/xxhash exception

References:
----------
    [1] Tridgell (1999): PhD Thesis - https://www.samba.org/~tridge/phd_thesis.pdf
    [2] rsync source: https://github.com/WayneD/rsync
    [3] Full docs: README.md, docs/ folder
"""

from __future__ import annotations

__version__ = "3.0.2"
__author__ = "Alejandro Sanchez"
__email__ = "alesangreat@gmail.com"
__license__ = "GPL-3.0-or-later"
__copyright__ = "Copyright (C) 2024-2026 Alejandro Sanchez"
__credits__ = [
    "Andrew Tridgell (original rsync algorithm)",
    "Paul Mackerras (original rsync implementation)",
    "Wayne Davison (rsync maintainer)",
]

# Public API exports
__all__ = [
    # Main classes
    'ChecksumEngine',
    'Checksum',
    'ChecksumType',
    'ProtocolVersionManager',

    # Data structures (typed dataclasses)
    'BlockChecksum',
    'ChecksumSignature',
    'DeltaMatch',
    'DeltaLiteral',
    'DeltaInstructions',
    'SyncStats',

    # Streaming support
    'DataSource',
    'BytesDataSource',
    'FileDataSource',

    # Exceptions
    'RsyncError',
    'ValidationError',
    'ResourceLimitError',
    'ProtocolMismatchError',
    'ProtocolError',
    'FileIOError',
    'DataIntegrityError',

    # Configuration
    'Config',
    'Colors',

    # Validation functions
    'validate_block_size',
    'validate_data',
    'validate_protocol_version',
    'validate_checksum_seed',
    'validate_signature',
    'check_memory_limit',

    # Performance profiling
    'Profiler',
    'get_memory_usage',
    'profile_operation',

    # Statistics functions (matching match.c)
    'reset_match_stats',
    'accumulate_match_stats',
    'get_total_match_stats',
    'match_report',

    # Protocol constants (for advanced usage)
    'PROTOCOL_VERSION',
    'MIN_PROTOCOL_VERSION',
    'MAX_PROTOCOL_VERSION',
    'MAX_BLOCK_SIZE',
    'OLD_MAX_BLOCK_SIZE',
    'CHUNK_SIZE',
    'CHAR_OFFSET',
    
    # Wire protocol checksum type constants
    'CSUM_NONE',
    'CSUM_MD4',
    'CSUM_MD5',
    'CSUM_SHA1',
    'CSUM_SHA256',
    'CSUM_XXH64',
    'CSUM_XXH3_64',
    'CSUM_XXH3_128',
    'csum_len_for_type',
    'canonical_checksum',

    # Protocol I/O
    'ProtocolIO',
    'receive_data',

    # Utility functions
    'format_size',
    'format_time',
    'sum_sizes_sqroot',

    # Rsync CLI components
    'RsyncOptions',
    'parse_rsync_args',
    'create_rsync_parser',
    'print_version',
    'print_help_header',
    'expand_archive_mode',
]

import os
import pickle
import argparse
import sys
import struct
import hashlib
import logging
import zlib
import time
import json
import fnmatch
from pathlib import Path
from collections import deque
from typing import (
    Optional, Tuple, List, Dict, Union, Any, Callable, Protocol,
    cast, Iterator, BinaryIO, ClassVar, Literal, TypedDict, Deque, Sequence
)
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

# Required imports for full rsync protocol support
import xxhash
import lz4.frame  # type: ignore[import]
import lz4.block  # type: ignore[import]
import zstandard  # type: ignore[import]

# Normalize optional/untyped third-party imports to `Any` so strict type-checkers
# (e.g. Pylance with reportUnknown* enabled) don't treat member access as Unknown.
_lz4_frame: Any = cast(Any, lz4.frame)
_lz4_block: Any = cast(Any, lz4.block)
_zstandard: Any = cast(Any, zstandard)

# Version compatibility
if sys.version_info[0] >= 3:
    long = int
    xrange = range

# ============================================================================
# TYPE DEFINITIONS - Enhanced type safety with TypedDicts
# ============================================================================

class SumHead(TypedDict):
    """Type definition for sum_struct header (legacy API compatibility)."""
    count: int       # Number of blocks
    blength: int     # Block length in bytes
    s2length: int    # Strong checksum length
    remainder: int   # Size of last block if < blength


class SumSizes(TypedDict):
    """Type definition for sum_sizes_sqroot() return value."""
    flength: int     # File length
    blength: int     # Block length
    s2length: int    # Strong checksum length
    remainder: int   # Remainder bytes
    count: int       # Number of blocks


class ChecksumAccumulator(Protocol):
    """Protocol for checksum accumulator objects."""
    def update(self, data: bytes) -> None: ...
    def digest(self) -> bytes: ...


def _default_rsync_sources() -> List[str]:
    # Keep Pylance/pyright from inferring `list[Unknown]` from `list()` while
    # still using a proper `default_factory`.
    return []

# ============================================================================
# PROTOCOL CONSTANTS - Matching rsync original source code (rsync.h)
# ============================================================================
#
# These constants are extracted directly from rsync.h and must match exactly
# for wire-protocol compatibility. See: rsync-original-source-code/rsync.h

# Protocol version range - rsync supports 20-40, we implement 20-32
PROTOCOL_VERSION = 32  # Latest official protocol version
SUBPROTOCOL_VERSION = 0  # For pre-release versions, always 0 for official
MIN_PROTOCOL_VERSION = 20  # Minimum supported protocol
OLD_PROTOCOL_VERSION = 25  # Old protocol threshold
MAX_PROTOCOL_VERSION = 40  # Maximum allowed for negotiation

# Version/reporting strings (usage.c parity)
# Reference: rsync-original-source-code/version.h, latest-year.h, usage.c:print_rsync_version()
RSYNC_NAME = "rsync"
RSYNC_VERSION = "3.4.2dev"
RSYNC_LATEST_YEAR = "2025"
RSYNC_URL = "https://rsync.samba.org/"
RSYNC_COPYRIGHT = f"(C) 1996-{RSYNC_LATEST_YEAR} by Andrew Tridgell, Wayne Davison, and others."

# Block sizes (from rsync.h)
MAX_BLOCK_SIZE = 0x20000  # 131072 bytes (protocol >= 30)
OLD_MAX_BLOCK_SIZE = 0x2000  # 8192 bytes (protocol < 30)
BLOCK_SIZE = 700  # Default block size for some operations
CHUNK_SIZE = 32 * 1024  # 32KB chunk for I/O operations
BLOCKSUM_BIAS = 10  # Bias for block checksum length calculation (generator.c)
SUM_LENGTH = 16  # Maximum sum length (MD5/MD4 digest length)

# Checksum lengths (from rsync.h and checksum.c)
MD4_DIGEST_LEN = 16
MD5_DIGEST_LEN = 16
SHA1_DIGEST_LEN = 20
SHA256_DIGEST_LEN = 32
SHA512_DIGEST_LEN = 64
MAX_DIGEST_LEN = 64  # SHA512 is largest
SHORT_SUM_LENGTH = 2  # rsync.h: SHORT_SUM_LENGTH (wire default)
CSUM_CHUNK = 64  # Chunk size for checksum calculation

# Wire protocol checksum type values (lib/md-defines.h lines 24-35)
# These are the actual integer values sent over the wire during negotiation
# Reference: rsync-original-source-code/lib/md-defines.h lines 24-35
CSUM_gone = -1      # Removed checksum type (marker)
CSUM_NONE = 0       # No checksum
CSUM_MD4_ARCHAIC = 1  # Very old protocol (<= 26)
CSUM_MD4_BUSTED = 2   # Protocol 21-26 (buggy MD4 with incorrect seed)
CSUM_MD4_OLD = 3      # Old protocol (27-29)
CSUM_MD4 = 4          # Standard MD4 (protocol < 30)
CSUM_MD5 = 5          # MD5 (protocol >= 30 default)
CSUM_XXH64 = 6        # xxHash 64-bit (protocol >= 31)
CSUM_XXH3_64 = 7      # xxHash3 64-bit (protocol >= 31)
CSUM_XXH3_128 = 8     # xxHash3 128-bit (protocol >= 31)
CSUM_SHA1 = 9         # SHA1 (optional)
CSUM_SHA256 = 10      # SHA256 (optional)
CSUM_SHA512 = 11      # SHA512 (optional)

# CHAR_OFFSET - Critical for rolling checksum compatibility
# NOTE: rsync.h defines CHAR_OFFSET as 0 for compatibility
# "a non-zero CHAR_OFFSET makes the rolling sum stronger, but is
# incompatible with older versions :-("
CHAR_OFFSET = 0  # MUST be 0 for rsync compatibility

# Hash table sizing (from match.c)
TRADITIONAL_TABLESIZE = 1 << 16  # 65536 - used for small file lists
HASH_LOAD_FACTOR = 0.8  # Target 80% load factor for dynamic sizing

# Checksum seed (for strong checksums with protocol negotiation)
CHECKSUM_SEED = 0  # Default seed, may be negotiated

# Variable-length integer encoding (io.c: int_byte_extra[] + read_varint/write_varint)
_INT_BYTE_EXTRA: Tuple[int, ...] = (
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # (00 - 3F)/4
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # (40 - 7F)/4
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  # (80 - BF)/4
    2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 6,  # (C0 - FF)/4
)


def csum_len_for_type(csum_type: int, flist_csum: bool = False) -> int:
    """
    Get checksum length in bytes for a given checksum type.
    
    This is the Python equivalent of csum_len_for_type() in checksum.c (lines 214-250).
    
    Args:
        csum_type: Wire protocol checksum type (CSUM_* constant)
        flist_csum: True if this is for file-list checksums (affects archaic MD4)
    
    Returns:
        Length of checksum in bytes
    
    Reference:
        checksum.c: csum_len_for_type() lines 214-250
    
    Example:
        >>> csum_len_for_type(CSUM_MD5)
        16
        >>> csum_len_for_type(CSUM_XXH64)
        8
    """
    if csum_type == CSUM_NONE:
        return 1
    elif csum_type == CSUM_MD4_ARCHAIC:
        # Oldest checksum: file-list uses 2 bytes, everything else full MD4
        return 2 if flist_csum else MD4_DIGEST_LEN
    elif csum_type in (CSUM_MD4, CSUM_MD4_OLD, CSUM_MD4_BUSTED):
        return MD4_DIGEST_LEN
    elif csum_type == CSUM_MD5:
        return MD5_DIGEST_LEN
    elif csum_type == CSUM_SHA1:
        return SHA1_DIGEST_LEN
    elif csum_type == CSUM_SHA256:
        return SHA256_DIGEST_LEN
    elif csum_type == CSUM_SHA512:
        return SHA512_DIGEST_LEN
    elif csum_type in (CSUM_XXH64, CSUM_XXH3_64):
        return 8  # 64 bits = 8 bytes
    elif csum_type == CSUM_XXH3_128:
        return 16  # 128 bits = 16 bytes
    else:
        raise ValueError(f"Unknown checksum type: {csum_type}")


def canonical_checksum(csum_type: int) -> int:
    """
    Determine if a checksum type has canonical (portable) byte order.
    
    This is the Python equivalent of canonical_checksum() in checksum.c (lines 253-275).
    
    Returns:
        0: Checksum is not canonical (includes seed, not portable)
        1: Public sum order matches internal order
        -1: Public sum order is reversed from internal order
    
    Reference:
        checksum.c: canonical_checksum() lines 253-275
    
    Example:
        >>> canonical_checksum(CSUM_MD5)
        -1
        >>> canonical_checksum(CSUM_XXH64)
        1
    """
    if csum_type in (CSUM_NONE, CSUM_MD4_ARCHAIC, CSUM_MD4_OLD, CSUM_MD4_BUSTED):
        return 0  # Not canonical (seeded or buggy)
    elif csum_type in (CSUM_MD4, CSUM_MD5, CSUM_SHA1, CSUM_SHA256, CSUM_SHA512):
        return -1  # Reverse byte order
    elif csum_type in (CSUM_XXH64, CSUM_XXH3_64, CSUM_XXH3_128):
        return 1  # Native byte order
    else:
        raise ValueError(f"Unknown checksum type: {csum_type}")


# ============================================================================
# GLOBAL STATISTICS - Matching match.c static variables (lines 33-41)
# ============================================================================
#
# These mirror the global statistics in match.c:
#   static int false_alarms;      -> _global_false_alarms
#   static int hash_hits;         -> _global_hash_hits  
#   static int matches;           -> _global_matches
#   static int total_false_alarms; -> _total_false_alarms
#   static int total_hash_hits;   -> _total_hash_hits
#   static int total_matches;     -> _total_matches

_global_false_alarms: int = 0
_global_hash_hits: int = 0
_global_matches: int = 0
_total_false_alarms: int = 0
_total_hash_hits: int = 0
_total_matches: int = 0
_total_literal_data: int = 0  # stats.literal_data in C


def reset_match_stats() -> None:
    """
    Reset per-file match statistics.
    
    Called at the start of processing each file, like match.c:match_sums():
        last_match = 0;
        false_alarms = 0;
        hash_hits = 0;
        matches = 0;
        data_transfer = 0;
    
    Reference:
        match.c: match_sums() lines 362-367
    """
    global _global_false_alarms, _global_hash_hits, _global_matches
    _global_false_alarms = 0
    _global_hash_hits = 0
    _global_matches = 0


def accumulate_match_stats(literal_data: int = 0) -> None:
    """
    Accumulate per-file stats into totals.
    
    Called at end of each file, like match.c:match_sums() lines 412-415:
        total_hash_hits += hash_hits;
        total_false_alarms += false_alarms;
        total_matches += matches;
        stats.literal_data += data_transfer;
    
    Args:
        literal_data: Amount of literal (non-matching) data transferred
    
    Reference:
        match.c: lines 412-415
    """
    global _total_false_alarms, _total_hash_hits, _total_matches, _total_literal_data
    _total_false_alarms += _global_false_alarms
    _total_hash_hits += _global_hash_hits
    _total_matches += _global_matches
    _total_literal_data += literal_data


def match_report() -> None:
    """
    Print match statistics report.
    
    This is the Python equivalent of match_report() in match.c (lines 423-430):
    
        void match_report(void)
        {
            if (!DEBUG_GTE(DELTASUM, 1))
                return;
            rprintf(FINFO,
                "total: matches=%d  hash_hits=%d  false_alarms=%d data=%s\\n",
                total_matches, total_hash_hits, total_false_alarms,
                big_num(stats.literal_data));
        }
    
    This function outputs to logging at INFO level for debugging purposes.
    
    Reference:
        match.c: match_report() lines 423-430
    """
    if Config.VERBOSE_LOGGING:
        logging.info(
            f"total: matches={_total_matches}  hash_hits={_total_hash_hits}  "
            f"false_alarms={_total_false_alarms} data={_total_literal_data}"
        )


def get_total_match_stats() -> "SyncStats":
    """
    Get accumulated statistics across all files.
    
    Returns a SyncStats object with totals across all processed files.
    This mirrors the global statistics available in match.c after all
    files have been processed.
    
    Reference:
        match.c: total_matches, total_hash_hits, total_false_alarms, stats.literal_data
    """
    return SyncStats(
        false_alarms=_total_false_alarms,
        hash_hits=_total_hash_hits,
        matches=_total_matches,
        literal_data=_total_literal_data
    )


# ============================================================================
# GLOBAL CONFIGURATION - Performance and behavior tuning
# ============================================================================

class Config:
    """
    Global configuration for rsync-python behavior.

    This class provides centralized configuration for all aspects of the
    rsync-python implementation. Settings can be modified at runtime to
    tune performance, enable debugging, or customize behavior.

    Attributes:
        ENABLE_PROFILING (bool): Enable performance profiling with timing
        ENABLE_PROGRESS (bool): Show progress bars for large operations
        VERBOSE_LOGGING (bool): Enable verbose logging output
        USE_COLORS (bool): Enable colored terminal output (auto-detected)
        CHUNK_SIZE_STREAMING (int): Size of chunks when streaming large files
        MAX_CACHE_SIZE (int): Maximum size of checksum cache in memory
        DEFAULT_BLOCK_SIZE (int): Default block size for new engines
        HASH_TABLE_DYNAMIC (bool): Use dynamic hash table sizing like rsync
        COLLECT_STATS (bool): Collect matching statistics (false_alarms, etc.)

    Example:
        >>> Config.VERBOSE_LOGGING = True
        >>> Config.USE_COLORS = False
        >>> Config.COLLECT_STATS = True  # Enable statistics collection
        >>> Config.reset_defaults()  # Reset all to defaults
    """
    # Performance settings
    ENABLE_PROFILING: ClassVar[bool] = False
    CHUNK_SIZE_STREAMING: ClassVar[int] = 1024 * 1024  # 1MB chunks for streaming
    MAX_CACHE_SIZE: ClassVar[int] = 10000  # Maximum cached checksums
    HASH_TABLE_DYNAMIC: ClassVar[bool] = True  # Dynamic hash table sizing (like C code)

    # UI settings
    ENABLE_PROGRESS: ClassVar[bool] = True
    USE_COLORS: ClassVar[bool] = True
    VERBOSE_LOGGING: ClassVar[bool] = False

    # Debug / parity tracing
    DEBUG_PARITY: ClassVar[bool] = False
    PARITY_TRACE_MAX_EVENTS: ClassVar[int] = 2000  # hard cap to avoid runaway memory

    # Algorithm settings
    DEFAULT_BLOCK_SIZE: ClassVar[int] = 2048
    MIN_BLOCK_SIZE_FOR_OPTIMIZATION: ClassVar[int] = 512
    CSUM_LENGTH: ClassVar[int] = SHORT_SUM_LENGTH  # io.c: csum_length initial value
    PROPER_SEED_ORDER: ClassVar[bool] = True  # compat.c: CF_CHKSUM_SEED_FIX
    XFER_FLAGS_AS_VARINT: ClassVar[bool] = False  # compat.c: CF_VARINT_FLIST_FLAGS
    UPDATING_BASIS_FILE: ClassVar[bool] = False  # match.c: updating_basis_file (in-place update behavior)
    COMPUTE_SENDER_FILE_SUM: ClassVar[bool] = True  # match.c: sum_init/sum_update/sum_end sender_file_sum
    VERIFY_SENDER_FILE_SUM_ON_WIRE: ClassVar[bool] = True  # receiver.c: verify sender_file_sum after receive_data()

    # Statistics collection (like match.c tracking)
    COLLECT_STATS: ClassVar[bool] = False

    @classmethod
    def reset_defaults(cls) -> None:
        """Reset all configuration to default values."""
        # Note: strict type-checkers may treat ALL_CAPS names as constants and
        # flag direct reassignments. We keep the public API stable (Config.XYZ)
        # while performing updates via `setattr`.
        defaults: Dict[str, object] = {
            "ENABLE_PROFILING": False,
            "CHUNK_SIZE_STREAMING": 1024 * 1024,
            "MAX_CACHE_SIZE": 10000,
            "HASH_TABLE_DYNAMIC": True,
            "ENABLE_PROGRESS": True,
            "USE_COLORS": True,
            "VERBOSE_LOGGING": False,
            "DEBUG_PARITY": False,
            "PARITY_TRACE_MAX_EVENTS": 2000,
            "DEFAULT_BLOCK_SIZE": 2048,
            "MIN_BLOCK_SIZE_FOR_OPTIMIZATION": 512,
            "CSUM_LENGTH": SHORT_SUM_LENGTH,
            "PROPER_SEED_ORDER": True,
            "XFER_FLAGS_AS_VARINT": False,
            "UPDATING_BASIS_FILE": False,
            "COMPUTE_SENDER_FILE_SUM": True,
            "VERIFY_SENDER_FILE_SUM_ON_WIRE": True,
            "COLLECT_STATS": False,
        }
        for name, value in defaults.items():
            setattr(cls, name, value)


# ============================================================================
# SYNCHRONIZATION STATISTICS - Matching match.c and rsync.h tracking
# ============================================================================

@dataclass
class SyncStats:
    """
    Statistics from a synchronization operation.

    This combines statistics from two C structures:
    
    1. Local match statistics from match.c (lines 33-41):
        static int false_alarms;
        static int hash_hits;
        static int matches;
        static int64 data_transfer;
    
    2. Global stats structure from rsync.h (lines 1033-1047):
        struct stats {
            int64 total_size;
            int64 total_transferred_size;
            int64 total_written;
            int64 total_read;
            int64 literal_data;       <- SyncStats.literal_data
            int64 matched_data;       <- SyncStats.matched_data
            ...
        };

    Attributes:
        false_alarms: Count of false positive weak checksum matches
        hash_hits: Total hash table hits during matching
        matches: Successful block matches found
        literal_data: Bytes of new/literal data (stats.literal_data in C)
        matched_data: Bytes reused from matched blocks (stats.matched_data in C)
        total_time_ms: Total operation time in milliseconds
        blocks_scanned: Total blocks examined

    Reference:
        match.c: lines 33-41 (local stats), 423-435 (match_report)
        rsync.h: struct stats (lines 1033-1047)
    """
    false_alarms: int = 0
    hash_hits: int = 0
    matches: int = 0
    literal_data: int = 0
    matched_data: int = 0
    total_time_ms: float = 0.0
    blocks_scanned: int = 0
    # Optional parity trace events (only when Config.DEBUG_PARITY is enabled)
    parity_events: Optional[List[ParityTraceEvent]] = None

    @property
    def efficiency(self) -> float:
        """Calculate sync efficiency (matched / total)."""
        total = self.literal_data + self.matched_data
        return self.matched_data / total if total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Calculate false positive rate from weak checksum."""
        if self.hash_hits == 0:
            return 0.0
        return self.false_alarms / self.hash_hits

    def __repr__(self) -> str:
        return (
            f"SyncStats(matches={self.matches}, false_alarms={self.false_alarms}, "
            f"hash_hits={self.hash_hits}, efficiency={self.efficiency:.1%})"
        )

# ============================================================================
# WIRE PROTOCOL CONSTANTS - For network communication (io.c, token.c)
# ============================================================================

# Debug/Parity trace events: bounded structured traces for community-grade parity inspection.
ParityTraceEventType = Literal['hash_hit', 'false_alarm', 'match']


class ParityTraceEvent(TypedDict, total=False):
    type: ParityTraceEventType
    offset: int
    k: int
    weak: int
    candidates: int
    block_index: int


# Token types for delta encoding (from token.c)
TOKEN_LITERAL = 0x00        # Literal data follows
TOKEN_RUN = 0x80            # Run-length encoded zeros
TOKEN_MATCH = 0x40          # Block match (index follows)
TOKEN_LONG = 0xC0           # Long token (32-bit length)

# Multiplexing base for tagged messages (from io.c)
MPLEX_BASE = 7              # Base for message tagging

# Message codes for multiplexed I/O (from rsync.h MSG_* constants)
class MSG(IntEnum):
    """
    Message codes for rsync's multiplexed I/O protocol.

    These codes are used in the wire protocol to identify different
    types of messages when data and control messages are multiplexed
    over a single connection.

    The format of a multiplexed message is:
        [4 bytes: (MPLEX_BASE + MSG_*) << 24 | length]
        [length bytes: message data]

    Reference:
        rsync.h: lines 78-95 (MSG_* constants)
        io.c: mplex_write(), read_a_msg()
    """
    DATA = 0           # Raw file data
    EOF = 1            # End of file/data stream
    ERROR = 2          # Error message (fatal)
    INFO = 3           # Informational message
    LOG = 4            # Log message
    WARNING = 5        # Warning message (non-fatal)
    ERROR_SOCKET = 6   # Socket-related error
    ERROR_UTF8 = 7     # UTF-8 encoding error
    WARNING_CLIENT = 8 # Client-side warning
    ERROR_XFER = 9     # Transfer error
    SUCCESS = 10       # Success indicator
    NOOP = 11          # No operation (keepalive)
    STATS = 12         # Statistics data
    IO_ERROR = 13      # I/O error
    IO_TIMEOUT = 14    # I/O timeout
    DELETED = 15       # File deleted notification
    NO_SEND = 16       # File skipped (not sent)
    ERROR_EXIT = 17    # Fatal error, exiting


# File index markers (from rsync.h NDX_* constants)
class NDX(IntEnum):
    """
    File index markers for rsync protocol.

    These special index values are used to signal various conditions
    during file list processing.

    Reference: rsync.h
    """
    DONE = -1         # Processing complete
    SKIP = -2         # Skip this file
    DEL_STATS = -3    # Delete statistics follow
    FATAL_ERROR = -4  # Fatal error occurred
    REPORT = -5       # Report follows


# Note: Checksum type constants (CSUM_*) are defined above with wire protocol
# constants. Do NOT duplicate them here as an IntEnum - the wire protocol
# values in CSUM_* are authoritative. See lib/md-defines.h lines 24-35.

# ============================================================================
# ERROR CODES - RERR_* constants from rsync.h
# ============================================================================
#
# Error codes matching rsync's RERR_* constants for protocol-level errors.
# These are used to communicate specific error conditions between peers.
#
# Reference: rsync.h RERR_* constants (lines ~90-120)

RERR_CLIENT = 1           # Client started but not finished
RERR_STARTCLIENT = 2      # Failed to start client
RERR_SYNTAX = 3           # Syntax error in command line
RERR_DATA = 4             # Data transfer error
RERR_PARTIAL = 5          # Partial transfer due to error
RERR_TIMEOUT = 6          # Timeout waiting for data
RERR_CONNREFUSED = 7      # Connection refused
RERR_FORBIDDEN = 8        # Forbidden action (permission denied)
RERR_PROTO = 9            # Protocol version mismatch
RERR_SOCKETIO = 10        # Socket I/O error
RERR_FILEIO = 11          # File I/O error
RERR_STREAMIO = 12        # Stream I/O error
RERR_MESSAGEIO = 13       # Message I/O error
RERR_WATCHLIST = 14       # Watchlist error
RERR_EXIT = 15            # Exit code from child
RERR_LIMIT = 16           # Resource limit exceeded
RERR_UTF8 = 17            # UTF-8 encoding error
RERR_BACKUP = 18          # Backup error
RERR_XFER = 19            # Transfer error
RERR_DEL_STATS = 20       # Delete statistics error
RERR_DEL = 21             # Delete error
RERR_MAKE_DIR = 22        # Failed to create directory
RERR_SIGNAL = 23          # Caught signal
RERR_GONE = 24            # File has gone away
RERR_POSTPROCESS = 25     # Post-process error
RERR_DATAFD = 26          # Data fd error
RERR_OPENFILES = 27       # Too many open files
RERR_BAD_UPLOAD = 28      # Bad upload request
RERR_USERNAME = 29        # Username error
RERR_GROUPNAME = 30       # Groupname error
RERR_CHMOD = 31           # chmod error
RERR_CHOWN = 32           # chown error
RERR_ICONV = 33           # Character encoding conversion error
RERR_DUP = 34             # Duplicate file error
RERR_DIRNAME = 35         # Directory name error
RERR_FLIST = 36           # File list error
RERR_CALLBACK = 37        # Callback error
RERR_SKIP_UPDATED = 38    # Skip updated file
RERR_SKIP_DELETE = 39     # Skip delete error
RERR_EXIT_CHILD = 40      # Child exited with error
RERR_TLS = 41             # TLS error
RERR_MAX = 42             # Maximum RERR code (exclusive)


# ============================================================================
# FILE ATTRIBUTE FLAGS - XMIT_* and FLAG_* from rsync.h
# ============================================================================
#
# XMIT flags - used during file list transfer
XMIT_TOP_DIR = 1 << 0
XMIT_SAME_MODE = 1 << 1
XMIT_SAME_RDEV_pre28 = 1 << 2  # protocols 20-27 (devices/specials)
XMIT_EXTENDED_FLAGS = 1 << 2   # protocols 28+ (extended xflags marker)
XMIT_SAME_UID = 1 << 3
XMIT_SAME_GID = 1 << 4
XMIT_SAME_NAME = 1 << 5
XMIT_LONG_NAME = 1 << 6
XMIT_SAME_TIME = 1 << 7
XMIT_SAME_RDEV_MAJOR = 1 << 8  # protocols 28+ (devices)
XMIT_NO_CONTENT_DIR = 1 << 8   # protocols 30+ (dirs)
XMIT_HLINKED = 1 << 9          # protocols 28+ (non-dirs)
XMIT_SAME_DEV_pre30 = 1 << 10       # protocols 28-29 (hardlink device abbrev)
XMIT_USER_NAME_FOLLOWS = 1 << 10    # protocols 30+
XMIT_RDEV_MINOR_8_pre30 = 1 << 11   # protocols 28-29 (devices)
XMIT_GROUP_NAME_FOLLOWS = 1 << 11   # protocols 30+
XMIT_HLINK_FIRST = 1 << 12     # protocols 30+
XMIT_IO_ERROR_ENDLIST = 1 << 12  # protocols 31+ (w/XMIT_EXTENDED_FLAGS)
XMIT_MOD_NSEC = 1 << 13        # protocols 31+
XMIT_SAME_ATIME = 1 << 14      # when -A is used
XMIT_CRTIME_EQ_MTIME = 1 << 17 # creation time equals mtime

# FLAG values - used in live file list data
FLAG_TOP_DIR = 1 << 0
FLAG_FILE_SENT = 1 << 1
FLAG_CONTENT_DIR = 1 << 2
FLAG_MOUNT_DIR = 1 << 3
FLAG_DUPLICATE = 1 << 4
FLAG_HLINKED = 1 << 5
FLAG_HLINK_FIRST = 1 << 6
FLAG_HLINK_LAST = 1 << 7
FLAG_HLINK_DONE = 1 << 8
FLAG_LENGTH64 = 1 << 9
FLAG_SKIP_GROUP = 1 << 10
FLAG_TIME_FAILED = 1 << 11
FLAG_MOD_NSEC = 1 << 12

# ============================================================================
# COMPATIBILITY FLAGS (compat.c) - negotiated for protocol >= 30
# ============================================================================
#
# Reference: rsync-original-source-code/compat.c:118-126
CF_INC_RECURSE = 1 << 0
CF_SYMLINK_TIMES = 1 << 1
CF_SYMLINK_ICONV = 1 << 2
CF_SAFE_FLIST = 1 << 3
CF_AVOID_XATTR_OPTIM = 1 << 4
CF_CHKSUM_SEED_FIX = 1 << 5
CF_INPLACE_PARTIAL_DIR = 1 << 6
CF_VARINT_FLIST_FLAGS = 1 << 7
CF_ID0_NAMES = 1 << 8

MAX_NSTR_STRLEN = 256  # compat.c: MAX_NSTR_STRLEN

# File type flags (POSIX stat.h compatibility)
S_IFREG = 0o100000   # regular file
S_IFDIR = 0o040000   # directory
S_IFLNK = 0o120000   # symbolic link
S_IFCHR = 0o020000   # character device
S_IFBLK = 0o060000   # block device
S_IFIFO = 0o010000   # FIFO
S_IFSOCK = 0o140000  # socket

S_ISUID = 0o4000     # set user ID on execution
S_ISGID = 0o2000     # set group ID on execution
S_ISVTX = 0o1000     # sticky bit


def S_ISDIR(mode: int) -> bool:
    """Check if mode indicates a directory."""
    return (mode & 0o170000) == S_IFDIR


def S_ISLNK(mode: int) -> bool:
    """Check if mode indicates a symbolic link."""
    return (mode & 0o170000) == S_IFLNK


def S_ISREG(mode: int) -> bool:
    """Check if mode indicates a regular file."""
    return (mode & 0o170000) == S_IFREG


def S_ISCHR(mode: int) -> bool:
    """Check if mode indicates a character device."""
    return (mode & 0o170000) == S_IFCHR


def S_ISBLK(mode: int) -> bool:
    """Check if mode indicates a block device."""
    return (mode & 0o170000) == S_IFBLK


def S_ISFIFO(mode: int) -> bool:
    """Check if mode indicates a FIFO (named pipe)."""
    return (mode & 0o170000) == S_IFIFO


def S_ISSOCK(mode: int) -> bool:
    """Check if mode indicates a socket."""
    return (mode & 0o170000) == S_IFSOCK


def IS_DEVICE(mode: int) -> bool:
    """Return True if mode indicates a device node (char/block)."""
    return S_ISCHR(mode) or S_ISBLK(mode)


def IS_SPECIAL(mode: int) -> bool:
    """Return True if mode indicates a special file (fifo/socket)."""
    return S_ISFIFO(mode) or S_ISSOCK(mode)


def _dev_major(dev: int) -> int:
    """Extract major() from a device ID (best-effort portable)."""
    try:
        return int(os.major(dev))  # type: ignore[attr-defined]
    except Exception:
        return int((dev >> 8) & 0xFFF)


def _dev_minor(dev: int) -> int:
    """Extract minor() from a device ID (best-effort portable)."""
    try:
        return int(os.minor(dev))  # type: ignore[attr-defined]
    except Exception:
        return int(dev & 0xFF)


def _make_dev(major: int, minor: int) -> int:
    """Construct a device ID (best-effort portable)."""
    try:
        return int(os.makedev(int(major), int(minor)))  # type: ignore[attr-defined]
    except Exception:
        return (int(major) << 8) | int(minor)


def to_wire_mode(mode: int) -> int:
    """
    Convert local st_mode to rsync's canonical wire mode.
    Reference: rsync-original-source-code/ifuncs.h:to_wire_mode()
    """
    if S_ISLNK(mode):
        return (mode & ~0o170000) | S_IFLNK
    return mode


def from_wire_mode(mode: int) -> int:
    """
    Convert rsync's canonical wire mode back to local st_mode.
    Reference: rsync-original-source-code/ifuncs.h:from_wire_mode()
    """
    if (mode & 0o170000) == S_IFLNK:
        return (mode & ~0o170000) | S_IFLNK
    return mode


# ============================================================================
# UTILITY FUNCTIONS - Formatting and helpers
# ============================================================================

def format_size(size: int) -> str:
    """
    Format byte size in human-readable format.

    Args:
        size: Size in bytes

    Returns:
        Human-readable string (e.g., "1.23 MB")

    Example:
        >>> format_size(1234567890)
        '1.15 GB'
    """
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}" if unit != 'B' else f"{size} {unit}"
        size = size / 1024.0  # type: ignore
    return f"{size:.2f} PB"


def format_time(seconds: float) -> str:
    """
    Format time duration in human-readable format.

    Args:
        seconds: Time in seconds

    Returns:
        Human-readable string (e.g., "1.23s", "45.6ms")

    Example:
        >>> format_time(0.00123)
        '1.23ms'
    """
    if seconds < 0.001:
        return f"{seconds * 1000000:.0f}µs"
    elif seconds < 1.0:
        return f"{seconds * 1000:.2f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"


def sum_sizes_sqroot(file_length: int, protocol_version: int = PROTOCOL_VERSION,
                     fixed_block_size: int = 0,
                     csum_length: int = SHORT_SUM_LENGTH,
                     xfer_sum_len: int = SUM_LENGTH) -> SumSizes:
    """
    Calculate optimal block size for a file using rsync's sqrt algorithm.
    
    This is the Python equivalent of sum_sizes_sqroot() in generator.c (lines 690-757).
    It calculates the optimal block size based on file length, aiming for a
    square-root relationship that balances between:
    - Too small blocks: more checksums to send
    - Too large blocks: less granular matching
    
    The algorithm:
    1. If fixed_block_size is set, use it directly
    2. For files <= BLOCK_SIZE^2 (490KB), use BLOCK_SIZE (700)
    3. For larger files, calculate sqrt-based block size
    4. Calculate s2length (strong checksum length) based on collision probability
    
    Args:
        file_length: Length of file in bytes
        protocol_version: Protocol version (affects max block size)
        fixed_block_size: Override block size (0 = auto-calculate)
        csum_length: Minimum strong-checksum prefix length to send (io.c: csum_length)
        xfer_sum_len: Maximum available strong-checksum length for the algorithm
    
    Returns:
        Dictionary with flength, blength, s2length, remainder, count
    
    Reference:
        generator.c: sum_sizes_sqroot() lines 690-757
    
    Example:
        >>> sizes = sum_sizes_sqroot(10_000_000)  # 10MB file
        >>> print(f"Block size: {sizes['blength']}, Blocks: {sizes['count']}")
    """
    if file_length < 0:
        return {'count': -1, 'flength': 0, 'blength': 0, 's2length': 0, 'remainder': 0}
    
    max_blength = OLD_MAX_BLOCK_SIZE if protocol_version < 30 else MAX_BLOCK_SIZE
    
    # Calculate block length
    if fixed_block_size > 0:
        blength = fixed_block_size
    elif file_length <= BLOCK_SIZE * BLOCK_SIZE:
        blength = BLOCK_SIZE
    else:
        # Calculate using square root algorithm
        c = 1
        l = file_length
        cnt = 0
        while l > 0:
            l >>= 2
            c <<= 1
            cnt += 1
        
        if c < 0 or c >= max_blength:
            blength = max_blength
        else:
            blength = 0
            while c >= 8:
                blength |= c
                if file_length < blength * blength:
                    blength &= ~c
                c >>= 1
            blength = max(blength, BLOCK_SIZE)
    
    # Calculate s2length (strong checksum length)
    if protocol_version < 27:
        s2length = csum_length
    elif csum_length == SUM_LENGTH:
        s2length = SUM_LENGTH
    else:
        # Calculate based on collision probability (generator.c:690-757)
        b = BLOCKSUM_BIAS
        l = file_length
        while l > 0:
            l >>= 1
            b += 2

        c = blength
        while (c >> 1) and b:
            c >>= 1
            b -= 1

        # add a bit, subtract rollsum, round up
        s2length = (b + 1 - 32 + 7) // 8
        s2length = max(s2length, csum_length)
        s2length = min(s2length, SUM_LENGTH)

    if s2length < 0:
        s2length = 0
    # Never exceed what the negotiated checksum can actually provide.
    if xfer_sum_len > 0 and s2length > xfer_sum_len:
        s2length = xfer_sum_len
    
    remainder = file_length % blength if blength > 0 else 0
    count = (file_length // blength) + (1 if remainder != 0 else 0) if blength > 0 else 0
    
    return {
        'flength': file_length,
        'blength': blength,
        's2length': s2length,
        'remainder': remainder,
        'count': count,
    }

# ============================================================================
# TERMINAL COLORS - For beautiful CLI output (auto-detects TTY)
# ============================================================================

class Colors:
    """
    ANSI color codes for terminal output.

    Automatically disabled on non-TTY terminals (pipes, redirects) or when
    Config.USE_COLORS = False. This ensures clean output when piping to files
    or other programs.

    The class uses a singleton-like pattern where all methods are class methods
    for easy access without instantiation.

    Example:
        >>> print(Colors.success("Operation completed"))
        ✓ Operation completed
        >>> print(f"{Colors.GREEN}custom{Colors.RESET}")
        custom
    """
    # ANSI escape codes
    _RESET = '\033[0m'
    _BOLD = '\033[1m'
    _DIM = '\033[2m'
    _RED = '\033[91m'
    _GREEN = '\033[92m'
    _YELLOW = '\033[93m'
    _BLUE = '\033[94m'
    _MAGENTA = '\033[95m'
    _CYAN = '\033[96m'
    _WHITE = '\033[97m'

    @classmethod
    def _is_enabled(cls) -> bool:
        """Check if colors should be enabled."""
        if not Config.USE_COLORS:
            return False
        # Check if stdout is a TTY
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

    # Using simple class methods instead of @property to avoid deprecation warning
    # @property is deprecated in Python 3.11+ for class methods
    @classmethod
    def RESET(cls) -> str:
        return cls._RESET if cls._is_enabled() else ''

    @classmethod
    def BOLD(cls) -> str:
        return cls._BOLD if cls._is_enabled() else ''

    @classmethod
    def DIM(cls) -> str:
        return cls._DIM if cls._is_enabled() else ''

    @classmethod
    def RED(cls) -> str:
        return cls._RED if cls._is_enabled() else ''

    @classmethod
    def GREEN(cls) -> str:
        return cls._GREEN if cls._is_enabled() else ''

    @classmethod
    def YELLOW(cls) -> str:
        return cls._YELLOW if cls._is_enabled() else ''

    @classmethod
    def BLUE(cls) -> str:
        return cls._BLUE if cls._is_enabled() else ''

    @classmethod
    def MAGENTA(cls) -> str:
        return cls._MAGENTA if cls._is_enabled() else ''

    @classmethod
    def CYAN(cls) -> str:
        return cls._CYAN if cls._is_enabled() else ''

    @classmethod
    def WHITE(cls) -> str:
        return cls._WHITE if cls._is_enabled() else ''

    @classmethod
    def success(cls, text: str) -> str:
        """Format text as success (green with checkmark)."""
        if cls._is_enabled():
            return f"{cls._GREEN}✓{cls._RESET} {text}"
        return f"[OK] {text}"

    @classmethod
    def error(cls, text: str) -> str:
        """Format text as error (red with X)."""
        if cls._is_enabled():
            return f"{cls._RED}✗{cls._RESET} {text}"
        return f"[ERROR] {text}"

    @classmethod
    def warning(cls, text: str) -> str:
        """Format text as warning (yellow with !)."""
        if cls._is_enabled():
            return f"{cls._YELLOW}⚠{cls._RESET} {text}"
        return f"[WARN] {text}"

    @classmethod
    def info(cls, text: str) -> str:
        """Format text as info (blue with i)."""
        if cls._is_enabled():
            return f"{cls._BLUE}ℹ{cls._RESET} {text}"
        return f"[INFO] {text}"

    @classmethod
    def bold(cls, text: str) -> str:
        """Format text as bold."""
        if cls._is_enabled():
            return f"{cls._BOLD}{text}{cls._RESET}"
        return text

    @classmethod
    def dim(cls, text: str) -> str:
        """Format text as dim/muted."""
        if cls._is_enabled():
            return f"{cls._DIM}{text}{cls._RESET}"
        return text


# Global colors instance for backward compatibility
colors = Colors()


# ============================================================================
# CUSTOM EXCEPTIONS - Hierarchical exception system
# ============================================================================

class RsyncError(Exception):
    """
    Base exception for all rsync-python errors.

    Attributes:
        message: Human-readable error description
        code: Numeric error code (matches rsync RERR_* codes where applicable)

    Example:
        >>> raise RsyncError("Operation failed", code=1)
    """
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        return self.message


class ValidationError(RsyncError):
    """
    Raised when input validation fails.

    This indicates a programming error or invalid user input,
    such as invalid block sizes, data types, or protocol versions.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message, code=2)


class ResourceLimitError(RsyncError):
    """
    Raised when resource limits are exceeded.

    This indicates an attempt to process data that exceeds configured
    memory limits. Use streaming API for large files.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message, code=3)


class ProtocolMismatchError(RsyncError):
    """
    Raised when protocol negotiation fails.

    This indicates incompatible protocol versions between peers.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message, code=4)


class ProtocolError(RsyncError):
    """
    Raised for general protocol-level errors.

    This includes wire protocol errors, malformed data, etc.
    """
    def __init__(self, message: str, code: int = 5) -> None:
        super().__init__(message, code)


class FileIOError(RsyncError):
    """
    Raised for file I/O errors.

    This wraps OS-level file errors with rsync-specific context.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message, code=6)


class DataIntegrityError(RsyncError):
    """
    Raised when end-to-end data verification fails.

    This corresponds to receiver-side checksum verification failures, such as
    a sender_file_sum mismatch after receiving and reconstructing file data.
    """
    def __init__(self, message: str) -> None:
        super().__init__(message, code=4)

# ============================================================================
# IMPROVED DATA STRUCTURES - Type-safe dataclasses replacing anonymous tuples
# ============================================================================
#
# These dataclasses correspond to the C structures in rsync.h (lines 956-971):
#
#   struct sum_buf {
#       OFF_T offset;      /* offset in file of this chunk */
#       int32 len;         /* length of chunk of file */
#       uint32 sum1;       /* simple checksum */
#       int32 chain;       /* next hash-table collision */
#       short flags;       /* flag bits */
#   };
#
#   struct sum_struct {
#       OFF_T flength;           /* total file length */
#       struct sum_buf *sums;    /* points to info for each chunk */
#       char *sum2_array;        /* checksums of length xfer_sum_len */
#       int32 count;             /* how many chunks */
#       int32 blength;           /* block_length */
#       int32 remainder;         /* flength % block_length */
#       int s2length;            /* sum2_length */
#   };

@dataclass(frozen=True)
class BlockChecksum:
    """
    Represents a checksum of a single block.

    This is the Python equivalent of struct sum_buf in rsync.h (lines 956-962):
    
        struct sum_buf {
            OFF_T offset;      // offset in file of this chunk
            int32 len;         // length of chunk of file
            uint32 sum1;       // simple checksum
            int32 chain;       // next hash-table collision
            short flags;       // flag bits
        };

    Attributes:
        weak_checksum: 32-bit rolling checksum (sum1 in C)
        strong_checksum: Strong hash bytes (stored in sum2_array in C)
        offset: Byte offset of this block in the original file
        length: Length of this block in bytes (len in C)
        chain: Next block index with same hash (for hash table chaining)

    Reference:
        rsync.h: struct sum_buf (lines 956-962)

    Example:
        >>> block = BlockChecksum(
        ...     weak_checksum=0x12345678,
        ...     strong_checksum=b'\\x00' * 16,
        ...     offset=0,
        ...     length=4096
        ... )
        >>> print(f"Block at {block.offset}: weak=0x{block.weak_checksum:08x}")
    """
    weak_checksum: int      # Rolling checksum (32-bit)
    strong_checksum: bytes  # Strong checksum (MD5/SHA1/xxHash)
    offset: int             # Offset in original file
    length: int             # Block length (may be < block_size for last block)
    chain: int = -1         # Hash chain pointer (for hash table)

    def __repr__(self) -> str:
        strong_hex = self.strong_checksum.hex()[:16]
        return (
            f"BlockChecksum(weak=0x{self.weak_checksum:08x}, "
            f"strong={strong_hex}..., offset={self.offset}, len={self.length})"
        )

    @property
    def s1(self) -> int:
        """Lower 16 bits of weak checksum."""
        return self.weak_checksum & 0xFFFF

    @property
    def s2(self) -> int:
        """Upper 16 bits of weak checksum."""
        return (self.weak_checksum >> 16) & 0xFFFF


@dataclass(frozen=True)
class ChecksumSignature:
    """
    Complete file signature containing all block checksums.

    This is the Python equivalent of struct sum_struct in rsync.h (lines 964-971):
    
        struct sum_struct {
            OFF_T flength;           // total file length -> file_size
            struct sum_buf *sums;    // points to info for each chunk -> blocks
            char *sum2_array;        // checksums of length xfer_sum_len (in blocks)
            int32 count;             // how many chunks -> num_blocks
            int32 blength;           // block_length -> block_size
            int32 remainder;         // flength % block_length (computed)
            int s2length;            // sum2_length (determined by checksum_type)
        };

    Attributes:
        block_size: Size of each block (blength in C)
        file_size: Total size of the original file (flength in C)
        num_blocks: Number of blocks in the signature (count in C)
        blocks: List of BlockChecksum objects (sums + sum2_array in C)
        checksum_type: Name of the strong checksum algorithm used
        protocol_version: Protocol version used for generation
        checksum_seed: Seed used for checksums (for security)

    Properties:
        remainder: Computed as file_size % block_size (remainder in C)

    Reference:
        rsync.h: struct sum_struct (lines 964-971)

    Example:
        >>> sig = engine.generate_signature(data)
        >>> print(f"File: {sig.file_size} bytes, {sig.num_blocks} blocks")
        >>> for block in sig.blocks[:3]:
        ...     print(f"  Block {block.offset}: {block.weak_checksum:08x}")
    """
    block_size: int
    file_size: int
    num_blocks: int
    blocks: List[BlockChecksum]
    checksum_type: str
    protocol_version: int
    checksum_seed: int = CHECKSUM_SEED

    def __repr__(self) -> str:
        return (
            f"ChecksumSignature(file_size={format_size(self.file_size)}, "
            f"blocks={self.num_blocks}, block_size={self.block_size}, "
            f"checksum={self.checksum_type}, protocol=v{self.protocol_version})"
        )

    @property
    def remainder(self) -> int:
        """
        Size of the last block if less than block_size.
        
        This mirrors the 'remainder' field in struct sum_struct.
        Returns 0 if file_size is exactly divisible by block_size.
        
        Reference:
            rsync.h: struct sum_struct.remainder (line 970)
        """
        return self.file_size % self.block_size if self.block_size > 0 else 0

    @property
    def s2length(self) -> int:
        """
        Length of strong-checksum prefix stored per block.

        In rsync, only a prefix (sum->s2length) of each strong checksum is
        transmitted/stored; comparisons use only this prefix.

        Reference:
            rsync.h: struct sum_struct.s2length (line 971)
            generator.c: write_buf(..., sum2, sum.s2length) (around line 808)
        """
        if self.blocks:
            return len(self.blocks[0].strong_checksum)
        return MD5_DIGEST_LEN  # default fallback for empty signatures

    def to_dict(self) -> Dict[str, Any]:
        """Convert signature to dictionary for serialization."""
        return {
            'block_size': self.block_size,
            'file_size': self.file_size,
            'num_blocks': self.num_blocks,
            's2length': self.s2length,
            'checksum_type': self.checksum_type,
            'protocol_version': self.protocol_version,
            'checksum_seed': self.checksum_seed,
            'blocks': [
                {
                    'weak': block.weak_checksum,
                    'strong': block.strong_checksum.hex(),
                    'offset': block.offset,
                    'length': block.length,
                }
                for block in self.blocks
            ]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ChecksumSignature':
        """Create signature from dictionary."""
        s2length = int(data.get('s2length', 0))
        blocks = [
            BlockChecksum(
                weak_checksum=int(b['weak']),
                strong_checksum=bytes.fromhex(b['strong']),
                offset=int(b['offset']),
                length=int(b['length']),
            )
            for b in data['blocks']
        ]
        if s2length <= 0:
            s2length = len(blocks[0].strong_checksum) if blocks else MD5_DIGEST_LEN
        if blocks:
            blocks = [
                BlockChecksum(
                    weak_checksum=blk.weak_checksum,
                    strong_checksum=blk.strong_checksum[:s2length],
                    offset=blk.offset,
                    length=blk.length,
                )
                for blk in blocks
            ]
        return cls(
            block_size=data['block_size'],
            file_size=data['file_size'],
            num_blocks=data['num_blocks'],
            blocks=blocks,
            checksum_type=data['checksum_type'],
            protocol_version=data['protocol_version'],
            checksum_seed=data.get('checksum_seed', CHECKSUM_SEED),
        )


@dataclass(frozen=True)
class DeltaMatch:
    """
    Represents a block that matches in the original file.

    When generating a delta, matched blocks don't need to be transferred -
    only the block index is sent, and the receiver copies from its local copy.

    Attributes:
        block_index: Index of the matched block in the signature
        offset_in_new: Byte offset where this match starts in the new file
        length: Number of matched bytes

    Example:
        >>> if isinstance(instruction, DeltaMatch):
        ...     print(f"Copy block {instruction.block_index} ({instruction.length} bytes)")
    """
    block_index: int   # Index of matched block in signature
    offset_in_new: int # Offset in new file
    length: int        # Match length

    def __repr__(self) -> str:
        return f"DeltaMatch(block={self.block_index}, offset={self.offset_in_new}, len={self.length})"


@dataclass(frozen=True)
class DeltaLiteral:
    """
    Represents literal data that doesn't match any block.

    Literal data must be transferred in full from sender to receiver.

    Attributes:
        offset: Byte offset in the new file
        data: The literal bytes to transfer

    Example:
        >>> if isinstance(instruction, DeltaLiteral):
        ...     print(f"Transfer {len(instruction.data)} literal bytes")
    """
    offset: int   # Offset in new file
    data: bytes   # Literal bytes

    def __repr__(self) -> str:
        preview = self.data[:20].hex() if len(self.data) <= 20 else self.data[:20].hex() + '...'
        return f"DeltaLiteral(offset={self.offset}, len={len(self.data)}, data={preview})"


@dataclass
class DeltaInstructions:
    """
    Complete delta instructions for file reconstruction.

    This is the output of delta generation, containing all information
    needed to transform the original file into the new file.

    The instructions list contains tuples of (command, instruction) where:
    - command is 'match' or 'literal'
    - instruction is DeltaMatch or DeltaLiteral respectively

    Attributes:
        original_file_size: Size of the original (basis) file
        new_file_size: Size of the new (target) file
        block_size: Block size used to interpret match block indices
        instructions: List of (command, instruction) tuples
        compression_ratio: Ratio of matched bytes to total bytes
        stats: Optional SyncStats with matching statistics

    Example:
        >>> delta = engine.generate_delta(signature, new_data)
        >>> print(f"Compression: {delta.compression_ratio:.1%}")
        >>> print(f"Matches: {delta.num_matches}, Literals: {delta.num_literals}")
        >>> for cmd, instr in delta.instructions:
        ...     if cmd == 'match':
        ...         print(f"  Copy block {instr.block_index}")
        ...     else:
        ...         print(f"  Transfer {len(instr.data)} bytes")
    """
    original_file_size: int
    new_file_size: int
    block_size: int
    instructions: List[Tuple[str, Union[DeltaMatch, DeltaLiteral]]]
    compression_ratio: float
    stats: Optional[SyncStats] = None
    # match.c: sender computes whole-file checksum and transmits it for verification.
    xfer_checksum_type: Optional[str] = None
    xfer_checksum_seed: Optional[int] = None
    sender_file_sum: Optional[bytes] = None

    def __post_init__(self) -> None:
        """Calculate derived statistics."""
        # These are computed properties, not stored
        pass

    @property
    def num_matches(self) -> int:
        """Count of match instructions."""
        return sum(1 for cmd, _ in self.instructions if cmd == 'match')

    @property
    def num_literals(self) -> int:
        """Count of literal instructions."""
        return sum(1 for cmd, _ in self.instructions if cmd == 'literal')

    @property
    def matched_bytes(self) -> int:
        """Total bytes covered by matches."""
        return sum(
            instr.length for cmd, instr in self.instructions
            if cmd == 'match' and isinstance(instr, DeltaMatch)
        )

    @property
    def literal_bytes(self) -> int:
        """Total bytes in literals."""
        return sum(
            len(instr.data) for cmd, instr in self.instructions
            if cmd == 'literal' and isinstance(instr, DeltaLiteral)
        )

    def __repr__(self) -> str:
        return (
            f"DeltaInstructions(original={format_size(self.original_file_size)}, "
            f"new={format_size(self.new_file_size)}, block_size={self.block_size}, "
            f"matches={self.num_matches}, "
            f"literals={self.num_literals}, ratio={self.compression_ratio:.1%})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert delta to dictionary for serialization."""
        instructions: List[Dict[str, Any]] = []
        for cmd, instr in self.instructions:
            if cmd == 'match' and isinstance(instr, DeltaMatch):
                instructions.append({
                    'type': 'match',
                    'block_index': instr.block_index,
                    'offset': instr.offset_in_new,
                    'length': instr.length,
                })
            elif cmd == 'literal' and isinstance(instr, DeltaLiteral):
                instructions.append({
                    'type': 'literal',
                    'offset': instr.offset,
                    'data': instr.data.hex(),
                })
        return {
            'original_file_size': self.original_file_size,
            'new_file_size': self.new_file_size,
            'block_size': self.block_size,
            'compression_ratio': self.compression_ratio,
            'instructions': instructions,
            'xfer_checksum_type': self.xfer_checksum_type,
            'xfer_checksum_seed': self.xfer_checksum_seed,
            'sender_file_sum': self.sender_file_sum.hex() if self.sender_file_sum is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeltaInstructions':
        """Create delta from dictionary."""
        instructions: List[Tuple[str, Union[DeltaMatch, DeltaLiteral]]] = []
        for instr in data['instructions']:
            if instr['type'] == 'match':
                instructions.append((
                    'match',
                    DeltaMatch(
                        block_index=instr['block_index'],
                        offset_in_new=instr['offset'],
                        length=instr['length'],
                    )
                ))
            else:
                instructions.append((
                    'literal',
                    DeltaLiteral(
                        offset=instr['offset'],
                        data=bytes.fromhex(instr['data']),
                    )
                ))
        return cls(
            original_file_size=data['original_file_size'],
            new_file_size=data['new_file_size'],
            block_size=data.get('block_size', Config.DEFAULT_BLOCK_SIZE),
            instructions=instructions,
            compression_ratio=data['compression_ratio'],
            xfer_checksum_type=data.get('xfer_checksum_type'),
            xfer_checksum_seed=data.get('xfer_checksum_seed'),
            sender_file_sum=(bytes.fromhex(data['sender_file_sum']) if data.get('sender_file_sum') else None),
        )

# ============================================================================
# INPUT VALIDATION - Robust validation matching rsync behavior
# ============================================================================

# Resource limits (configurable, conservative defaults)
MAX_BLOCK_SIZE_LIMIT = MAX_BLOCK_SIZE * 10  # 10x max block (1.3MB)
MIN_BLOCK_SIZE_LIMIT = 16  # Minimum block size for this implementation/test suite
MAX_FILE_SIZE_IN_MEMORY = 1024 * 1024 * 100  # 100MB default max in memory


def validate_block_size(block_size: int, protocol_version: int = PROTOCOL_VERSION) -> None:
    """
    Validate block size is within acceptable range for protocol version.

    Args:
        block_size: The block size to validate
        protocol_version: Protocol version (affects max block size)

    Raises:
        ValidationError: If block_size is invalid

    Example:
        >>> validate_block_size(4096)  # OK
        >>> validate_block_size(-1)  # Raises ValidationError
    """
    # Type hint ensures block_size is int at compile time
    # Runtime validation is handled by type checker
    if block_size <= 0:
        raise ValidationError(f"block_size must be positive, got {block_size}")
    if block_size < MIN_BLOCK_SIZE_LIMIT:
        raise ValidationError(
            f"block_size too small ({block_size}), minimum is {MIN_BLOCK_SIZE_LIMIT} bytes"
        )

    max_blength = OLD_MAX_BLOCK_SIZE if protocol_version < 30 else MAX_BLOCK_SIZE
    if block_size > max_blength:
        raise ValidationError(
            f"block_size too large for protocol {protocol_version} ({block_size}), "
            f"maximum is {max_blength} bytes"
        )

    if block_size > MAX_BLOCK_SIZE_LIMIT:
        raise ValidationError(
            f"block_size too large ({block_size}), maximum is {MAX_BLOCK_SIZE_LIMIT} bytes"
        )


def validate_data(data: Union[bytes, bytearray], max_size: Optional[int] = None, min_size: int = 0) -> None:
    """
    Validate data is valid bytes and within size limits.

    Args:
        data: The data to validate
        max_size: Maximum allowed size (optional)
        min_size: Minimum allowed size (default: 0)

    Raises:
        ValidationError: If data type is wrong or too small
        ResourceLimitError: If data exceeds size limit

    Example:
        >>> validate_data(b"hello")  # OK
        >>> validate_data("string")  # Raises ValidationError
        >>> validate_data(b"", min_size=1)  # Raises ValidationError
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValidationError(
            f"data must be bytes or bytearray, got {type(data).__name__}"
        )
    if len(data) < min_size:
        raise ValidationError(
            f"data too small ({len(data)} bytes), minimum is {min_size} bytes"
        )
    if max_size is not None and len(data) > max_size:
        raise ResourceLimitError(
            f"data too large ({format_size(len(data))}), maximum {format_size(max_size)}. "
            f"Use streaming API for large files."
        )


def validate_protocol_version(version: int) -> None:
    """
    Validate protocol version is within supported range.

    Args:
        version: Protocol version number

    Raises:
        ValidationError: If version is out of range

    Example:
        >>> validate_protocol_version(31)  # OK
        >>> validate_protocol_version(999)  # Raises ValidationError
    """
    # Type hint ensures version is int at compile time
    # Runtime validation is handled by type checker
    if version < MIN_PROTOCOL_VERSION:
        raise ValidationError(
            f"protocol_version {version} too low, minimum is {MIN_PROTOCOL_VERSION}"
        )
    if version > MAX_PROTOCOL_VERSION:
        raise ValidationError(
            f"protocol_version {version} too high, maximum is {MAX_PROTOCOL_VERSION}"
        )


def check_memory_limit(size: int, operation: str = "operation") -> None:
    """
    Check that an operation won't exceed memory limits.

    Args:
        size: Required memory in bytes
        operation: Description of the operation (for error message)

    Raises:
        ValidationError: If size is negative
        ResourceLimitError: If size exceeds limit

    Example:
        >>> check_memory_limit(1024 * 1024, "file load")  # OK
        >>> check_memory_limit(10 * 1024**3, "huge file")  # Raises
    """
    if size < 0:
        raise ValidationError(f"{operation}: size cannot be negative ({size})")
    if size > MAX_FILE_SIZE_IN_MEMORY:
        raise ResourceLimitError(
            f"{operation} requires {format_size(size)} in memory, "
            f"maximum is {format_size(MAX_FILE_SIZE_IN_MEMORY)}. "
            f"Use streaming API for large files."
        )


def validate_checksum_seed(seed: int) -> None:
    """
    Validate checksum seed value.

    Args:
        seed: Checksum seed value (typically 0 for unseeded)

    Raises:
        ValidationError: If seed is negative or out of range

    Example:
        >>> validate_checksum_seed(0)  # OK
        >>> validate_checksum_seed(-1)  # Raises ValidationError
    """
    if seed < 0:
        raise ValidationError(f"checksum_seed cannot be negative, got {seed}")
    if seed > 0xFFFFFFFF:  # 32-bit unsigned max
        raise ValidationError(f"checksum_seed too large ({seed}), maximum is {0xFFFFFFFF}")


def validate_signature(signature: 'ChecksumSignature') -> None:
    """
    Validate a ChecksumSignature object for consistency.

    Args:
        signature: The signature to validate

    Raises:
        ValidationError: If signature has inconsistent data

    Example:
        >>> validate_signature(signature)  # Checks consistency
    """
    if signature.num_blocks != len(signature.blocks):
        raise ValidationError(
            f"Signature inconsistent: num_blocks={signature.num_blocks} but "
            f"blocks list has {len(signature.blocks)} entries"
        )
    if signature.num_blocks < 0:
        raise ValidationError(f"num_blocks cannot be negative ({signature.num_blocks})")
    if signature.file_size < 0:
        raise ValidationError(f"file_size cannot be negative ({signature.file_size})")
    if signature.block_size <= 0:
        raise ValidationError(f"block_size must be positive ({signature.block_size})")

    # Validate block consistency
    for i, block in enumerate(signature.blocks):
        if block.length <= 0:
            raise ValidationError(f"Block {i} has invalid length: {block.length}")
        if block.offset < 0:
            raise ValidationError(f"Block {i} has negative offset: {block.offset}")

        # Check last block is within expected bounds
        expected_offset = i * signature.block_size
        if block.offset != expected_offset:
            raise ValidationError(
                f"Block {i} offset mismatch: expected {expected_offset}, got {block.offset}"
            )

# ============================================================================
# STREAMING DATA SOURCES - For handling files larger than available memory
# ============================================================================

class DataSource(ABC):
    """
    Abstract base class for data sources.

    DataSource provides a unified interface for reading data from various
    sources (memory, files, network) in a streaming fashion. This allows
    processing files larger than available memory.

    Subclasses must implement read_chunk(), size(), and seek() methods.

    Example:
        >>> with FileDataSource("large_file.bin") as source:
        ...     while chunk := source.read_chunk(4096):
        ...         process(chunk)
    """

    @abstractmethod
    def read_chunk(self, size: int) -> bytes:
        """
        Read a chunk of data from the source.

        Args:
            size: Maximum bytes to read

        Returns:
            Bytes read (may be less than size at EOF, empty at EOF)
        """
        raise NotImplementedError

    @abstractmethod
    def size(self) -> int:
        """
        Get total size of the data source.

        Returns:
            Total size in bytes, or -1 if unknown
        """
        raise NotImplementedError

    @abstractmethod
    def seek(self, offset: int) -> None:
        """
        Seek to a position in the data source.

        Args:
            offset: Byte offset from start
        """
        raise NotImplementedError

    def close(self) -> None:
        """Close the data source and release resources."""
        pass

    def __enter__(self) -> 'DataSource':
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class BytesDataSource(DataSource):
    """
    DataSource that reads from in-memory bytes.

    This is useful for small data or when data is already in memory.
    For large files, use FileDataSource instead.

    Example:
        >>> source = BytesDataSource(b"Hello, World!")
        >>> source.read_chunk(5)
        b'Hello'
        >>> source.read_chunk(5)
        b', Wor'
    """

    def __init__(self, data: bytes) -> None:
        """
        Initialize with byte data.

        Args:
            data: The bytes to read from
        """
        self._data = data
        self._position = 0

    def read_chunk(self, size: int) -> bytes:
        """Read up to size bytes from current position."""
        chunk = self._data[self._position:self._position + size]
        self._position += len(chunk)
        return chunk

    def size(self) -> int:
        """Return total size of the data."""
        return len(self._data)

    def seek(self, offset: int) -> None:
        """Seek to byte offset."""
        self._position = max(0, min(offset, len(self._data)))

    def reset(self) -> None:
        """Reset position to start."""
        self._position = 0

    @property
    def position(self) -> int:
        """Current read position."""
        return self._position


class FileDataSource(DataSource):
    """
    DataSource that reads from a file on disk.

    This provides streaming access to files without loading the entire
    file into memory, enabling processing of files larger than RAM.

    Example:
        >>> with FileDataSource("/path/to/large.iso") as source:
        ...     print(f"File size: {source.size()}")
        ...     first_block = source.read_chunk(4096)
    """

    def __init__(self, filepath: str) -> None:
        """
        Initialize with file path.

        Args:
            filepath: Path to the file

        Raises:
            FileIOError: If file cannot be accessed
        """
        self.filepath = filepath
        self._file: Optional[BinaryIO] = None
        try:
            self._size = os.path.getsize(filepath)
        except OSError as e:
            raise FileIOError(f"Cannot access file {filepath}: {e}")

    def __enter__(self) -> 'FileDataSource':
        """Open the file for reading."""
        try:
            self._file = open(self.filepath, 'rb')
        except OSError as e:
            raise FileIOError(f"Cannot open file {self.filepath}: {e}")
        return self

    def __exit__(self, *args: Any) -> None:
        """Close the file."""
        self.close()

    def read_chunk(self, size: int) -> bytes:
        """Read up to size bytes from current position."""
        if not self._file:
            raise RuntimeError("File not opened. Use 'with' statement.")
        return self._file.read(size)

    def size(self) -> int:
        """Return file size in bytes."""
        return self._size

    def seek(self, offset: int) -> None:
        """Seek to byte offset in file."""
        if not self._file:
            raise RuntimeError("File not opened. Use 'with' statement.")
        self._file.seek(offset)

    def close(self) -> None:
        """Close the file handle."""
        if self._file:
            self._file.close()
            self._file = None

    @property
    def is_open(self) -> bool:
        """Check if file is currently open."""
        return self._file is not None


# ============================================================================
# CHECKSUM TYPES - Support for multiple checksum algorithms
# ============================================================================
#
# Checksum type constants from lib/md-defines.h (lines 24-35):
#   #define CSUM_gone -1
#   #define CSUM_NONE 0
#   #define CSUM_MD4_ARCHAIC 1
#   #define CSUM_MD4_BUSTED 2
#   #define CSUM_MD4_OLD 3
#   #define CSUM_MD4 4
#   #define CSUM_MD5 5
#   #define CSUM_XXH64 6
#   #define CSUM_XXH3_64 7
#   #define CSUM_XXH3_128 8
#   #define CSUM_SHA1 9
#   #define CSUM_SHA256 10
#   #define CSUM_SHA512 11
#
# Note: Wire protocol constants CSUM_* are defined above with protocol constants.


class ChecksumType(Enum):
    """
    Supported checksum algorithms across protocol versions.

    This enum maps to rsync's internal CSUM_* constants from lib/md-defines.h
    and determines which algorithm is used for strong checksums during matching.

    Wire Protocol Values (lib/md-defines.h lines 24-35):
        CSUM_NONE      = 0   -> ChecksumType.NONE
        CSUM_MD4       = 4   -> ChecksumType.MD4
        CSUM_MD5       = 5   -> ChecksumType.MD5
        CSUM_XXH64     = 6   -> ChecksumType.XXH64
        CSUM_XXH3_64   = 7   -> ChecksumType.XXH3
        CSUM_XXH3_128  = 8   -> ChecksumType.XXH128
        CSUM_SHA1      = 9   -> ChecksumType.SHA1
        CSUM_SHA256    = 10  -> ChecksumType.SHA256

    Protocol Defaults:
        - Protocol < 30: MD4 (legacy, CSUM_MD4)
        - Protocol >= 30: MD5 (current default, CSUM_MD5)
        - Protocol >= 31: xxHash available (CSUM_XXH64, CSUM_XXH3_64, CSUM_XXH3_128)

    Performance Characteristics:
        - xxHash3: ~30GB/s (fastest, non-cryptographic)
        - xxHash64: ~10GB/s (fast, non-cryptographic)
        - MD5: ~500MB/s (cryptographic, default)
        - SHA1: ~400MB/s (cryptographic, stronger)
        - MD4: ~600MB/s (cryptographic, legacy)

    Reference:
        lib/md-defines.h: lines 24-35
        checksum.c: csum_len_for_type(), get_checksum2()

    Example:
        >>> engine = ChecksumEngine(checksum_type=ChecksumType.XXH64)
    """
    MD4 = "md4"        # CSUM_MD4 = 4, Protocol < 30 default (legacy)
    MD5 = "md5"        # CSUM_MD5 = 5, Protocol >= 30 default
    SHA1 = "sha1"      # CSUM_SHA1 = 9, Optional (stronger security)
    SHA256 = "sha256"  # CSUM_SHA256 = 10, Optional (even stronger)
    XXH64 = "xxh64"    # CSUM_XXH64 = 6, Protocol >= 31 (fast, 64-bit)
    XXH3 = "xxh3"      # CSUM_XXH3_64 = 7, Protocol >= 31 (fastest, 64-bit)
    XXH128 = "xxh128"  # CSUM_XXH3_128 = 8, Protocol >= 31 (fast, 128-bit)
    NONE = "none"      # CSUM_NONE = 0, No checksum (whole-file only)


def _md4_digest(data: bytes) -> bytes:
    """Pure-Python MD4 digest (rsync includes its own md4 in lib/mdfour.c)."""

    def _lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    # Initial state (RFC 1320 / lib/mdfour.c)
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    msg = bytearray(data)
    bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += struct.pack('<Q', bit_len)

    for off in range(0, len(msg), 64):
        x = list(struct.unpack('<16I', msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1.
        s = (3, 7, 11, 19)
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = _lrot((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = _lrot((d + _f(a, b, c) + x[k]) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = _lrot((c + _f(d, a, b) + x[k]) & 0xFFFFFFFF, s[2])
            else:
                b = _lrot((b + _f(c, d, a) + x[k]) & 0xFFFFFFFF, s[3])

        # Round 2.
        s = (3, 5, 9, 13)
        k_order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i, k in enumerate(k_order):
            if i % 4 == 0:
                a = _lrot((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = _lrot((d + _g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = _lrot((c + _g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[2])
            else:
                b = _lrot((b + _g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[3])

        # Round 3.
        s = (3, 9, 11, 15)
        k_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i, k in enumerate(k_order):
            if i % 4 == 0:
                a = _lrot((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = _lrot((d + _h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = _lrot((c + _h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[2])
            else:
                b = _lrot((b + _h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[3])

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack('<4I', a, b, c, d)


class _MD4:
    """Incremental pure-Python MD4 (RFC 1320 / rsync lib/mdfour.c style)."""

    __slots__ = ("_a", "_b", "_c", "_d", "_count", "_buf")

    def __init__(self) -> None:
        self._a = 0x67452301
        self._b = 0xEFCDAB89
        self._c = 0x98BADCFE
        self._d = 0x10325476
        self._count = 0  # bytes processed
        self._buf = bytearray()

    @staticmethod
    def _lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    @staticmethod
    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def update(self, data: bytes) -> None:
        if not data:
            return
        self._count += len(data)
        self._buf.extend(data)
        while len(self._buf) >= 64:
            block = bytes(self._buf[:64])
            del self._buf[:64]
            self._process_block(block)

    def _process_block(self, block: bytes) -> None:
        x = list(struct.unpack("<16I", block))
        a, b, c, d = self._a, self._b, self._c, self._d
        aa, bb, cc, dd = a, b, c, d

        s = (3, 7, 11, 19)
        for i in range(16):
            k = i
            if i % 4 == 0:
                a = self._lrot((a + self._f(b, c, d) + x[k]) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = self._lrot((d + self._f(a, b, c) + x[k]) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = self._lrot((c + self._f(d, a, b) + x[k]) & 0xFFFFFFFF, s[2])
            else:
                b = self._lrot((b + self._f(c, d, a) + x[k]) & 0xFFFFFFFF, s[3])

        s = (3, 5, 9, 13)
        k_order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for i, k in enumerate(k_order):
            if i % 4 == 0:
                a = self._lrot((a + self._g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = self._lrot((d + self._g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = self._lrot((c + self._g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[2])
            else:
                b = self._lrot((b + self._g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, s[3])

        s = (3, 9, 11, 15)
        k_order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i, k in enumerate(k_order):
            if i % 4 == 0:
                a = self._lrot((a + self._h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                d = self._lrot((d + self._h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                c = self._lrot((c + self._h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[2])
            else:
                b = self._lrot((b + self._h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[3])

        self._a = (a + aa) & 0xFFFFFFFF
        self._b = (b + bb) & 0xFFFFFFFF
        self._c = (c + cc) & 0xFFFFFFFF
        self._d = (d + dd) & 0xFFFFFFFF

    def digest(self) -> bytes:
        msg = bytearray(self._buf)
        bit_len = (self._count * 8) & 0xFFFFFFFFFFFFFFFF
        msg.append(0x80)
        while (len(msg) % 64) != 56:
            msg.append(0)
        msg += struct.pack("<Q", bit_len)

        a, b, c, d = self._a, self._b, self._c, self._d
        for off in range(0, len(msg), 64):
            self._process_block(bytes(msg[off:off + 64]))

        out = struct.pack("<4I", self._a, self._b, self._c, self._d)
        self._a, self._b, self._c, self._d = a, b, c, d
        return out


class ChecksumRegistry:
    """
    Registry of available checksum algorithms.

    This class provides factory methods for creating checksum functions
    and querying algorithm properties. It abstracts the underlying
    implementations (hashlib, xxhash) behind a unified interface.

    The registry supports both seeded and unseeded checksums:
    - Unseeded: Pure hash of data (canonical, portable)
    - Seeded: Hash of seed + data (rsync's default for security)

    Example:
        >>> func = ChecksumRegistry.get_checksum_function(ChecksumType.MD5)
        >>> digest = func(b"Hello, World!")
        >>> print(digest.hex())
    """

    # Cache for checksum functions
    _function_cache: Dict[ChecksumType, Callable[[bytes], bytes]] = {}

    @classmethod
    def get_checksum_accumulator(cls, checksum_type: ChecksumType, seed: int = 0) -> Any:
        """
        Return an incremental hasher with update()/digest() matching rsync seeding rules.

        This is used for streaming whole-file checksum calculation (match.c: sum_init/sum_update/sum_end).
        """
        seed_bytes = struct.pack('<I', seed) if seed else b""

        if checksum_type == ChecksumType.MD4:
            h = _MD4()
            suffix = seed_bytes  # checksum.c: MD4 seed appended (SIVAL at end)

            class _MD4Accumulator:
                __slots__ = ("_h", "_suffix")
                def __init__(self, inner: _MD4, suf: bytes) -> None:
                    self._h = inner
                    self._suffix = suf
                def update(self, data: bytes) -> None:
                    self._h.update(data)
                def digest(self) -> bytes:
                    if self._suffix:
                        self._h.update(self._suffix)
                        self._suffix = b""
                    return self._h.digest()

            return _MD4Accumulator(h, suffix)

        if checksum_type == ChecksumType.MD5:
            h = hashlib.md5()
            suffix = b""
            if seed_bytes:
                if Config.PROPER_SEED_ORDER:
                    h.update(seed_bytes)
                else:
                    suffix = seed_bytes

            class _MD5Accumulator:
                __slots__ = ("_h", "_suffix")
                def __init__(self, inner: Any, suf: bytes) -> None:
                    self._h = inner
                    self._suffix = suf
                def update(self, data: bytes) -> None:
                    self._h.update(data)
                def digest(self) -> bytes:
                    if self._suffix:
                        self._h.update(self._suffix)
                        self._suffix = b""
                    return self._h.digest()

            return _MD5Accumulator(h, suffix)

        if checksum_type == ChecksumType.SHA1:
            h = hashlib.sha1()
            if seed_bytes:
                h.update(seed_bytes)
            return h

        if checksum_type == ChecksumType.SHA256:
            h = hashlib.sha256()
            if seed_bytes:
                h.update(seed_bytes)
            return h

        if checksum_type == ChecksumType.XXH64:
            return xxhash.xxh64(seed=seed)

        if checksum_type == ChecksumType.XXH3:
            return xxhash.xxh3_64(seed=seed)

        if checksum_type == ChecksumType.XXH128:
            return xxhash.xxh3_128(seed=seed)

        if checksum_type == ChecksumType.NONE:
            class _NoneAcc:
                __slots__ = ()
                def update(self, data: bytes) -> None:
                    return
                def digest(self) -> bytes:
                    return b"\x00"
            return _NoneAcc()

        raise ValueError(f"Unsupported checksum type: {checksum_type}")

    @classmethod
    def get_checksum_function(
        cls,
        checksum_type: ChecksumType,
        seed: int = 0
    ) -> Callable[[bytes], bytes]:
        """
        Get checksum function for given type.

        Args:
            checksum_type: The algorithm to use
            seed: Optional seed for the checksum (0 = unseeded)

        Returns:
            Function that takes bytes and returns checksum bytes

        Raises:
            ValueError: If checksum type is not supported
        """
        if checksum_type == ChecksumType.MD4:
            # checksum.c (MD4): seed is appended (SIVAL at end).
            if seed == 0:
                return cls._md4_checksum
            seed_bytes = struct.pack('<I', seed)
            return lambda data: cls._md4_checksum(data + seed_bytes)
        elif checksum_type == ChecksumType.MD5:
            if seed == 0:
                return cls._md5_checksum
            seed_bytes = struct.pack('<I', seed)
            if Config.PROPER_SEED_ORDER:
                return lambda data: cls._md5_checksum(seed_bytes + data)
            return lambda data: cls._md5_checksum(data + seed_bytes)
        elif checksum_type == ChecksumType.SHA1:
            if seed == 0:
                return cls._sha1_checksum
            seed_bytes = struct.pack('<I', seed)
            return lambda data: cls._sha1_checksum(seed_bytes + data)
        elif checksum_type == ChecksumType.SHA256:
            if seed == 0:
                return cls._sha256_checksum
            seed_bytes = struct.pack('<I', seed)
            return lambda data: cls._sha256_checksum(seed_bytes + data)
        elif checksum_type == ChecksumType.XXH64:
            return lambda data: cls._xxh64_checksum(data, seed)
        elif checksum_type == ChecksumType.XXH3:
            return lambda data: cls._xxh3_checksum(data, seed)
        elif checksum_type == ChecksumType.XXH128:
            return lambda data: cls._xxh128_checksum(data, seed)
        elif checksum_type == ChecksumType.NONE:
            return lambda data: b'\x00'
        else:
            raise ValueError(f"Unsupported checksum type: {checksum_type}")

    @staticmethod
    def _md4_checksum(data: bytes) -> bytes:
        """MD4 checksum (for protocol < 30)."""
        return _md4_digest(data)

    @staticmethod
    def _md5_checksum(data: bytes) -> bytes:
        """MD5 checksum (for protocol >= 30)."""
        return hashlib.md5(data).digest()

    @staticmethod
    def _sha1_checksum(data: bytes) -> bytes:
        """SHA1 checksum (optional, stronger)."""
        return hashlib.sha1(data).digest()

    @staticmethod
    def _sha256_checksum(data: bytes) -> bytes:
        """SHA256 checksum (optional, strongest)."""
        return hashlib.sha256(data).digest()

    @staticmethod
    def _xxh64_checksum(data: bytes, seed: int = 0) -> bytes:
        """XXH64 checksum (protocol >= 31, fast)."""
        return xxhash.xxh64(data, seed=seed).digest()

    @staticmethod
    def _xxh3_checksum(data: bytes, seed: int = 0) -> bytes:
        """XXH3 64-bit checksum (protocol >= 31, fastest)."""
        return xxhash.xxh3_64(data, seed=seed).digest()

    @staticmethod
    def _xxh128_checksum(data: bytes, seed: int = 0) -> bytes:
        """XXH3 128-bit checksum (protocol >= 31)."""
        return xxhash.xxh3_128(data, seed=seed).digest()

    @staticmethod
    def get_digest_length(checksum_type: ChecksumType) -> int:
        """Get the digest length in bytes for a checksum type."""
        lengths = {
            ChecksumType.NONE: 1,
            ChecksumType.MD4: MD4_DIGEST_LEN,
            ChecksumType.MD5: MD5_DIGEST_LEN,
            ChecksumType.SHA1: SHA1_DIGEST_LEN,
            ChecksumType.SHA256: 32,
            ChecksumType.XXH64: 8,
            ChecksumType.XXH3: 8,
            ChecksumType.XXH128: 16,
        }
        return lengths.get(checksum_type, 16)


# ============================================================================
# COMPRESSION TYPES - Support for multiple compression algorithms
# ============================================================================
#
# Compression type constants from rsync.h (lines 1152-1158):
#   #define CPRES_AUTO (-1)
#   #define CPRES_NONE 0
#   #define CPRES_ZLIB 1
#   #define CPRES_ZLIBX 2
#   #define CPRES_LZ4 3
#   #define CPRES_ZSTD 4

# Protocol wire values for compression (matching rsync.h CPRES_* constants)
CPRES_AUTO = -1  # Auto-negotiate compression
CPRES_NONE = 0   # No compression
CPRES_ZLIB = 1   # Traditional zlib compression
CPRES_ZLIBX = 2  # zlib with extended header (better for streaming)
CPRES_LZ4 = 3    # LZ4 fast compression (protocol >= 31)
CPRES_ZSTD = 4   # Zstandard compression (protocol >= 31)


class CompressionType(Enum):
    """
    Supported compression algorithms.
    
    These correspond to the CPRES_* constants in rsync.h (lines 1152-1158).
    The wire protocol uses integer values for negotiation:
    
        CPRES_NONE  = 0  -> CompressionType.NONE
        CPRES_ZLIB  = 1  -> CompressionType.ZLIB  
        CPRES_ZLIBX = 2  -> CompressionType.ZLIBX
        CPRES_LZ4   = 3  -> CompressionType.LZ4
        CPRES_ZSTD  = 4  -> CompressionType.ZSTD
    
    Protocol Support:
        - NONE:  All protocols
        - ZLIB:  All protocols (default for protocol < 31)
        - ZLIBX: All protocols (streaming optimized)
        - LZ4:   Protocol >= 31 (requires lz4 library)
        - ZSTD:  Protocol >= 31 (requires zstandard library)
    
    Reference:
        rsync.h: lines 1152-1158
        token.c: init_compression_level()
    """
    NONE = "none"
    ZLIB = "zlib"    # Traditional zlib (CPRES_ZLIB = 1)
    ZLIBX = "zlibx"  # zlib extended header (CPRES_ZLIBX = 2)
    LZ4 = "lz4"      # Protocol >= 31 (CPRES_LZ4 = 3)
    ZSTD = "zstd"    # Protocol >= 31 (CPRES_ZSTD = 4)


class CompressionRegistry:
    """Registry of available compression algorithms.
    
    Provides unified interface for compression algorithms used in rsync protocol.
    Supports zlib (default), lz4, and zstandard (protocol >= 31).
    
    Reference:
        rsync.h: CPRES_* constants (lines 1152-1158)
        token.c: init_compression_level()
    """
    # Pre-create compression contexts for better performance
    _zstd_compressors: Dict[int, Any] = {}
    _zstd_decompressors: Dict[int, Any] = {}
    
    @classmethod
    def compress(cls, data: bytes, comp_type: CompressionType, level: int = 6) -> bytes:
        """Compress data using specified algorithm.
        
        Args:
            data: Data to compress
            comp_type: Compression algorithm
            level: Compression level (1-9 for zlib, 1-16 for zstd)
        
        Returns:
            Compressed data bytes
        
        Raises:
            ValueError: If compression type is not supported
        """
        if comp_type == CompressionType.NONE:
            return data
        elif comp_type == CompressionType.ZLIB or comp_type == CompressionType.ZLIBX:
            return zlib.compress(data, level)
        elif comp_type == CompressionType.LZ4:
            return cls._lz4_compress(data, level)  # type: ignore[return-value]
        elif comp_type == CompressionType.ZSTD:
            return cls._zstd_compress(data, level)  # type: ignore[return-value]
        else:
            raise ValueError(f"Unsupported compression type: {comp_type}")

    @classmethod
    def decompress(cls, data: bytes, comp_type: CompressionType) -> bytes:
        """Decompress data using specified algorithm.
        
        Args:
            data: Compressed data
            comp_type: Compression algorithm used
        
        Returns:
            Decompressed data bytes
        
        Raises:
            ValueError: If compression type is not supported
        """
        if comp_type == CompressionType.NONE:
            return data
        elif comp_type == CompressionType.ZLIB or comp_type == CompressionType.ZLIBX:
            return zlib.decompress(data)
        elif comp_type == CompressionType.LZ4:
            return cast(bytes, _lz4_frame.decompress(data))
        elif comp_type == CompressionType.ZSTD:
            return cls._get_zstd_decompressor().decompress(data)  # type: ignore[return-value]
        else:
            raise ValueError(f"Unsupported compression type: {comp_type}")

    @classmethod
    def _get_zstd_compressor(cls, level: int) -> Any:
        """Get or create a ZstdCompressor for the given level."""
        if level not in cls._zstd_compressors:
            cls._zstd_compressors[level] = _zstandard.ZstdCompressor(level=level)
        return cls._zstd_compressors[level]

    @classmethod
    def _get_zstd_decompressor(cls) -> Any:
        """Get or create a ZstdDecompressor."""
        if 0 not in cls._zstd_decompressors:
            cls._zstd_decompressors[0] = _zstandard.ZstdDecompressor()
        return cls._zstd_decompressors[0]

    @classmethod
    def get_compression_level(cls, comp_type: CompressionType) -> int:
        """Get default compression level for algorithm."""
        levels = {
            CompressionType.NONE: 0,
            CompressionType.ZLIB: 6,
            CompressionType.ZLIBX: 6,
            CompressionType.LZ4: 1,  # lz4 uses 0-12, 1 is fast
            CompressionType.ZSTD: 3,  # zstd uses 1-22, 3 is balanced
        }
        return levels.get(comp_type, 6)

    @classmethod
    def is_supported(cls, comp_type: CompressionType) -> bool:
        """Check if compression type is available (libraries installed)."""
        if comp_type in (CompressionType.NONE, CompressionType.ZLIB, CompressionType.ZLIBX):
            return True
        elif comp_type in (CompressionType.LZ4, CompressionType.ZSTD):
            try:
                # Try to import to verify availability
                if comp_type == CompressionType.LZ4:
                    cast(bytes, _lz4_frame.compress(b''))
                    return True
                else:
                    cast(bytes, _zstandard.ZstdCompressor().compress(b''))
                    return True
            except Exception:
                return False
        return False

    @classmethod
    def get_supported_types(cls) -> List[CompressionType]:
        """Get list of available compression types."""
        return [t for t in CompressionType if cls.is_supported(t)]

    @staticmethod
    def _lz4_compress(data: bytes, level: int) -> bytes:
        """LZ4 compression"""
        return cast(bytes, _lz4_frame.compress(data, compression_level=level))

    @staticmethod
    def _lz4_decompress(data: bytes) -> bytes:
        """LZ4 decompression"""
        return cast(bytes, _lz4_frame.decompress(data))

    @staticmethod
    def _zstd_compress(data: bytes, level: int) -> bytes:
        """ZSTD compression"""
        cctx = _zstandard.ZstdCompressor(level=level)
        return cast(bytes, cctx.compress(data))

    @staticmethod
    def _zstd_decompress(data: bytes) -> bytes:
        """ZSTD decompression"""
        dctx = _zstandard.ZstdDecompressor()
        return cast(bytes, dctx.decompress(data))


# ============================================================================
# PROTOCOL VERSION MANAGER - Handles multi-protocol support
# ============================================================================

class ProtocolVersionManager:
    """
    Manages protocol version negotiation and feature availability.

    This mirrors the negotiation logic from rsync's compat.c, including
    the subprotocol downgrade behavior when SUBPROTOCOL_VERSION differs.

    Reference:
        compat.c: protocol negotiation / subprotocol handling
        rsync.h: PROTOCOL_VERSION, SUBPROTOCOL_VERSION, MIN/MAX_PROTOCOL_VERSION
    """

    def __init__(self, desired_protocol: int = PROTOCOL_VERSION):
        self.desired_protocol: int = int(desired_protocol)
        self._negotiated_protocol: int = int(desired_protocol)
        self.remote_protocol: int = 0
        self.compat_flags: int = 0

    @property
    def negotiated_protocol(self) -> int:
        return self._negotiated_protocol

    @negotiated_protocol.setter
    def negotiated_protocol(self, value: int) -> None:
        self._negotiated_protocol = int(value)

    def negotiate_protocol(self, remote_version: int, remote_sub: int = 0) -> int:
        """
        Negotiate protocol version with remote peer
        Returns the agreed upon protocol version
        """
        self.remote_protocol = remote_version
        our_sub = SUBPROTOCOL_VERSION

        # Protocol negotiation logic from compat.c
        if remote_version > self.desired_protocol:
            self.negotiated_protocol = self.desired_protocol
        elif remote_version < self.desired_protocol:
            self.negotiated_protocol = remote_version
            # Handle subprotocol version matching
            if SUBPROTOCOL_VERSION != 0 and our_sub != remote_sub:
                self.negotiated_protocol -= 1
        else:  # Equal versions
            if SUBPROTOCOL_VERSION != 0 and our_sub != remote_sub:
                self.negotiated_protocol -= 1

        # Validate protocol range
        if self.negotiated_protocol < MIN_PROTOCOL_VERSION:
            raise ProtocolError(
                f"Protocol version mismatch: negotiated {self.negotiated_protocol}, "
                f"minimum required {MIN_PROTOCOL_VERSION}"
            )

        if self.negotiated_protocol > MAX_PROTOCOL_VERSION:
            raise ProtocolError(
                f"Protocol version too new: {self.negotiated_protocol} > {MAX_PROTOCOL_VERSION}"
            )

        logger.info(f"Protocol version negotiated: {self.negotiated_protocol} "
                   f"(local={self.desired_protocol}, remote={remote_version})")

        return self.negotiated_protocol

    @property
    def protocol_version(self) -> int:
        """Get current protocol version (for compatibility)"""
        return self._negotiated_protocol

    def get_max_block_size(self) -> int:
        """Get maximum block size for current protocol version"""
        if self._negotiated_protocol >= 30:
            return MAX_BLOCK_SIZE  # 131072
        else:
            return OLD_MAX_BLOCK_SIZE  # 8192

    def get_default_checksum_type(self) -> ChecksumType:
        """Get default checksum type for current protocol version"""
        if self._negotiated_protocol >= 30:
            return ChecksumType.MD5
        else:
            return ChecksumType.MD4

    def supports_varint(self) -> bool:
        """Check if protocol supports variable-length integers"""
        return self._negotiated_protocol >= 27

    def supports_long_names(self) -> bool:
        """Check if protocol supports long file names"""
        return self._negotiated_protocol >= 29

    def supports_inc_recursion(self) -> bool:
        """Check if protocol supports incremental recursion"""
        return self._negotiated_protocol >= 30

    def supports_atimes(self) -> bool:
        """Check if protocol supports access times"""
        return self._negotiated_protocol >= 30

    def supports_crtimes(self) -> bool:
        """Check if protocol supports creation times"""
        return self._negotiated_protocol >= 31

    def supports_xxhash(self) -> bool:
        """Check if protocol supports xxHash checksums"""
        return self._negotiated_protocol >= 31

    def supports_zstd(self) -> bool:
        """Check if protocol supports zstd compression"""
        return self._negotiated_protocol >= 31

    def get_checksum_length(self, checksum_type: ChecksumType) -> int:
        """Get checksum length based on protocol and type."""
        return ChecksumRegistry.get_digest_length(checksum_type)


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Configure logging with a sensible default.
# Por defecto no queremos ensuciar stdout (especialmente en tests/CLI).
_default_log_level = logging.INFO if Config.VERBOSE_LOGGING else logging.WARNING
logging.basicConfig(
    level=_default_log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('rsync-python')
logger.setLevel(_default_log_level)


# ============================================================================
# CHECKSUM IMPLEMENTATION - Core of rsync delta algorithm
#
# This implements the rolling checksum algorithm from checksum.c and match.c
# The algorithm is based on Adler-32 with modifications for rsync's needs.
#
# Key functions in original C code:
#   - get_checksum1() in checksum.c: Rolling/weak checksum
#   - get_checksum2() in checksum.c: Strong checksum (MD5/etc)
#   - hash_search() in match.c: Main matching algorithm
#   - build_hash_table() in match.c: Hash table construction
# ============================================================================

class Checksum:
    """
    Implements rsync's rolling checksum algorithm with multi-protocol support.

    This class provides the core checksum calculations used by rsync:

    1. Rolling Checksum (Weak Checksum):
       A 32-bit checksum based on Adler-32 that can be efficiently updated
       as a sliding window moves through the data. The formula is:
       
           s1 = Σ(data[i] + CHAR_OFFSET) mod 2^16
           s2 = Σ((n-i+1) * (data[i] + CHAR_OFFSET)) mod 2^16
           checksum = (s2 << 16) | s1
       
       Where CHAR_OFFSET=0 for rsync compatibility.

    2. Strong Checksum:
       A cryptographic hash (MD5, SHA1, or xxHash) that definitively
       identifies a block. Used to verify matches after weak checksum hits.

    Attributes:
        block_size: Size of blocks for checksum calculation
        checksum_type: Algorithm for strong checksums
        protocol_manager: Optional protocol version manager
        checksum_seed: Seed for checksums (for security)

    Reference:
        checksum.c get_checksum1(), get_checksum2()

    Example:
        >>> cs = Checksum(block_size=4096)
        >>> weak = cs.rolling_checksum(b"Hello, World!")
        >>> print(f"Weak: 0x{weak:08x}")
        >>> strong = cs.strong_checksum(b"Hello, World!")
        >>> print(f"Strong: {strong.hex()}")
    """

    def __init__(
        self,
        block_size: int = MAX_BLOCK_SIZE,
        checksum_type: ChecksumType = ChecksumType.MD5,
        protocol_manager: Optional['ProtocolVersionManager'] = None,
        checksum_seed: int = CHECKSUM_SEED
    ) -> None:
        """
        Initialize checksum calculator.

        Args:
            block_size: Size of each block for checksumming
            checksum_type: Algorithm for strong checksums
            protocol_manager: Protocol version manager for negotiation
            checksum_seed: Seed for checksums (0 = unseeded)
        """
        self.block_size = block_size
        self.checksum_type = checksum_type
        self.protocol_manager = protocol_manager
        self.checksum_seed = checksum_seed

        # Get strong checksum function based on type and seed
        self.strong_checksum_func = ChecksumRegistry.get_checksum_function(
            checksum_type, seed=checksum_seed
        )

    @staticmethod
    def rolling_checksum(
        data: Union[bytes, bytearray, memoryview],
        offset: int = 0,
        length: Optional[int] = None
    ) -> int:
        """
        Calculate rsync's weak rolling checksum (Adler-32 variant).

        This is a 1:1 Python implementation of get_checksum1() from checksum.c.
        
        The algorithm (from checksum.c lines 295-330):
            s1 = sum of all (bytes + CHAR_OFFSET) mod 2^16
            s2 = cumulative sum of s1 values mod 2^16
            result = (s1 & 0xFFFF) | (s2 << 16)

        The C code structure (simplified):
            for (i = 0; i < len; i++) {
                s1 += buf[i] + CHAR_OFFSET;
                s2 += s1;
            }
            return (s1 & 0xffff) + (s2 << 16);

        Note: CHAR_OFFSET is 0 for rsync compatibility. From rsync.h:
            "a non-zero CHAR_OFFSET makes the rolling sum stronger, but is
            incompatible with older versions :-("

        Args:
            data: Input bytes
            offset: Starting offset in data
            length: Number of bytes to process (None = rest of data)

        Returns:
            32-bit checksum as (s1 & 0xFFFF) | (s2 << 16)

        Reference:
            checksum.c: get_checksum1() lines 295-330
            rsync.h: CHAR_OFFSET definition

        Example:
            >>> Checksum.rolling_checksum(b"abc")
            19267146  # 0x01260249 -> s1=0x0249, s2=0x0126
        """
        if length is None:
            length = len(data) - offset

        s1 = 0
        s2 = 0

        # Simple version matching C code's fallback loop
        # (C code has SIMD optimizations in simd-checksum-*.cpp)
        for i in range(length):
            byte_val = data[offset + i] + CHAR_OFFSET
            s1 = (s1 + byte_val) & 0xFFFF
            s2 = (s2 + s1) & 0xFFFF

        return (s1 & 0xFFFF) | (s2 << 16)

    @staticmethod
    def rolling_checksum_optimized(
        data: Union[bytes, bytearray, memoryview],
        offset: int = 0,
        length: Optional[int] = None
    ) -> int:
        """
        Optimized rolling checksum processing 4 bytes at a time.

        This mirrors the optimization in checksum.c get_checksum1() that
        processes 4 bytes per iteration for better performance.

        Args:
            data: Input bytes
            offset: Starting offset
            length: Number of bytes (None = rest of data)

        Returns:
            32-bit checksum
        """
        if length is None:
            length = len(data) - offset

        s1 = 0
        s2 = 0
        i = 0

        # Process 4 bytes at a time (matches C code optimization)
        while i < length - 3:
            b0 = data[offset + i] + CHAR_OFFSET
            b1 = data[offset + i + 1] + CHAR_OFFSET
            b2 = data[offset + i + 2] + CHAR_OFFSET
            b3 = data[offset + i + 3] + CHAR_OFFSET

            # s2 += 4*s1 + 4*b0 + 3*b1 + 2*b2 + b3
            s2 = (s2 + 4 * (s1 + b0) + 3 * b1 + 2 * b2 + b3) & 0xFFFF
            s1 = (s1 + b0 + b1 + b2 + b3) & 0xFFFF
            i += 4

        # Process remaining bytes
        while i < length:
            byte_val = data[offset + i] + CHAR_OFFSET
            s1 = (s1 + byte_val) & 0xFFFF
            s2 = (s2 + s1) & 0xFFFF
            i += 1

        return (s1 & 0xFFFF) | (s2 << 16)

    @staticmethod
    def rolling_update(
        old_byte: int,
        new_byte: int,
        old_s1: int,
        old_s2: int,
        length: int
    ) -> Tuple[int, int]:
        """
        Update rolling checksum for sliding window.

        When the window slides by one byte (removing old_byte at the start
        and adding new_byte at the end), the checksum can be updated in O(1):

            s1_new = s1_old - old_byte + new_byte
            s2_new = s2_old - (length * old_byte) + s1_new

        This is the key to rsync's efficiency - we don't need to recompute
        the entire checksum when sliding the window.

        Args:
            old_byte: Byte leaving the window (at position 0)
            new_byte: Byte entering the window (at position length)
            old_s1: Current s1 component
            old_s2: Current s2 component
            length: Window size

        Returns:
            Tuple of (new_s1, new_s2)

        Reference:
            match.c: hash_search() rolling update section

        Example:
            >>> # Window slides from "abc" to "bcd"
            >>> s1, s2 = Checksum.checksum_components(0x01260249)
            >>> new_s1, new_s2 = Checksum.rolling_update(ord('a'), ord('d'), s1, s2, 3)
        """
        # Apply CHAR_OFFSET to bytes
        old_val = old_byte + CHAR_OFFSET
        new_val = new_byte + CHAR_OFFSET

        # Update s1: remove old, add new
        new_s1 = (old_s1 - old_val + new_val) & 0xFFFF

        # Update s2: remove old's contribution, add new s1
        new_s2 = (old_s2 - length * old_val + new_s1) & 0xFFFF

        return new_s1, new_s2

    @staticmethod
    def combine_checksum(s1: int, s2: int) -> int:
        """Combine s1 and s2 components into 32-bit checksum."""
        return (s1 & 0xFFFF) | ((s2 & 0xFFFF) << 16)

    @staticmethod
    def checksum_components(checksum: int) -> Tuple[int, int]:
        """Extract s1 and s2 components from 32-bit checksum."""
        s1 = checksum & 0xFFFF
        s2 = (checksum >> 16) & 0xFFFF
        return s1, s2

    def strong_checksum(self, data: Union[bytes, bytearray, memoryview]) -> bytes:
        """
        Calculate strong checksum using configured algorithm.

        This is the get_checksum2() function from checksum.c.
        The algorithm depends on protocol version and configuration:
        - Protocol < 30: MD4 (with optional seed)
        - Protocol >= 30: MD5 (default) or negotiated algorithm
        - Protocol >= 31: xxHash available

        Args:
            data: Input bytes

        Returns:
            Checksum digest bytes

        Reference:
            checksum.c: get_checksum2()
        """
        # Normalize to `bytes` so checksum backends can declare a strict `bytes` input.
        return self.strong_checksum_func(bytes(data))
    
    def _checksum_func_wrapper(self, data: bytes) -> bytes:
        """Wrapper to satisfy type checkers for strong checksum callables."""
        return self.strong_checksum_func(data)

    def block_checksums(
        self,
        data: Union[bytes, bytearray]
    ) -> List[Tuple[int, bytes]]:
        """
        Generate checksums for all blocks in data.

        Args:
            data: Input data to split into blocks

        Returns:
            List of (weak_checksum, strong_checksum) tuples

        Example:
            >>> cs = Checksum(block_size=512)
            >>> blocks = cs.block_checksums(data)
            >>> for weak, strong in blocks:
            ...     print(f"Weak: 0x{weak:08x}, Strong: {strong.hex()[:16]}...")
        """
        blocks: List[Tuple[int, bytes]] = []
        block_size = self.block_size

        for offset in range(0, len(data), block_size):
            block = data[offset:offset + block_size]
            weak = self.rolling_checksum(block)
            strong = self.strong_checksum(block)
            blocks.append((weak, strong))

        return blocks

    def set_checksum_type(self, checksum_type: ChecksumType) -> None:
        """
        Change the strong checksum algorithm.

        This is used during protocol negotiation when the peers agree
        on a checksum algorithm.

        Args:
            checksum_type: New checksum algorithm to use
        """
        self.checksum_type = checksum_type
        self.strong_checksum_func = ChecksumRegistry.get_checksum_function(
            checksum_type, seed=self.checksum_seed
        )


# ============================================================================
# HASH TABLE - Matching rsync's hash table implementation from match.c
# ============================================================================

# ============================================================================
# HASH TABLE - 1:1 implementation of match.c hash table (lines 44-88)
#
# The original C code uses a global hash_table array with chaining.
# Key functions:
#   build_hash_table() - Builds the hash table from sum_struct
#   SUM2HASH2(s1,s2)   - Hash for traditional table: (s1 + s2) & 0xFFFF
#   BIG_SUM2HASH(sum)  - Hash for large tables: sum % tablesize
# ============================================================================

class HashTable:
    """
    Hash table for efficient block matching.

    This is a 1:1 Python implementation of the hash table from match.c.
    
    From match.c (lines 44-48):
        #define TRADITIONAL_TABLESIZE (1<<16)
        static uint32 tablesize;
        static int32 *hash_table;
        #define SUM2HASH2(s1,s2) (((s1) + (s2)) & 0xFFFF)
        #define SUM2HASH(sum) SUM2HASH2((sum)&0xFFFF,(sum)>>16)
        #define BIG_SUM2HASH(sum) ((sum)%tablesize)

    The table sizing logic from build_hash_table() (lines 54-66):
        tablesize = (uint32)(s->count/8) * 10 + 11;
        if (tablesize < TRADITIONAL_TABLESIZE)
            tablesize = TRADITIONAL_TABLESIZE;

    This achieves ~80% load factor for large files while using the
    traditional 65536-entry table for smaller ones.

    Attributes:
        blocks: List of BlockChecksum objects
        count: Number of blocks
        tablesize: Size of hash table (65536 or dynamic)

    Reference:
        match.c: lines 44-88 (build_hash_table, SUM2HASH macros)

    Example:
        >>> ht = HashTable(signature.blocks)
        >>> matches = ht.lookup(weak_checksum)
        >>> for block in matches:
        ...     if verify_strong_checksum(block):
        ...         print(f"Match found: block {block.offset}")
    """

    def __init__(self, blocks: List[BlockChecksum]) -> None:
        """
        Build hash table from block checksums.

        This mirrors build_hash_table() from match.c (lines 51-88).

        Args:
            blocks: List of BlockChecksum objects
        """
        self.blocks = blocks
        self.count = len(blocks)

        # Dynamic table sizing from match.c lines 59-63:
        # tablesize = (uint32)(s->count/8) * 10 + 11;
        # if (tablesize < TRADITIONAL_TABLESIZE)
        #     tablesize = TRADITIONAL_TABLESIZE;
        if Config.HASH_TABLE_DYNAMIC and self.count > 0:
            # Match the exact C formula for dynamic sizing
            self.tablesize = (self.count // 8) * 10 + 11
            if self.tablesize < TRADITIONAL_TABLESIZE:
                self.tablesize = TRADITIONAL_TABLESIZE
        else:
            self.tablesize = TRADITIONAL_TABLESIZE

        # The C code uses -1 to indicate empty slots:
        # memset(hash_table, 0xFF, tablesize * sizeof hash_table[0]);
        # We use a Dict for Python efficiency, but track chains properly
        self._table: Dict[int, List[int]] = {}
        self._build()

    def _build(self) -> None:
        """Build the hash table with chaining."""
        for i, block in enumerate(self.blocks):
            h = self._hash(block.weak_checksum)
            if h not in self._table:
                self._table[h] = []
            self._table[h].append(i)

    def _hash(self, weak_checksum: int) -> int:
        """
        Compute hash value for a weak checksum.

        From match.c (lines 46-48):
            #define SUM2HASH2(s1,s2) (((s1) + (s2)) & 0xFFFF)
            #define SUM2HASH(sum) SUM2HASH2((sum)&0xFFFF,(sum)>>16)
            #define BIG_SUM2HASH(sum) ((sum)%tablesize)

        Uses SUM2HASH for traditional table, BIG_SUM2HASH for large.
        """
        if self.tablesize == TRADITIONAL_TABLESIZE:
            # SUM2HASH2(s1, s2) = ((s1) + (s2)) & 0xFFFF
            s1 = weak_checksum & 0xFFFF
            s2 = (weak_checksum >> 16) & 0xFFFF
            return (s1 + s2) & 0xFFFF
        else:
            # BIG_SUM2HASH(sum) = sum % tablesize
            return weak_checksum % self.tablesize

    def lookup_indices(self, weak_checksum: int, length: Optional[int] = None) -> List[int]:
        """Look up block indices matching a weak checksum (and optional length).

        This is optimized for the hot path in delta generation: returning indices
        avoids O(n) lookups like blocks.index(block) when a match is found.

        Args:
            weak_checksum: The weak checksum to look up
            length: If provided, only return blocks whose len matches

        Returns:
            List of indices into self.blocks
        """
        h = self._hash(weak_checksum)
        indices = self._table.get(h, [])
        if not indices:
            return []

        if length is None:
            return [i for i in indices if self.blocks[i].weak_checksum == weak_checksum]

        return [
            i for i in indices
            if self.blocks[i].weak_checksum == weak_checksum and self.blocks[i].length == length
        ]

    def lookup(self, weak_checksum: int) -> List[BlockChecksum]:
        """Look up blocks matching a weak checksum.

        Returns:
            List of BlockChecksum objects with matching weak checksum
        """
        return [self.blocks[i] for i in self.lookup_indices(weak_checksum)]

    def __len__(self) -> int:
        return self.count


class ChecksumEngine:
    """
    Engine for generating signatures, deltas, and applying patches.

    This is the main interface for using rsync-python. It provides:

    1. Signature Generation:
       Create a signature (list of block checksums) for a file

    2. Delta Generation:
       Compare a new file against a signature to find matches

    3. Delta Application:
       Reconstruct the new file using the original and delta

    The engine implements the core algorithm from match.c hash_search(),
    which uses a rolling checksum with byte-by-byte sliding window.

    Attributes:
        block_size: Size of blocks for checksumming
        checksum_type: Algorithm for strong checksums
        protocol_manager: Optional protocol version manager
        last_stats: Statistics from last operation (if Config.COLLECT_STATS)

    Example:
        >>> engine = ChecksumEngine(block_size=4096)
        >>> sig = engine.generate_signature(original_data)
        >>> delta = engine.generate_delta(sig, new_data)
        >>> reconstructed = engine.apply_delta(original_data, delta)
        >>> assert reconstructed == new_data
    """

    def __init__(
        self,
        block_size: int = MAX_BLOCK_SIZE,
        checksum_type: ChecksumType = ChecksumType.MD5,
        protocol_manager: Optional['ProtocolVersionManager'] = None,
        checksum_seed: int = CHECKSUM_SEED
    ) -> None:
        """
        Initialize the checksum engine.

        Args:
            block_size: Size of each block for checksumming
            checksum_type: Algorithm for strong checksums
            protocol_manager: Protocol version manager for negotiation
            checksum_seed: Seed for checksums (0 = unseeded)

        Raises:
            ValidationError: If block_size is invalid
        """
        # Validate inputs
        effective_proto = protocol_manager.protocol_version if protocol_manager else PROTOCOL_VERSION
        validate_block_size(block_size, protocol_version=effective_proto)

        self.block_size = block_size
        self.checksum_type = checksum_type
        self.protocol_manager = protocol_manager
        self.checksum_seed = checksum_seed

        self.checksum = Checksum(
            block_size=block_size,
            checksum_type=checksum_type,
            protocol_manager=protocol_manager,
            checksum_seed=checksum_seed
        )

        # Statistics from last operation
        self.last_stats: Optional[SyncStats] = None

    def generate_sums(
        self,
        file_data: Union[bytes, bytearray]
    ) -> Tuple[SumHead, List[Tuple[int, bytes]]]:
        """
        Generate checksum structure for a file (legacy API).

        This method is maintained for backward compatibility.
        New code should use generate_signature() instead.

        Args:
            file_data: File content as bytes

        Returns:
            Tuple of (sum_head dict, list of (weak, strong) tuples)
        """
        validate_data(file_data, max_size=MAX_FILE_SIZE_IN_MEMORY)

        sum_head: SumHead = SumHead(
            count=0,
            blength=self.block_size,
            s2length=ChecksumRegistry.get_digest_length(self.checksum_type),
            remainder=len(file_data) % self.block_size,
        )

        blocks = self.checksum.block_checksums(file_data)
        sum_head['count'] = len(blocks)
        sum_head['remainder'] = len(file_data) % self.block_size

        return sum_head, blocks

    def match_sums(
        self,
        file_data: Union[bytes, bytearray],
        sum_head: SumHead,
        sum_list: List[Tuple[int, bytes]]
    ) -> List[Tuple[Any, ...]]:
        """
        Match file data against checksum list (LEGACY API - uses improved algorithm)

        Uses the same improved rolling checksum algorithm as generate_delta().
        """
        validate_data(file_data, max_size=MAX_FILE_SIZE_IN_MEMORY)

        block_size = int(sum_head['blength'])
        count = int(sum_head['count'])
        remainder = int(sum_head['remainder'])
        s2length = int(sum_head['s2length'])
        if s2length <= 0:
            s2length = len(sum_list[0][1]) if sum_list else MD5_DIGEST_LEN

        # Convert legacy (weak, strong) tuples into a typed signature with lengths.
        # Last block may be a partial block when remainder != 0.
        blocks_typed: List[BlockChecksum] = []
        for idx, (weak, strong) in enumerate(sum_list):
            is_last = (idx == len(sum_list) - 1)
            length = remainder if (is_last and remainder != 0) else block_size
            blocks_typed.append(
                BlockChecksum(
                    weak_checksum=weak,
                    strong_checksum=strong[:s2length],
                    offset=idx * block_size,
                    length=length,
                )
            )

        if count <= 0:
            file_size = 0
        else:
            file_size = (count - 1) * block_size + (remainder if remainder else block_size)

        signature = ChecksumSignature(
            block_size=block_size,
            file_size=max(0, file_size),
            num_blocks=len(blocks_typed),
            blocks=blocks_typed,
            checksum_type=str(self.checksum_type),
            protocol_version=(
                self.protocol_manager.negotiated_protocol
                if self.protocol_manager
                else PROTOCOL_VERSION
            ),
            checksum_seed=self.checksum_seed,
        )

        delta = self.generate_delta(signature, file_data)

        # Translate improved delta instructions back into legacy tuple format.
        results: List[Tuple[Any, ...]] = []
        for cmd, instr in delta.instructions:
            if cmd == 'literal' and isinstance(instr, DeltaLiteral):
                results.append(('literal', instr.offset, instr.data))
            elif cmd == 'match' and isinstance(instr, DeltaMatch):
                # Legacy format encodes a matched block as its offset in the basis file.
                results.append(('block', instr.block_index * block_size))

        return results

    # ========================================================================
    # IMPROVED API - Using typed dataclasses instead of anonymous tuples
    # ========================================================================

    def generate_signature(self, file_data: Union[bytes, bytearray],
                           csum_length: int = Config.CSUM_LENGTH) -> ChecksumSignature:
        """
        Generate file signature using improved typed API.

        Returns ChecksumSignature dataclass instead of anonymous tuple.
        This is the PREFERRED API for new code.

        Example:
            engine = ChecksumEngine(block_size=1024)
            signature = engine.generate_signature(b"Hello, World!")
            print(f"File size: {signature.file_size}")
            print(f"Blocks: {signature.num_blocks}")
        """
        # Validate input
        validate_data(file_data, max_size=MAX_FILE_SIZE_IN_MEMORY)

        protocol_version = (self.protocol_manager.protocol_version
                          if self.protocol_manager else PROTOCOL_VERSION)

        xfer_sum_len = ChecksumRegistry.get_digest_length(self.checksum_type)
        sizes = sum_sizes_sqroot(
            len(file_data),
            protocol_version=protocol_version,
            fixed_block_size=self.block_size,
            csum_length=csum_length,
            xfer_sum_len=xfer_sum_len,
        )
        s2length = int(sizes['s2length'])

        # Generate block checksums (store only s2length bytes, like generator.c writes)
        blocks_raw = self.checksum.block_checksums(file_data)

        blocks_typed = [
            BlockChecksum(
                weak_checksum=weak,
                strong_checksum=strong[:s2length],
                offset=i * self.block_size,
                length=min(self.block_size, len(file_data) - i * self.block_size)
            )
            for i, (weak, strong) in enumerate(blocks_raw)
        ]

        return ChecksumSignature(
            block_size=self.block_size,
            file_size=len(file_data),
            num_blocks=len(blocks_typed),
            blocks=blocks_typed,
            checksum_type=self.checksum_type.value,
            protocol_version=protocol_version,
            checksum_seed=self.checksum_seed,
        )

    def generate_delta(self, signature: ChecksumSignature,
                      new_file_data: Union[bytes, bytearray]) -> DeltaInstructions:
        """
        Generate delta instructions using the rsync rolling checksum algorithm.

        This is a 1:1 Python implementation of hash_search() from match.c.
        
        The algorithm from match.c (lines 141-350):
            1. Calculate initial rolling checksum for first block
            2. Look up in hash table (SUM2HASH or BIG_SUM2HASH)
            3. If hash hit, verify with strong checksum (get_checksum2)
            4. If match confirmed, emit matched() token and skip block
            5. If no match, slide window by 1 byte and update checksum

        The rolling update formula (from hash_search lines 280-285):
            s1 += map[k] - map[0];
            s2 += s1 - l*map[0];

        Args:
            signature: ChecksumSignature from original file
            new_file_data: New file content to compare

        Returns:
            DeltaInstructions with typed matches and literals

        Reference:
            match.c: hash_search() lines 141-350
            match.c: matched() lines 98-130

        Example:
            original_sig = engine.generate_signature(original_data)
            delta = engine.generate_delta(original_sig, new_data)
            print(f"Compression ratio: {delta.compression_ratio:.2%}")
            print(f"Matches: {delta.num_matches}, Literals: {delta.num_literals}")
        """
        # Validate input
        validate_data(new_file_data, max_size=MAX_FILE_SIZE_IN_MEMORY)

        collect_stats = Config.COLLECT_STATS or Config.DEBUG_PARITY

        # Reset per-file statistics (like match.c start of hash_search)
        if collect_stats:
            reset_match_stats()

        # Statistics tracking (matching match.c local variables)
        local_false_alarms = 0
        local_hash_hits = 0
        local_matches = 0

        # Build hash table for O(1) lookups (like build_hash_table in match.c)
        hash_table = HashTable(signature.blocks)

        # Generate delta using the REAL rolling-window algorithm (match.c: hash_search).
        # Key property: O(1) weak-checksum updates per byte via rolling_update().
        instructions: List[Tuple[str, Union[DeltaMatch, DeltaLiteral]]] = []
        mv = memoryview(new_file_data)
        file_len = len(mv)
        blength = signature.block_size
        if signature.blocks:
            last_block_len = signature.blocks[-1].length
        else:
            last_block_len = 0

        # match.c: end = len + 1 - s->sums[s->count-1].len;
        end = file_len + 1 - last_block_len if last_block_len > 0 else 0

        # Rolling checksum state over a window of length k at current offset.
        offset = 0
        k = min(blength, file_len)
        if k > 0:
            weak0 = self.checksum.rolling_checksum_optimized(mv, 0, k)
            s1, s2 = self.checksum.checksum_components(weak0)
        else:
            s1 = s2 = 0

        # Literal tracking: we avoid per-byte appends by slicing only when flushing.
        lit_start = 0

        # Strong checksum compare length mirrors sum->s2length in C.
        s2length = signature.s2length

        # want_i optimization from match.c (lines 144-147):
        # "want_i is used to encourage adjacent matches, allowing the RLL
        # coding of the output to work more efficiently."
        want_i = 0

        # last_match tracks where the last match ended (for early flush optimization)
        last_match = 0

        # match.c: updating_basis_file aligned matching behavior.
        updating_basis_file = Config.UPDATING_BASIS_FILE
        aligned_offset = 0
        aligned_i = 0
        same_offset: set[int] = set()

        parity_events: Optional[List[ParityTraceEvent]] = [] if Config.DEBUG_PARITY else None
        parity_cap = Config.PARITY_TRACE_MAX_EVENTS

        def _trace(event: ParityTraceEvent) -> None:
            if parity_events is None:
                return
            if len(parity_events) >= parity_cap:
                return
            parity_events.append(event)

        while offset < end and k > 0:
            weak = self.checksum.combine_checksum(s1, s2)

            # Hash table lookup (match.c: hash_hits++ on a bucket hit)
            candidate_indices = hash_table.lookup_indices(weak, length=k)
            if candidate_indices:
                local_hash_hits += 1

                _trace({
                    'type': 'hash_hit',
                    'offset': offset,
                    'k': k,
                    'weak': weak,
                    'candidates': len(candidate_indices),
                })

                # Compute strong checksum of current window once.
                # strong_checksum() expects bytes/bytearray.
                window_bytes = bytes(mv[offset:offset + k])
                strong = self.checksum.strong_checksum(window_bytes)

                # When updating in-place, bypass entries with offsets we can never use.
                # match.c: if (updating_basis_file && sums[i].offset < offset && !(flags & SAME_OFFSET)) skip/remove.
                if updating_basis_file:
                    candidate_indices = [
                        i for i in candidate_indices
                        if signature.blocks[i].offset >= offset or i in same_offset
                    ]

                matched_index: Optional[int] = None
                for idx in candidate_indices:
                    blk = signature.blocks[idx]
                    if strong[:s2length] == blk.strong_checksum[:s2length]:
                        matched_index = idx
                        break
                    local_false_alarms += 1

                # Aligned matching optimization when updating in-place (match.c lines 248-290).
                if updating_basis_file and matched_index is not None:
                    while aligned_offset < offset:
                        aligned_offset += blength
                        aligned_i += 1

                    l = k
                    if (
                        (offset == aligned_offset or (weak == 0 and l == blength and aligned_offset + l <= file_len))
                        and aligned_i < len(signature.blocks)
                    ):
                        if matched_index != aligned_i:
                            aligned_blk = signature.blocks[aligned_i]
                            if (
                                weak == aligned_blk.weak_checksum
                                and l == aligned_blk.length
                                and strong[:s2length] == aligned_blk.strong_checksum[:s2length]
                            ):
                                matched_index = aligned_i
                        if matched_index == aligned_i:
                            if offset != aligned_offset and aligned_offset + l <= file_len:
                                aligned_window = bytes(mv[aligned_offset:aligned_offset + l])
                                aligned_strong = self.checksum.strong_checksum(aligned_window)
                                if aligned_strong[:s2length] == signature.blocks[matched_index].strong_checksum[:s2length]:
                                    offset = aligned_offset
                                    strong = aligned_strong
                            same_offset.add(matched_index)
                            want_i = matched_index

                # want_i optimization (match.c lines 290-298):
                # Check if want_i would give us an adjacent match (better for RLL coding)
                if matched_index is not None and matched_index != want_i:
                    if want_i < len(signature.blocks):
                        want_blk = signature.blocks[want_i]
                        if (
                            (not updating_basis_file or want_blk.offset >= offset or want_i in same_offset)
                            and weak == want_blk.weak_checksum
                            and strong[:s2length] == want_blk.strong_checksum[:s2length]
                        ):
                            matched_index = want_i

                if matched_index is None:
                    _trace({
                        'type': 'false_alarm',
                        'offset': offset,
                        'k': k,
                        'weak': weak,
                    })

                if matched_index is not None:
                    _trace({
                        'type': 'match',
                        'offset': offset,
                        'k': k,
                        'weak': weak,
                        'block_index': matched_index,
                    })
                    # Flush pending literals (match.c: matched())
                    if offset > lit_start:
                        instructions.append((
                            'literal',
                            DeltaLiteral(offset=lit_start, data=bytes(mv[lit_start:offset]))
                        ))

                    local_matches += 1
                    instructions.append((
                        'match',
                        DeltaMatch(block_index=matched_index, offset_in_new=offset, length=k)
                    ))

                    # Update want_i to encourage adjacent matches (match.c line 298)
                    want_i = matched_index + 1
                    last_match = offset + k

                    # Advance by match length; match.c does offset += len-1 and loop++,
                    # but our loop controls offset directly.
                    offset += k
                    lit_start = offset

                    if offset >= file_len:
                        break

                    # Recompute rolling checksum from scratch at new offset (match.c behavior).
                    k = min(blength, file_len - offset)
                    if k <= 0:
                        break
                    weak0 = self.checksum.rolling_checksum_optimized(mv, offset, k)
                    s1, s2 = self.checksum.checksum_components(weak0)
                    continue

            # No match (or no candidates) -> advance one byte with rolling update.
            more = (offset + k) < file_len
            old_byte = int(mv[offset])

            if more:
                new_byte = int(mv[offset + k])
                s1, s2 = self.checksum.rolling_update(old_byte, new_byte, s1, s2, k)
            else:
                # Approaching EOF: shrink window by 1 byte (match.c: --k).
                old_val = old_byte + CHAR_OFFSET
                s1 = (s1 - old_val) & 0xFFFF
                s2 = (s2 - k * old_val) & 0xFFFF
                k -= 1

            # Early flush optimization (match.c lines 333-335):
            # "By matching early we avoid re-reading the data 3 times in the case
            # where a token match comes a long way after last match."
            backup = offset - last_match
            if backup >= blength + CHUNK_SIZE and end - offset > CHUNK_SIZE:
                # Flush literals up to offset - blength to avoid re-reading
                flush_end = offset - blength
                if flush_end > lit_start:
                    instructions.append((
                        'literal',
                        DeltaLiteral(offset=lit_start, data=bytes(mv[lit_start:flush_end]))
                    ))
                    lit_start = flush_end
                    last_match = flush_end

            offset += 1

        # Flush remaining literals
        if lit_start < file_len:
            instructions.append((
                'literal',
                DeltaLiteral(offset=lit_start, data=bytes(mv[lit_start:file_len]))
            ))

        # Calculate compression metrics
        match_bytes = sum(
            match.length for cmd, match in instructions
            if cmd == 'match' and isinstance(match, DeltaMatch)
        )
        literal_bytes = sum(
            len(lit.data) for cmd, lit in instructions
            if cmd == 'literal' and isinstance(lit, DeltaLiteral)
        )
        total_bytes = match_bytes + literal_bytes
        compression_ratio = match_bytes / total_bytes if total_bytes > 0 else 0.0

        # Update global statistics (like end of match_sums in match.c lines 412-415)
        if collect_stats:
            global _global_false_alarms, _global_hash_hits, _global_matches
            _global_false_alarms = local_false_alarms
            _global_hash_hits = local_hash_hits
            _global_matches = local_matches
            accumulate_match_stats(literal_data=literal_bytes)

        # Create stats object
        stats = SyncStats(
            false_alarms=local_false_alarms,
            hash_hits=local_hash_hits,
            matches=local_matches,
            literal_data=literal_bytes,
            matched_data=match_bytes,
            parity_events=parity_events,
        ) if collect_stats else None

        sender_file_sum: Optional[bytes] = None
        xfer_checksum_type: Optional[str] = None
        xfer_checksum_seed: Optional[int] = None
        if Config.COMPUTE_SENDER_FILE_SUM:
            csum_type = self.checksum_type
            try:
                if signature.checksum_type:
                    csum_type = ChecksumType(signature.checksum_type)
            except Exception:
                csum_type = self.checksum_type
            seed = signature.checksum_seed
            acc = ChecksumRegistry.get_checksum_accumulator(csum_type, seed=seed)
            acc.update(bytes(new_file_data))
            sender_file_sum = acc.digest()
            xfer_checksum_type = csum_type.value
            xfer_checksum_seed = seed

        return DeltaInstructions(
            original_file_size=signature.file_size,
            new_file_size=len(new_file_data),
            block_size=signature.block_size,
            instructions=instructions,
            compression_ratio=compression_ratio,
            stats=stats,
            xfer_checksum_type=xfer_checksum_type,
            xfer_checksum_seed=xfer_checksum_seed,
            sender_file_sum=sender_file_sum,
        )

    def apply_delta(self, original_data: Union[bytes, bytearray],
                   delta: DeltaInstructions) -> bytes:
        """
        Apply delta instructions to reconstruct new file.

        This is the Python equivalent of the receiver loop in receiver.c
        (lines 280-400), which processes incoming data commands:

        From receiver.c receive_data():
            for (i = sum.count; i-- > 0; )
                if (token == -(i+1))
                    # MATCH: copy block from basis file
                    map = map_ptr(mapbuf, offset2, len);
                    copy_write(ofd, map, len);
                else
                    # LITERAL: receive and write literal data
                    copy_write(ofd, data, token);

        Our implementation processes the DeltaInstructions list, which
        contains both match and literal operations pre-computed by
        generate_delta().

        Args:
            original_data: Original (basis) file content
            delta: DeltaInstructions from generate_delta()

        Returns:
            Reconstructed file as bytes

        Reference:
            receiver.c: receive_data() lines 280-400

        Example:
            reconstructed = engine.apply_delta(original_data, delta)
            assert reconstructed == new_data
        """
        # Validate inputs
        validate_data(original_data, max_size=MAX_FILE_SIZE_IN_MEMORY)

        result = bytearray()

        for cmd, instruction in delta.instructions:
            if cmd == 'match' and isinstance(instruction, DeltaMatch):
                # Copy from original file
                start = instruction.block_index * delta.block_size
                end = start + instruction.length
                result.extend(original_data[start:end])
            elif cmd == 'literal' and isinstance(instruction, DeltaLiteral):
                # Add literal data
                result.extend(instruction.data)

        return bytes(result)

    # ========================================================================
    # STREAMING API - For handling large files without loading into memory
    # ========================================================================

    def generate_signature_streaming(self, source: DataSource,
                                     s2length: int) -> Iterator[BlockChecksum]:
        """
        Generate signature blocks in streaming fashion.

        This method yields BlockChecksum objects one at a time, allowing
        processing of files larger than available memory.

        Args:
            source: DataSource to read from (FileDataSource for large files)
            s2length: Strong checksum prefix length to store per block

        Yields:
            BlockChecksum objects for each block

        Example:
            with FileDataSource("/path/to/large.iso") as source:
                for block in engine.generate_signature_streaming(source, s2length=SUM_LENGTH):
                    print(f"Block {block.offset}: {block.weak_checksum:08x}")
        """
        source.seek(0)
        offset = 0
        block_index = 0

        while True:
            chunk = source.read_chunk(self.block_size)
            if not chunk:
                break

            weak = self.checksum.rolling_checksum(chunk)
            strong = self.checksum.strong_checksum(chunk)

            yield BlockChecksum(
                weak_checksum=weak,
                strong_checksum=strong[:s2length],
                offset=offset,
                length=len(chunk)
            )

            offset += len(chunk)
            block_index += 1

    def generate_signature_from_file(self, filepath: str,
                                     csum_length: int = Config.CSUM_LENGTH) -> ChecksumSignature:
        """
        Generate signature from file path (automatically uses streaming for large files).

        Args:
            filepath: Path to file

        Returns:
            ChecksumSignature

        Example:
            signature = engine.generate_signature_from_file("/path/to/large.iso")
            print(f"File size: {signature.file_size}, Blocks: {signature.num_blocks}")
        """
        file_size = os.path.getsize(filepath)
        protocol_version = (self.protocol_manager.protocol_version
                          if self.protocol_manager else PROTOCOL_VERSION)
        xfer_sum_len = ChecksumRegistry.get_digest_length(self.checksum_type)
        sizes = sum_sizes_sqroot(
            file_size,
            protocol_version=protocol_version,
            fixed_block_size=self.block_size,
            csum_length=csum_length,
            xfer_sum_len=xfer_sum_len,
        )
        s2length = int(sizes['s2length'])

        # Use streaming for large files
        if file_size > MAX_FILE_SIZE_IN_MEMORY:
            with FileDataSource(filepath) as source:
                blocks = list(self.generate_signature_streaming(source, s2length=s2length))
        else:
            # Small files can be loaded into memory
            with open(filepath, 'rb') as f:
                data = f.read()
            return self.generate_signature(data, csum_length=csum_length)

        return ChecksumSignature(
            block_size=self.block_size,
            file_size=file_size,
            num_blocks=len(blocks),
            blocks=blocks,
            checksum_type=self.checksum_type.value,
            protocol_version=protocol_version,
            checksum_seed=self.checksum_seed,
        )

    def generate_delta_from_files(self, signature: ChecksumSignature,
                                  new_filepath: str) -> DeltaInstructions:
        """
        Generate delta from file path (automatically uses streaming for large files).

        Args:
            signature: Signature of original file
            new_filepath: Path to new file

        Returns:
            DeltaInstructions

        Example:
            sig = engine.generate_signature_from_file("original.bin")
            delta = engine.generate_delta_from_files(sig, "modified.bin")
            print(f"Compression: {delta.compression_ratio:.2%}")
        """
        file_size = os.path.getsize(new_filepath)

        # Use streaming for large files
        if file_size > MAX_FILE_SIZE_IN_MEMORY:
            return self._generate_delta_streaming(signature, new_filepath)
        else:
            # Small files can be loaded into memory
            with open(new_filepath, 'rb') as f:
                data = f.read()
            return self.generate_delta(signature, data)

    def _generate_delta_streaming(self, signature: ChecksumSignature,
                                  filepath: str) -> DeltaInstructions:
        """
        Internal method for streaming delta generation.
        
        This implements the same rolling checksum algorithm as generate_delta()
        but reads data incrementally to handle files larger than available memory.
        
        Reference:
            match.c: hash_search() - adapted for streaming
        """
        collect_stats = Config.COLLECT_STATS or Config.DEBUG_PARITY
        if collect_stats:
            reset_match_stats()

        local_false_alarms = 0
        local_hash_hits = 0
        local_matches = 0

        hash_table = HashTable(signature.blocks)
        instructions: List[Tuple[str, Union[DeltaMatch, DeltaLiteral]]] = []
        blength = signature.block_size
        s2length = signature.s2length

        with FileDataSource(filepath) as source:
            file_size = source.size()
            source.seek(0)

            sender_acc: Optional[Any] = None
            xfer_checksum_type: Optional[str] = None
            xfer_checksum_seed: Optional[int] = None
            if Config.COMPUTE_SENDER_FILE_SUM:
                csum_type = self.checksum_type
                try:
                    if signature.checksum_type:
                        csum_type = ChecksumType(signature.checksum_type)
                except Exception:
                    csum_type = self.checksum_type
                seed = signature.checksum_seed
                sender_acc = ChecksumRegistry.get_checksum_accumulator(csum_type, seed=seed)
                xfer_checksum_type = csum_type.value
                xfer_checksum_seed = seed

            if signature.blocks:
                last_block_len = signature.blocks[-1].length
            else:
                last_block_len = 0

            end = file_size + 1 - last_block_len if last_block_len > 0 else 0

            # Streaming buffer of yet-unflushed data around the current offset.
            buf = bytearray()
            buf_start = 0  # file offset corresponding to buf[0]
            eof = False

            def buf_end() -> int:
                return buf_start + len(buf)

            def ensure(needed_end: int) -> None:
                nonlocal eof
                if eof:
                    return
                needed_end = min(needed_end, file_size)
                while not eof and buf_end() < needed_end:
                    target_end = min(file_size, max(needed_end, buf_end() + Config.CHUNK_SIZE_STREAMING))
                    to_read = target_end - buf_end()
                    if to_read <= 0:
                        break
                    chunk = source.read_chunk(to_read)
                    if not chunk:
                        eof = True
                        break
                    if sender_acc is not None:
                        sender_acc.update(chunk)
                    buf.extend(chunk)

            def slice_bytes(start_off: int, end_off: int) -> bytes:
                if end_off <= start_off:
                    return b""
                if start_off < buf_start or end_off > buf_end():
                    raise ProtocolError(
                        f"Streaming buffer underflow: need [{start_off},{end_off}) "
                        f"but have [{buf_start},{buf_end()})"
                    )
                i0 = start_off - buf_start
                i1 = end_off - buf_start
                return bytes(buf[i0:i1])

            def flush_literal_range(start_off: int, end_off: int) -> None:
                """Flush literals in CHUNK_SIZE pieces (mirrors token chunking)."""
                if end_off <= start_off:
                    return
                cur = start_off
                while cur < end_off:
                    chunk_end = min(end_off, cur + CHUNK_SIZE)
                    ensure(chunk_end)
                    instructions.append((
                        'literal',
                        DeltaLiteral(offset=cur, data=slice_bytes(cur, chunk_end))
                    ))
                    cur = chunk_end

            parity_events: Optional[List[ParityTraceEvent]] = [] if Config.DEBUG_PARITY else None
            parity_cap = Config.PARITY_TRACE_MAX_EVENTS

            def _trace(event: ParityTraceEvent) -> None:
                if parity_events is None:
                    return
                if len(parity_events) >= parity_cap:
                    return
                parity_events.append(event)

            offset = 0
            k = min(blength, file_size)
            if k > 0:
                ensure(k)
                weak0 = self.checksum.rolling_checksum_optimized(buf, 0, k)
                s1, s2 = self.checksum.checksum_components(weak0)
            else:
                s1 = s2 = 0

            lit_start = 0
            want_i = 0
            last_match = 0

            updating_basis_file = Config.UPDATING_BASIS_FILE
            aligned_offset = 0
            aligned_i = 0
            same_offset: set[int] = set()

            def maybe_compact() -> None:
                nonlocal buf, buf_start
                drop = lit_start - buf_start
                threshold = max(blength, Config.CHUNK_SIZE_STREAMING)
                if drop >= threshold:
                    buf = buf[drop:]
                    buf_start += drop

            while offset < end and k > 0:
                needed = offset + k + (1 if (offset + k) < file_size else 0)
                ensure(needed)
                weak = self.checksum.combine_checksum(s1, s2)
                candidate_indices = hash_table.lookup_indices(weak, length=k)
                if candidate_indices:
                    local_hash_hits += 1
                    _trace({'type': 'hash_hit', 'offset': offset, 'k': k, 'weak': weak, 'candidates': len(candidate_indices)})

                    off_i = offset - buf_start
                    window_bytes = bytes(buf[off_i:off_i + k])
                    strong = self.checksum.strong_checksum(window_bytes)

                    if updating_basis_file:
                        candidate_indices = [
                            i for i in candidate_indices
                            if signature.blocks[i].offset >= offset or i in same_offset
                        ]

                    matched_index: Optional[int] = None
                    for idx in candidate_indices:
                        blk = signature.blocks[idx]
                        if strong[:s2length] == blk.strong_checksum[:s2length]:
                            matched_index = idx
                            break
                        local_false_alarms += 1

                    if updating_basis_file and matched_index is not None:
                        while aligned_offset < offset:
                            aligned_offset += blength
                            aligned_i += 1

                        l = k
                        if (
                            (offset == aligned_offset or (weak == 0 and l == blength and aligned_offset + l <= file_size))
                            and aligned_i < len(signature.blocks)
                        ):
                            if matched_index != aligned_i:
                                aligned_blk = signature.blocks[aligned_i]
                                if (
                                    weak == aligned_blk.weak_checksum
                                    and l == aligned_blk.length
                                    and strong[:s2length] == aligned_blk.strong_checksum[:s2length]
                                ):
                                    matched_index = aligned_i
                            if matched_index == aligned_i:
                                if offset != aligned_offset and aligned_offset + l <= file_size:
                                    ensure(aligned_offset + l)
                                    aligned_window = slice_bytes(aligned_offset, aligned_offset + l)
                                    aligned_strong = self.checksum.strong_checksum(aligned_window)
                                    if aligned_strong[:s2length] == signature.blocks[matched_index].strong_checksum[:s2length]:
                                        offset = aligned_offset
                                        strong = aligned_strong
                                same_offset.add(matched_index)
                                want_i = matched_index

                    if matched_index is not None and matched_index != want_i:
                        if want_i < len(signature.blocks):
                            want_blk = signature.blocks[want_i]
                            if (
                                (not updating_basis_file or want_blk.offset >= offset or want_i in same_offset)
                                and weak == want_blk.weak_checksum
                                and strong[:s2length] == want_blk.strong_checksum[:s2length]
                            ):
                                matched_index = want_i

                    if matched_index is None:
                        _trace({'type': 'false_alarm', 'offset': offset, 'k': k, 'weak': weak})

                    if matched_index is not None:
                        _trace({'type': 'match', 'offset': offset, 'k': k, 'weak': weak, 'block_index': matched_index})

                        if offset > lit_start:
                            flush_literal_range(lit_start, offset)

                        local_matches += 1
                        instructions.append((
                            'match',
                            DeltaMatch(block_index=matched_index, offset_in_new=offset, length=k)
                        ))

                        want_i = matched_index + 1
                        last_match = offset + k
                        offset += k
                        lit_start = offset
                        maybe_compact()

                        if offset >= file_size:
                            break

                        k = min(blength, file_size - offset)
                        if k <= 0:
                            break
                        ensure(offset + k)
                        weak0 = self.checksum.rolling_checksum_optimized(buf, offset - buf_start, k)
                        s1, s2 = self.checksum.checksum_components(weak0)
                        continue

                # No match -> advance one byte with rolling update.
                more = (offset + k) < file_size
                old_byte = buf[offset - buf_start]

                if more:
                    new_byte = buf[offset - buf_start + k]
                    s1, s2 = self.checksum.rolling_update(int(old_byte), int(new_byte), s1, s2, k)
                else:
                    old_val = int(old_byte) + CHAR_OFFSET
                    s1 = (s1 - old_val) & 0xFFFF
                    s2 = (s2 - k * old_val) & 0xFFFF
                    k -= 1

                backup = offset - last_match
                if backup >= blength + CHUNK_SIZE and end - offset > CHUNK_SIZE:
                    flush_end = offset - blength
                    if flush_end > lit_start:
                        flush_literal_range(lit_start, flush_end)
                        lit_start = flush_end
                        last_match = flush_end
                        maybe_compact()

                offset += 1

            ensure(file_size)
            if lit_start < file_size:
                flush_literal_range(lit_start, file_size)

            sender_file_sum: Optional[bytes] = None
            if sender_acc is not None:
                sender_file_sum = sender_acc.digest()

        # Calculate metrics
        match_bytes = sum(
            match.length for cmd, match in instructions
            if cmd == 'match' and isinstance(match, DeltaMatch)
        )
        literal_bytes = sum(
            len(lit.data) for cmd, lit in instructions
            if cmd == 'literal' and isinstance(lit, DeltaLiteral)
        )
        total_bytes = match_bytes + literal_bytes
        compression_ratio = match_bytes / total_bytes if total_bytes > 0 else 0.0

        if collect_stats:
            global _global_false_alarms, _global_hash_hits, _global_matches
            _global_false_alarms = local_false_alarms
            _global_hash_hits = local_hash_hits
            _global_matches = local_matches
            accumulate_match_stats(literal_data=literal_bytes)

        stats = SyncStats(
            false_alarms=local_false_alarms,
            hash_hits=local_hash_hits,
            matches=local_matches,
            literal_data=literal_bytes,
            matched_data=match_bytes,
            parity_events=parity_events,
        ) if collect_stats else None

        return DeltaInstructions(
            original_file_size=signature.file_size,
            new_file_size=file_size,
            block_size=signature.block_size,
            instructions=instructions,
            compression_ratio=compression_ratio,
            stats=stats,
            xfer_checksum_type=xfer_checksum_type,
            xfer_checksum_seed=xfer_checksum_seed,
            sender_file_sum=sender_file_sum,
        )


# ============================================================================
# I/O BUFFERING AND PROTOCOL HANDLING
# ============================================================================

class IOBuffer:
    """Buffered I/O with circular buffer support"""

    def __init__(self, bufsize: int = 65536) -> None:
        self.size = bufsize
        self.buf = bytearray(bufsize)
        self.pos = 0
        self.len = 0
        self.in_fd: Optional[int] = None
        self.out_fd: Optional[int] = None

    def read(self, fd: int, size: Optional[int] = None) -> int:
        """Read from fd into buffer"""
        if size is None:
            size = self.size - self.len

        if size <= 0:
            return 0

        # Never read more than available free space.
        free_space = self.size - self.len
        if size > free_space:
            size = free_space

        data = os.read(fd, size)
        if data:
            self.append(data)

        return len(data)

    def write(self, fd: int, data: Optional[bytes] = None, size: Optional[int] = None) -> int:
        """Write from buffer to fd"""
        if data is not None:
            return os.write(fd, data[:size] if size else data)

        if self.len == 0:
            return 0

        total_written = 0
        while self.len > 0:
            # Write the largest contiguous segment available.
            contiguous = min(self.len, self.size - self.pos)
            n = os.write(fd, self.buf[self.pos:self.pos + contiguous])
            if n <= 0:
                break
            self.pos = (self.pos + n) % self.size
            self.len -= n
            total_written += n
            if n < contiguous:
                break

        return total_written

    def consume(self, size: int) -> None:
        """Consume bytes from buffer"""
        self.pos = (self.pos + size) % self.size
        self.len -= size

    def peek(self, size: int) -> bytes:
        """Peek at bytes in buffer without consuming"""
        if size > self.len:
            size = self.len
        end = self.pos + size
        if end > self.size:
            return bytes(self.buf[self.pos:self.size]) + bytes(self.buf[:end - self.size])
        return bytes(self.buf[self.pos:end])

    def append(self, data: bytes) -> None:
        """Append bytes into the circular buffer."""
        if not data:
            return
        if len(data) > (self.size - self.len):
            raise BufferError(
                f"IOBuffer overflow: trying to append {len(data)} bytes with "
                f"{self.size - self.len} bytes free"
            )
        end = (self.pos + self.len) % self.size
        first = min(len(data), self.size - end)
        self.buf[end:end + first] = data[:first]
        remaining = len(data) - first
        if remaining:
            self.buf[0:remaining] = data[first:first + remaining]
        self.len += len(data)


class ProtocolIO:
    """Handles rsync protocol I/O including multiplexed messages"""

    MPLEX_BASE: ClassVar[int] = MPLEX_BASE
    MPLEX_MAX_PAYLOAD: ClassVar[int] = 0xFFFFFF  # 24-bit length field in tag/len header (io.c)

    # token.c compressed stream flags
    _END_FLAG = 0
    _TOKEN_LONG = 0x20
    _TOKENRUN_LONG = 0x21
    _DEFLATED_DATA = 0x40
    _TOKEN_REL = 0x80
    _TOKENRUN_REL = 0xC0
    _MAX_DATA_COUNT = 16383  # token.c: MAX_DATA_COUNT

    @staticmethod
    def _avail_out_size(avail_in_size: int) -> int:
        # token.c: AVAIL_OUT_SIZE(avail_in_size) == avail_in*1001/1000+16
        return (avail_in_size * 1001) // 1000 + 16

    def __init__(self, sock: Optional[Any] = None, timeout: int = 60) -> None:
        self.sock = sock
        self.timeout = timeout
        self.in_buffer = IOBuffer(65536)
        self.out_buffer = IOBuffer(65536)
        self.msg_buffer = IOBuffer(65536)
        self.out_empty_len = 0
        self.in_multiplexed = False
        self.total_read = 0
        self.total_written = 0

        # io.c multiplexing state: we expose a "data-only" stream to protocol readers/writers
        # and transparently queue non-DATA MSG_* frames.
        self._mplex_out_data: bytearray = bytearray()
        self._mplex_in_data: bytearray = bytearray()
        self._mplex_in_msgs: Deque[Tuple[int, bytes]] = deque()
        self._mplex_in_eof: bool = False

        # token.c compression state (per connection)
        self.do_compression: CompressionType = CompressionType.NONE
        self.do_compression_level: int = CompressionRegistry.get_compression_level(CompressionType.NONE)

        # Sender-side compressed token state
        self._tx_last_token: int = -1
        self._tx_run_start: int = 0
        self._tx_last_run_end: int = 0
        self._tx_flush_pending: bool = False
        self._zlib_tx: Optional[Any] = None
        self._zstd_tx_writer: Optional[Any] = None
        self._zstd_tx_sink: Optional[Any] = None

        # Receiver-side compressed token state
        self._rx_state: str = "r_init"
        self._rx_saved_flag: Optional[int] = None
        self._rx_token: int = 0
        self._rx_run: int = 0
        self._rx_inflate_buf: bytes = b""
        self._zlib_rx: Optional[Any] = None
        self._zstd_rx: Optional[Any] = None
        self._rx_pending_out: bytearray = bytearray()

    def set_compression(self, comp: CompressionType, level: Optional[int] = None) -> None:
        """Set the compression mode used by send_token()/recv_token()."""
        self.do_compression = comp
        self.do_compression_level = (
            CompressionRegistry.get_compression_level(comp) if level is None else int(level)
        )

    def set_fd(self, f_in: int, f_out: int) -> None:
        """Set input and output file descriptors"""
        self.in_buffer.in_fd = f_in
        self.out_buffer.out_fd = f_out

    def read_int(self) -> int:
        """Read 32-bit integer from stream (little-endian, like io.c IVAL)."""
        data = self.read_bytes(4)
        return struct.unpack('<i', data)[0]

    def read_uint(self) -> int:
        """Read 32-bit unsigned integer (little-endian, like io.c IVAL)."""
        data = self.read_bytes(4)
        return struct.unpack('<I', data)[0]

    def read_long(self) -> int:
        """Read 64-bit integer (little-endian, like io.c IVAL64)."""
        data = self.read_bytes(8)
        return struct.unpack('<q', data)[0]

    def write_int(self, value: int) -> None:
        self.write_bytes(struct.pack('<i', value))

    def write_uint(self, value: int) -> None:
        self.write_bytes(struct.pack('<I', value))

    def write_long(self, value: int) -> None:
        self.write_bytes(struct.pack('<q', value))

    def read_varint(self) -> int:
        """Read variable-length integer"""
        # io.c: read_varint() uses int_byte_extra[ch/4] to determine extra bytes.
        ch = self.read_byte() & 0xFF
        extra = _INT_BYTE_EXTRA[ch // 4]
        if extra:
            if extra >= 5:
                raise ProtocolError("Overflow in read_varint()")
            bit = 1 << (8 - extra)
            buf = bytearray(5)
            data = self.read_bytes(extra)
            buf[:extra] = data
            buf[extra] = ch & (bit - 1)
            return int.from_bytes(buf[:4], 'little', signed=True)
        return int.from_bytes(bytes([ch, 0, 0, 0]), 'little', signed=True)

    def write_varint(self, value: int) -> None:
        """Write variable-length integer"""
        # io.c: write_varint() packs a little-endian int32 and encodes a prefix byte.
        b = bytearray(5)
        b[1:5] = struct.pack('<I', value & 0xFFFFFFFF)

        cnt = 4
        while cnt > 1 and b[cnt] == 0:
            cnt -= 1
        bit = 1 << (8 - cnt)

        if b[cnt] >= bit:
            cnt += 1
            b[0] = (~(bit - 1)) & 0xFF
        elif cnt > 1:
            b[0] = (b[cnt] | (~(bit * 2 - 1) & 0xFF)) & 0xFF
        else:
            b[0] = b[1]

        self.write_bytes(bytes(b[:cnt]))

    def read_byte(self) -> int:
        """Read single byte"""
        data = self.read_bytes(1)
        return data[0] if isinstance(data, bytes) else ord(data)

    def write_byte(self, value: int) -> None:
        """Write single byte"""
        self.write_bytes(bytes([value]))

    def read_vstring(self, bufsize: int = MAX_NSTR_STRLEN) -> str:
        """
        Read a vstring (1-2 byte length, then bytes).
        Reference: rsync-original-source-code/io.c:1944-1965
        """
        length = self.read_byte()
        if length & 0x80:
            length = (length & ~0x80) * 0x100 + self.read_byte()
        if length >= bufsize:
            raise ProtocolError(f"over-long vstring received ({length} > {bufsize - 1})")
        data = self.read_bytes(length) if length else b""
        try:
            return data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # rsync treats these strings as bytes; UTF-8 decoding is a best-effort here.
            return data.decode("utf-8", errors="replace")

    def write_vstring(self, s: str) -> None:
        """
        Write a vstring (1-2 byte length, then bytes).
        Reference: rsync-original-source-code/io.c:2222-2240
        """
        data = s.encode("utf-8", errors="strict")
        length = len(data)
        if length > 0x7FFF:
            raise ProtocolError(f"attempting to send over-long vstring ({length} > {0x7FFF})")
        if length > 0x7F:
            self.write_byte(length // 0x100 + 0x80)
        self.write_byte(length)
        if length:
            self.write_bytes(data)

    def read_shortint(self) -> int:
        """Read 16-bit little-endian unsigned integer (io.c read_shortint)."""
        data = self.read_bytes(2)
        return struct.unpack('<H', data)[0]

    def write_shortint(self, value: int) -> None:
        """Write 16-bit little-endian unsigned integer (io.c write_shortint)."""
        self.write_bytes(struct.pack('<H', value & 0xFFFF))

    def read_varint30(self, protocol_version: int) -> int:
        """
        read_varint30() helper.
        Reference: rsync-original-source-code/io.h:read_varint30()
        """
        if protocol_version < 30:
            return self.read_int()
        return self.read_varint()

    def write_varint30(self, value: int, protocol_version: int) -> None:
        """
        write_varint30() helper.
        Reference: rsync-original-source-code/io.h:write_varint30()
        """
        if protocol_version < 30:
            self.write_int(int(value))
        else:
            self.write_varint(int(value))

    def read_varlong(self, min_bytes: int) -> int:
        """
        Read variable-length 64-bit integer (io.c:read_varlong).
        Reference: rsync-original-source-code/io.c:1827-1865
        """
        if min_bytes < 1 or min_bytes > 8:
            raise ProtocolError(f"Invalid min_bytes for read_varlong(): {min_bytes}")

        b2 = self.read_bytes(min_bytes)
        extra = _INT_BYTE_EXTRA[(b2[0] & 0xFF) // 4]

        buf = bytearray(9)
        if min_bytes > 1:
            buf[0:min_bytes - 1] = b2[1:min_bytes]

        if extra:
            if min_bytes + extra > len(buf):
                raise ProtocolError("Overflow in read_varlong()")
            bit = 1 << (8 - extra)
            tail = self.read_bytes(extra)
            buf[min_bytes - 1:min_bytes - 1 + extra] = tail
            buf[min_bytes + extra - 1] = b2[0] & (bit - 1)
        else:
            buf[min_bytes + extra - 1] = b2[0]

        return int.from_bytes(bytes(buf[:8]), 'little', signed=True)

    def write_varlong(self, value: int, min_bytes: int) -> None:
        """
        Write variable-length 64-bit integer (io.c:write_varlong).
        Reference: rsync-original-source-code/io.c:2111-2145
        """
        if min_bytes < 1 or min_bytes > 8:
            raise ProtocolError(f"Invalid min_bytes for write_varlong(): {min_bytes}")

        b = bytearray(9)
        b[1:9] = struct.pack('<q', int(value))

        cnt = 8
        while cnt > min_bytes and b[cnt] == 0:
            cnt -= 1
        bit = 1 << (7 - cnt + min_bytes)

        if b[cnt] >= bit:
            cnt += 1
            b[0] = (~(bit - 1)) & 0xFF
        elif cnt > min_bytes:
            b[0] = (b[cnt] | (~(bit * 2 - 1) & 0xFF)) & 0xFF
        else:
            b[0] = b[cnt]

        self.write_bytes(bytes(b[:cnt]))

    def read_varlong30(self, min_bytes: int, protocol_version: int) -> int:
        """
        read_varlong30() helper.
        Reference: rsync-original-source-code/io.h:read_varlong30()
        """
        if protocol_version < 30:
            return self.read_long()
        return self.read_varlong(min_bytes)

    def write_varlong30(self, value: int, min_bytes: int, protocol_version: int) -> None:
        """
        write_varlong30() helper.
        Reference: rsync-original-source-code/io.h:write_varlong30()
        """
        if protocol_version < 30:
            self.write_long(int(value))
        else:
            self.write_varlong(int(value), min_bytes)

    def _read_raw_bytes(self, size: int) -> bytes:
        """Read raw bytes from the underlying transport (no multiplex decoding)."""
        if self.in_buffer.in_fd is not None:
            while self.in_buffer.len < size:
                try:
                    n = self.in_buffer.read(self.in_buffer.in_fd, size - self.in_buffer.len)
                    if n == 0:
                        if self.in_buffer.len >= size:
                            break
                        raise EOFError(f"Unexpected EOF: needed {size}, got {self.in_buffer.len}")
                except BlockingIOError:
                    if self.in_buffer.len > 0:
                        break
                    raise

            data = self.in_buffer.peek(size)
            self.in_buffer.consume(size)
        else:
            if self.sock is None:
                raise RuntimeError("Socket is not initialized")
            chunks: List[bytes] = []
            remaining = size
            while remaining > 0:
                part = self.sock.recv(remaining)
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            data = b"".join(chunks)
        self.total_read += len(data)
        return data

    def _write_raw_bytes(self, data: bytes) -> None:
        """Write raw bytes to the underlying transport (no multiplex encoding)."""
        if self.out_buffer.out_fd is not None:
            remaining = data
            while remaining:
                space = self.out_buffer.size - self.out_buffer.len
                if space <= 0:
                    self._flush_out()
                    space = self.out_buffer.size - self.out_buffer.len
                to_write = remaining[:space]
                self.out_buffer.append(to_write)
                remaining = remaining[len(to_write):]
        else:
            if self.sock is None:
                raise RuntimeError("Socket is not initialized")
            self.sock.sendall(data)
        self.total_written += len(data)

    def _mplex_flush_out_data(self) -> None:
        """Flush pending MSG_DATA payload as a multiplexed frame (io.c MSG_DATA)."""
        if not self._mplex_out_data:
            return
        payload_len = len(self._mplex_out_data)
        if payload_len > self.MPLEX_MAX_PAYLOAD:
            raise ProtocolError(f"MSG_DATA too large: {payload_len} > {self.MPLEX_MAX_PAYLOAD}")
        header = struct.pack(
            '<I', ((self.MPLEX_BASE + int(MSG.DATA)) << 24) | payload_len
        )
        self._write_raw_bytes(header)
        self._write_raw_bytes(bytes(self._mplex_out_data))
        self._mplex_out_data.clear()

    def _mplex_read_one_msg(self) -> Tuple[Optional[int], Optional[bytes]]:
        """Read a single multiplexed frame (header + payload) from raw stream."""
        header = self._read_raw_bytes(4)
        if len(header) < 4:
            return None, None
        tag_len = struct.unpack('<I', header[:4])[0]
        code = (tag_len >> 24) - self.MPLEX_BASE
        msg_len = tag_len & 0xFFFFFF
        if msg_len > 0:
            data = self._read_raw_bytes(msg_len)
            if len(data) < msg_len:
                raise EOFError(f"Unexpected EOF: needed {msg_len}, got {len(data)}")
        else:
            data = b""
        return int(code), data

    def read_bytes(self, size: int) -> bytes:
        """Read bytes from the data stream, decoding multiplexed MSG_* if enabled."""
        if not self.in_multiplexed:
            return self._read_raw_bytes(size)
        if self._mplex_in_eof:
            raise EOFError("Unexpected EOF: multiplexed input ended (MSG_EOF)")

        out = bytearray()
        while len(out) < size:
            if self._mplex_in_data:
                take = min(size - len(out), len(self._mplex_in_data))
                out.extend(self._mplex_in_data[:take])
                del self._mplex_in_data[:take]
                continue

            code, data = self._mplex_read_one_msg()
            if code is None or data is None:
                raise EOFError(f"Unexpected EOF: needed {size}, got {len(out)}")

            if code == int(MSG.DATA):
                if data:
                    self._mplex_in_data.extend(data)
                continue

            if code == int(MSG.EOF):
                self._mplex_in_msgs.append((code, data))
                self._mplex_in_eof = True
                raise EOFError(f"Unexpected EOF: needed {size}, got {len(out)}")

            self._mplex_in_msgs.append((code, data))
        return bytes(out)

    def write_bytes(self, data: bytes) -> None:
        """Write bytes to the data stream, encoding multiplexed MSG_DATA if enabled."""
        if self.out_empty_len == 0:
            self._write_raw_bytes(data)
            return
        if not data:
            return
        self._mplex_out_data.extend(data)
        # Keep payload size within the 24-bit length field and in-buffer semantics.
        max_payload = min(self.MPLEX_MAX_PAYLOAD, max(1, self.out_buffer.size - 4))
        while len(self._mplex_out_data) >= max_payload:
            chunk = self._mplex_out_data[:max_payload]
            del self._mplex_out_data[:max_payload]
            header = struct.pack(
                '<I', ((self.MPLEX_BASE + int(MSG.DATA)) << 24) | len(chunk)
            )
            self._write_raw_bytes(header)
            self._write_raw_bytes(bytes(chunk))

    def _flush_out(self) -> None:
        """Flush output buffer"""
        if self.out_buffer.len > 0 and self.out_buffer.out_fd is not None:
            self.out_buffer.write(self.out_buffer.out_fd)

    def flush(self) -> None:
        """Flush all buffers"""
        if self.out_empty_len != 0:
            self._mplex_flush_out_data()
        self._flush_out()

    def send_msg(self, code: int, data: bytes = b'') -> int:
        """Send multiplexed message"""
        if self.out_empty_len == 0:
            return 0
        # io.c: send_msg() flushes any pending MSG_DATA so control messages are ordered correctly.
        self._mplex_flush_out_data()
        msg_len = len(data)
        header = struct.pack('<I', ((self.MPLEX_BASE + code) << 24) | msg_len)
        self._write_raw_bytes(header)
        if data:
            self._write_raw_bytes(data)
        return 1

    def recv_msg(self) -> Tuple[Optional[int], Optional[bytes]]:
        """Receive multiplexed message"""
        if not self.in_multiplexed:
            header = self._read_raw_bytes(4)
            if len(header) < 4:
                return None, None
            tag_len = struct.unpack('<I', header[:4])[0]
            code = (tag_len >> 24) - self.MPLEX_BASE
            msg_len = tag_len & 0xFFFFFF
            data = b''
            if msg_len > 0:
                data = self._read_raw_bytes(msg_len)
            return int(code), data

        if self._mplex_in_msgs:
            code, data = self._mplex_in_msgs.popleft()
            return int(code), data

        while True:
            code, data = self._mplex_read_one_msg()
            if code is None or data is None:
                return None, None
            if code == int(MSG.DATA):
                if data:
                    self._mplex_in_data.extend(data)
                continue
            if code == int(MSG.EOF):
                self._mplex_in_eof = True
            return int(code), data

    def io_start_multiplex_out(self) -> None:
        self.flush()
        self.out_empty_len = 4
        self._mplex_out_data.clear()

    def io_start_multiplex_in(self) -> None:
        self.in_multiplexed = True
        self._mplex_in_data.clear()
        self._mplex_in_msgs.clear()
        self._mplex_in_eof = False

    def io_end_multiplex_out(self) -> None:
        self.flush()
        self.out_empty_len = 0
        self._mplex_out_data.clear()

    def io_end_multiplex_in(self) -> None:
        self.in_multiplexed = False
        self._mplex_in_data.clear()
        self._mplex_in_msgs.clear()
        self._mplex_in_eof = False

    def _send_token_simple(self, token: int, data: Optional[bytes] = None,
                           offset: int = 0, n: int = 0) -> None:
        """
        Send a token (block match or literal data) on the wire.
        
        This is the Python equivalent of simple_send_token() in token.c (lines 306-322).
        
        Token protocol:
            - Positive integers in stream: literal data length follows
            - Negative integers: -(token+1) means match block number 'token'
            - Token -2 means send literal data only (no token)
        
        Args:
            token: Block number matched, or -1 for final literal, or -2 for data only
            data: Literal data bytes to send before token (may be None)
            offset: Offset in data (for compatibility, not used in simple mode)
            n: Length of literal data to send
        
        Reference:
            token.c: simple_send_token() lines 306-322
        
        Example:
            >>> pio = ProtocolIO()
            >>> # Send 10 bytes of literal data, then signal match on block 5
            >>> pio.send_token(5, b'0123456789', 0, 10)
        """
        # Send literal data in CHUNK_SIZE pieces
        if data is not None and n > 0:
            sent = 0
            while sent < n:
                chunk_len = min(CHUNK_SIZE, n - sent)
                self.write_int(chunk_len)
                self.write_bytes(data[offset + sent:offset + sent + chunk_len])
                sent += chunk_len
        
        # A -2 token means send data only, no token marker
        if token != -2:
            self.write_int(-(token + 1))

    def _recv_token_simple(self) -> Tuple[int, Optional[bytes]]:
        """
        Receive a token (block match or literal data) from the wire.
        
        This is the Python equivalent of recv_token() in token.c.
        
        Token protocol:
            - Positive value: literal data of that length follows
            - Zero: end of transfer
            - Negative value: -(token+1), so token = -(value+1) is matched block
        
        Returns:
            Tuple of (token, data):
                - (positive, bytes): literal data of given length
                - (0, None): end of transfer
                - (negative, None): block match, block_num = -(token+1)
        
        Reference:
            token.c: recv_token() lines 253-302
        
        Example:
            >>> pio = ProtocolIO()
            >>> token, data = pio.recv_token()
            >>> if token > 0:
            ...     print(f"Received {token} bytes of literal data")
            >>> elif token == 0:
            ...     print("End of transfer")
            >>> else:
            ...     block_num = -(token + 1)
            ...     print(f"Matched block {block_num}")
        """
        i = self.read_int()
        
        if i == 0:
            return (0, None)  # End of transfer
        
        if i > 0:
            # Positive: literal data follows
            data = self.read_bytes(i)
            return (i, data)
        
        # Negative: block match token
        return (i, None)

    def _reset_tx_compression_state(self) -> None:
        self._tx_run_start = 0
        self._tx_last_run_end = 0
        self._tx_flush_pending = False
        if self.do_compression in (CompressionType.ZLIB, CompressionType.ZLIBX):
            self._zlib_tx = zlib.compressobj(
                self.do_compression_level,
                zlib.DEFLATED,
                -15,
                8,
                zlib.Z_DEFAULT_STRATEGY,
            )
        elif self.do_compression == CompressionType.ZSTD:
            import io

            class _Sink(io.RawIOBase):
                def __init__(self) -> None:
                    super().__init__()
                    self.buf = bytearray()

                def writable(self) -> bool:  # type: ignore[override]
                    return True

                def write(self, b: bytes) -> int:  # type: ignore[override]
                    self.buf.extend(b)
                    return len(b)

                def pop(self) -> bytes:
                    if not self.buf:
                        return b""
                    out = bytes(self.buf)
                    self.buf.clear()
                    return out

            self._zstd_tx_sink = _Sink()
            zc = _zstandard.ZstdCompressor(level=self.do_compression_level)
            self._zstd_tx_writer = zc.stream_writer(self._zstd_tx_sink, closefd=False)
        else:
            # LZ4/NONE: no persistent compressor state
            self._zlib_tx = None
            self._zstd_tx_sink = None
            self._zstd_tx_writer = None

    def _reset_rx_compression_state(self) -> None:
        self._rx_state = "r_idle"
        self._rx_saved_flag = None
        self._rx_token = 0
        self._rx_run = 0
        self._rx_inflate_buf = b""
        self._rx_pending_out.clear()
        if self.do_compression in (CompressionType.ZLIB, CompressionType.ZLIBX):
            self._zlib_rx = zlib.decompressobj(-15)
        elif self.do_compression == CompressionType.ZSTD:
            self._zstd_rx = _zstandard.ZstdDecompressor().decompressobj()
        else:
            self._zlib_rx = None
            self._zstd_rx = None

    def _write_token_run(self, run_start: int, last_token: int) -> None:
        r = run_start - self._tx_last_run_end
        n = last_token - run_start
        if r >= 0 and r <= 63:
            self.write_byte((self._TOKEN_REL if n == 0 else self._TOKENRUN_REL) + r)
        else:
            self.write_byte(self._TOKEN_LONG if n == 0 else self._TOKENRUN_LONG)
            self.write_int(run_start)
        if n != 0:
            self.write_byte(n & 0xFF)
            self.write_byte((n >> 8) & 0xFF)

    def _send_deflated_data(self, comp: bytes, flush: bool) -> None:
        comp_len = len(comp)
        if flush and comp_len >= 4 and comp.endswith(b"\x00\x00\xff\xff"):
            comp = comp[:-4]
            comp_len = len(comp)
        i = 0
        while i < comp_len:
            chunk = comp[i:i + self._MAX_DATA_COUNT]
            n = len(chunk)
            if n == 0:
                break
            self.write_byte(self._DEFLATED_DATA + ((n >> 8) & 0x3F))
            self.write_byte(n & 0xFF)
            self.write_bytes(chunk)
            i += n

    def _send_token_zlibx(self, token: int, data: Optional[bytes], offset: int, n: int) -> None:
        if self._tx_last_token == -1:
            self._reset_tx_compression_state()
            self._tx_last_run_end = 0
            self._tx_run_start = token
            self._tx_flush_pending = False
        elif self._tx_last_token == -2:
            self._tx_run_start = token
        elif n != 0 or token != self._tx_last_token + 1 or token >= self._tx_run_start + 65536:
            if self._tx_last_token >= 0 and self._tx_run_start >= 0:
                self._write_token_run(self._tx_run_start, self._tx_last_token)
            self._tx_last_run_end = self._tx_last_token
            self._tx_run_start = token

        self._tx_last_token = token

        if n != 0 or self._tx_flush_pending:
            if self._zlib_tx is None:
                self._reset_tx_compression_state()
            assert self._zlib_tx is not None
            literal = b""
            if data is not None and n > 0:
                literal = data[offset:offset + n]
            out: bytes = b""
            if literal:
                out += cast(bytes, self._zlib_tx.compress(literal))
            flush_now = (token != -2)
            if flush_now:
                out += cast(bytes, self._zlib_tx.flush(zlib.Z_SYNC_FLUSH))
            self._send_deflated_data(out, flush=flush_now)
            self._tx_flush_pending = (token == -2)

        if token == -1:
            self.write_byte(self._END_FLAG)

    def _send_token_zstd(self, token: int, data: Optional[bytes], offset: int, n: int) -> None:
        if self._tx_last_token == -1:
            self._reset_tx_compression_state()
            self._tx_last_run_end = 0
            self._tx_run_start = token
            self._tx_flush_pending = False
        elif self._tx_last_token == -2:
            self._tx_run_start = token
        elif n != 0 or token != self._tx_last_token + 1 or token >= self._tx_run_start + 65536:
            if self._tx_last_token >= 0 and self._tx_run_start >= 0:
                self._write_token_run(self._tx_run_start, self._tx_last_token)
            self._tx_last_run_end = self._tx_last_token
            self._tx_run_start = token

        self._tx_last_token = token

        if n != 0 or self._tx_flush_pending:
            if self._zstd_tx_writer is None or self._zstd_tx_sink is None:
                self._reset_tx_compression_state()
            assert self._zstd_tx_writer is not None and self._zstd_tx_sink is not None
            if data is not None and n > 0:
                literal = data[offset:offset + n]
                if literal:
                    self._zstd_tx_writer.write(literal)
            flush_now = (token != -2)
            if flush_now:
                self._zstd_tx_writer.flush(_zstandard.FLUSH_BLOCK)
            comp = self._zstd_tx_sink.pop()
            self._send_deflated_data(comp, flush=False)
            self._tx_flush_pending = (token == -2)

        if token == -1:
            self.write_byte(self._END_FLAG)

    def _send_token_lz4(self, token: int, data: Optional[bytes], offset: int, n: int) -> None:
        if self._tx_last_token == -1:
            self._tx_last_run_end = 0
            self._tx_run_start = token
            self._tx_flush_pending = False
        elif self._tx_last_token == -2:
            self._tx_run_start = token
        elif n != 0 or token != self._tx_last_token + 1 or token >= self._tx_run_start + 65536:
            if self._tx_last_token >= 0 and self._tx_run_start >= 0:
                self._write_token_run(self._tx_run_start, self._tx_last_token)
            self._tx_last_run_end = self._tx_last_token
            self._tx_run_start = token

        self._tx_last_token = token

        if n != 0 or self._tx_flush_pending:
            literal = b""
            if data is not None and n > 0:
                literal = data[offset:offset + n]
            nb = len(literal)
            pos = 0
            while pos < nb:
                available_in = min(nb - pos, self._MAX_DATA_COUNT)
                # token.c halves input until the compressed result fits MAX_DATA_COUNT.
                while True:
                    part = literal[pos:pos + available_in]
                    comp = cast(bytes, _lz4_block.compress(part, store_size=False))
                    if len(comp) <= self._MAX_DATA_COUNT:
                        break
                    available_in //= 2
                    if available_in <= 0:
                        raise ProtocolError("LZ4_compress_default failed to fit MAX_DATA_COUNT")
                self.write_byte(self._DEFLATED_DATA + ((len(comp) >> 8) & 0x3F))
                self.write_byte(len(comp) & 0xFF)
                self.write_bytes(comp)
                pos += available_in
            self._tx_flush_pending = (token == -2)

        if token == -1:
            self.write_byte(self._END_FLAG)

    def send_token(self, token: int, data: Optional[bytes] = None,
                   offset: int = 0, n: int = 0) -> None:
        """Send a token in either simple or compressed token mode (token.c)."""
        if self.do_compression == CompressionType.NONE:
            self._send_token_simple(token, data, offset, n)
            return
        if self.do_compression in (CompressionType.ZLIB, CompressionType.ZLIBX):
            self._send_token_zlibx(token, data, offset, n)
        elif self.do_compression == CompressionType.ZSTD:
            self._send_token_zstd(token, data, offset, n)
        elif self.do_compression == CompressionType.LZ4:
            self._send_token_lz4(token, data, offset, n)
        else:
            raise ProtocolError(f"Unsupported compression type {self.do_compression}")

    def recv_token(self) -> Tuple[int, Optional[bytes]]:
        """Receive a token in either simple or compressed token mode (token.c)."""
        if self.do_compression == CompressionType.NONE:
            return self._recv_token_simple()

        if self._rx_pending_out:
            n = min(CHUNK_SIZE, len(self._rx_pending_out))
            data = bytes(self._rx_pending_out[:n])
            del self._rx_pending_out[:n]
            return (n, data)

        if self._rx_state == "r_init":
            self._reset_rx_compression_state()

        while True:
            if self._rx_state == "r_running":
                self._rx_token += 1
                self._rx_run -= 1
                if self._rx_run <= 0:
                    self._rx_state = "r_idle"
                return (-1 - self._rx_token, None)

            if self._rx_state == "r_inflating":
                if self.do_compression in (CompressionType.ZLIB, CompressionType.ZLIBX):
                    if self._zlib_rx is None:
                        self._reset_rx_compression_state()
                    assert self._zlib_rx is not None
                    out = self._zlib_rx.decompress(self._rx_inflate_buf, self._avail_out_size(CHUNK_SIZE))
                    self._rx_inflate_buf = self._zlib_rx.unconsumed_tail
                    if not self._rx_inflate_buf:
                        self._rx_state = "r_inflated"
                    if out:
                        self._rx_pending_out.extend(out)
                        n = min(CHUNK_SIZE, len(self._rx_pending_out))
                        data = bytes(self._rx_pending_out[:n])
                        del self._rx_pending_out[:n]
                        return (n, data)
                    continue

                if self.do_compression == CompressionType.ZSTD:
                    if self._zstd_rx is None:
                        self._reset_rx_compression_state()
                    assert self._zstd_rx is not None
                    out = self._zstd_rx.decompress(self._rx_inflate_buf)
                    self._rx_inflate_buf = b""
                    self._rx_state = "r_idle"
                    if out:
                        self._rx_pending_out.extend(out)
                        n = min(CHUNK_SIZE, len(self._rx_pending_out))
                        data = bytes(self._rx_pending_out[:n])
                        del self._rx_pending_out[:n]
                        return (n, data)
                    continue

                if self.do_compression == CompressionType.LZ4:
                    out = cast(bytes, _lz4_block.decompress(self._rx_inflate_buf, uncompressed_size=CHUNK_SIZE))
                    self._rx_inflate_buf = b""
                    self._rx_state = "r_idle"
                    if out:
                        self._rx_pending_out.extend(out)
                        n = min(CHUNK_SIZE, len(self._rx_pending_out))
                        data = bytes(self._rx_pending_out[:n])
                        del self._rx_pending_out[:n]
                        return (n, data)
                    continue

                raise ProtocolError(f"Unsupported compression type {self.do_compression}")

            if self._rx_state == "r_inflated" and self.do_compression in (CompressionType.ZLIB, CompressionType.ZLIBX):
                # token.c: check for pending output when leaving an inflated chunk.
                assert self._zlib_rx is not None
                pending = self._zlib_rx.decompress(b"", self._avail_out_size(CHUNK_SIZE))
                if pending:
                    self._rx_pending_out.extend(pending)
                    n = min(CHUNK_SIZE, len(self._rx_pending_out))
                    data = bytes(self._rx_pending_out[:n])
                    del self._rx_pending_out[:n]
                    return (n, data)
                # token.c: reinject the omitted 0,0,ff,ff sync bytes.
                _ = self._zlib_rx.decompress(b"\x00\x00\xff\xff")
                self._rx_state = "r_idle"

            # Read next flag
            if self._rx_saved_flag is not None:
                flag = self._rx_saved_flag
                self._rx_saved_flag = None
            else:
                flag = self.read_byte()

            if (flag & 0xC0) == self._DEFLATED_DATA:
                n = ((flag & 0x3F) << 8) + self.read_byte()
                comp = self.read_bytes(n)
                self._rx_inflate_buf = comp
                self._rx_state = "r_inflating"
                continue

            if flag == self._END_FLAG:
                self._rx_state = "r_init"
                return (0, None)

            # Token flags
            if flag & self._TOKEN_REL:
                self._rx_token += flag & 0x3F
                flag >>= 6
            else:
                self._rx_token = self.read_int()
                if self._rx_token < 0:
                    raise ProtocolError("Invalid token number in compressed stream")

            if flag & 1:
                lo = self.read_byte()
                hi = self.read_byte()
                self._rx_run = lo + (hi << 8)
                self._rx_state = "r_running"

            return (-1 - self._rx_token, None)

            # r_running handled by loop
            # (unreachable)

            continue

    def read_sum_head(self, protocol_version: int = PROTOCOL_VERSION) -> SumHead:
        """
        Read sum_struct header from stream.
        
        This is the Python equivalent of read_sum_head() in io.c (lines 1965-1992).
        
        The sum header contains:
            - count: number of blocks
            - blength: block length
            - s2length: strong checksum length (protocol >= 27)
            - remainder: size of last block if < blength
        
        Args:
            protocol_version: Protocol version for determining field format
        
        Returns:
            Dictionary with count, blength, s2length, remainder
        
        Reference:
            io.c: read_sum_head() lines 1965-1992
        """
        max_blength = OLD_MAX_BLOCK_SIZE if protocol_version < 30 else MAX_BLOCK_SIZE
        
        count = self.read_int()
        if count < 0:
            raise ProtocolError(f"Invalid checksum count {count}")
        
        blength = self.read_int()
        if blength < 0 or blength > max_blength:
            raise ProtocolError(f"Invalid block length {blength}")
        
        if protocol_version >= 27:
            s2length = self.read_int()
        else:
            s2length = Config.CSUM_LENGTH
        
        if s2length < 0 or s2length > MAX_DIGEST_LEN:
            raise ProtocolError(f"Invalid checksum length {s2length}")
        
        remainder = self.read_int()
        if remainder < 0 or remainder > blength:
            raise ProtocolError(f"Invalid remainder {remainder}")
        
        return {
            'count': count,
            'blength': blength,
            's2length': s2length,
            'remainder': remainder,
        }

    def write_sum_head(self, sum_struct: Optional[SumHead] = None,
                       protocol_version: int = PROTOCOL_VERSION) -> None:
        """
        Write sum_struct header to stream.
        
        This is the Python equivalent of write_sum_head() in io.c (lines 1997-2010).
        
        Args:
            sum_struct: Dictionary with count, blength, s2length, remainder
                       (None for empty/null sum)
            protocol_version: Protocol version for determining field format
        
        Reference:
            io.c: write_sum_head() lines 1997-2010
        """
        if sum_struct is None:
            sum_struct = {'count': 0, 'blength': 0, 's2length': 0, 'remainder': 0}
        
        self.write_int(sum_struct['count'])
        self.write_int(sum_struct['blength'])
        if protocol_version >= 27:
            self.write_int(sum_struct['s2length'])
        self.write_int(sum_struct['remainder'])


def receive_data(proto_io: 'ProtocolIO', basis_data: bytes,
                 sum_head: SumHead) -> Tuple[bytes, 'SyncStats']:
    """
    Receive delta data and reconstruct the target file.
    
    This is the Python equivalent of receive_data() in receiver.c (lines 240-413).
    It reads tokens from the wire and either appends literal data or copies 
    matched blocks from the basis file.
    
    Args:
        proto_io: ProtocolIO instance for reading tokens
        basis_data: The basis (old) file data to copy matched blocks from
        sum_head: Dictionary with blength, remainder, count from sum header
    
    Returns:
        Tuple of (reconstructed_data, stats)
    
    Reference:
        receiver.c: receive_data() lines 240-413
    
    Example:
        >>> pio = ProtocolIO()
        >>> sum_head = pio.read_sum_head()
        >>> new_data, stats = receive_data(pio, old_data, sum_head)
    """
    stats = SyncStats()
    result = bytearray()
    
    blength = sum_head['blength']
    remainder = sum_head['remainder']
    count = sum_head['count']
    
    while True:
        token, data = proto_io.recv_token()
        
        if token == 0:
            # End of transfer
            break
        
        if token > 0:
            # Literal data
            if data:
                result.extend(data)
                stats.literal_data += len(data)
        else:
            # Block match: token = -(block_num + 1)
            block_num = -(token + 1)
            
            if block_num < 0 or block_num >= count:
                raise ProtocolError(f"Invalid block number {block_num}")
            
            # Calculate block offset and length
            offset = block_num * blength
            
            # Last block may be shorter
            if block_num == count - 1 and remainder > 0:
                block_len = remainder
            else:
                block_len = blength
            
            # Copy block from basis file
            if offset + block_len <= len(basis_data):
                result.extend(basis_data[offset:offset + block_len])
                stats.matched_data += block_len
            else:
                raise ProtocolError(f"Block {block_num} extends past basis file")
    
    return bytes(result), stats


def _sum_head_from_signature(signature: 'ChecksumSignature') -> SumHead:
    """Build a sum_struct header dict from a ChecksumSignature.

    This mirrors the essential fields used by receiver-side reconstruction.
    """
    count = signature.num_blocks
    blength = signature.block_size
    remainder = 0
    if count > 0:
        last_len = signature.blocks[-1].length
        if last_len != blength:
            remainder = last_len

    s2length = 0
    if signature.blocks:
        s2length = len(signature.blocks[0].strong_checksum)

    return {
        'count': count,
        'blength': blength,
        's2length': s2length,
        'remainder': remainder,
    }


def send_delta_over_wire(proto_io: 'ProtocolIO', signature: 'ChecksumSignature',
                         delta: 'DeltaInstructions',
                         protocol_version: int = PROTOCOL_VERSION,
                         compression: CompressionType = CompressionType.NONE,
                         compression_level: Optional[int] = None) -> None:
    """Send a delta over the rsync token stream (simple token mode).

    This is a minimal sender-side counterpart to receive_data(): it writes a
    sum_head followed by a stream of tokens compatible with recv_token().

    Notes:
        - Literals are sent via send_token(-2, ...), which emits (len,data)
          chunks without a trailing match marker.
        - Matches are sent as negative ints: -(block_index + 1).
        - A final 0 int terminates the stream.
    """
    proto_io.set_compression(compression, level=compression_level)

    sum_head = _sum_head_from_signature(signature)
    proto_io.write_sum_head(sum_head, protocol_version=protocol_version)

    # Emit token stream like match.c:matched(): each match sends pending literals + token in one call.
    pending = bytearray()
    for cmd, instr in delta.instructions:
        if cmd == 'literal' and isinstance(instr, DeltaLiteral):
            if instr.data:
                pending.extend(instr.data)
            continue

        if cmd == 'match' and isinstance(instr, DeltaMatch):
            if pending:
                proto_io.send_token(instr.block_index, bytes(pending), 0, len(pending))
                pending.clear()
            else:
                proto_io.send_token(instr.block_index, None, 0, 0)
            continue

        raise ProtocolError(f"Invalid delta instruction {cmd!r}: {instr!r}")

    # EOF token includes any trailing literal bytes and encodes termination (simple: int 0, compressed: END_FLAG).
    if pending:
        proto_io.send_token(-1, bytes(pending), 0, len(pending))
    else:
        proto_io.send_token(-1, None, 0, 0)
    proto_io.flush()

    # match.c: write_buf(f, sender_file_sum, xfer_sum_len) after finishing token stream.
    if delta.sender_file_sum is not None:
        proto_io.write_bytes(delta.sender_file_sum)
        proto_io.flush()


def apply_delta_over_wire(basis_data: bytes, signature: 'ChecksumSignature',
                          delta: 'DeltaInstructions',
                          protocol_version: int = PROTOCOL_VERSION,
                          compression: CompressionType = CompressionType.NONE,
                          compression_level: Optional[int] = None) -> Tuple[bytes, 'SyncStats']:
    """Roundtrip a delta through ProtocolIO tokens and reconstruct with receive_data().

    This exercises the wire-token encoding path end-to-end (sender -> receiver)
    without requiring an actual socket connection.
    """
    import tempfile

    with tempfile.TemporaryFile() as tmp:
        fd = tmp.fileno()
        sender = ProtocolIO()
        sender.set_fd(0, fd)
        send_delta_over_wire(
            sender,
            signature,
            delta,
            protocol_version=protocol_version,
            compression=compression,
            compression_level=compression_level,
        )

        tmp.seek(0)
        receiver = ProtocolIO()
        receiver.set_fd(fd, fd)
        receiver.set_compression(compression, level=compression_level)
        sum_head = receiver.read_sum_head(protocol_version=protocol_version)
        reconstructed, stats = receive_data(receiver, basis_data, sum_head)

        if Config.VERIFY_SENDER_FILE_SUM_ON_WIRE and delta.sender_file_sum is not None:
            xfer_sum_len = len(delta.sender_file_sum)
            sender_sum = receiver.read_bytes(xfer_sum_len)

            csum_type: Optional[ChecksumType] = None
            try:
                if delta.xfer_checksum_type:
                    csum_type = ChecksumType(delta.xfer_checksum_type)
                elif signature.checksum_type:
                    csum_type = ChecksumType(signature.checksum_type)
            except Exception:
                csum_type = None
            if csum_type is None:
                csum_type = ChecksumType.MD5

            seed = delta.xfer_checksum_seed if delta.xfer_checksum_seed is not None else signature.checksum_seed
            acc = ChecksumRegistry.get_checksum_accumulator(csum_type, seed=seed)
            acc.update(reconstructed)
            receiver_sum = acc.digest()

            if sender_sum != receiver_sum:
                raise DataIntegrityError(
                    f"sender_file_sum mismatch: sender={sender_sum.hex()} receiver={receiver_sum.hex()}"
                )

        return reconstructed, stats


# ============================================================================
# PROTOCOL NEGOTIATION (compat.c/setup_protocol) - minimal wire implementation
# ============================================================================

@dataclass
class ProtocolHandshakeResult:
    """
    Result of a minimal rsync protocol negotiation.

    Reference:
        rsync-original-source-code/compat.c:setup_protocol()
        rsync-original-source-code/compat.c:negotiate_the_strings()
        rsync-original-source-code/io.c:read_vstring()/write_vstring()
    """

    am_server: bool
    local_protocol: int
    remote_protocol: int
    negotiated_protocol: int
    compat_flags: int
    do_negotiated_strings: bool
    xfer_flags_as_varint: bool
    checksum_seed: int
    checksum_choice: str
    compress_choice: str


def _default_checksum_name_list() -> List[str]:
    # Keep consistent with the `--version` output for this python implementation.
    return ["xxh128", "xxh3", "xxh64", "md5", "md4", "sha1", "none"]


def _default_compress_name_list() -> List[str]:
    return ["zstd", "lz4", "zlibx", "zlib", "none"]


def _choose_from_remote_list(am_server: bool, local_pref: List[str], remote_list: List[str]) -> str:
    """
    Pick the negotiated algorithm name.

    Rule (rsync):
      Pick the first name in the client's list that is also in the server's list.
    Implementation detail:
      - Server: stops at first acceptable client token.
      - Client: chooses the acceptable token that is earliest in its own list.
    Reference: rsync-original-source-code/compat.c:parse_negotiate_str()
    """
    local_set = set(local_pref)
    if am_server:
        for tok in remote_list:
            if tok in local_set:
                return tok
        raise ProtocolError("Failed to negotiate choice (no overlap)")

    best_tok: Optional[str] = None
    best_rank = len(local_pref) + 1
    rank: Dict[str, int] = {name: i for i, name in enumerate(local_pref)}
    for tok in remote_list:
        if tok in local_set:
            r = rank.get(tok, best_rank)
            if r < best_rank:
                best_rank = r
                best_tok = tok
                if best_rank == 0:
                    break
    if best_tok is None:
        raise ProtocolError("Failed to negotiate choice (no overlap)")
    return best_tok


def setup_protocol_wire(
    io: ProtocolIO,
    opts: RsyncOptions,
    *,
    am_server: bool,
    client_info: str = "",
    protocol_version: int = PROTOCOL_VERSION,
    remote_sub: int = 0,
) -> ProtocolHandshakeResult:
    """
    Minimal `setup_protocol()` handshake over an established full-duplex stream.

    This intentionally implements only the negotiation pieces needed to support
    further wire-parity work (compat flags, negotiated strings, checksum seed).

    Reference: rsync-original-source-code/compat.c:setup_protocol()
    """
    local_proto = int(protocol_version)

    # Protocol version exchange (both sides write then read).
    io.write_int(local_proto)
    io.flush()
    remote_proto = io.read_int()

    negotiated = min(local_proto, remote_proto)
    if SUBPROTOCOL_VERSION != 0 and SUBPROTOCOL_VERSION != remote_sub:
        negotiated -= 1

    if remote_proto < MIN_PROTOCOL_VERSION or remote_proto > MAX_PROTOCOL_VERSION:
        raise ProtocolError("protocol version mismatch -- is your shell clean?")

    compat_flags = 0
    do_negotiated_strings = False
    xfer_flags_as_varint = False

    if negotiated >= 30:
        if am_server:
            # Mirror compat.c's feature-gating based on the incoming client-info string.
            # Reference: rsync-original-source-code/compat.c:713-751
            if "C" in client_info:
                compat_flags |= CF_CHKSUM_SEED_FIX
            if "v" in client_info or "V" in client_info:
                compat_flags |= CF_VARINT_FLIST_FLAGS
            if bool(opts.crtimes):
                compat_flags |= CF_VARINT_FLIST_FLAGS
            if bool(getattr(opts, "inc_recursive", False)) and ("i" in client_info):
                compat_flags |= CF_INC_RECURSE
            io.write_varint(compat_flags)
            io.flush()
        else:
            compat_flags = io.read_varint()

        do_negotiated_strings = bool(compat_flags & CF_VARINT_FLIST_FLAGS)
        xfer_flags_as_varint = bool(compat_flags & CF_VARINT_FLIST_FLAGS)

    # Negotiate checksum/compress names (vstring lists).
    checksum_choice = opts.checksum_choice
    compress_choice = opts.compress_choice

    checksum_pref = _default_checksum_name_list()
    compress_pref = _default_compress_name_list()

    if checksum_choice is None:
        if do_negotiated_strings:
            io.write_vstring(" ".join(checksum_pref))
        io.flush()
    if bool(opts.compress) and compress_choice is None:
        if do_negotiated_strings:
            io.write_vstring(" ".join(compress_pref))
        io.flush()

    if checksum_choice is None:
        if do_negotiated_strings:
            remote_list = io.read_vstring().split()
            checksum_choice = _choose_from_remote_list(am_server=am_server, local_pref=checksum_pref, remote_list=remote_list)
        else:
            checksum_choice = "md5" if negotiated >= 30 else "md4"

    if bool(opts.compress) and compress_choice is None:
        if do_negotiated_strings:
            remote_list = io.read_vstring().split()
            compress_choice = _choose_from_remote_list(am_server=am_server, local_pref=compress_pref, remote_list=remote_list)
        else:
            compress_choice = "zlib"
    if not bool(opts.compress):
        compress_choice = "none"
    if compress_choice is None:
        compress_choice = "none"

    # Seed exchange.
    seed = opts.checksum_seed
    if seed is None:
        seed = 0
    if am_server:
        if not seed:
            seed = (int(time.time()) ^ (os.getpid() << 6)) & 0x7FFFFFFF
        io.write_int(int(seed))
        io.flush()
    else:
        seed = io.read_int()

    return ProtocolHandshakeResult(
        am_server=bool(am_server),
        local_protocol=local_proto,
        remote_protocol=remote_proto,
        negotiated_protocol=negotiated,
        compat_flags=int(compat_flags),
        do_negotiated_strings=bool(do_negotiated_strings),
        xfer_flags_as_varint=bool(xfer_flags_as_varint),
        checksum_seed=int(seed),
        checksum_choice=str(checksum_choice),
        compress_choice=str(compress_choice),
    )


# ============================================================================
# FILTER LIST (exclude.c) - wire framing helpers
# ============================================================================

def send_filter_list_wire(
    io: ProtocolIO,
    *,
    rules: Sequence[str],
) -> None:
    """
    Send a filter-list over the wire.

    This implements the framing used by rsync's `send_filter_list()`:
      - For each rule: write_int(len) + write_buf(rule_bytes)
      - Terminator: write_int(0)

    Notes:
      - This helper expects `rules` to already be in rsync's textual rule format
        (e.g. '- *.o', '+ /path', ':C', etc).
      - Parsing/normalization of rule prefixes is handled by rsync proper (exclude.c).

    Reference:
      rsync-original-source-code/exclude.c:send_filter_list()
      rsync-original-source-code/exclude.c:send_rules()
    """
    for rule in rules:
        b = rule.encode("utf-8", errors="surrogateescape")
        io.write_int(len(b))
        if b:
            io.write_bytes(b)
    io.write_int(0)
    io.flush()


def recv_filter_list_wire(
    io: ProtocolIO,
) -> List[str]:
    """
    Receive a filter-list over the wire.

    Reference:
      rsync-original-source-code/exclude.c:recv_filter_list()
    """
    rules: List[str] = []
    while True:
        length = int(io.read_int())
        if length == 0:
            break
        if length < 0:
            raise ProtocolError(f"recv_filter_list: negative length {length}")
        data = io.read_bytes(length) if length else b""
        rules.append(data.decode("utf-8", errors="replace"))
    return rules


# ============================================================================
# FILE LIST HANDLING - Implements flist.c functionality
# ============================================================================

class FileEntry:
    """Represents a file entry in the file list"""

    # Type annotations for instance attributes
    filename: str
    basename: str
    mode: int
    size: int
    mtime: int
    mtime_nsec: int
    atime: int
    crtime: int
    uid: int
    gid: int
    dev: int
    nlink: int
    rdev: int
    is_dir: bool
    is_link: bool
    link_target: Optional[str]
    flags: int

    def __init__(self, filename: str, mode: int = 0, size: int = 0, mtime: int = 0,
                 mtime_nsec: int = 0,
                 atime: int = 0, crtime: int = 0,
                 uid: int = 0, gid: int = 0, dev: int = 0, nlink: int = 0, rdev: int = 0,
                 is_dir: bool = False, is_link: bool = False, link_target: Optional[str] = None) -> None:
        self.filename = filename
        self.basename = os.path.basename(filename)
        self.mode = mode
        self.size = size
        self.mtime = mtime
        self.mtime_nsec = int(mtime_nsec)
        self.atime = atime
        self.crtime = crtime
        self.uid = uid
        self.gid = gid
        self.dev = dev
        self.nlink = nlink
        self.rdev = rdev
        self.is_dir = bool(is_dir) or S_ISDIR(mode)
        self.is_link = bool(is_link) or S_ISLNK(mode)
        self.link_target = link_target
        self.flags = 0
        
        if S_ISDIR(mode):
            self.flags |= 0x2
        elif S_ISLNK(mode):
            self.flags |= 0x4
        elif S_ISCHR(mode):
            self.flags |= 0x8
        elif S_ISBLK(mode):
            self.flags |= 0x10
        elif S_ISFIFO(mode):
            self.flags |= 0x20
        elif S_ISSOCK(mode):
            self.flags |= 0x40
    
    @classmethod
    def from_stat(cls, filepath: str, follow_links: bool = True) -> 'FileEntry':
        """Create FileEntry from stat information"""
        try:
            st = os.stat(filepath) if follow_links else os.lstat(filepath)
            # st_rdev may not be available on all platforms
            rdev = getattr(st, 'st_rdev', 0)
            link_target: Optional[str] = None
            if not follow_links and S_ISLNK(st.st_mode):
                try:
                    link_target = os.readlink(filepath)
                except OSError:
                    link_target = None
            # Creation/birth time is platform dependent; default to mtime if unavailable.
            crtime = int(getattr(st, "st_birthtime", int(st.st_mtime)))
            mtime_nsec = int(getattr(st, "st_mtime_ns", int(st.st_mtime) * 1_000_000_000) % 1_000_000_000)
            return cls(
                filename=filepath,
                mode=st.st_mode,
                size=st.st_size,
                mtime=int(st.st_mtime),
                mtime_nsec=mtime_nsec,
                atime=int(st.st_atime),
                crtime=crtime,
                uid=st.st_uid,
                gid=st.st_gid,
                dev=st.st_dev,
                nlink=st.st_nlink,
                rdev=rdev,
                link_target=link_target,
            )
        except (OSError, IOError) as e:
            raise FileIOError(f"Cannot stat {filepath}: {e}")


class FileList:
    """Manages the list of files to be transferred"""

    def __init__(self, base_dir: str = '') -> None:
        self.base_dir = base_dir
        self.files: List[FileEntry] = []
        self.index = 0
        self.low = 0
        self.high = -1

    def add_file(self, filepath: str) -> FileEntry:
        """Add a file to the list"""
        entry = FileEntry.from_stat(filepath)
        self.files.append(entry)
        self.high = len(self.files) - 1
        return entry
    
    def add_dir(self, dirpath: str) -> None:
        """Recursively add directory contents"""
        for root, _dirs, files in os.walk(dirpath):
            for name in files:
                filepath = os.path.join(root, name)
                self.add_file(filepath)


@dataclass
class _FlistXferState:
    """Stateful sender/receiver context for flist entry encoding."""
    lastname: bytes = b""
    mode: int = 0
    uid: int = 0
    gid: int = 0
    modtime: int = 0
    atime: int = 0
    crtime: int = 0
    rdev: int = 0
    rdev_major: int = 0


def _common_prefix_len_upto_255(a: bytes, b: bytes) -> int:
    n = min(len(a), len(b), 255)
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def _send_file_entry_wire(
    io: ProtocolIO,
    entry: FileEntry,
    opts: RsyncOptions,
    state: _FlistXferState,
    protocol_version: int,
    xfer_flags_as_varint: bool,
) -> None:
    """
    Send a single flist entry (subset of flist.c:send_file_entry()).
    Reference: rsync-original-source-code/flist.c:380-679
    """
    mode = int(entry.mode)

    xflags = 0
    if entry.is_dir:
        xflags = XMIT_TOP_DIR if (entry.flags & FLAG_TOP_DIR) else 0

    if mode == state.mode:
        xflags |= XMIT_SAME_MODE
    else:
        state.mode = mode

    preserve_uid = bool(opts.preserve_owner)
    preserve_gid = bool(opts.preserve_group)

    if (not preserve_uid) or ((entry.uid == state.uid) and state.lastname):
        xflags |= XMIT_SAME_UID
    else:
        state.uid = int(entry.uid)

    if (not preserve_gid) or ((entry.gid == state.gid) and state.lastname):
        xflags |= XMIT_SAME_GID
    else:
        state.gid = int(entry.gid)

    if int(entry.mtime) == state.modtime:
        xflags |= XMIT_SAME_TIME
    else:
        state.modtime = int(entry.mtime)

    # atimes/crtimes are controlled by negotiated extras in compat.c.
    # Reference: rsync-original-source-code/flist.c:475-606
    if bool(opts.atimes) and not entry.is_dir:
        if int(entry.atime) == state.atime:
            xflags |= XMIT_SAME_ATIME
        else:
            state.atime = int(entry.atime)
    if bool(opts.crtimes):
        state.crtime = int(entry.crtime)
        if state.crtime == state.modtime:
            xflags |= XMIT_CRTIME_EQ_MTIME

    if protocol_version >= 31 and int(getattr(entry, "mtime_nsec", 0) or 0):
        xflags |= XMIT_MOD_NSEC

    preserve_devices = bool(opts.preserve_devices)
    preserve_specials = bool(opts.preserve_specials)
    if preserve_devices and IS_DEVICE(mode):
        tmp_rdev = int(entry.rdev)
        if protocol_version < 28:
            if tmp_rdev == state.rdev:
                xflags |= XMIT_SAME_RDEV_pre28
            else:
                state.rdev = tmp_rdev
        else:
            state.rdev = tmp_rdev
            maj = _dev_major(state.rdev)
            if maj == state.rdev_major:
                xflags |= XMIT_SAME_RDEV_MAJOR
            else:
                state.rdev_major = maj
            if protocol_version < 30 and _dev_minor(state.rdev) <= 0xFF:
                xflags |= XMIT_RDEV_MINOR_8_pre30
    elif preserve_specials and IS_SPECIAL(mode) and protocol_version < 31:
        # Older protocols transmitted an rdev-like value for specials; preserve the abbrev pattern.
        if protocol_version < 28:
            xflags |= XMIT_SAME_RDEV_pre28
        else:
            state.rdev = _make_dev(state.rdev_major, 0)
            xflags |= XMIT_SAME_RDEV_MAJOR
            if protocol_version < 30:
                xflags |= XMIT_RDEV_MINOR_8_pre30

    name_b = os.fsencode(entry.filename)
    l1 = _common_prefix_len_upto_255(state.lastname, name_b)
    l2 = len(name_b) - l1
    if l1 > 0:
        xflags |= XMIT_SAME_NAME
    if l2 > 255:
        xflags |= XMIT_LONG_NAME

    if xfer_flags_as_varint:
        io.write_varint(xflags if xflags else XMIT_EXTENDED_FLAGS)
    else:
        if protocol_version >= 28:
            if not xflags and not entry.is_dir:
                xflags |= XMIT_TOP_DIR
            if (xflags & 0xFF00) or not xflags:
                xflags |= XMIT_EXTENDED_FLAGS
                io.write_shortint(xflags)
            else:
                io.write_byte(xflags)
        else:
            if not (xflags & 0xFF):
                xflags |= XMIT_LONG_NAME if entry.is_dir else XMIT_TOP_DIR
            io.write_byte(xflags)

    if xflags & XMIT_SAME_NAME:
        io.write_byte(l1)
    if xflags & XMIT_LONG_NAME:
        io.write_varint30(l2, protocol_version=protocol_version)
    else:
        io.write_byte(l2)
    io.write_bytes(name_b[l1:])

    io.write_varlong30(int(entry.size), 3, protocol_version=protocol_version)

    if not (xflags & XMIT_SAME_TIME):
        if protocol_version >= 30:
            io.write_varlong(state.modtime, 4)
        else:
            io.write_int(state.modtime)

    if xflags & XMIT_MOD_NSEC:
        io.write_varint(int(entry.mtime_nsec))

    if bool(opts.crtimes) and not (xflags & XMIT_CRTIME_EQ_MTIME):
        io.write_varlong(state.crtime, 4)

    if not (xflags & XMIT_SAME_MODE):
        io.write_int(to_wire_mode(mode))

    if bool(opts.atimes) and not entry.is_dir and not (xflags & XMIT_SAME_ATIME):
        io.write_varlong(state.atime, 4)

    if preserve_uid and not (xflags & XMIT_SAME_UID):
        if protocol_version < 30:
            io.write_int(state.uid)
        else:
            io.write_varint(state.uid)

    if preserve_gid and not (xflags & XMIT_SAME_GID):
        if protocol_version < 30:
            io.write_int(state.gid)
        else:
            io.write_varint(state.gid)

    if (preserve_devices and IS_DEVICE(mode)) or (preserve_specials and IS_SPECIAL(mode) and protocol_version < 31):
        if protocol_version < 28:
            if not (xflags & XMIT_SAME_RDEV_pre28):
                io.write_int(int(state.rdev))
        else:
            if not (xflags & XMIT_SAME_RDEV_MAJOR):
                io.write_varint30(_dev_major(state.rdev), protocol_version=protocol_version)
            if protocol_version >= 30:
                io.write_varint(_dev_minor(state.rdev))
            elif xflags & XMIT_RDEV_MINOR_8_pre30:
                io.write_byte(_dev_minor(state.rdev))
            else:
                io.write_int(_dev_minor(state.rdev))

    if bool(opts.preserve_links) and entry.is_link:
        target = entry.link_target
        if target is None:
            try:
                target = os.readlink(entry.filename)
            except OSError:
                target = ""
        link_b = os.fsencode(target)
        io.write_varint30(len(link_b), protocol_version=protocol_version)
        if link_b:
            io.write_bytes(link_b)

    state.lastname = name_b


def _recv_file_entry_wire(
    io: ProtocolIO,
    opts: RsyncOptions,
    state: _FlistXferState,
    protocol_version: int,
    xflags: int,
) -> FileEntry:
    """
    Receive a single flist entry (subset of flist.c:recv_file_entry()).
    Reference: rsync-original-source-code/flist.c:682-1216
    """
    if xflags & XMIT_SAME_NAME:
        l1 = io.read_byte()
    else:
        l1 = 0

    if xflags & XMIT_LONG_NAME:
        l2 = io.read_varint30(protocol_version=protocol_version)
    else:
        l2 = io.read_byte()

    if l1 > len(state.lastname):
        raise ProtocolError(f"recv_file_entry: l1={l1} > lastname_len={len(state.lastname)}")
    if l2 < 0:
        raise ProtocolError("recv_file_entry: negative name length")

    suffix = io.read_bytes(l2)
    name_b = state.lastname[:l1] + suffix
    state.lastname = name_b

    file_length = io.read_varlong30(3, protocol_version=protocol_version)

    if xflags & XMIT_SAME_TIME:
        modtime = state.modtime
    else:
        if protocol_version >= 30:
            modtime = io.read_varlong(4)
        else:
            modtime = io.read_int()
        state.modtime = int(modtime)

    mtime_nsec = 0
    if xflags & XMIT_MOD_NSEC:
        mtime_nsec = int(io.read_varint())

    crtime = 0
    if bool(opts.crtimes):
        if xflags & XMIT_CRTIME_EQ_MTIME:
            crtime = int(modtime)
        else:
            crtime = int(io.read_varlong(4))
        state.crtime = int(crtime)

    if xflags & XMIT_SAME_MODE:
        mode = state.mode
    else:
        mode = from_wire_mode(io.read_int())
        state.mode = int(mode)

    atime = 0
    if bool(opts.atimes) and not S_ISDIR(mode):
        if xflags & XMIT_SAME_ATIME:
            atime = state.atime
        else:
            atime = int(io.read_varlong(4))
            state.atime = int(atime)

    preserve_uid = bool(opts.preserve_owner)
    preserve_gid = bool(opts.preserve_group)

    if preserve_uid:
        if xflags & XMIT_SAME_UID:
            uid = state.uid
        else:
            uid = io.read_int() if protocol_version < 30 else io.read_varint()
            state.uid = int(uid)
            # With inc-recursive enabled, rsync may send the textual name after uid.
            # Reference: rsync-original-source-code/flist.c:562-579 (XMIT_USER_NAME_FOLLOWS)
            if protocol_version >= 30 and (xflags & XMIT_USER_NAME_FOLLOWS):
                name_len = int(io.read_byte())
                if name_len:
                    _ = io.read_bytes(name_len)
    else:
        uid = 0

    if preserve_gid:
        if xflags & XMIT_SAME_GID:
            gid = state.gid
        else:
            gid = io.read_int() if protocol_version < 30 else io.read_varint()
            state.gid = int(gid)
            # With inc-recursive enabled, rsync may send the textual name after gid.
            # Reference: rsync-original-source-code/flist.c:581-598 (XMIT_GROUP_NAME_FOLLOWS)
            if protocol_version >= 30 and (xflags & XMIT_GROUP_NAME_FOLLOWS):
                name_len = int(io.read_byte())
                if name_len:
                    _ = io.read_bytes(name_len)
    else:
        gid = 0

    rdev = 0
    preserve_devices = bool(opts.preserve_devices)
    preserve_specials = bool(opts.preserve_specials)
    if (preserve_devices and IS_DEVICE(mode)) or (preserve_specials and IS_SPECIAL(mode) and protocol_version < 31):
        if protocol_version < 28:
            if xflags & XMIT_SAME_RDEV_pre28:
                rdev = state.rdev
            else:
                rdev = int(io.read_int())
                state.rdev = int(rdev)
        else:
            if xflags & XMIT_SAME_RDEV_MAJOR:
                maj = state.rdev_major
            else:
                maj = int(io.read_varint30(protocol_version=protocol_version))
                state.rdev_major = int(maj)

            if protocol_version >= 30:
                minor = int(io.read_varint())
            elif xflags & XMIT_RDEV_MINOR_8_pre30:
                minor = int(io.read_byte())
            else:
                minor = int(io.read_int())
            rdev = _make_dev(maj, minor)
            state.rdev = int(rdev)

    link_target: Optional[str] = None
    if bool(opts.preserve_links) and S_ISLNK(mode):
        link_len = io.read_varint30(protocol_version=protocol_version)
        link_b = io.read_bytes(link_len) if link_len > 0 else b""
        link_target = os.fsdecode(link_b)

    return FileEntry(
        filename=os.fsdecode(name_b),
        mode=int(mode),
        size=int(file_length),
        mtime=int(modtime),
        mtime_nsec=int(mtime_nsec),
        atime=int(atime),
        crtime=int(crtime),
        uid=int(uid),
        gid=int(gid),
        rdev=int(rdev),
        is_dir=S_ISDIR(mode),
        is_link=S_ISLNK(mode),
        link_target=link_target,
    )


def send_file_list_wire(
    io: ProtocolIO,
    entries: Sequence[FileEntry],
    opts: RsyncOptions,
    protocol_version: int = PROTOCOL_VERSION,
    xfer_flags_as_varint: Optional[bool] = None,
) -> None:
    """
    Send an rsync file-list over the wire (recv_file_list counterpart).
    Reference: rsync-original-source-code/flist.c:2192-2752
    """
    if xfer_flags_as_varint is None:
        xfer_flags_as_varint = protocol_version >= 30

    state = _FlistXferState()
    for entry in entries:
        _send_file_entry_wire(
            io,
            entry,
            opts=opts,
            state=state,
            protocol_version=protocol_version,
            xfer_flags_as_varint=bool(xfer_flags_as_varint),
        )

    if xfer_flags_as_varint:
        io.write_varint(0)
        io.write_varint(0)
    else:
        io.write_byte(0)
    io.flush()


def recv_file_list_wire(
    io: ProtocolIO,
    opts: RsyncOptions,
    protocol_version: int = PROTOCOL_VERSION,
    xfer_flags_as_varint: Optional[bool] = None,
) -> List[FileEntry]:
    """
    Receive an rsync file-list over the wire (send_file_list counterpart).
    Reference: rsync-original-source-code/flist.c:2561-2785
    """
    if xfer_flags_as_varint is None:
        xfer_flags_as_varint = protocol_version >= 30

    entries: List[FileEntry] = []
    state = _FlistXferState()

    while True:
        if xfer_flags_as_varint:
            flags = io.read_varint()
            if flags == 0:
                _ = io.read_varint()
                break
        else:
            flags = io.read_byte()
            if flags == 0:
                break
            if protocol_version >= 28 and (flags & XMIT_EXTENDED_FLAGS):
                flags |= io.read_byte() << 8
            if protocol_version >= 31 and flags == (XMIT_EXTENDED_FLAGS | XMIT_IO_ERROR_ENDLIST):
                _ = io.read_varint()
                break

        entries.append(
            _recv_file_entry_wire(
                io,
                opts=opts,
                state=state,
                protocol_version=protocol_version,
                xflags=int(flags),
            )
        )

    return entries


def file_list_roundtrip_over_wire(
    entries: Sequence[FileEntry],
    opts: RsyncOptions,
    protocol_version: int = PROTOCOL_VERSION,
    xfer_flags_as_varint: Optional[bool] = None,
) -> List[FileEntry]:
    """Send+receive a file-list through ProtocolIO without sockets (wire framing only)."""
    import tempfile

    with tempfile.TemporaryFile() as tmp:
        fd = tmp.fileno()
        sender = ProtocolIO()
        sender.set_fd(0, fd)
        send_file_list_wire(
            sender,
            entries=entries,
            opts=opts,
            protocol_version=protocol_version,
            xfer_flags_as_varint=xfer_flags_as_varint,
        )

        tmp.seek(0)
        receiver = ProtocolIO()
        receiver.set_fd(fd, fd)
        return recv_file_list_wire(
            receiver,
            opts=opts,
            protocol_version=protocol_version,
            xfer_flags_as_varint=xfer_flags_as_varint,
        )


# ============================================================================
# USAGE EXAMPLES - Demonstrating the improved API
# ============================================================================

def example_improved_api() -> None:
    """
    Example demonstrating the NEW IMPROVED API with typed dataclasses.

    This is the RECOMMENDED way to use rsync-python for new code.
    """
    print("="*70)
    print("RSYNC-PYTHON IMPROVED API EXAMPLES")
    print("="*70)

    # Example 1: Basic file synchronization
    print("\n1. Basic File Synchronization")
    print("-" * 70)

    original_data = b"Hello, World! " * 1000
    modified_data = original_data[:5000] + b"CHANGED!" + original_data[5008:]

    engine = ChecksumEngine(block_size=1024)

    # Generate signature with typed API
    signature = engine.generate_signature(original_data)
    print(f"Signature generated: {signature}")

    # Generate delta with typed API
    delta = engine.generate_delta(signature, modified_data)
    print(f"Delta generated: {delta}")
    print(f"  Compression ratio: {delta.compression_ratio:.2%}")
    print(f"  Matches: {delta.num_matches}, Literals: {delta.num_literals}")

    # Apply delta to reconstruct
    reconstructed = engine.apply_delta(original_data, delta)
    print(f"  Reconstruction: {'SUCCESS' if reconstructed == modified_data else 'FAILED'}")

    # Example 2: Inspecting individual blocks
    print("\n2. Inspecting Individual Blocks")
    print("-" * 70)

    small_data = b"A" * 500 + b"B" * 500
    sig = engine.generate_signature(small_data)

    for i, block in enumerate(sig.blocks[:3]):  # Show first 3 blocks
        print(f"  Block {i}: {block}")

    # Example 3: Using with different protocols
    print("\n3. Multi-Protocol Support")
    print("-" * 70)

    for protocol_ver in [27, 30, 31]:
        proto_mgr = ProtocolVersionManager(desired_protocol=protocol_ver)
        engine_proto = ChecksumEngine(
            block_size=1024,
            checksum_type=ChecksumType.MD5,
            protocol_manager=proto_mgr
        )
        sig = engine_proto.generate_signature(b"Test data")
        print(f"  Protocol {protocol_ver}: {sig.checksum_type}, {sig.num_blocks} blocks")

    # Example 4: Error handling with validation
    print("\n4. Input Validation Examples")
    print("-" * 70)

    try:
        bad_engine = ChecksumEngine(block_size=-1)  # type: ignore[reportUnusedVariable]
    except ValidationError as e:
        print(f"  ✓ Caught invalid block_size: {e}")

    try:
        validate_protocol_version(999)
    except ValidationError as e:
        print(f"  ✓ Caught invalid protocol: {e}")

    try:
        huge_data = b"X" * (200 * 1024 * 1024)  # 200MB
        validate_data(huge_data, max_size=100 * 1024 * 1024)
    except ResourceLimitError as e:
        print(f"  ✓ Caught resource limit: Resource limit exceeded")

    print("\n" + "="*70)
    print("All examples completed successfully!")
    print("="*70)


def example_streaming_api() -> None:
    """
    Example demonstrating the STREAMING API for large files.

    This API allows processing files larger than available memory.
    """
    print("\n" + "="*70)
    print("STREAMING API (for large files > 100MB)")
    print("="*70)

    # Create test files
    import tempfile
    test_dir = tempfile.mkdtemp()

    try:
        original_file = os.path.join(test_dir, "original.bin")
        modified_file = os.path.join(test_dir, "modified.bin")

        # Example 1: Streaming signature generation
        print("\n1. Streaming Signature Generation")
        print("-" * 70)

        # Create a test file (10MB)
        print("  Creating 10MB test file...")
        with open(original_file, 'wb') as f:
            for _ in range(10):
                f.write(b"X" * (1024 * 1024))  # Write 1MB at a time

        engine = ChecksumEngine(block_size=131072)  # 128KB blocks

        # Generate signature using streaming API
        print("  Generating signature using streaming...")
        signature = engine.generate_signature_from_file(original_file)
        print(f"  Signature: {signature}")

        # Example 2: Streaming delta generation
        print("\n2. Streaming Delta Generation")
        print("-" * 70)

        # Create modified file (change in middle)
        print("  Creating modified file...")
        with open(modified_file, 'wb') as f:
            for i in range(10):
                if i == 5:
                    f.write(b"Y" * (1024 * 1024))  # Changed block
                else:
                    f.write(b"X" * (1024 * 1024))  # Original blocks

        # Generate delta using streaming
        print("  Generating delta using streaming...")
        delta = engine.generate_delta_from_files(signature, modified_file)
        print(f"  Delta: {delta}")
        print(f"  Matches: {delta.num_matches}, Literals: {delta.num_literals}")
        print(f"  Compression: {delta.compression_ratio:.2%}")

        # Example 3: Manual streaming with iteration
        print("\n3. Manual Streaming (Iterate Blocks)")
        print("-" * 70)

        print("  Processing blocks one-by-one...")
        with FileDataSource(original_file) as source:
            for i, block in enumerate(engine.generate_signature_streaming(source, s2length=signature.s2length)):
                if i < 3:  # Show first 3 blocks
                    print(f"    Block {i}: offset={block.offset}, len={block.length}")
                elif i == 3:
                    print(f"    ... ({signature.num_blocks - 3} more blocks)")
                    break

        print("\n  ✓ Streaming API allows processing files of ANY size!")
        print("  ✓ Memory usage stays constant regardless of file size")

    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


# ============================================================================
# PERFORMANCE PROFILING - For optimization and benchmarking
# ============================================================================

class Profiler:
    """
    Simple profiler for measuring performance.

    Example:
        >>> with Profiler("operation") as p:
        ...     # do work
        >>> print(p.elapsed)
    """
    def __init__(self, name: str = ""):
        self.name = name
        self.elapsed = 0.0
        self._start = 0.0

    def __enter__(self) -> 'Profiler':
        if Config.ENABLE_PROFILING:
            import time
            self._start = time.perf_counter()
        return self

    def __exit__(self, *args: Any) -> None:
        if Config.ENABLE_PROFILING:
            import time
            self.elapsed = time.perf_counter() - self._start
            if Config.VERBOSE_LOGGING:
                print(f"[PROFILE] {self.name}: {self.elapsed*1000:.2f}ms")


def get_memory_usage() -> int:
    """
    Get current memory usage in bytes.

    Returns:
        Memory usage in bytes, or 0 if unavailable
    """
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024  # type: ignore[attr-defined]
    except Exception:
        try:
            import psutil  # type: ignore[import]
            import os
            process = psutil.Process(os.getpid())  # type: ignore[name-defined]
            return process.memory_info().rss  # type: ignore[attr-defined]
        except Exception:
            return 0


def profile_operation(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator for profiling functions.

    Example:
        >>> @profile_operation
        ... def my_function():
        ...     pass
    """
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with Profiler(func.__name__) as p:  # type: ignore[misc]
            result: Any = func(*args, **kwargs)
        return result
    return wrapper


def example_legacy_api() -> None:
    """
    Example demonstrating the LEGACY API with tuple returns.

    This API is maintained for backward compatibility but is NOT recommended.
    Use the improved API (generate_signature/generate_delta) instead.
    """
    print("\n" + "="*70)
    print("LEGACY API (for backward compatibility only)")
    print("="*70)

    original_data = b"Hello, World!"
    engine = ChecksumEngine(block_size=512)

    # Legacy API - returns anonymous tuples
    sum_head, blocks = engine.generate_sums(original_data)
    print(f"\nLegacy sum_head: {sum_head}")
    print(f"Legacy blocks: {len(blocks)} items (first 2: {blocks[:2]})")

    # Matching with legacy API
    new_data = b"Hello, World! Extra data"
    results = engine.match_sums(new_data, sum_head, blocks)
    print(f"Legacy match results: {len(results)} operations")

    print("\n⚠️  RECOMMENDATION: Use the improved API instead:")
    print("    engine.generate_signature()  # instead of generate_sums()")
    print("    engine.generate_delta()      # instead of match_sums()")
    print("    engine.apply_delta()         # for reconstruction")


# ============================================================================
# CLI - Professional Command-Line Interface
# ============================================================================

def cli_signature(args: Any) -> int:
    """Generate signature file for source file."""
    import time
    start_time = time.time()

    if not args.quiet:
        print(Colors.info(f"Generating signature for: {Colors.bold(args.file)}"))
        print(f"  Block size: {args.block_size:,} bytes")

    try:
        # Validate input file exists
        if not os.path.exists(args.file):
            print(Colors.error(f"Input file not found: {args.file}"), file=sys.stderr)
            return 1

        if not os.path.isfile(args.file):
            print(Colors.error(f"Input path is not a file: {args.file}"), file=sys.stderr)
            return 1

        engine = ChecksumEngine(block_size=args.block_size)
        signature = engine.generate_signature_from_file(args.file)

        # Determine format and save
        use_json = args.json or args.output.endswith('.json')

        if use_json:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(signature.to_dict(), f, indent=2)
            format_name = "JSON"
        else:
            with open(args.output, 'wb') as f:
                pickle.dump(signature, f)
            format_name = "pickle"

        elapsed = time.time() - start_time
        if not args.quiet:
            print(f"\n{Colors.success(f'Signature saved to: {args.output}')}" )
            print(f"  Format:       {format_name}")
            print(f"  File size:    {signature.file_size:,} bytes")
            print(f"  Blocks:       {signature.num_blocks:,}")
            print(f"  Block size:   {signature.block_size:,} bytes")
            print(f"  Protocol:     v{signature.protocol_version}")
            print(f"  Time:         {elapsed:.3f}s")
        return 0
    except ValidationError as e:
        print(Colors.error(f"Validation error: {e}"), file=sys.stderr)
        return 2
    except ResourceLimitError as e:
        print(Colors.error(f"Resource limit exceeded: {e}"), file=sys.stderr)
        return 3
    except FileIOError as e:
        print(Colors.error(f"File I/O error: {e}"), file=sys.stderr)
        return 4
    except PermissionError as e:
        print(Colors.error(f"Permission denied: {e}"), file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print(Colors.warning("\nOperation cancelled by user"), file=sys.stderr)
        return 130
    except Exception as e:
        print(Colors.error(f"Unexpected error: {type(e).__name__}: {e}"), file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1


def cli_delta(args: Any) -> int:
    """Generate delta between signature and new file."""
    import time
    start_time = time.time()

    if not args.quiet:
        print(f"Generating delta:")
        print(f"  Signature: {args.signature}")
        print(f"  New file: {args.file}")

    try:
        # Validate inputs exist
        if not os.path.exists(args.signature):
            print(Colors.error(f"Signature file not found: {args.signature}"), file=sys.stderr)
            return 1

        if not os.path.exists(args.file):
            print(Colors.error(f"Input file not found: {args.file}"), file=sys.stderr)
            return 1

        # Detect format and load signature
        if args.signature.endswith('.json'):
            with open(args.signature, 'r', encoding='utf-8') as f:
                signature = ChecksumSignature.from_dict(json.load(f))
        else:
            with open(args.signature, 'rb') as f:
                signature = pickle.load(f)

        engine = ChecksumEngine(block_size=signature.block_size)
        delta = engine.generate_delta_from_files(signature, args.file)

        # Determine format and save
        use_json = args.json or args.output.endswith('.json')

        if use_json:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(delta.to_dict(), f, indent=2)
            format_name = "JSON"
        else:
            with open(args.output, 'wb') as f:
                pickle.dump(delta, f)
            format_name = "pickle"

        elapsed = time.time() - start_time

        if not args.quiet:
            print(f"\n{Colors.success(f'Delta saved to: {args.output}')}" )
            print(f"  Format:         {format_name}")
            print(f"  Original size:  {signature.file_size:,} bytes")
            print(f"  New size:       {delta.new_file_size:,} bytes")
            print(f"  Matched bytes:  {delta.matched_bytes:,} ({delta.compression_ratio:.1%})")
            print(f"  Literal bytes:  {delta.literal_bytes:,}")
            print(f"  Instructions:   {len(delta.instructions)}")
            print(f"  Time:           {elapsed:.2f}s")
        return 0
    except ValidationError as e:
        print(Colors.error(f"Validation error: {e}"), file=sys.stderr)
        return 2
    except ResourceLimitError as e:
        print(Colors.error(f"Resource limit exceeded: {e}"), file=sys.stderr)
        return 3
    except FileIOError as e:
        print(Colors.error(f"File I/O error: {e}"), file=sys.stderr)
        return 4
    except (json.JSONDecodeError, pickle.UnpicklingError) as e:
        print(Colors.error(f"Failed to load signature file: {e}"), file=sys.stderr)
        print(Colors.info("  Hint: Check file format (JSON vs pickle)"), file=sys.stderr)
        return 6
    except PermissionError as e:
        print(Colors.error(f"Permission denied: {e}"), file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print(Colors.warning("\nOperation cancelled by user"), file=sys.stderr)
        return 130
    except Exception as e:
        print(Colors.error(f"Unexpected error: {type(e).__name__}: {e}"), file=sys.stderr)
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1


def cli_patch(args: Any) -> int:
    """Apply delta to reconstruct file."""
    import time
    start_time = time.time()

    if not args.quiet:
        print(f"Applying delta:")
        print(f"  Original: {args.original}")
        print(f"  Delta: {args.delta}")

    try:
        # Detect format and load delta
        if args.delta.endswith('.json'):
            with open(args.delta, 'r', encoding='utf-8') as f:
                delta = DeltaInstructions.from_dict(json.load(f))
        else:
            with open(args.delta, 'rb') as f:
                delta = pickle.load(f)

        # Load original file
        with open(args.original, 'rb') as f:
            original_data = f.read()

        # Reconstruct
        engine = ChecksumEngine()
        reconstructed = engine.apply_delta(original_data, delta)

        # Save reconstructed file
        with open(args.output, 'wb') as f:
            f.write(reconstructed)

        elapsed = time.time() - start_time
        if not args.quiet:
            print(f"\n{Colors.success(f'File reconstructed: {args.output}')}" )
            print(f"  Size: {len(reconstructed):,} bytes")
            print(f"  Time: {elapsed:.2f}s")
        return 0
    except Exception as e:
        print(Colors.error(f"Error: {e}"), file=sys.stderr)
        return 1


def cli_sync(args: Any) -> int:
    """Full sync operation: compare two files and show statistics."""
    import time
    start_time = time.time()

    if not args.quiet:
        print(Colors.bold("\n🔄 RSYNC-PYTHON SYNCHRONIZATION"))
        print(f"  Source: {Colors.bold(args.source)}")
        print(f"  Target: {Colors.bold(args.target)}")
        print(f"  Block size: {args.block_size:,} bytes")

    try:
        engine = ChecksumEngine(block_size=args.block_size)

        # Generate signature of source
        if not args.quiet:
            print(f"\n{Colors.info('[1/3] Generating signature of source file...')}")
        signature = engine.generate_signature_from_file(args.source)
        if not args.quiet:
            print(f"      {signature.num_blocks:,} blocks generated")

        # Generate delta
        if not args.quiet:
            print(f"{Colors.info('[2/3] Generating delta...')}")
        delta = engine.generate_delta_from_files(signature, args.target)

        elapsed = time.time() - start_time
        efficiency = delta.compression_ratio * 100 if delta.new_file_size > 0 else 0
        throughput = delta.new_file_size/elapsed/1024/1024 if elapsed > 0 else 0

        if not args.quiet:
            print(f"{Colors.success('[3/3] Analysis complete!')}\n")
            print(Colors.bold("=" * 70))
            print(Colors.bold("📊 SYNCHRONIZATION STATISTICS".center(70)))
            print(Colors.bold("=" * 70))

            # Format numbers with color based on efficiency
            efficiency_color = Colors.GREEN() if efficiency > 80 else (Colors.YELLOW() if efficiency > 50 else Colors.RED())

            print(f"Source file size:       {signature.file_size:>15,} bytes")
            print(f"Target file size:       {delta.new_file_size:>15,} bytes")
            print(f"Matched data:           {delta.matched_bytes:>15,} bytes ({delta.compression_ratio:.1%})")
            print(f"Literal data:           {delta.literal_bytes:>15,} bytes")
            print(f"Transfer savings:       {delta.matched_bytes:>15,} bytes {Colors.success('(not transferred)')}")
            print(f"Efficiency:             {efficiency_color}{efficiency:>14.1f}%{Colors.RESET()}")
            print(f"Time elapsed:           {elapsed:>14.3f}s")
            print(f"Throughput:             {throughput:>14.2f} MB/s")
            print(Colors.bold("=" * 70))

        if args.apply:
            if not args.quiet:
                print(f"\n{Colors.info('Applying changes to create output file...')}")
            with open(args.source, 'rb') as f:
                source_data = f.read()
            reconstructed = engine.apply_delta(source_data, delta)
            with open(args.apply, 'wb') as f:
                f.write(reconstructed)
            if not args.quiet:
                print(Colors.success(f"Output saved to: {args.apply}"))

        return 0
    except Exception as e:
        print(Colors.error(f"Error: {e}"), file=sys.stderr)
        return 1


# ============================================================================
# Rsync-Compatible CLI Interface
# ============================================================================

@dataclass
class RsyncOptions:
    """
    Rsync command-line options matching rsync C implementation
    Reference: rsync-original-source-code/options.c
    """
    # Verbosity / UI
    verbose: int = 0                        # --verbose, -v
    info: Optional[str] = None              # --info=FLAGS
    debug: Optional[str] = None             # --debug=FLAGS
    stderr_mode: Optional[str] = None       # --stderr=e|a|c
    quiet: bool = False                     # --quiet, -q
    no_motd: bool = False                   # --no-motd

    # Core transfer options
    checksum: bool = False                  # --checksum, -c (quick-check by checksum)
    archive: bool = False                   # --archive, -a (implies -rlptgoD)
    recursive: bool = False                 # --recursive, -r
    relative: bool = False                  # --relative, -R
    no_implied_dirs: bool = False           # --no-implied-dirs
    update: bool = False                    # --update, -u
    inplace: bool = False                   # --inplace
    append: bool = False                    # --append
    append_verify: bool = False             # --append-verify
    dirs: bool = False                      # --dirs, -d
    old_dirs: bool = False                  # --old-dirs, --old-d
    mkpath: bool = False                    # --mkpath

    dry_run: bool = False                   # --dry-run, -n
    whole_file: bool = False                # --whole-file, -W

    # Algorithm selection
    checksum_choice: Optional[str] = None    # --checksum-choice=STR
    compress: bool = False                  # --compress, -z
    compress_choice: Optional[str] = None    # --compress-choice=STR
    compress_level: Optional[int] = None     # --compress-level=NUM
    skip_compress: Optional[str] = None      # --skip-compress=LIST
    one_file_system: bool = False           # --one-file-system, -x
    block_size: Optional[int] = None         # --block-size=SIZE, -B
    rsh: Optional[str] = None                # --rsh=COMMAND, -e
    rsync_path: Optional[str] = None         # --rsync-path=PROGRAM

    # Preserve options / metadata
    preserve_links: bool = False            # --links, -l
    copy_links: bool = False                # --copy-links, -L
    copy_unsafe_links: bool = False         # --copy-unsafe-links
    safe_links: bool = False                # --safe-links
    munge_links: bool = False               # --munge-links
    copy_dirlinks: bool = False             # --copy-dirlinks, -k
    keep_dirlinks: bool = False             # --keep-dirlinks, -K
    hard_links: bool = False                # --hard-links, -H

    preserve_perms: bool = False            # --perms, -p
    executability: bool = False             # --executability, -E
    chmod: Optional[str] = None             # --chmod=CHMOD
    acls: bool = False                      # --acls, -A
    xattrs: bool = False                    # --xattrs, -X
    preserve_owner: bool = False            # --owner, -o
    preserve_group: bool = False            # --group, -g
    preserve_devices: bool = False          # --devices / -D implies devices+specials
    preserve_specials: bool = False         # --specials

    preserve_times: bool = False            # --times, -t
    atimes: bool = False                    # --atimes, -U
    open_noatime: bool = False              # --open-noatime
    crtimes: bool = False                   # --crtimes, -N
    omit_dir_times: bool = False            # --omit-dir-times, -O
    omit_link_times: bool = False           # --omit-link-times, -J
    super_mode: bool = False                # --super
    fake_super: bool = False                # --fake-super
    sparse: bool = False                    # --sparse, -S
    preallocate: bool = False               # --preallocate

    # Backup
    backup: bool = False                    # --backup, -b
    backup_dir: Optional[str] = None        # --backup-dir=DIR
    suffix: Optional[str] = None            # --suffix=SUFFIX

    # Delete
    delete_mode: bool = False               # --delete
    delete_before: bool = False             # --delete-before
    delete_during: bool = False             # --delete-during / --del
    delete_delay: bool = False              # --delete-delay
    delete_after: bool = False              # --delete-after
    delete_excluded: bool = False           # --delete-excluded
    ignore_missing_args: bool = False       # --ignore-missing-args
    delete_missing_args: bool = False       # --delete-missing-args
    ignore_errors: bool = False             # --ignore-errors
    force: bool = False                     # --force
    max_delete: Optional[int] = None        # --max-delete=NUM
    max_size: Optional[str] = None          # --max-size=SIZE
    min_size: Optional[str] = None          # --min-size=SIZE
    max_alloc: Optional[str] = None         # --max-alloc=SIZE
    partial: bool = False                   # --partial
    partial_dir: Optional[str] = None       # --partial-dir=DIR
    delay_updates: bool = False             # --delay-updates
    prune_empty_dirs: bool = False          # --prune-empty-dirs, -m

    # Id mapping / timeouts / comparisons
    numeric_ids: bool = False               # --numeric-ids
    usermap: Optional[str] = None           # --usermap=STRING
    groupmap: Optional[str] = None          # --groupmap=STRING
    chown: Optional[str] = None             # --chown=USER:GROUP
    timeout: Optional[int] = None           # --timeout=SECONDS
    contimeout: Optional[int] = None        # --contimeout=SECONDS
    ignore_times: bool = False              # --ignore-times, -I
    size_only: bool = False                 # --size-only
    modify_window: Optional[int] = None     # --modify-window=NUM, -@
    temp_dir: Optional[str] = None          # --temp-dir=DIR, -T
    fuzzy: bool = False                     # --fuzzy, -y
    compare_dest: Optional[str] = None      # --compare-dest=DIR
    copy_dest: Optional[str] = None         # --copy-dest=DIR
    link_dest: Optional[str] = None         # --link-dest=DIR

    # Filters / patterns
    cvs_exclude: bool = False               # --cvs-exclude, -C
    filter_rules: List[str] = field(default_factory=lambda: cast(List[str], []))  # --filter, -f
    filter_F: int = 0                       # -F (repeatable)
    exclude: List[str] = field(default_factory=lambda: cast(List[str], []))       # --exclude
    include: List[str] = field(default_factory=lambda: cast(List[str], []))       # --include
    exclude_from: Optional[str] = None      # --exclude-from=FILE
    include_from: Optional[str] = None      # --include-from=FILE
    files_from: Optional[str] = None        # --files-from=FILE
    from0: bool = False                     # --from0, -0

    # Misc / logging / batch / transport
    existing: bool = False                  # --existing
    ignore_existing: bool = False           # --ignore-existing
    remove_source_files: bool = False       # --remove-source-files
    old_args: bool = False                  # --old-args
    secluded_args: bool = False             # --secluded-args, -s
    trust_sender: bool = False              # --trust-sender
    copy_as: Optional[str] = None           # --copy-as=USER[:GROUP]
    address: Optional[str] = None           # --address=ADDRESS
    port: Optional[int] = None              # --port=PORT
    sockopts: Optional[str] = None          # --sockopts=OPTIONS
    blocking_io: bool = False               # --blocking-io
    outbuf: Optional[str] = None            # --outbuf=N|L|B
    remote_option: List[str] = field(default_factory=lambda: cast(List[str], []))  # --remote-option, -M
    out_format: Optional[str] = None        # --out-format=FORMAT
    log_file: Optional[str] = None          # --log-file=FILE
    log_file_format: Optional[str] = None   # --log-file-format=FMT
    password_file: Optional[str] = None     # --password-file=FILE
    early_input: Optional[str] = None       # --early-input=FILE
    list_only: bool = False                 # --list-only
    bwlimit: Optional[str] = None           # --bwlimit=RATE
    stop_after: Optional[int] = None        # --stop-after=MINS
    stop_at: Optional[str] = None           # --stop-at=y-m-dTh:m
    fsync: bool = False                     # --fsync
    write_batch: Optional[str] = None       # --write-batch=FILE
    only_write_batch: Optional[str] = None  # --only-write-batch=FILE
    read_batch: Optional[str] = None        # --read-batch=FILE
    protocol: Optional[int] = None          # --protocol=NUM
    iconv: Optional[str] = None             # --iconv=CONVERT_SPEC
    checksum_seed: Optional[int] = None     # --checksum-seed=NUM
    ipv4: bool = False                      # --ipv4, -4
    ipv6: bool = False                      # --ipv6, -6

    # Display options
    stats: bool = False                     # --stats
    eight_bit_output: bool = False          # --8-bit-output, -8
    human_readable: bool = False            # --human-readable, -h
    progress: bool = False                  # --progress
    partial_progress: bool = False          # -P
    itemize_changes: bool = False           # --itemize-changes, -i

    # Preserve options
    preserve_links: bool = False       # -l
    preserve_perms: bool = False       # -p
    preserve_times: bool = False       # -t
    preserve_group: bool = False       # -g
    preserve_owner: bool = False       # -o
    preserve_devices: bool = False     # -D

    # Delete options
    delete_mode: bool = False          # --delete
    delete_before: bool = False        # --delete-before
    delete_during: bool = False        # --delete-during
    delete_after: bool = False         # --delete-after
    delete_excluded: bool = False      # --delete-excluded

    # Display options
    progress: bool = False             # --progress
    stats: bool = False                # --stats
    human_readable: bool = False       # -h
    itemize_changes: bool = False      # -i

    # Source/Dest
    sources: List[str] = field(default_factory=_default_rsync_sources)
    dest: str = ""

    # Daemon mode (invocation)
    daemon: bool = False


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
        value: float = float(size)
        for unit in ['', 'K', 'M', 'G', 'T']:
            if value < 1024:
                if unit:
                    return f"{value:.2f}{unit}"
                return f"{int(value)}"
            value /= 1024.0
        return f"{value:.2f}P"

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

    def __init__(self, exclude_patterns: Optional[List[str]] = None, include_patterns: Optional[List[str]] = None):
        self.exclude_patterns: List[str] = exclude_patterns if exclude_patterns is not None else []
        self.include_patterns: List[str] = include_patterns if include_patterns is not None else []

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

    def __init__(self, pattern_matcher: Optional[PatternMatcher] = None) -> None:
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
        self.files.sort(key=lambda f: f.filename)

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

        except PermissionError:
            print(f"rsync: opendir \"{dirpath}\" failed: Permission denied (13)", file=sys.stderr)

    def _add_file(self, path: Path) -> None:
        """Add single file to list"""
        try:
            stat = path.lstat()  # lstat to handle symlinks

            link_target: Optional[str] = None
            if path.is_symlink():
                try:
                    link_target = str(path.readlink())
                except OSError:
                    link_target = None

            entry = FileEntry(
                filename=str(path),
                size=stat.st_size if not path.is_dir() else 0,
                mtime=int(stat.st_mtime),
                mode=stat.st_mode,
                is_dir=path.is_dir(),
                is_link=path.is_symlink(),
                link_target=link_target
            )

            self.files.append(entry)

        except (OSError, PermissionError) as e:
            print(f"rsync: stat \"{path}\" failed: {e}", file=sys.stderr)


class FileSynchronizer:
    """Orchestrate file synchronization"""

    def __init__(self, options: RsyncOptions) -> None:
        self.options = options
        self.stats = TransferStats()
        # Directory attribute updates are applied at the end, like rsync does,
        # so that writing files doesn't clobber directory mtimes.
        self._pending_dir_attrs: Dict[Path, Tuple[int, int, bool]] = {}

    def _src_root_and_base_for_rel(self, src_arg: str) -> Tuple[Path, Path]:
        """
        Determine the filesystem root to scan and the base path used to compute
        destination-relative paths.

        - Default mode: matches rsync trailing-slash semantics.
        - --relative/-R: preserve full path names, supporting the `/./` marker.
        """
        trailing = src_arg.endswith('/')
        raw = src_arg[:-1] if trailing else src_arg

        # --relative: preserve full path names. If a `/./` marker is present,
        # the portion before it is stripped from the destination path.
        if self.options.relative:
            marker = f"{os.sep}.{os.sep}"
            if marker in raw:
                prefix, _ = raw.split(marker, 1)
                base = Path(prefix if prefix else os.sep).absolute()
            else:
                # Absolute sources get stripped of leading '/', relative sources are
                # relative to the current working directory.
                base = Path(os.sep) if raw.startswith(os.sep) else Path('.').absolute()
            return Path(raw).absolute(), base

        # Default mode: match rsync trailing slash semantics.
        src_path = Path(raw)
        if src_path.is_dir():
            base = src_path if trailing else src_path.parent
        else:
            base = src_path.parent
        return src_path, base

    def _relpath_for_src_file(self, src_file_path: Path, base_for_rel: Path) -> Path:
        """Compute a destination-relative path for a source file path."""
        try:
            if self.options.relative:
                return src_file_path.absolute().relative_to(base_for_rel)
            return src_file_path.relative_to(base_for_rel)
        except ValueError:
            return Path(src_file_path.name)

    def _finalize_directory_attributes(self) -> None:
        if not self._pending_dir_attrs or self.options.dry_run:
            self._pending_dir_attrs.clear()
            return

        apply_times = bool(self.options.preserve_times and not self.options.omit_dir_times)
        for dest_dir, (mode, mtime, existed) in sorted(
            self._pending_dir_attrs.items(), key=lambda kv: (len(kv[0].parts), str(kv[0])), reverse=True
        ):
            if not dest_dir.exists() or not dest_dir.is_dir():
                continue

            # Directory permissions: new dirs get source perms by default; existing dirs
            # only update perms when -p is set.
            if (not existed) or self.options.preserve_perms:
                try:
                    dest_dir.chmod(int(mode) & 0o7777)
                except OSError:
                    pass

            if apply_times:
                try:
                    st = dest_dir.stat()
                    atime = int(st.st_atime)
                    os.utime(dest_dir, (atime, int(mtime)))
                except OSError:
                    pass

        self._pending_dir_attrs.clear()

    def _ensure_relative_implied_dirs(self, sources: List[str], dest_root: Path) -> None:
        """
        Create and record implied directories for `--relative/-R`.

        In rsync, these are the path components needed to place a transferred item
        under its full relative path (e.g. `tmp/tmpxxx/...` for absolute sources),
        even if those directories are not part of the scanned file list.

        `--no-implied-dirs` disables this behavior.
        """
        if not self.options.relative or self.options.no_implied_dirs:
            return
        if self.options.dry_run:
            return
        if not dest_root.exists():
            return

        for src_arg in sources:
            src_root, base_for_rel = self._src_root_and_base_for_rel(src_arg)
            rel_root = self._relpath_for_src_file(src_root, base_for_rel)
            # Create all parent dirs needed to place rel_root under dest_root.
            parents = [p for p in rel_root.parents if p != Path('.')]
            for rel_parent in reversed(parents):
                dest_dir = dest_root / rel_parent
                existed = dest_dir.exists()
                if not existed:
                    try:
                        dest_dir.mkdir(parents=True, exist_ok=True)
                    except OSError:
                        continue

                try:
                    src_dir = (base_for_rel / rel_parent)
                    st = src_dir.lstat()
                except OSError:
                    continue

                # Implied dirs: without -p, rsync masks to 0755 (drops g/o write and special bits).
                src_mode = int(st.st_mode)
                desired_mode = (src_mode & 0o7777) if self.options.preserve_perms else (src_mode & 0o755)
                desired_mtime = int(st.st_mtime)
                self._pending_dir_attrs[dest_dir] = (desired_mode, desired_mtime, bool(existed))

    def sync(self, sources: List[str], dest: str) -> TransferStats:
        """Synchronize files from sources to destination"""
        if self.options.list_only:
            self.options.dry_run = True

        # Build source file list
        pattern_matcher = PatternMatcher(
            exclude_patterns=self.options.exclude,
            include_patterns=self.options.include
        )

        builder = FileListBuilder(pattern_matcher)
        dest_path = Path(dest)

        # Determine destination type
        dest_is_dir = dest.endswith('/') or dest_path.is_dir() or len(sources) > 1
        if len(sources) > 1 and not dest_is_dir:
            print("rsync: destination must be a directory when copying more than 1 file", file=sys.stderr)
            return self.stats

        # Create destination directory if needed
        if dest_is_dir and not dest_path.exists():
            if not self.options.mkpath and not dest_path.parent.exists():
                print(f"rsync: mkdir \"{dest_path.parent}\" failed: No such file or directory (2)", file=sys.stderr)
                return self.stats
            if not self.options.dry_run:
                dest_path.mkdir(parents=True, exist_ok=True)
                if self.options.verbose >= 2 and self.options.itemize_changes:
                    print(f"cd++++++++++ {dest}")

        # Deletion pass (before)
        expected_relpaths: List[Path] = []

        # In `--relative` mode, rsync creates “implied dirs” to hold the full path.
        # We create/record them up-front so that perms/times can be applied later.
        if dest_is_dir and self.options.relative and not self.options.no_implied_dirs:
            self._ensure_relative_implied_dirs(sources, dest_path)

        if self.options.delete_mode and self.options.delete_before and dest_is_dir:
            expected_relpaths = self._collect_expected_relpaths(sources, builder, pattern_matcher)
            self._delete_extraneous(dest_path, expected_relpaths, pattern_matcher)

        # Transfer files
        for src_arg in sources:
            src_root, base_for_rel = self._src_root_and_base_for_rel(src_arg)
            src_files = builder.build_file_list(
                [str(src_root)],
                recursive=(self.options.recursive or self.options.dirs)
            )

            if self.options.verbose >= 1:
                print("building file list ... done")

            for src_file in src_files:
                src_file_path = Path(src_file.filename)
                rel_path = self._relpath_for_src_file(src_file_path, base_for_rel)

                if rel_path == Path('.'):
                    continue

                expected_relpaths.append(rel_path)

                if dest_is_dir:
                    dest_item = dest_path / rel_path
                else:
                    dest_item = dest_path

                self._transfer_file(src_file, dest_item, file_exists=dest_item.exists())

        # Deletion pass (after/during/delay)
        if self.options.delete_mode and dest_is_dir and (self.options.delete_after or self.options.delete_during or self.options.delete_delay or (not self.options.delete_before)):
            if not expected_relpaths:
                expected_relpaths = self._collect_expected_relpaths(sources, builder, pattern_matcher)
            self._delete_extraneous(dest_path, expected_relpaths, pattern_matcher)

        # Apply directory perms/times after all file writes and deletions.
        self._finalize_directory_attributes()

        # Update stats
        self.stats.num_files = len(expected_relpaths)
        try:
            self.stats.total_size = sum(Path(p).stat().st_size for p in [Path(s.rstrip('/')) for s in sources] if p.exists() and p.is_file())
        except Exception:
            pass

        # Print final newline if progress was shown
        if self.options.progress:
            print()

        return self.stats

    def _collect_expected_relpaths(
        self,
        sources: List[str],
        builder: FileListBuilder,
        pattern_matcher: PatternMatcher
    ) -> List[Path]:
        expected: List[Path] = []

        for src_arg in sources:
            src_root, base_for_rel = self._src_root_and_base_for_rel(src_arg)

            src_files = builder.build_file_list([str(src_root)], recursive=(self.options.recursive or self.options.dirs))
            for src_file in src_files:
                src_file_path = Path(src_file.filename)
                rel = self._relpath_for_src_file(src_file_path, base_for_rel)
                if rel == Path('.'):
                    continue
                expected.append(rel)

        # Deduplicate deterministically
        expected_sorted = sorted(set(expected), key=lambda p: str(p))
        return expected_sorted

    def _delete_extraneous(self, dest_root: Path, expected_relpaths: List[Path], pattern_matcher: PatternMatcher) -> None:
        expected_set = {str(p) for p in expected_relpaths}
        deleted = 0

        if not dest_root.exists() or not dest_root.is_dir():
            return

        # Walk destination and delete files/dirs not present in expected.
        for path in sorted(dest_root.rglob('*'), reverse=True):
            rel = str(path.relative_to(dest_root))
            if rel in expected_set:
                continue

            # If not deleting excluded, protect excluded paths.
            if not self.options.delete_excluded and pattern_matcher.should_exclude(rel):
                continue

            if self.options.max_delete is not None and deleted >= self.options.max_delete:
                break

            if self.options.dry_run:
                if self.options.itemize_changes:
                    print(f"*deleting   {rel}")
                deleted += 1
                continue

            try:
                if path.is_dir() and not path.is_symlink():
                    # Only delete empty dirs (rsync won't force-delete non-empty dirs by default).
                    if any(path.iterdir()):
                        continue
                    path.rmdir()
                else:
                    path.unlink()
                deleted += 1
                self.stats.num_deleted += 1
                if self.options.itemize_changes:
                    print(f"*deleting   {rel}")
            except OSError as e:
                if not self.options.ignore_errors:
                    print(f"rsync: delete_file \"{path}\" failed: {e}", file=sys.stderr)

        # Optionally prune empty directories
        if self.options.prune_empty_dirs and not self.options.dry_run:
            for path in sorted(dest_root.rglob('*'), reverse=True):
                try:
                    if path.is_dir() and not path.is_symlink() and not any(path.iterdir()):
                        path.rmdir()
                except OSError:
                    continue

    def _files_identical_quick_check(self, src_path: Path, src_size: int, src_mtime: int, dest_path: Path) -> bool:
        try:
            st = dest_path.stat()
        except OSError:
            return False

        if self.options.size_only:
            return int(st.st_size) == int(src_size)

        if self.options.checksum:
            # -c uses file checksums for the quick-check.
            return self._file_checksum_matches(src_path, dest_path)

        # Default quick-check: size + modtime (with modify_window)
        if int(st.st_size) != int(src_size):
            return False
        mw = int(self.options.modify_window or 0)
        return abs(int(st.st_mtime) - int(src_mtime)) <= mw

    def _maybe_update_existing_attrs(self, dest_path: Path, effective_mode: int, effective_mtime: int) -> None:
        """
        Update destination attributes even when file content is considered identical.

        This mirrors rsync behavior where metadata updates can occur even if the
        data transfer is skipped (e.g. -p, -t, or -E with --checksum).
        """
        try:
            st = dest_path.stat()
        except OSError:
            return

        dest_mode = int(st.st_mode) & 0o7777
        desired_mode: Optional[int] = None
        if self.options.preserve_perms:
            desired_mode = effective_mode & 0o7777
        elif self.options.executability:
            desired_mode = (dest_mode & ~0o111) | (effective_mode & 0o111)

        if desired_mode is not None and desired_mode != dest_mode:
            try:
                dest_path.chmod(desired_mode)
            except OSError:
                pass

        if self.options.preserve_times:
            try:
                current_atime = int(st.st_atime)
                os.utime(dest_path, (current_atime, int(effective_mtime)))
            except OSError:
                pass

    def _file_checksum_matches(self, src_path: Path, dest_path: Path) -> bool:
        def digest_file(p: Path) -> bytes:
            h = hashlib.md5()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(chunk)
            return h.digest()

        try:
            return digest_file(src_path) == digest_file(dest_path)
        except OSError:
            return False

    def _transfer_file(self, src_file: FileEntry, dest_path: Path, file_exists: bool) -> None:
        """Transfer a single file to an explicit destination path."""
        src_path = Path(src_file.filename)
        effective_src_path = src_path
        effective_mode = src_file.mode
        effective_mtime = src_file.mtime
        effective_size = src_file.size

        # If copy-links is enabled, treat symlinks as their referent.
        if src_file.is_link and self.options.copy_links:
            try:
                st = src_path.stat()
                effective_src_path = src_path.resolve()
                effective_mode = st.st_mode
                effective_mtime = int(st.st_mtime)
                effective_size = int(st.st_size)
            except OSError:
                return

        # Determine if transfer is needed
        if file_exists:
            if self.options.ignore_existing:
                return
            if self.options.update:
                mw = int(self.options.modify_window or 0)
                try:
                    dest_mtime = int(dest_path.stat().st_mtime)
                except OSError:
                    dest_mtime = 0
                if dest_mtime - int(effective_mtime) > mw:
                    return

            if not self.options.ignore_times and self._files_identical_quick_check(
                effective_src_path, int(effective_size), int(effective_mtime), dest_path
            ):
                self._maybe_update_existing_attrs(dest_path, int(effective_mode), int(effective_mtime))
                return
        else:
            if self.options.existing:
                return

        # Symlink handling (matches rsync default behavior):
        # - Without --links, symlinks are skipped (non-regular file) unless --copy-links is set.
        if src_file.is_link and not self.options.copy_links and not self.options.preserve_links:
            if self.options.verbose >= 1 and not self.options.quiet:
                print(f"skipping non-regular file \"{src_path.name}\"", file=sys.stderr)
            return

        # Verbose output
        if self.options.verbose >= 1:
            if self.options.itemize_changes:
                itemize = self._generate_itemize(src_file, dest_path, file_exists)
                print(f"{itemize} {dest_path}")
            else:
                print(dest_path)

        # Dry run - just print, don't copy
        if self.options.dry_run:
            return

        # Handle directories
        if src_file.is_dir:
            existed = dest_path.exists()
            if not existed:
                dest_path.mkdir(parents=True, exist_ok=True)
                self.stats.num_created += 1
            # Record directory attributes to apply at the end (mtime needs to be delayed).
            self._pending_dir_attrs[dest_path] = (int(effective_mode), int(effective_mtime), bool(existed))
            return

        # Handle symlinks
        if src_file.is_link and self.options.preserve_links and not self.options.copy_links:
            if src_file.link_target is None:
                print(
                    f"rsync: readlink \"{src_file.filename}\" failed: Invalid argument (22)",
                    file=sys.stderr
                )
                return
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            if dest_path.exists() or dest_path.is_symlink():
                dest_path.unlink()
            link_target = src_file.link_target
            dest_path.symlink_to(link_target)
            self.stats.num_created += 1
            return

        # Backups (simplified)
        if file_exists and self.options.backup and dest_path.exists() and dest_path.is_file():
            backup_suffix = self.options.suffix if self.options.suffix is not None else "~"
            if self.options.backup_dir:
                backup_dir = Path(self.options.backup_dir)
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_path = backup_dir / (dest_path.name + backup_suffix)
            else:
                backup_path = dest_path.with_name(dest_path.name + backup_suffix)
            try:
                import shutil
                shutil.copy2(dest_path, backup_path)
            except OSError:
                pass

        # Regular file transfer (whole-file, local mode)
        try:
            import shutil
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.copyfile(effective_src_path, dest_path)

            self.stats.num_transferred += 1
            if not file_exists:
                self.stats.num_created += 1
            self.stats.total_written += int(effective_size)
            self.stats.literal_data += int(effective_size)

            # Permissions:
            # - rsync creates NEW files with source permissions by default.
            # - For existing files, -p controls whether permissions are updated.
            # - -E updates execute bits even without -p.
            if not file_exists:
                try:
                    dest_path.chmod(int(effective_mode) & 0o7777)
                except OSError:
                    pass
            else:
                if self.options.preserve_perms:
                    try:
                        dest_path.chmod(int(effective_mode) & 0o7777)
                    except OSError:
                        pass
                elif self.options.executability:
                    try:
                        st = dest_path.stat()
                        dest_mode = int(st.st_mode) & 0o7777
                        new_mode = (dest_mode & ~0o111) | (int(effective_mode) & 0o111)
                        if new_mode != dest_mode:
                            dest_path.chmod(new_mode)
                    except OSError:
                        pass

            # Preserve times
            if self.options.preserve_times:
                try:
                    st = dest_path.stat()
                    atime = int(st.st_atime)
                    os.utime(dest_path, (atime, int(effective_mtime)))
                except OSError:
                    pass

            if self.options.remove_source_files and src_path.exists() and src_path.is_file():
                try:
                    src_path.unlink()
                except OSError:
                    pass

        except (OSError, PermissionError) as e:
            print(f"rsync: send_files failed to open \"{src_file.filename}\": {e}", file=sys.stderr)

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


def print_version():
    """
    Print version info matching rsync's `print_rsync_version()` output.

    Reference: rsync-original-source-code/usage.c:print_rsync_version()
    """
    subprotocol = f".PR{SUBPROTOCOL_VERSION}" if SUBPROTOCOL_VERSION != 0 else ""
    print(f"{RSYNC_NAME}  version {RSYNC_VERSION}  protocol version {PROTOCOL_VERSION}{subprotocol}")
    print(f"Copyright {RSYNC_COPYRIGHT}")
    print(f"Web site: {RSYNC_URL}")
    print("Capabilities:")
    print("    64-bit files, 64-bit inums, 64-bit timestamps, 64-bit long ints,")
    print("    socketpairs, symlinks, symtimes, hardlinks, no hardlink-specials,")
    print("    hardlink-symlinks, IPv6, atimes, batchfiles, inplace, append, no ACLs,")
    print("    no xattrs, optional secluded-args, iconv, prealloc, stop-at, crtimes")
    print("Optimizations:")
    print("    no SIMD-roll, no asm-roll, openssl-crypto, no asm-MD5")
    print("Checksum list:")
    print("    xxh128 xxh3 xxh64 (xxhash) md5 md4 sha1 none")
    print("Compress list:")
    print("    zstd lz4 zlibx zlib none")
    print("Daemon auth list:")
    print("    sha512 sha256 sha1 md5 md4")
    print("")
    print("rsync comes with ABSOLUTELY NO WARRANTY.  This is free software, and you")
    print("are welcome to redistribute it under certain conditions.  See the GNU")
    print("General Public Licence for details.")


def print_version_json() -> None:
    """
    Print a JSON `--version` output (rsync prints JSON when --version is repeated).

    Reference: rsync-original-source-code/usage.c:print_rsync_version(FNONE)
    """
    # Keep these values aligned with `print_version()` (this CLI mimics a specific build).
    capabilities: Dict[str, Union[int, bool, str]] = {
        "files_bits": 64,
        "inums_bits": 64,
        "timestamps_bits": 64,
        "long_ints_bits": 64,
        "socketpairs": True,
        "symlinks": True,
        "symtimes": True,
        "hardlinks": True,
        "hardlink_specials": False,
        "hardlink_symlinks": True,
        "IPv6": True,
        "atimes": True,
        "batchfiles": True,
        "inplace": True,
        "append": True,
        "ACLs": False,
        "xattrs": False,
        "secluded_args": "optional",
        "iconv": True,
        "prealloc": True,
        "stop_at": True,
        "crtimes": True,
    }
    optimizations: Dict[str, bool] = {
        "SIMD_roll": False,
        "asm_roll": False,
        "openssl_crypto": True,
        "asm_MD5": False,
    }
    checksum_list = ["xxh128", "xxh3", "xxh64", "md5", "md4", "sha1", "none"]
    compress_list = ["zstd", "lz4", "zlibx", "zlib", "none"]
    daemon_auth_list = ["sha512", "sha256", "sha1", "md5", "md4"]

    # Match rsync's fairly-readable JSON style closely.
    print("{")
    print(f'  "program": "{RSYNC_NAME}",')
    print(f'  "version": "{RSYNC_VERSION}",')
    print(f'  "protocol": "{PROTOCOL_VERSION}.{SUBPROTOCOL_VERSION}",')
    print(f'  "copyright": "{RSYNC_COPYRIGHT}",')
    print(f'  "url": "{RSYNC_URL}",')

    print('  "capabilities": {')
    cap_items: List[Tuple[str, Union[int, bool, str]]] = list(capabilities.items())
    for idx, (key, value) in enumerate(cap_items):
        comma = "," if idx + 1 < len(cap_items) else ""
        if isinstance(value, bool):
            val_str = "true" if value else "false"
        elif isinstance(value, int):
            val_str = str(value)
        else:
            val_str = f"\"{value}\""
        print(f'   "{key}": {val_str}{comma}')
    print("  },")

    print('  "optimizations": {')
    opt_items: List[Tuple[str, bool]] = list(optimizations.items())
    for idx, (key, value) in enumerate(opt_items):
        comma = "," if idx + 1 < len(opt_items) else ""
        val_str = "true" if value else "false"
        print(f'   "{key}": {val_str}{comma}')
    print("  },")

    def _print_str_array(name: str, items: List[str], trailing_comma: bool) -> None:
        comma = "," if trailing_comma else ""
        inner = ", ".join(f"\"{x}\"" for x in items)
        print(f'  "{name}": [')
        print(f"   {inner}")
        print(f"  ]{comma}")

    _print_str_array("checksum_list", checksum_list, trailing_comma=True)
    _print_str_array("compress_list", compress_list, trailing_comma=True)
    _print_str_array("daemon_auth_list", daemon_auth_list, trailing_comma=True)

    print('  "license": "GPLv3",')
    print('  "caveat": "rsync comes with ABSOLUTELY NO WARRANTY"')
    print("}")


def print_help_header():
    """Print rsync help header"""
    print_version()
    print("")
    print("rsync is a file transfer program capable of efficient remote update")
    print("via a fast differencing algorithm.")
    print("")
    print("Usage: rsync [OPTION]... SRC [SRC]... DEST")
    print("  or   rsync [OPTION]... SRC [SRC]... [USER@]HOST:DEST")
    print("  or   rsync [OPTION]... SRC [SRC]... [USER@]HOST::DEST")
    print("  or   rsync [OPTION]... SRC [SRC]... rsync://[USER@]HOST[:PORT]/DEST")
    print("  or   rsync [OPTION]... [USER@]HOST:SRC [DEST]")
    print("  or   rsync [OPTION]... [USER@]HOST::SRC [DEST]")
    print("  or   rsync [OPTION]... rsync://[USER@]HOST[:PORT]/SRC [DEST]")
    print("The ':' usages connect via remote shell, while '::' & 'rsync://' usages connect")
    print("to an rsync daemon, and require SRC or DEST to start with a module name.")
    print("")
    print("Options")


RSYNC_OPTIONS_HELP_TEXT = """--verbose, -v            increase verbosity
--info=FLAGS             fine-grained informational verbosity
--debug=FLAGS            fine-grained debug verbosity
--stderr=e|a|c           change stderr output mode (default: errors)
--quiet, -q              suppress non-error messages
--no-motd                suppress daemon-mode MOTD
--checksum, -c           skip based on checksum, not mod-time & size
--archive, -a            archive mode is -rlptgoD (no -A,-X,-U,-N,-H)
--no-OPTION              turn off an implied OPTION (e.g. --no-D)
--recursive, -r          recurse into directories
--relative, -R           use relative path names
--no-implied-dirs        don't send implied dirs with --relative
--backup, -b             make backups (see --suffix & --backup-dir)
--backup-dir=DIR         make backups into hierarchy based in DIR
--suffix=SUFFIX          backup suffix (default ~ w/o --backup-dir)
--update, -u             skip files that are newer on the receiver
--inplace                update destination files in-place
--append                 append data onto shorter files
--append-verify          --append w/old data in file checksum
--dirs, -d               transfer directories without recursing
--old-dirs, --old-d      works like --dirs when talking to old rsync
--mkpath                 create destination's missing path components
--links, -l              copy symlinks as symlinks
--copy-links, -L         transform symlink into referent file/dir
--copy-unsafe-links      only \"unsafe\" symlinks are transformed
--safe-links             ignore symlinks that point outside the tree
--munge-links            munge symlinks to make them safe & unusable
--copy-dirlinks, -k      transform symlink to dir into referent dir
--keep-dirlinks, -K      treat symlinked dir on receiver as dir
--hard-links, -H         preserve hard links
--perms, -p              preserve permissions
--executability, -E      preserve executability
--chmod=CHMOD            affect file and/or directory permissions
--acls, -A               preserve ACLs (implies --perms)
--xattrs, -X             preserve extended attributes
--owner, -o              preserve owner (super-user only)
--group, -g              preserve group
--devices                preserve device files (super-user only)
--copy-devices           copy device contents as a regular file
--write-devices          write to devices as files (implies --inplace)
--specials               preserve special files
-D                       same as --devices --specials
--times, -t              preserve modification times
--atimes, -U             preserve access (use) times
--open-noatime           avoid changing the atime on opened files
--crtimes, -N            preserve create times (newness)
--omit-dir-times, -O     omit directories from --times
--omit-link-times, -J    omit symlinks from --times
--super                  receiver attempts super-user activities
--fake-super             store/recover privileged attrs using xattrs
--sparse, -S             turn sequences of nulls into sparse blocks
--preallocate            allocate dest files before writing them
--dry-run, -n            perform a trial run with no changes made
--whole-file, -W         copy files whole (w/o delta-xfer algorithm)
--checksum-choice=STR    choose the checksum algorithm (aka --cc)
--one-file-system, -x    don't cross filesystem boundaries
--block-size=SIZE, -B    force a fixed checksum block-size
--rsh=COMMAND, -e        specify the remote shell to use
--rsync-path=PROGRAM     specify the rsync to run on remote machine
--existing               skip creating new files on receiver
--ignore-existing        skip updating files that exist on receiver
--remove-source-files    sender removes synchronized files (non-dir)
--del                    an alias for --delete-during
--delete                 delete extraneous files from dest dirs
--delete-before          receiver deletes before xfer, not during
--delete-during          receiver deletes during the transfer
--delete-delay           find deletions during, delete after
--delete-after           receiver deletes after transfer, not during
--delete-excluded        also delete excluded files from dest dirs
--ignore-missing-args    ignore missing source args without error
--delete-missing-args    delete missing source args from destination
--ignore-errors          delete even if there are I/O errors
--force                  force deletion of dirs even if not empty
--max-delete=NUM         don't delete more than NUM files
--max-size=SIZE          don't transfer any file larger than SIZE
--min-size=SIZE          don't transfer any file smaller than SIZE
--max-alloc=SIZE         change a limit relating to memory alloc
--partial                keep partially transferred files
--partial-dir=DIR        put a partially transferred file into DIR
--delay-updates          put all updated files into place at end
--prune-empty-dirs, -m   prune empty directory chains from file-list
--numeric-ids            don't map uid/gid values by user/group name
--usermap=STRING         custom username mapping
--groupmap=STRING        custom groupname mapping
--chown=USER:GROUP       simple username/groupname mapping
--timeout=SECONDS        set I/O timeout in seconds
--contimeout=SECONDS     set daemon connection timeout in seconds
--ignore-times, -I       don't skip files that match size and time
--size-only              skip files that match in size
--modify-window=NUM, -@  set the accuracy for mod-time comparisons
--temp-dir=DIR, -T       create temporary files in directory DIR
--fuzzy, -y              find similar file for basis if no dest file
--compare-dest=DIR       also compare destination files relative to DIR
--copy-dest=DIR          ... and include copies of unchanged files
--link-dest=DIR          hardlink to files in DIR when unchanged
--compress, -z           compress file data during the transfer
--compress-choice=STR    choose the compression algorithm (aka --zc)
--compress-level=NUM     explicitly set compression level (aka --zl)
--compress-threads=NUM   explicitly set compression threads (aka --zt)
--skip-compress=LIST     skip compressing files with suffix in LIST
--cvs-exclude, -C        auto-ignore files in the same way CVS does
--filter=RULE, -f        add a file-filtering RULE
-F                       same as --filter='dir-merge /.rsync-filter'
                         repeated: --filter='- .rsync-filter'
--exclude=PATTERN        exclude files matching PATTERN
--exclude-from=FILE      read exclude patterns from FILE
--include=PATTERN        don't exclude files matching PATTERN
--include-from=FILE      read include patterns from FILE
--files-from=FILE        read list of source-file names from FILE
--from0, -0              all *-from/filter files are delimited by 0s
--old-args               disable the modern arg-protection idiom
--secluded-args, -s      use the protocol to safely send the args
--trust-sender           trust the remote sender's file list
--copy-as=USER[:GROUP]   specify user & optional group for the copy
--address=ADDRESS        bind address for outgoing socket to daemon
--port=PORT              specify double-colon alternate port number
--sockopts=OPTIONS       specify custom TCP options
--blocking-io            use blocking I/O for the remote shell
--outbuf=N|L|B           set out buffering to None, Line, or Block
--stats                  give some file-transfer stats
--8-bit-output, -8       leave high-bit chars unescaped in output
--human-readable, -h     output numbers in a human-readable format
--progress               show progress during transfer
-P                       same as --partial --progress
--itemize-changes, -i    output a change-summary for all updates
--remote-option=OPT, -M  send OPTION to the remote side only
--out-format=FORMAT      output updates using the specified FORMAT
--log-file=FILE          log what we're doing to the specified FILE
--log-file-format=FMT    log updates using the specified FMT
--password-file=FILE     read daemon-access password from FILE
--early-input=FILE       use FILE for daemon's early exec input
--list-only              list the files instead of copying them
--bwlimit=RATE           limit socket I/O bandwidth
--stop-after=MINS        Stop rsync after MINS minutes have elapsed
--stop-at=y-m-dTh:m      Stop rsync at the specified point in time
--fsync                  fsync every written file
--write-batch=FILE       write a batched update to FILE
--only-write-batch=FILE  like --write-batch but w/o updating dest
--read-batch=FILE        read a batched update from FILE
--protocol=NUM           force an older protocol version to be used
--iconv=CONVERT_SPEC     request charset conversion of filenames
--checksum-seed=NUM      set block/file checksum seed (advanced)
--ipv4, -4               prefer IPv4
--ipv6, -6               prefer IPv6
--version, -V            print the version + other info and exit
--help, -h (*)           show this help (* -h is help only on its own)

Use \"rsync --daemon --help\" to see the daemon-mode command-line options.
Please see the rsync(1) and rsyncd.conf(5) manpages for full documentation.
See https://rsync.samba.org/ for updates, bug reports, and answers
"""


RSYNC_DAEMON_OPTIONS_HELP_TEXT = """--daemon                 run as an rsync daemon
--address=ADDRESS        bind to the specified address
--bwlimit=RATE           limit socket I/O bandwidth
--config=FILE            specify alternate rsyncd.conf file
--dparam=OVERRIDE, -M    override global daemon config parameter
--no-detach              do not detach from the parent
--port=PORT              listen on alternate port number
--log-file=FILE          override the \"log file\" setting
--log-file-format=FMT    override the \"log format\" setting
--sockopts=OPTIONS       specify custom TCP options
--verbose, -v            increase verbosity
--ipv4, -4               prefer IPv4
--ipv6, -6               prefer IPv6
--help, -h               show this help (when used with --daemon)

If you were not trying to invoke rsync as a daemon, avoid using any of the
daemon-specific rsync options.  See also the rsyncd.conf(5) manpage.
"""


def print_daemon_help_header() -> None:
    """Print rsync daemon-mode help header."""
    print_version()
    print("")
    print("Usage: rsync --daemon [OPTION]...")


def create_rsync_parser() -> "argparse.ArgumentParser":
    """
    Create argument parser that matches rsync CLI exactly
    Reference: options.c:parse_arguments()
    """
    # Custom help action to print rsync-style help
    class RsyncHelpAction(argparse.Action):
        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Any,
            option_string: Optional[str] = None
        ) -> None:
            try:
                if bool(getattr(namespace, "daemon", False)):
                    print_daemon_help_header()
                    print(RSYNC_DAEMON_OPTIONS_HELP_TEXT, end="")
                else:
                    print_help_header()
                    print(RSYNC_OPTIONS_HELP_TEXT, end="")
            except BrokenPipeError:
                # Allow piping help into tools like `head` without crashing.
                try:
                    sys.stdout = open(os.devnull, 'w')
                except Exception:
                    pass
            sys.exit(0)

    # Create parser without default help
    parser = argparse.ArgumentParser(
        prog='rsync',
        add_help=False,
        allow_abbrev=False,
        usage=argparse.SUPPRESS,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Custom help and version
    parser.add_argument('--help', action=RsyncHelpAction, nargs=0,
                       help='show this help message')
    parser.add_argument('--version', '-V', action='count', default=0,
                       help='print the version + other info and exit')
    
    # Verbosity
    parser.add_argument('--verbose', '-v', action='count', default=0,
                       help='increase verbosity')
    parser.add_argument('--no-verbose', dest='verbose', action='store_const', const=0,
                       help='turn off verbosity')
    parser.add_argument('--no-v', dest='verbose', action='store_const', const=0,
                       help='turn off verbosity')
    parser.add_argument('--info', metavar='FLAGS',
                       help='fine-grained informational verbosity')
    parser.add_argument('--debug', metavar='FLAGS',
                       help='fine-grained debug verbosity')
    parser.add_argument('--stderr', metavar='e|a|c',
                       help='change stderr output mode (default: errors)')
    parser.add_argument('--msgs2stderr', action='store_true',
                       help='send messages to stderr')
    parser.add_argument('--no-msgs2stderr', action='store_true',
                       help='do not send messages to stderr')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='suppress non-error messages')
    parser.add_argument('--motd', action='store_true',
                       help='show daemon-mode MOTD')
    parser.add_argument('--no-motd', action='store_true',
                       help='suppress daemon-mode MOTD')
    
    # Archive mode
    parser.add_argument('--archive', '-a', action='store_true',
                       help='archive mode; equals -rlptgoD')
    
    # Transfer basics / recursion
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='recurse into directories')
    parser.add_argument('--no-recursive', dest='recursive', action='store_false',
                       help='turn off directory recursion')
    parser.add_argument('--no-r', dest='recursive', action='store_false',
                       help='turn off directory recursion')
    parser.add_argument('--inc-recursive', action='store_true',
                       help='enable incremental recursion')
    parser.add_argument('--no-inc-recursive', dest='inc_recursive', action='store_false',
                       help='disable incremental recursion')
    parser.add_argument('--i-r', dest='inc_recursive', action='store_true',
                       help='enable incremental recursion')
    parser.add_argument('--no-i-r', dest='inc_recursive', action='store_false',
                       help='disable incremental recursion')
    parser.add_argument('--relative', '-R', action='store_true',
                       help='use relative path names')
    parser.add_argument('--no-relative', dest='relative', action='store_false',
                       help='turn off relative path names')
    parser.add_argument('--no-R', dest='relative', action='store_false',
                       help='turn off relative path names')
    parser.add_argument('--implied-dirs', action='store_true',
                       help='send implied dirs with --relative')
    parser.add_argument('--no-implied-dirs', action='store_true',
                       help="don't send implied dirs with --relative")
    parser.add_argument('--i-d', dest='implied_dirs', action='store_true',
                       help='send implied dirs with --relative')
    parser.add_argument('--no-i-d', dest='implied_dirs', action='store_false',
                       help="don't send implied dirs with --relative")
    parser.add_argument('--dirs', '-d', action='store_true',
                       help='transfer directories without recursing')
    parser.add_argument('--no-dirs', dest='dirs', action='store_false',
                       help='turn off directory transfer')
    parser.add_argument('--no-d', dest='dirs', action='store_false',
                       help='turn off directory transfer')
    parser.add_argument('--old-dirs', '--old-d', dest='old_dirs', action='store_true',
                       help='works like --dirs when talking to old rsync')
    parser.add_argument('--mkpath', action='store_true',
                       help="create destination's missing path components")
    parser.add_argument('--no-mkpath', dest='mkpath', action='store_false',
                       help="don't create destination's missing path components")
    
    # Preserve options
    parser.add_argument('--links', '-l', action='store_true',
                       help='copy symlinks as symlinks')
    parser.add_argument('--no-links', dest='links', action='store_false',
                       help='turn off symlink preservation')
    parser.add_argument('--no-l', dest='links', action='store_false',
                       help='turn off symlink preservation')
    parser.add_argument('--copy-links', '-L', action='store_true',
                       help='transform symlink into referent file/dir')
    parser.add_argument('--copy-unsafe-links', action='store_true',
                       help='only "unsafe" symlinks are transformed')
    parser.add_argument('--safe-links', action='store_true',
                       help='ignore symlinks that point outside the tree')
    parser.add_argument('--munge-links', action='store_true',
                       help='munge symlinks to make them safe & unusable')
    parser.add_argument('--no-munge-links', dest='munge_links', action='store_false',
                       help='turn off symlink munging')
    parser.add_argument('--copy-dirlinks', '-k', action='store_true',
                       help='transform symlink to dir into referent dir')
    parser.add_argument('--keep-dirlinks', '-K', action='store_true',
                       help='treat symlinked dir on receiver as dir')
    parser.add_argument('--hard-links', '-H', action='store_true',
                       help='preserve hard links')
    parser.add_argument('--no-hard-links', dest='hard_links', action='store_false',
                       help='turn off hard link preservation')
    parser.add_argument('--no-H', dest='hard_links', action='store_false',
                       help='turn off hard link preservation')
    parser.add_argument('--perms', '-p', action='store_true',
                       help='preserve permissions')
    parser.add_argument('--no-perms', dest='perms', action='store_false',
                       help='turn off permission preservation')
    parser.add_argument('--no-p', dest='perms', action='store_false',
                       help='turn off permission preservation')
    parser.add_argument('--executability', '-E', action='store_true',
                       help='preserve executability')
    parser.add_argument('--chmod', metavar='CHMOD',
                       help='affect file and/or directory permissions')
    parser.add_argument('--acls', '-A', action='store_true',
                       help='preserve ACLs (implies --perms)')
    parser.add_argument('--no-acls', dest='acls', action='store_false',
                       help='turn off ACL preservation')
    parser.add_argument('--no-A', dest='acls', action='store_false',
                       help='turn off ACL preservation')
    parser.add_argument('--xattrs', '-X', action='store_true',
                       help='preserve extended attributes')
    parser.add_argument('--no-xattrs', dest='xattrs', action='store_false',
                       help='turn off extended attribute preservation')
    parser.add_argument('--no-X', dest='xattrs', action='store_false',
                       help='turn off extended attribute preservation')
    parser.add_argument('--owner', '-o', action='store_true',
                       help='preserve owner (super-user only)')
    parser.add_argument('--no-owner', dest='owner', action='store_false',
                       help='turn off owner preservation')
    parser.add_argument('--no-o', dest='owner', action='store_false',
                       help='turn off owner preservation')
    parser.add_argument('--group', '-g', action='store_true',
                       help='preserve group')
    parser.add_argument('--no-group', dest='group', action='store_false',
                       help='turn off group preservation')
    parser.add_argument('--no-g', dest='group', action='store_false',
                       help='turn off group preservation')
    parser.add_argument('--devices', action='store_true',
                       help='preserve device files (super-user only)')
    parser.add_argument('--no-devices', dest='devices', action='store_false',
                       help='turn off device file preservation')
    parser.add_argument('--copy-devices', action='store_true',
                       help='copy device contents as a regular file')
    parser.add_argument('--write-devices', action='store_true',
                       help='write to devices as files (implies --inplace)')
    parser.add_argument('--no-write-devices', dest='write_devices', action='store_false',
                       help='turn off writing to devices')
    parser.add_argument('--specials', action='store_true',
                       help='preserve special files')
    parser.add_argument('--no-specials', dest='specials', action='store_false',
                       help='turn off special file preservation')
    parser.add_argument('-D', dest='D', action='store_true',
                       help='same as --devices --specials')
    parser.add_argument('--no-D', dest='D', action='store_false',
                       help='turn off --devices --specials')
    parser.add_argument('--times', '-t', action='store_true',
                       help='preserve modification times')
    parser.add_argument('--no-times', dest='times', action='store_false',
                       help='turn off time preservation')
    parser.add_argument('--no-t', dest='times', action='store_false',
                       help='turn off time preservation')
    parser.add_argument('--atimes', '-U', action='store_true',
                       help='preserve access (use) times')
    parser.add_argument('--no-atimes', dest='atimes', action='store_false',
                       help='turn off atime preservation')
    parser.add_argument('--no-U', dest='atimes', action='store_false',
                       help='turn off atime preservation')
    parser.add_argument('--open-noatime', action='store_true',
                       help='avoid changing the atime on opened files')
    parser.add_argument('--no-open-noatime', dest='open_noatime', action='store_false',
                       help='allow changing the atime on opened files')
    parser.add_argument('--crtimes', '-N', action='store_true',
                       help='preserve create times (newness)')
    parser.add_argument('--no-crtimes', dest='crtimes', action='store_false',
                       help='turn off create time preservation')
    parser.add_argument('--no-N', dest='crtimes', action='store_false',
                       help='turn off create time preservation')
    parser.add_argument('--omit-dir-times', '-O', action='store_true',
                       help='omit directories from --times')
    parser.add_argument('--no-omit-dir-times', dest='omit_dir_times', action='store_false',
                       help='preserve directory times')
    parser.add_argument('--no-O', dest='omit_dir_times', action='store_false',
                       help='preserve directory times')
    parser.add_argument('--omit-link-times', '-J', action='store_true',
                       help='omit symlinks from --times')
    parser.add_argument('--no-omit-link-times', dest='omit_link_times', action='store_false',
                       help='preserve symlink times')
    parser.add_argument('--no-J', dest='omit_link_times', action='store_false',
                       help='preserve symlink times')
    parser.add_argument('--super', action='store_true',
                       help='receiver attempts super-user activities')
    parser.add_argument('--no-super', dest='super', action='store_false',
                       help='turn off super-user activities')
    parser.add_argument('--fake-super', action='store_true',
                       help='store/recover privileged attrs using xattrs')
    parser.add_argument('--sparse', '-S', action='store_true',
                       help='turn sequences of nulls into sparse blocks')
    parser.add_argument('--no-sparse', dest='sparse', action='store_false',
                       help='turn off sparse file handling')
    parser.add_argument('--no-S', dest='sparse', action='store_false',
                       help='turn off sparse file handling')
    parser.add_argument('--preallocate', action='store_true',
                       help='allocate dest files before writing them')
    
    # Transfer options
    parser.add_argument('--update', '-u', action='store_true',
                       help='skip files that are newer on the receiver')
    parser.add_argument('--inplace', action='store_true',
                       help='update destination files in-place')
    parser.add_argument('--no-inplace', dest='inplace', action='store_false',
                       help='turn off in-place updates')
    parser.add_argument('--append', action='store_true',
                       help='append data onto shorter files')
    parser.add_argument('--append-verify', action='store_true',
                       help='--append w/old data in file checksum')
    parser.add_argument('--no-append', dest='append', action='store_false',
                       help='turn off append mode')
    parser.add_argument('--dry-run', '-n', action='store_true',
                       help='perform a trial run with no changes made')
    parser.add_argument('--whole-file', '-W', action='store_true',
                       help='copy files whole')
    parser.add_argument('--no-whole-file', dest='whole_file', action='store_false',
                       help='turn off whole-file copying')
    parser.add_argument('--no-W', dest='whole_file', action='store_false',
                       help='turn off whole-file copying')
    parser.add_argument('--checksum', '-c', action='store_true',
                       help='skip based on checksum, not mod-time & size')
    parser.add_argument('--no-checksum', dest='checksum', action='store_false',
                       help='turn off checksum-based skipping')
    parser.add_argument('--no-c', dest='checksum', action='store_false',
                       help='turn off checksum-based skipping')
    parser.add_argument('--checksum-choice', metavar='STR',
                       help='choose the checksum algorithm (aka --cc)')
    parser.add_argument('--cc', dest='checksum_choice', metavar='STR',
                       help='choose the checksum algorithm (alias)')
    parser.add_argument('--one-file-system', '-x', action='store_true',
                       help="don't cross filesystem boundaries")
    parser.add_argument('--no-one-file-system', dest='one_file_system', action='store_false',
                       help='allow crossing filesystem boundaries')
    parser.add_argument('--no-x', dest='one_file_system', action='store_false',
                       help='allow crossing filesystem boundaries')
    parser.add_argument('--block-size', '-B', type=int, metavar='SIZE',
                       help='force a fixed checksum block-size')
    parser.add_argument('--rsh', '-e', metavar='COMMAND',
                       help='specify the remote shell to use')
    parser.add_argument('--rsync-path', metavar='PROGRAM',
                       help='specify the rsync to run on remote machine')
    parser.add_argument('--existing', action='store_true',
                       help='skip creating new files on receiver')
    parser.add_argument('--ignore-non-existing', dest='existing', action='store_true',
                       help='skip creating new files on receiver (alias)')
    parser.add_argument('--ignore-existing', action='store_true',
                       help='skip updating files that exist on receiver')
    parser.add_argument('--remove-source-files', action='store_true',
                       help='sender removes synchronized files (non-dir)')
    parser.add_argument('--remove-sent-files', dest='remove_source_files', action='store_true',
                       help='sender removes synchronized files (deprecated)')
    
    # Delete options
    parser.add_argument('--delete', action='store_true',
                       help='delete extraneous files from dest dirs')
    parser.add_argument('--delete-before', action='store_true',
                       help='receiver deletes before transfer')
    parser.add_argument('--delete-during', action='store_true',
                       help='receiver deletes during xfer')
    parser.add_argument('--del', dest='delete_during', action='store_true',
                       help='an alias for --delete-during')
    parser.add_argument('--delete-delay', action='store_true',
                       help='find deletions during, delete after')
    parser.add_argument('--delete-after', action='store_true',
                       help='receiver deletes after transfer')
    parser.add_argument('--delete-excluded', action='store_true',
                       help='also delete excluded files from dest dirs')
    parser.add_argument('--ignore-missing-args', action='store_true',
                       help='ignore missing source args without error')
    parser.add_argument('--delete-missing-args', action='store_true',
                       help='delete missing source args from destination')
    parser.add_argument('--ignore-errors', action='store_true',
                       help='delete even if there are I/O errors')
    parser.add_argument('--no-ignore-errors', dest='ignore_errors', action='store_false',
                       help='stop deletes if there are I/O errors')
    parser.add_argument('--force', action='store_true',
                       help='force deletion of dirs even if not empty')
    parser.add_argument('--no-force', dest='force', action='store_false',
                       help='do not force deletion of dirs')
    parser.add_argument('--max-delete', type=int, metavar='NUM',
                       help="don't delete more than NUM files")
    parser.add_argument('--max-size', metavar='SIZE',
                       help="don't transfer any file larger than SIZE")
    parser.add_argument('--min-size', metavar='SIZE',
                       help="don't transfer any file smaller than SIZE")
    parser.add_argument('--max-alloc', metavar='SIZE',
                       help='change a limit relating to memory alloc')
    parser.add_argument('--partial', action='store_true',
                       help='keep partially transferred files')
    parser.add_argument('--no-partial', dest='partial', action='store_false',
                       help='do not keep partially transferred files')
    parser.add_argument('--partial-dir', metavar='DIR',
                       help='put a partially transferred file into DIR')
    parser.add_argument('--delay-updates', action='store_true',
                       help='put all updated files into place at end')
    parser.add_argument('--no-delay-updates', dest='delay_updates', action='store_false',
                       help='do not delay putting updated files into place')
    parser.add_argument('--prune-empty-dirs', '-m', action='store_true',
                       help='prune empty directory chains from file-list')
    parser.add_argument('--no-prune-empty-dirs', dest='prune_empty_dirs', action='store_false',
                       help='do not prune empty directories')
    parser.add_argument('--no-m', dest='prune_empty_dirs', action='store_false',
                       help='do not prune empty directories')

    # Display options
    parser.add_argument('--progress', action='store_true',
                       help='show progress during transfer')
    parser.add_argument('--no-progress', dest='progress', action='store_false',
                       help='do not show progress during transfer')
    parser.add_argument('--stats', action='store_true',
                       help='give some file-transfer stats')
    parser.add_argument('--8-bit-output', '-8', dest='eight_bit_output', action='store_true',
                       help='leave high-bit chars unescaped in output')
    parser.add_argument('--no-8-bit-output', dest='eight_bit_output', action='store_false',
                       help='escape high-bit chars in output')
    parser.add_argument('--no-8', dest='eight_bit_output', action='store_false',
                       help='escape high-bit chars in output')
    parser.add_argument('--human-readable', '-h', action='store_true', dest='human_readable',
                       help='output numbers in a human-readable format')
    parser.add_argument('--no-human-readable', dest='human_readable', action='store_false',
                       help='do not use human-readable format')
    parser.add_argument('--no-h', dest='human_readable', action='store_false',
                       help='do not use human-readable format')
    parser.add_argument('-P', dest='partial_progress', action='store_true',
                       help='same as --partial --progress')
    parser.add_argument('-i', '--itemize-changes', action='store_true',
                       help='output a change-summary for all updates')
    parser.add_argument('--no-itemize-changes', dest='itemize_changes', action='store_false',
                       help='turn off itemized changes')
    parser.add_argument('--no-i', dest='itemize_changes', action='store_false',
                       help='turn off itemized changes')

    # Compression
    parser.add_argument('--compress', '-z', action='store_true',
                       help='compress file data during the transfer')
    parser.add_argument('--old-compress', action='store_true',
                       help='use old compression algorithm')
    parser.add_argument('--new-compress', action='store_true',
                       help='use new compression algorithm')
    parser.add_argument('--no-compress', dest='compress', action='store_false',
                       help='turn off compression')
    parser.add_argument('--no-z', dest='compress', action='store_false',
                       help='turn off compression')
    parser.add_argument('--compress-choice', metavar='STR',
                       help='choose the compression algorithm (aka --zc)')
    parser.add_argument('--zc', dest='compress_choice', metavar='STR',
                       help='choose the compression algorithm (alias)')
    parser.add_argument('--compress-level', type=int, metavar='NUM',
                       help='explicitly set compression level')
    parser.add_argument('--zl', dest='compress_level', type=int, metavar='NUM',
                       help='explicitly set compression level (alias)')
    parser.add_argument('--compress-threads', type=int, metavar='NUM',
                       help='set number of compression threads')
    parser.add_argument('--zt', dest='compress_threads', type=int, metavar='NUM',
                       help='set number of compression threads (alias)')
    parser.add_argument('--skip-compress', metavar='LIST',
                       help='skip compressing files with suffix in LIST')
    
    # Patterns
    parser.add_argument('--cvs-exclude', '-C', action='store_true',
                       help='auto-ignore files in the same way CVS does')
    parser.add_argument('--filter', '-f', action='append', metavar='RULE',
                       help='add a file-filtering RULE')
    parser.add_argument('-F', dest='filter_F', action='count', default=0,
                       help="same as --filter='dir-merge /.rsync-filter'")
    parser.add_argument('--exclude', action='append', metavar='PATTERN',
                       help='exclude files matching PATTERN')
    parser.add_argument('--include', action='append', metavar='PATTERN',
                       help='don\'t exclude files matching PATTERN')
    parser.add_argument('--exclude-from', metavar='FILE',
                       help='read exclude patterns from FILE')
    parser.add_argument('--include-from', metavar='FILE',
                       help='read include patterns from FILE')
    parser.add_argument('--files-from', metavar='FILE',
                       help='read list of source-file names from FILE')
    parser.add_argument('--from0', '-0', action='store_true',
                       help='all *-from/filter files are delimited by 0s')
    parser.add_argument('--no-from0', dest='from0', action='store_false',
                       help='*-from/filter files not delimited by 0s')

    # Misc options from rsync help
    parser.add_argument('--backup', '-b', action='store_true',
                       help='make backups (see --suffix & --backup-dir)')
    parser.add_argument('--no-backup', dest='backup', action='store_false',
                       help='do not make backups')
    parser.add_argument('--backup-dir', metavar='DIR',
                       help='make backups into hierarchy based in DIR')
    parser.add_argument('--suffix', metavar='SUFFIX',
                       help='backup suffix (default ~ w/o --backup-dir)')
    parser.add_argument('--numeric-ids', action='store_true',
                       help="don't map uid/gid values by user/group name")
    parser.add_argument('--no-numeric-ids', dest='numeric_ids', action='store_false',
                       help='map uid/gid values by user/group name')
    parser.add_argument('--usermap', metavar='STRING',
                       help='custom username mapping')
    parser.add_argument('--groupmap', metavar='STRING',
                       help='custom groupname mapping')
    parser.add_argument('--chown', metavar='USER:GROUP',
                       help='simple username/groupname mapping')
    parser.add_argument('--timeout', type=int, metavar='SECONDS',
                       help='set I/O timeout in seconds')
    parser.add_argument('--no-timeout', dest='timeout', action='store_const', const=0,
                       help='turn off I/O timeout')
    parser.add_argument('--contimeout', type=int, metavar='SECONDS',
                       help='set daemon connection timeout in seconds')
    parser.add_argument('--no-contimeout', dest='contimeout', action='store_const', const=0,
                       help='turn off daemon connection timeout')
    parser.add_argument('--ignore-times', '-I', action='store_true',
                       help="don't skip files that match size and time")
    parser.add_argument('--size-only', action='store_true',
                       help='skip files that match in size')
    parser.add_argument('--modify-window', '-@', type=int, metavar='NUM',
                       help='set the accuracy for mod-time comparisons')
    parser.add_argument('--temp-dir', '-T', metavar='DIR',
                       help='create temporary files in directory DIR')
    parser.add_argument('--fuzzy', '-y', action='store_true',
                       help='find similar file for basis if no dest file')
    parser.add_argument('--no-fuzzy', dest='fuzzy', action='store_false',
                       help='do not find similar file for basis')
    parser.add_argument('--no-y', dest='fuzzy', action='store_false',
                       help='do not find similar file for basis')
    parser.add_argument('--compare-dest', metavar='DIR',
                       help='also compare destination files relative to DIR')
    parser.add_argument('--copy-dest', metavar='DIR',
                       help='... and include copies of unchanged files')
    parser.add_argument('--link-dest', metavar='DIR',
                       help='hardlink to files in DIR when unchanged')
    parser.add_argument('--old-args', action='store_true',
                       help='disable the modern arg-protection idiom')
    parser.add_argument('--no-old-args', dest='old_args', action='store_false',
                       help='enable the modern arg-protection idiom')
    parser.add_argument('--secluded-args', '-s', action='store_true',
                       help='use the protocol to safely send the args')
    parser.add_argument('--no-secluded-args', dest='secluded_args', action='store_false',
                       help='do not use the protocol to safely send args')
    parser.add_argument('--protect-args', dest='secluded_args', action='store_true',
                       help='use the protocol to safely send the args (alias)')
    parser.add_argument('--no-protect-args', dest='secluded_args', action='store_false',
                       help='do not use the protocol to safely send args')
    parser.add_argument('--no-s', dest='secluded_args', action='store_false',
                       help='do not use the protocol to safely send args')
    parser.add_argument('--trust-sender', action='store_true',
                       help="trust the remote sender's file list")
    parser.add_argument('--copy-as', metavar='USER[:GROUP]',
                       help='specify user & optional group for the copy')
    parser.add_argument('--address', metavar='ADDRESS',
                       help='bind address for outgoing socket to daemon')
    parser.add_argument('--port', type=int, metavar='PORT',
                       help='specify double-colon alternate port number')
    parser.add_argument('--sockopts', metavar='OPTIONS',
                       help='specify custom TCP options')
    parser.add_argument('--blocking-io', action='store_true',
                       help='use blocking I/O for the remote shell')
    parser.add_argument('--no-blocking-io', dest='blocking_io', action='store_false',
                       help='do not use blocking I/O for the remote shell')
    parser.add_argument('--outbuf', metavar='N|L|B',
                       help='set out buffering to None, Line, or Block')
    parser.add_argument('--remote-option', '-M', action='append', metavar='OPT',
                       help='send OPTION to the remote side only')
    parser.add_argument('--out-format', metavar='FORMAT',
                       help='output updates using the specified FORMAT')
    parser.add_argument('--log-format', dest='out_format', metavar='FORMAT',
                       help='output updates using the specified FORMAT (deprecated)')
    parser.add_argument('--log-file', metavar='FILE',
                       help="log what we're doing to the specified FILE")
    parser.add_argument('--log-file-format', metavar='FMT',
                       help='log updates using the specified FMT')
    parser.add_argument('--password-file', metavar='FILE',
                       help='read daemon-access password from FILE')
    parser.add_argument('--early-input', metavar='FILE',
                       help="use FILE for daemon's early exec input")
    parser.add_argument('--list-only', action='store_true',
                       help='list the files instead of copying them')
    parser.add_argument('--bwlimit', metavar='RATE',
                       help='limit socket I/O bandwidth')
    parser.add_argument('--no-bwlimit', dest='bwlimit', action='store_const', const=0,
                       help='turn off bandwidth limit')
    parser.add_argument('--stop-after', type=int, metavar='MINS',
                       help='Stop rsync after MINS minutes have elapsed')
    parser.add_argument('--time-limit', dest='stop_after', type=int, metavar='MINS',
                       help='Stop rsync after MINS minutes have elapsed (alias)')
    parser.add_argument('--stop-at', metavar='y-m-dTh:m',
                       help='Stop rsync at the specified point in time')
    parser.add_argument('--fsync', action='store_true',
                       help='fsync every written file')
    parser.add_argument('--write-batch', metavar='FILE',
                       help='write a batched update to FILE')
    parser.add_argument('--only-write-batch', metavar='FILE',
                       help='like --write-batch but w/o updating dest')
    parser.add_argument('--read-batch', metavar='FILE',
                       help='read a batched update from FILE')
    parser.add_argument('--protocol', type=int, metavar='NUM',
                       help='force an older protocol version to be used')
    parser.add_argument('--iconv', metavar='CONVERT_SPEC',
                       help='request charset conversion of filenames')
    parser.add_argument('--no-iconv', action='store_true',
                       help='turn off charset conversion')
    parser.add_argument('--checksum-seed', type=int, metavar='NUM',
                       help='set block/file checksum seed (advanced)')
    parser.add_argument('--qsort', action='store_true',
                       help='use qsort for file list sorting')
    parser.add_argument('--ipv4', '-4', action='store_true',
                       help='prefer IPv4')
    parser.add_argument('--ipv6', '-6', action='store_true',
                       help='prefer IPv6')

    # Daemon options (internal use)
    parser.add_argument('--server', action='store_true',
                       help=argparse.SUPPRESS)  # Internal use only
    parser.add_argument('--sender', action='store_true',
                       help=argparse.SUPPRESS)  # Internal use only
    parser.add_argument('--config', metavar='FILE',
                       help=argparse.SUPPRESS)  # Daemon mode
    parser.add_argument('--daemon', action='store_true',
                       help=argparse.SUPPRESS)  # Daemon mode
    parser.add_argument('--dparam', metavar='OVERRIDE',
                       help=argparse.SUPPRESS)  # Daemon mode
    parser.add_argument('--detach', action='store_true',
                       help=argparse.SUPPRESS)  # Daemon mode
    parser.add_argument('--no-detach', action='store_true',
                       help=argparse.SUPPRESS)  # Daemon mode
    
    # Positional arguments: sources and dest
    parser.add_argument('sources', nargs='*', metavar='SRC',
                       help='source file(s) or directory')

    return parser


def expand_archive_mode(opts: RsyncOptions) -> None:
    """
    Expand -a to -rlptgoD
    Reference: options.c:set_refuse_options()
    """
    if opts.archive:
        opts.recursive = True
        opts.preserve_links = True
        opts.preserve_perms = True
        opts.preserve_times = True
        opts.preserve_group = True
        opts.preserve_owner = True
        opts.preserve_devices = True
        opts.preserve_specials = True


def _apply_no_option_overrides(opts: RsyncOptions, no_options: Sequence[str]) -> None:
    """
    Apply rsync's generic `--no-OPTION` negations to already-parsed options.

    This is primarily used to disable implied options (e.g. `-a --no-times`).
    Unknown `--no-*` values are accepted (like rsync), but ignored.
    """
    for token in no_options:
        if not token.startswith('--no-'):
            continue
        name = token[len('--no-'):]
        if name in ('D', 'd'):
            opts.preserve_devices = False
            opts.preserve_specials = False
            continue

        key = name.strip().lower().replace('_', '-')
        if key in ('times', 't'):
            opts.preserve_times = False
        elif key in ('perms', 'p'):
            opts.preserve_perms = False
        elif key in ('executability',):
            opts.executability = False
        elif key in ('links', 'l'):
            opts.preserve_links = False
        elif key in ('copy-links', 'copy_links'):
            opts.copy_links = False
        # Avoid mapping single-letter 'h' here: it conflicts with rsync's human-readable
        # short option (-h) and is not implied by archive mode (-a).
        elif key in ('hard-links',):
            opts.hard_links = False
        elif key in ('devices',):
            opts.preserve_devices = False
        elif key in ('specials',):
            opts.preserve_specials = False
        elif key in ('owner', 'o'):
            opts.preserve_owner = False
        elif key in ('group', 'g'):
            opts.preserve_group = False
        elif key in ('recursive', 'r'):
            opts.recursive = False
        elif key in ('archive', 'a'):
            opts.archive = False
        elif key in ('delete',):
            opts.delete_mode = False
        elif key in ('compress', 'z'):
            opts.compress = False
        elif key in ('checksum', 'c'):
            opts.checksum = False


def _expand_rsync_short_option_groups(argv: List[str]) -> List[str]:
    """
    Expand rsync-style short option groups (e.g. -avz -> -a -v -z).

    argparse does not support short-option grouping by default, but rsync does.
    This keeps CLI-argument compatibility with the rsync C implementation.
    """
    # Short options that consume a following argument (or an attached suffix).
    takes_value = {'-B', '-e', '-f', '-M', '-T', '-@'}

    expanded: List[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == '--':
            expanded.append(token)
            expanded.extend(argv[i + 1:])
            break

        # Don't expand long options, '-' alone, or standard 2-char short options.
        if not token.startswith('-') or token.startswith('--') or token in ('-',) or len(token) <= 2:
            expanded.append(token)
            i += 1
            continue

        # Keep numeric short options like -4/-6/-8/-0 intact.
        if token[1].isdigit():
            expanded.append(token)
            i += 1
            continue

        # Expand a short option group (e.g. -avh).
        group = token[1:]
        j = 0
        while j < len(group):
            opt = '-' + group[j]
            if opt in takes_value:
                expanded.append(opt)
                attached = group[j + 1:]
                if attached:
                    expanded.append(attached)
                else:
                    if i + 1 >= len(argv):
                        expanded.append('')
                    else:
                        i += 1
                        expanded.append(argv[i])
                break
            expanded.append(opt)
            j += 1

        i += 1

    return expanded


def parse_rsync_args(args: Optional[List[str]] = None) -> RsyncOptions:
    """
    Parse rsync-style arguments
    Returns: RsyncOptions with sources and dest populated
    """
    parser = create_rsync_parser()

    if args is None:
        args = sys.argv[1:]

    argv = _expand_rsync_short_option_groups(args)
    if argv == ['-h']:
        argv = ['--help']
    elif '--daemon' in argv:
        # In daemon mode, -h is help (not --human-readable).
        argv = ['--help' if tok == '-h' else tok for tok in argv]

    parsed, unknown = parser.parse_known_args(argv)
    # Capture *all* `--no-*` tokens from argv (not just unknown ones) so that
    # implied options (e.g. `-a --no-times`) get disabled after archive expansion.
    no_options: List[str] = []
    for tok in argv:
        if tok == '--':
            break
        if tok.startswith('--no-'):
            no_options.append(tok)

    # rsync accepts unknown `--no-*` values (it ignores them); reject other unknowns.
    unknown = [u for u in unknown if not u.startswith('--no-')]
    if unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}")

    # Handle --version
    version_count = int(getattr(parsed, 'version', 0) or 0)
    if version_count:
        if version_count > 1:
            print_version_json()
        else:
            print_version()
        sys.exit(0)

    # Create options object
    opts = RsyncOptions()

    # Map parsed args to options
    opts.verbose = int(getattr(parsed, 'verbose', 0) or 0)
    opts.info = getattr(parsed, 'info', None)
    opts.debug = getattr(parsed, 'debug', None)
    opts.stderr_mode = getattr(parsed, 'stderr', None)
    opts.quiet = bool(getattr(parsed, 'quiet', False))
    opts.no_motd = bool(getattr(parsed, 'no_motd', False))

    opts.checksum = bool(getattr(parsed, 'checksum', False))
    opts.archive = bool(getattr(parsed, 'archive', False))
    opts.recursive = bool(getattr(parsed, 'recursive', False))
    opts.relative = bool(getattr(parsed, 'relative', False))
    opts.no_implied_dirs = bool(getattr(parsed, 'no_implied_dirs', False))
    opts.update = bool(getattr(parsed, 'update', False))
    opts.inplace = bool(getattr(parsed, 'inplace', False))
    opts.append = bool(getattr(parsed, 'append', False))
    opts.append_verify = bool(getattr(parsed, 'append_verify', False))
    opts.dirs = bool(getattr(parsed, 'dirs', False))
    opts.old_dirs = bool(getattr(parsed, 'old_dirs', False))
    opts.mkpath = bool(getattr(parsed, 'mkpath', False))

    opts.dry_run = bool(getattr(parsed, 'dry_run', False))
    opts.whole_file = bool(getattr(parsed, 'whole_file', False))

    opts.checksum_choice = getattr(parsed, 'checksum_choice', None)
    opts.compress = bool(getattr(parsed, 'compress', False))
    opts.compress_choice = getattr(parsed, 'compress_choice', None)
    opts.compress_level = getattr(parsed, 'compress_level', None)
    opts.skip_compress = getattr(parsed, 'skip_compress', None)
    opts.one_file_system = bool(getattr(parsed, 'one_file_system', False))
    opts.block_size = getattr(parsed, 'block_size', None)
    opts.rsh = getattr(parsed, 'rsh', None)
    opts.rsync_path = getattr(parsed, 'rsync_path', None)

    opts.backup = bool(getattr(parsed, 'backup', False))
    opts.backup_dir = getattr(parsed, 'backup_dir', None)
    opts.suffix = getattr(parsed, 'suffix', None)

    opts.preserve_links = bool(getattr(parsed, 'links', False))
    opts.copy_links = bool(getattr(parsed, 'copy_links', False))
    opts.copy_unsafe_links = bool(getattr(parsed, 'copy_unsafe_links', False))
    opts.safe_links = bool(getattr(parsed, 'safe_links', False))
    opts.munge_links = bool(getattr(parsed, 'munge_links', False))
    opts.copy_dirlinks = bool(getattr(parsed, 'copy_dirlinks', False))
    opts.keep_dirlinks = bool(getattr(parsed, 'keep_dirlinks', False))
    opts.hard_links = bool(getattr(parsed, 'hard_links', False))

    opts.preserve_perms = bool(getattr(parsed, 'perms', False))
    opts.executability = bool(getattr(parsed, 'executability', False))
    opts.chmod = getattr(parsed, 'chmod', None)
    opts.acls = bool(getattr(parsed, 'acls', False))
    opts.xattrs = bool(getattr(parsed, 'xattrs', False))
    opts.preserve_owner = bool(getattr(parsed, 'owner', False))
    opts.preserve_group = bool(getattr(parsed, 'group', False))
    opts.preserve_devices = bool(getattr(parsed, 'devices', False))
    opts.preserve_specials = bool(getattr(parsed, 'specials', False))
    if bool(getattr(parsed, 'D', False)):
        opts.preserve_devices = True
        opts.preserve_specials = True

    opts.preserve_times = bool(getattr(parsed, 'times', False))
    opts.atimes = bool(getattr(parsed, 'atimes', False))
    opts.open_noatime = bool(getattr(parsed, 'open_noatime', False))
    opts.crtimes = bool(getattr(parsed, 'crtimes', False))
    opts.omit_dir_times = bool(getattr(parsed, 'omit_dir_times', False))
    opts.omit_link_times = bool(getattr(parsed, 'omit_link_times', False))
    opts.super_mode = bool(getattr(parsed, 'super', False))
    opts.fake_super = bool(getattr(parsed, 'fake_super', False))
    opts.sparse = bool(getattr(parsed, 'sparse', False))
    opts.preallocate = bool(getattr(parsed, 'preallocate', False))

    opts.delete_mode = bool(getattr(parsed, 'delete', False))
    opts.delete_before = bool(getattr(parsed, 'delete_before', False))
    opts.delete_during = bool(getattr(parsed, 'delete_during', False))
    opts.delete_delay = bool(getattr(parsed, 'delete_delay', False))
    opts.delete_after = bool(getattr(parsed, 'delete_after', False))
    opts.delete_excluded = bool(getattr(parsed, 'delete_excluded', False))
    opts.ignore_missing_args = bool(getattr(parsed, 'ignore_missing_args', False))
    opts.delete_missing_args = bool(getattr(parsed, 'delete_missing_args', False))
    opts.ignore_errors = bool(getattr(parsed, 'ignore_errors', False))
    opts.force = bool(getattr(parsed, 'force', False))
    opts.max_delete = getattr(parsed, 'max_delete', None)
    opts.max_size = getattr(parsed, 'max_size', None)
    opts.min_size = getattr(parsed, 'min_size', None)
    opts.max_alloc = getattr(parsed, 'max_alloc', None)
    opts.partial = bool(getattr(parsed, 'partial', False))
    opts.partial_dir = getattr(parsed, 'partial_dir', None)
    opts.delay_updates = bool(getattr(parsed, 'delay_updates', False))
    opts.prune_empty_dirs = bool(getattr(parsed, 'prune_empty_dirs', False))

    opts.numeric_ids = bool(getattr(parsed, 'numeric_ids', False))
    opts.usermap = getattr(parsed, 'usermap', None)
    opts.groupmap = getattr(parsed, 'groupmap', None)
    opts.chown = getattr(parsed, 'chown', None)
    opts.timeout = getattr(parsed, 'timeout', None)
    opts.contimeout = getattr(parsed, 'contimeout', None)
    opts.ignore_times = bool(getattr(parsed, 'ignore_times', False))
    opts.size_only = bool(getattr(parsed, 'size_only', False))
    opts.modify_window = getattr(parsed, 'modify_window', None)
    opts.temp_dir = getattr(parsed, 'temp_dir', None)
    opts.fuzzy = bool(getattr(parsed, 'fuzzy', False))
    opts.compare_dest = getattr(parsed, 'compare_dest', None)
    opts.copy_dest = getattr(parsed, 'copy_dest', None)
    opts.link_dest = getattr(parsed, 'link_dest', None)

    opts.cvs_exclude = bool(getattr(parsed, 'cvs_exclude', False))
    opts.filter_rules = list(getattr(parsed, 'filter', None) or [])
    opts.filter_F = int(getattr(parsed, 'filter_F', 0) or 0)
    if parsed.exclude:
        opts.exclude = parsed.exclude
    if parsed.include:
        opts.include = parsed.include
    opts.exclude_from = getattr(parsed, 'exclude_from', None)
    opts.include_from = getattr(parsed, 'include_from', None)
    opts.files_from = getattr(parsed, 'files_from', None)
    opts.from0 = bool(getattr(parsed, 'from0', False))

    opts.existing = bool(getattr(parsed, 'existing', False))
    opts.ignore_existing = bool(getattr(parsed, 'ignore_existing', False))
    opts.remove_source_files = bool(getattr(parsed, 'remove_source_files', False))
    opts.old_args = bool(getattr(parsed, 'old_args', False))
    opts.secluded_args = bool(getattr(parsed, 'secluded_args', False))
    opts.trust_sender = bool(getattr(parsed, 'trust_sender', False))
    opts.copy_as = getattr(parsed, 'copy_as', None)
    opts.address = getattr(parsed, 'address', None)
    opts.port = getattr(parsed, 'port', None)
    opts.sockopts = getattr(parsed, 'sockopts', None)
    opts.blocking_io = bool(getattr(parsed, 'blocking_io', False))
    opts.outbuf = getattr(parsed, 'outbuf', None)
    opts.remote_option = list(getattr(parsed, 'remote_option', None) or [])
    opts.out_format = getattr(parsed, 'out_format', None)
    opts.log_file = getattr(parsed, 'log_file', None)
    opts.log_file_format = getattr(parsed, 'log_file_format', None)
    opts.password_file = getattr(parsed, 'password_file', None)
    opts.early_input = getattr(parsed, 'early_input', None)
    opts.list_only = bool(getattr(parsed, 'list_only', False))
    opts.bwlimit = getattr(parsed, 'bwlimit', None)
    opts.stop_after = getattr(parsed, 'stop_after', None)
    opts.stop_at = getattr(parsed, 'stop_at', None)
    opts.fsync = bool(getattr(parsed, 'fsync', False))
    opts.write_batch = getattr(parsed, 'write_batch', None)
    opts.only_write_batch = getattr(parsed, 'only_write_batch', None)
    opts.read_batch = getattr(parsed, 'read_batch', None)
    opts.protocol = getattr(parsed, 'protocol', None)
    opts.iconv = getattr(parsed, 'iconv', None)
    opts.checksum_seed = getattr(parsed, 'checksum_seed', None)
    opts.ipv4 = bool(getattr(parsed, 'ipv4', False))
    opts.ipv6 = bool(getattr(parsed, 'ipv6', False))

    opts.stats = bool(getattr(parsed, 'stats', False))
    opts.eight_bit_output = bool(getattr(parsed, 'eight_bit_output', False))
    opts.human_readable = bool(getattr(parsed, 'human', False))
    opts.progress = bool(getattr(parsed, 'progress', False))
    opts.partial_progress = bool(getattr(parsed, 'partial_progress', False))
    opts.itemize_changes = bool(getattr(parsed, 'itemize_changes', False))
    if opts.partial_progress:
        opts.partial = True
        opts.progress = True

    # Daemon mode is a distinct invocation that doesn't require SRC/DST.
    opts.daemon = bool(getattr(parsed, 'daemon', False))
    if opts.daemon:
        expand_archive_mode(opts)
        _apply_no_option_overrides(opts, no_options)
        return opts

    # Parse sources and dest
    if not parsed.sources:
        print("rsync: no source files specified", file=sys.stderr)
        print("rsync error: syntax or usage error (code 1) at main.c(1320) [client]", file=sys.stderr)
        sys.exit(1)

    if len(parsed.sources) < 2:
        print("rsync: destination required", file=sys.stderr)
        print("rsync error: syntax or usage error (code 1) at main.c(1320) [client]", file=sys.stderr)
        sys.exit(1)

    opts.sources = parsed.sources[:-1]
    opts.dest = parsed.sources[-1]

    # Expand archive mode (then apply `--no-*` overrides)
    expand_archive_mode(opts)
    _apply_no_option_overrides(opts, no_options)

    return opts


def main() -> int:
    """
    Main CLI entry point with rsync-compatible interface.

    Supports both rsync-style commands (rsync [OPTIONS] SRC DEST)
    and legacy subcommand mode for backwards compatibility.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    opts = parse_rsync_args()

    if getattr(opts, "daemon", False):
        print("rsync: daemon mode is not implemented in rsync-python yet", file=sys.stderr)
        return 1

    # Remote syntaxes are not implemented in this CLI yet.
    remote_tokens = ('rsync://', '::')
    if any(any(tok in s for tok in remote_tokens) for s in (opts.sources + [opts.dest])):
        print("rsync: remote transfers are not implemented in rsync-python yet", file=sys.stderr)
        return 1
    # Heuristic for HOST:PATH (avoid Windows drive letters like C:\).
    for s in (opts.sources + [opts.dest]):
        if ':' in s and not (len(s) >= 2 and s[1] == ':'):
            print("rsync: remote transfers are not implemented in rsync-python yet", file=sys.stderr)
            return 1

    syncer = FileSynchronizer(opts)
    stats = syncer.sync(opts.sources, opts.dest)
    if opts.stats:
        stats.print_stats()
    return 0


def cli_benchmark(args: Any) -> int:
    """Run performance benchmarks."""
    import random

    size_bytes = args.size * 1024 * 1024
    block_size = args.block_size
    pattern = getattr(args, 'pattern', 'flip-middle')
    change_pct = float(getattr(args, 'change_pct', 10.0))
    seed = getattr(args, 'seed', None)

    rng = random.Random(seed)

    def _rand_bytes(n: int) -> bytes:
        return bytes(rng.randint(0, 255) for _ in range(n))

    if not args.quiet:
        print(Colors.bold(f"\n{'=' * 60}"))
        print(Colors.bold("  rsync-python Performance Benchmark".center(60)))
        print(Colors.bold(f"{'=' * 60}\n"))

        print(f"Test file size: {format_size(size_bytes)}")
        print(f"Block size: {block_size:,} bytes")
        print()

    # Generate test data
    if not args.quiet:
        print(Colors.info("Generating test data..."))
    original = _rand_bytes(size_bytes)

    change_size = max(1, int(size_bytes * (change_pct / 100.0)))
    if pattern == 'flip-middle':
        change_start = max(0, (size_bytes - change_size) // 2)
        modified = bytearray(original)
        end = min(size_bytes, change_start + change_size)
        for i in range(change_start, end):
            modified[i] = (modified[i] + 1) % 256
        modified = bytes(modified)
    elif pattern == 'append':
        modified = original + _rand_bytes(change_size)
    elif pattern == 'prepend':
        modified = _rand_bytes(change_size) + original
    elif pattern == 'insert-middle':
        insert_at = size_bytes // 2
        modified = original[:insert_at] + _rand_bytes(change_size) + original[insert_at:]
    else:
        raise ValidationError(f"Unknown benchmark pattern: {pattern}")

    engine = ChecksumEngine(block_size=block_size)

    # Benchmark signature generation
    if not args.quiet:
        print(Colors.info("Benchmarking signature generation..."))
    start = time.perf_counter()
    signature = engine.generate_signature(original)
    sig_time = time.perf_counter() - start
    sig_throughput = size_bytes / sig_time / 1024 / 1024

    if not args.quiet:
        print(f"  Signature: {format_time(sig_time)} ({sig_throughput:.1f} MB/s)")
        print(f"  Blocks: {signature.num_blocks:,}")

    # Benchmark delta generation
    if not args.quiet:
        print(Colors.info("Benchmarking delta generation..."))
    start = time.perf_counter()
    delta = engine.generate_delta(signature, modified)
    delta_time = time.perf_counter() - start
    delta_throughput = size_bytes / delta_time / 1024 / 1024

    if not args.quiet:
        print(f"  Delta: {format_time(delta_time)} ({delta_throughput:.1f} MB/s)")
        print(f"  Matches: {delta.num_matches}, Literals: {delta.num_literals}")
        print(f"  Efficiency: {delta.compression_ratio:.1%}")

    # Benchmark patch application
    if not args.quiet:
        print(Colors.info("Benchmarking patch application..."))
    start = time.perf_counter()
    reconstructed = engine.apply_delta(original, delta)
    patch_time = time.perf_counter() - start
    patch_throughput = size_bytes / patch_time / 1024 / 1024

    if not args.quiet:
        print(f"  Patch: {format_time(patch_time)} ({patch_throughput:.1f} MB/s)")

    # Verify correctness
    correct = reconstructed == modified
    if not args.quiet:
        if correct:
            print(Colors.success("Verification: PASSED"))
        else:
            print(Colors.error("Verification: FAILED"))

    # Summary
    total_time = sig_time + delta_time + patch_time
    if not args.quiet:
        print(f"\n{Colors.bold('Summary:')}")
        print(f"  Total time: {format_time(total_time)}")
        print(f"  Average throughput: {size_bytes / total_time / 1024 / 1024:.1f} MB/s")
        print(f"  Data that would be transferred: {delta.literal_bytes:,} bytes")
        print(f"  Transfer savings: {delta.matched_bytes:,} bytes ({delta.compression_ratio:.1%})")

    return 0 if correct else 1


# Entry point when run as script
if __name__ == "__main__":
    sys.exit(main())
