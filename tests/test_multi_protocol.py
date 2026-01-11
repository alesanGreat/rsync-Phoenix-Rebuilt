#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for multi-protocol support in rsync_phoenix_rebuilt.py
Validates compatibility with protocol versions 20-32
"""

import sys
from rsync_phoenix_rebuilt import (
    ProtocolVersionManager,
    ChecksumType,
    ChecksumRegistry,
    CompressionType,
    CompressionRegistry,
    Checksum,
    ChecksumEngine,
    PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
    MAX_PROTOCOL_VERSION,
    MAX_BLOCK_SIZE,
    OLD_MAX_BLOCK_SIZE
)


def test_protocol_version_manager():
    """Test protocol version negotiation"""
    print("=" * 70)
    print("TEST: Protocol Version Manager")
    print("=" * 70)

    # Test various protocol negotiations
    test_cases = [
        (32, 31, 31, "Remote older version"),
        (31, 32, 31, "Remote newer version"),
        (30, 30, 30, "Same version"),
        (25, 20, 20, "Old protocol versions"),
        (20, 25, 20, "Mixed old versions"),
    ]

    for local, remote, expected, description in test_cases:
        manager = ProtocolVersionManager(desired_protocol=local)
        result = manager.negotiate_protocol(remote)
        status = "PASS" if result == expected else "FAIL"
        print(f"  {description}: local={local}, remote={remote}, "
              f"negotiated={result}, expected={expected} [{status}]")

    print()


def test_protocol_features():
    """Test protocol-specific feature availability"""
    print("=" * 70)
    print("TEST: Protocol Features by Version")
    print("=" * 70)

    for version in [20, 25, 27, 29, 30, 31, 32]:
        manager = ProtocolVersionManager(desired_protocol=version)
        manager.negotiate_protocol(version)

        print(f"\n  Protocol {version}:")
        print(f"    Max block size: {manager.get_max_block_size()}")
        print(f"    Default checksum: {manager.get_default_checksum_type().value}")
        print(f"    Supports varint: {manager.supports_varint()}")
        print(f"    Supports long names: {manager.supports_long_names()}")
        print(f"    Supports inc recursion: {manager.supports_inc_recursion()}")
        print(f"    Supports atimes: {manager.supports_atimes()}")
        print(f"    Supports crtimes: {manager.supports_crtimes()}")
        print(f"    Supports xxhash: {manager.supports_xxhash()}")
        print(f"    Supports zstd: {manager.supports_zstd()}")

    print()


def test_checksum_types():
    """Test different checksum algorithms"""
    print("=" * 70)
    print("TEST: Checksum Algorithms")
    print("=" * 70)

    test_data = b"The quick brown fox jumps over the lazy dog"

    checksum_types = [
        ChecksumType.MD4,
        ChecksumType.MD5,
        ChecksumType.SHA1,
        ChecksumType.XXH64,
        ChecksumType.XXH3,
        ChecksumType.XXH128,
    ]

    for checksum_type in checksum_types:
        try:
            checksum_func = ChecksumRegistry.get_checksum_function(checksum_type)
            result = checksum_func(test_data)
            print(f"  {checksum_type.value:10s}: {result.hex()[:32]}... (len={len(result)}) [OK]")
        except Exception as e:
            print(f"  {checksum_type.value:10s}: FAILED - {e}")

    print()


def test_compression_types():
    """Test different compression algorithms"""
    print("=" * 70)
    print("TEST: Compression Algorithms")
    print("=" * 70)

    test_data = b"The quick brown fox jumps over the lazy dog" * 100

    compression_types = [
        CompressionType.NONE,
        CompressionType.ZLIB,
        CompressionType.ZLIBX,
        CompressionType.LZ4,
        CompressionType.ZSTD,
    ]

    for comp_type in compression_types:
        try:
            compressed = CompressionRegistry.compress(test_data, comp_type, level=6)
            decompressed = CompressionRegistry.decompress(compressed, comp_type)

            # Verify round-trip
            if decompressed == test_data:
                ratio = len(compressed) / len(test_data) * 100
                print(f"  {comp_type.value:10s}: {len(test_data):5d} -> {len(compressed):5d} bytes "
                      f"({ratio:5.1f}%) [OK]")
            else:
                print(f"  {comp_type.value:10s}: FAILED - decompressed data mismatch")
        except Exception as e:
            print(f"  {comp_type.value:10s}: FAILED - {e}")

    print()


def test_checksum_with_protocols():
    """Test checksums with different protocol versions"""
    print("=" * 70)
    print("TEST: Checksums with Protocol Versions")
    print("=" * 70)

    test_data = b"A" * 1400

    test_cases = [
        (25, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (27, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (29, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (30, ChecksumType.MD5, MAX_BLOCK_SIZE),
        (31, ChecksumType.MD5, MAX_BLOCK_SIZE),
        (32, ChecksumType.MD5, MAX_BLOCK_SIZE),
    ]

    for protocol, checksum_type, block_size in test_cases:
        manager = ProtocolVersionManager(desired_protocol=protocol)
        manager.negotiate_protocol(protocol)

        checksum = Checksum(
            block_size=block_size,
            checksum_type=checksum_type,
            protocol_manager=manager
        )

        blocks = checksum.block_checksums(test_data)
        expected_blocks = (len(test_data) + block_size - 1) // block_size

        status = "PASS" if len(blocks) == expected_blocks else "FAIL"
        print(f"  Protocol {protocol}: checksum={checksum_type.value}, "
              f"block_size={block_size}, blocks={len(blocks)}/{expected_blocks} [{status}]")

    print()


def test_checksum_engine_with_protocols():
    """Test ChecksumEngine with different protocols"""
    print("=" * 70)
    print("TEST: ChecksumEngine with Protocols")
    print("=" * 70)

    test_data = b"The quick brown fox jumps over the lazy dog. " * 20

    for protocol in [25, 27, 29, 30, 31, 32]:
        manager = ProtocolVersionManager(desired_protocol=protocol)
        manager.negotiate_protocol(protocol)

        checksum_type = manager.get_default_checksum_type()
        block_size = manager.get_max_block_size()

        engine = ChecksumEngine(
            block_size=block_size,
            checksum_type=checksum_type,
            protocol_manager=manager
        )

        # Generate signature
        sum_head, blocks = engine.generate_sums(test_data)

        # Match against identical data
        results = engine.match_sums(test_data, sum_head, blocks)

        block_matches = [r for r in results if r[0] == 'block']

        status = "PASS" if len(block_matches) > 0 else "FAIL"
        print(f"  Protocol {protocol}: checksum={checksum_type.value}, "
              f"block_size={block_size}, blocks={sum_head['count']}, "
              f"matches={len(block_matches)} [{status}]")

    print()


def main():
    """Run all multi-protocol tests"""
    print("\n" + "=" * 70)
    print("RSYNC-PYTHON MULTI-PROTOCOL TEST SUITE")
    print(f"Protocol Range: {MIN_PROTOCOL_VERSION}-{PROTOCOL_VERSION}")
    print("=" * 70)
    print()

    try:
        test_protocol_version_manager()
        test_protocol_features()
        test_checksum_types()
        test_compression_types()
        test_checksum_with_protocols()
        test_checksum_engine_with_protocols()

        print("=" * 70)
        print("ALL TESTS COMPLETED")
        print("=" * 70)

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
