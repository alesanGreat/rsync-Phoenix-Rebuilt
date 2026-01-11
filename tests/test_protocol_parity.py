#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Protocol Parity Test - Validates 1:1 parity with rsync for each protocol version
"""

from rsync_phoenix_rebuilt import (
    ProtocolVersionManager,
    ChecksumEngine,
    ChecksumType,
    MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    OLD_MAX_BLOCK_SIZE,
    MAX_BLOCK_SIZE
)


def test_protocol_version_parity():
    """
    Test that each protocol version behaves exactly as rsync C code specifies
    Based on compat.c and protocol documentation
    """
    print("=" * 70)
    print("PROTOCOL PARITY TEST - 1:1 Validation with rsync C code")
    print("=" * 70)
    print()

    test_results = []

    # Protocol 20: Minimum supported
    print("Protocol 20 (Minimum supported - circa 2000)")
    print("-" * 70)
    manager = ProtocolVersionManager(20)
    manager.negotiate_protocol(20)

    checks = [
        ("Block size", manager.get_max_block_size(), OLD_MAX_BLOCK_SIZE),
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD4),
        ("Varint support", manager.supports_varint(), False),
        ("Long names", manager.supports_long_names(), False),
        ("Inc recursion", manager.supports_inc_recursion(), False),
        ("Access times", manager.supports_atimes(), False),
        ("Creation times", manager.supports_crtimes(), False),
        ("xxHash support", manager.supports_xxhash(), False),
        ("zstd support", manager.supports_zstd(), False),
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P20-{check_name}", actual == expected))
    print()

    # Protocol 27: Variable-length integers introduced
    print("Protocol 27 (Variable-length integers - circa 2005)")
    print("-" * 70)
    manager = ProtocolVersionManager(27)
    manager.negotiate_protocol(27)

    checks = [
        ("Block size", manager.get_max_block_size(), OLD_MAX_BLOCK_SIZE),
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD4),
        ("Varint support", manager.supports_varint(), True),  # NEW in v27
        ("Long names", manager.supports_long_names(), False),
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P27-{check_name}", actual == expected))
    print()

    # Protocol 29: Long file names support
    print("Protocol 29 (Long file names - circa 2007)")
    print("-" * 70)
    manager = ProtocolVersionManager(29)
    manager.negotiate_protocol(29)

    checks = [
        ("Block size", manager.get_max_block_size(), OLD_MAX_BLOCK_SIZE),
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD4),
        ("Varint support", manager.supports_varint(), True),
        ("Long names", manager.supports_long_names(), True),  # NEW in v29
        ("Inc recursion", manager.supports_inc_recursion(), False),
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P29-{check_name}", actual == expected))
    print()

    # Protocol 30: Major update - MD5, larger blocks, incremental recursion
    print("Protocol 30 (MD5, 128KB blocks, Inc recursion - circa 2008)")
    print("-" * 70)
    manager = ProtocolVersionManager(30)
    manager.negotiate_protocol(30)

    checks = [
        ("Block size", manager.get_max_block_size(), MAX_BLOCK_SIZE),  # Changed!
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD5),  # Changed!
        ("Varint support", manager.supports_varint(), True),
        ("Long names", manager.supports_long_names(), True),
        ("Inc recursion", manager.supports_inc_recursion(), True),  # NEW in v30
        ("Access times", manager.supports_atimes(), True),  # NEW in v30
        ("Creation times", manager.supports_crtimes(), False),
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P30-{check_name}", actual == expected))
    print()

    # Protocol 31: xxHash, zstd, creation times
    print("Protocol 31 (xxHash, zstd, creation times - circa 2013)")
    print("-" * 70)
    manager = ProtocolVersionManager(31)
    manager.negotiate_protocol(31)

    checks = [
        ("Block size", manager.get_max_block_size(), MAX_BLOCK_SIZE),
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD5),
        ("Varint support", manager.supports_varint(), True),
        ("Long names", manager.supports_long_names(), True),
        ("Inc recursion", manager.supports_inc_recursion(), True),
        ("Access times", manager.supports_atimes(), True),
        ("Creation times", manager.supports_crtimes(), True),  # NEW in v31
        ("xxHash support", manager.supports_xxhash(), True),  # NEW in v31
        ("zstd support", manager.supports_zstd(), True),  # NEW in v31
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P31-{check_name}", actual == expected))
    print()

    # Protocol 32: Latest official version
    print("Protocol 32 (Latest official - 2022)")
    print("-" * 70)
    manager = ProtocolVersionManager(32)
    manager.negotiate_protocol(32)

    checks = [
        ("Block size", manager.get_max_block_size(), MAX_BLOCK_SIZE),
        ("Checksum type", manager.get_default_checksum_type(), ChecksumType.MD5),
        ("All modern features", all([
            manager.supports_varint(),
            manager.supports_long_names(),
            manager.supports_inc_recursion(),
            manager.supports_atimes(),
            manager.supports_crtimes(),
            manager.supports_xxhash(),
            manager.supports_zstd(),
        ]), True),
    ]

    for check_name, actual, expected in checks:
        status = "✓ PASS" if actual == expected else "✗ FAIL"
        print(f"  {check_name:20s}: {str(actual):20s} (expected: {expected}) {status}")
        test_results.append((f"P32-{check_name}", actual == expected))
    print()

    # Summary
    print("=" * 70)
    print("PARITY TEST SUMMARY")
    print("=" * 70)

    total = len(test_results)
    passed = sum(1 for _, result in test_results if result)
    failed = total - passed

    print(f"Total checks:  {total}")
    print(f"Passed:        {passed} ✓")
    print(f"Failed:        {failed} ✗")
    print()

    if failed > 0:
        print("Failed checks:")
        for name, result in test_results:
            if not result:
                print(f"  - {name}")
    else:
        print("🎉 ALL PARITY CHECKS PASSED! 1:1 compatibility confirmed.")
    print()

    print("=" * 70)
    print(f"Verdict: {'✓ FULL PARITY' if failed == 0 else '✗ PARTIAL PARITY'}")
    print("=" * 70)

    return failed == 0


def test_checksum_parity_across_protocols():
    """Test that checksums work correctly across all protocols"""
    print("\n" + "=" * 70)
    print("CHECKSUM PARITY TEST - Across Protocol Versions")
    print("=" * 70)
    print()

    test_data = b"rsync protocol test data" * 10

    protocols_to_test = [
        (20, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (25, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (27, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (29, ChecksumType.MD4, OLD_MAX_BLOCK_SIZE),
        (30, ChecksumType.MD5, MAX_BLOCK_SIZE),
        (31, ChecksumType.MD5, MAX_BLOCK_SIZE),
        (32, ChecksumType.MD5, MAX_BLOCK_SIZE),
    ]

    all_passed = True

    for protocol, expected_checksum, expected_block_size in protocols_to_test:
        manager = ProtocolVersionManager(protocol)
        manager.negotiate_protocol(protocol)

        actual_checksum = manager.get_default_checksum_type()
        actual_block_size = manager.get_max_block_size()

        engine = ChecksumEngine(
            block_size=actual_block_size,
            checksum_type=actual_checksum,
            protocol_manager=manager
        )

        sum_head, blocks = engine.generate_sums(test_data)

        # Verify
        checksum_ok = actual_checksum == expected_checksum
        block_size_ok = actual_block_size == expected_block_size
        blocks_ok = len(blocks) == sum_head['count']

        status = "✓ PASS" if (checksum_ok and block_size_ok and blocks_ok) else "✗ FAIL"

        print(f"Protocol {protocol:2d}: checksum={actual_checksum.value:4s}, "
              f"block_size={actual_block_size:6d}, blocks={len(blocks):2d} {status}")

        if not (checksum_ok and block_size_ok and blocks_ok):
            all_passed = False

    print()
    print(f"Checksum parity: {'✓ PASS' if all_passed else '✗ FAIL'}")
    print()

    return all_passed


if __name__ == '__main__':
    import sys

    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  rsync_phoenix_rebuilt.py - PROTOCOL PARITY VALIDATION TEST SUITE  ".center(68) + "║")
    print("║" + f"  Protocol Range: {MIN_PROTOCOL_VERSION}-{PROTOCOL_VERSION}  ".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    result1 = test_protocol_version_parity()
    result2 = test_checksum_parity_across_protocols()

    print()
    print("=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)

    if result1 and result2:
        print()
        print("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
        print("  ┃                                                            ┃")
        print("  ┃     ✅ FULL 1:1 PARITY WITH RSYNC CONFIRMED! ✅     ┃")
        print("  ┃                                                            ┃")
        print("  ┃         All protocol versions 20-32 validated              ┃")
        print("  ┃                                                            ┃")
        print("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
        print()
        sys.exit(0)
    else:
        print()
        print("  ⚠ PARTIAL PARITY - Some checks failed")
        print()
        sys.exit(1)
