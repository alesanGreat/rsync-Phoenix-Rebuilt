#!/usr/bin/env python3
"""
Benchmark: rsync-python vs rsync real
=====================================

Compara el rendimiento y precisión de rsync-python contra rsync nativo.
"""

import os
import time
import tempfile
import subprocess

from rsync_phoenix_rebuilt import ChecksumEngine, Colors

colors = Colors


def create_test_file(path: str, size_mb: int) -> None:
    """Create test file with random-ish data"""
    with open(path, 'wb') as f:
        # Pattern that compresses well
        pattern = b"Hello World! " * 100
        iterations = (size_mb * 1024 * 1024) // len(pattern)
        for _ in range(iterations):
            f.write(pattern)


def modify_file(
    source: str,
    dest: str,
    change_percent: float,
    seed: int = 123,
    pattern: str = 'flip-random',
) -> None:
    """Create a modified version of a file (reproducible).

    Supported patterns:
        - flip-random: flip random bytes across the file
        - append: append new bytes to the end
        - prepend: prepend new bytes to the beginning
        - insert-middle: insert new bytes in the middle
    """
    with open(source, 'rb') as f:
        original = f.read()

    import random
    rnd = random.Random(seed)

    def _make_insert_bytes(n: int) -> bytes:
        # Deterministic but not trivially compressible.
        return bytes(rnd.randint(0, 255) for _ in range(n))

    if pattern == 'flip-random':
        data = bytearray(original)
        num_changes = int(len(data) * change_percent / 100)
        if len(data) == 0:
            modified = bytes(data)
        else:
            for _ in range(num_changes):
                pos = rnd.randint(0, len(data) - 1)
                data[pos] = rnd.randint(0, 255)
            modified = bytes(data)
    elif pattern == 'append':
        insert_len = int(len(original) * change_percent / 100)
        modified = original + _make_insert_bytes(insert_len)
    elif pattern == 'prepend':
        insert_len = int(len(original) * change_percent / 100)
        modified = _make_insert_bytes(insert_len) + original
    elif pattern == 'insert-middle':
        insert_len = int(len(original) * change_percent / 100)
        mid = len(original) // 2
        modified = original[:mid] + _make_insert_bytes(insert_len) + original[mid:]
    else:
        raise ValueError(f"Unknown pattern: {pattern}")

    with open(dest, 'wb') as f:
        f.write(modified)


def benchmark_rsync_python(source: str, target: str, block_size: int) -> dict:
    """Benchmark rsync-python"""
    engine = ChecksumEngine(block_size=block_size)

    # Timing
    start = time.time()

    # Phase 1: Generate signature
    t1 = time.time()
    signature = engine.generate_signature_from_file(source)
    t2 = time.time()

    # Phase 2: Generate delta
    delta = engine.generate_delta_from_files(signature, target)
    t3 = time.time()

    # Phase 3: Apply delta (for verification)
    with open(source, 'rb') as f:
        original = f.read()
    reconstructed = engine.apply_delta(original, delta)
    t4 = time.time()

    # Verify
    with open(target, 'rb') as f:
        expected = f.read()
    verified = reconstructed == expected

    new_size = len(expected)

    total_time = time.time() - start

    return {
        'signature_time': t2 - t1,
        'delta_time': t3 - t2,
        'apply_time': t4 - t3,
        'total_time': total_time,
        'blocks': signature.num_blocks,
        'match_bytes': sum(m.length for cmd, m in delta.instructions if cmd == 'match'),
        'literal_bytes': sum(len(l.data) for cmd, l in delta.instructions if cmd == 'literal'),
        'new_size': new_size,
        'compression_ratio': delta.compression_ratio,
        'verified': verified,
    }


def benchmark_rsync_native(source: str, target: str, block_size: int) -> dict:
    """Benchmark native rsync via batch generation.

    For local transfers, rsync defaults to --whole-file (skips the delta
    algorithm). We force --no-whole-file so timings and batch size are meaningful.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        delta_file = os.path.join(tmpdir, 'delta')
        sender_dir = os.path.join(tmpdir, 'sender')
        receiver_dir = os.path.join(tmpdir, 'receiver')
        applied_dir = os.path.join(tmpdir, 'applied')
        os.makedirs(sender_dir, exist_ok=True)
        os.makedirs(receiver_dir, exist_ok=True)
        os.makedirs(applied_dir, exist_ok=True)

        # Use a stable filename so rsync batch replay is predictable.
        filename = 'file.dat'
        sender_path = os.path.join(sender_dir, filename)
        receiver_path = os.path.join(receiver_dir, filename)
        applied_path = os.path.join(applied_dir, filename)

        # Sender has the NEW file (target). Receiver has the OLD basis (source).
        with open(target, 'rb') as fsrc, open(sender_path, 'wb') as fdst:
            fdst.write(fsrc.read())
        with open(source, 'rb') as fsrc, open(receiver_path, 'wb') as fdst:
            fdst.write(fsrc.read())

        # Generate signature
        t1 = time.time()
        cmd = [
            'rsync',
            '-a',
            '-I',
            '--no-whole-file',
            f'--block-size={block_size}',
            '--only-write-batch=' + delta_file,
            sender_dir + '/',
            receiver_dir + '/',
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                return {'error': 'rsync failed'}
        except Exception:
            return {'error': 'rsync not available or timeout'}
        t2 = time.time()

        # Get file sizes for comparison
        if os.path.exists(delta_file):
            delta_size = os.path.getsize(delta_file)
        else:
            delta_size = 0

        try:
            target_size = os.path.getsize(sender_path)
        except OSError:
            target_size = 0

        # Best-effort: apply batch for correctness verification.
        # Batch mode can be finicky depending on rsync version/build/options.
        verified = None
        apply_time = None
        try:
            # Start with a basis file in the destination dir.
            with open(receiver_path, 'rb') as fsrc, open(applied_path, 'wb') as fdst:
                fdst.write(fsrc.read())

            t3 = time.time()
            apply_cmd = [
                'rsync',
                '-a',
                '-I',
                '--read-batch=' + delta_file,
                applied_dir + '/',
            ]
            apply_res = subprocess.run(apply_cmd, capture_output=True, timeout=30)
            t4 = time.time()
            apply_time = t4 - t3

            if apply_res.returncode == 0 and os.path.exists(applied_path):
                with open(applied_path, 'rb') as f_applied, open(sender_path, 'rb') as f_target:
                    verified = (f_applied.read() == f_target.read())
            else:
                verified = False
        except Exception:
            verified = None

        return {
            'total_time': t2 - t1,
            'apply_time': apply_time,
            'delta_size': delta_size,
            'target_size': target_size,
            'verified': verified,
            'available': True,
        }


def run_benchmark_suite():
    """Run complete benchmark suite"""
    print(colors.bold("\n" + "=" * 80))
    print(colors.bold("🏁 BENCHMARK: rsync-python vs rsync native".center(80)))
    print(colors.bold("=" * 80))

    test_cases = [
        ('1MB flip-random 1%', 1, 'flip-random', 1, 2048),
        ('1MB flip-random 10%', 1, 'flip-random', 10, 2048),
        ('1MB append 5%', 1, 'append', 5, 2048),
        ('1MB prepend 5%', 1, 'prepend', 5, 2048),
        ('1MB insert-middle 5%', 1, 'insert-middle', 5, 2048),
        ('10MB flip-random 1%', 10, 'flip-random', 1, 2048),
        ('10MB append 1%', 10, 'append', 1, 2048),
        ('10MB insert-middle 1%', 10, 'insert-middle', 1, 2048),
    ]

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for case_i, (name, size_mb, pattern, change_percent, block_size) in enumerate(test_cases, start=1):
            print(f"\n{colors.info(f'Testing: {name}')}")

            source = os.path.join(tmpdir, 'source.dat')
            target = os.path.join(tmpdir, 'target.dat')

            # Create files
            create_test_file(source, size_mb)
            modify_file(source, target, change_percent, seed=123 + case_i, pattern=pattern)

            # Benchmark rsync-python
            print("  Running rsync-python...", end=' ', flush=True)
            py_result = benchmark_rsync_python(source, target, block_size)
            print(colors.success(f"{py_result['total_time']:.3f}s"))

            # Benchmark native rsync
            print("  Running rsync native...", end=' ', flush=True)
            native_result = benchmark_rsync_native(source, target, block_size)
            if 'error' not in native_result:
                print(colors.success(f"{native_result['total_time']:.3f}s"))
            else:
                print(colors.warning(native_result['error']))

            results.append({
                'name': name,
                'python': py_result,
                'native': native_result,
            })

    # Print summary
    print(f"\n{colors.bold('=' * 80)}")
    print(colors.bold("📊 BENCHMARK RESULTS SUMMARY".center(80)))
    print(colors.bold("=" * 80))

    for r in results:
        print(f"\n{colors.bold(r['name'])}")
        py = r['python']
        native = r['native']

        print(f"  rsync-python:")
        print(f"    Time:         {py['total_time']:.3f}s")
        print(f"    Signature:    {py['signature_time']:.3f}s")
        print(f"    Delta:        {py['delta_time']:.3f}s")
        print(f"    Apply:        {py['apply_time']:.3f}s")
        print(f"    Compression:  {py['compression_ratio']:.1%}")
        if py.get('new_size'):
            delta_ratio = py.get('literal_bytes', 0) / py['new_size']
            print(f"    Delta ratio:  {delta_ratio:.1%}")
        print(f"    Verified:     {colors.success('✓') if py['verified'] else colors.error('✗')}")

        if 'error' not in native:
            print(f"  rsync native:")
            print(f"    Time:         {native['total_time']:.3f}s")
            print(f"    Batch size:   {native.get('delta_size', 0)} bytes")
            if native.get('target_size'):
                ratio = native.get('delta_size', 0) / native['target_size']
                print(f"    Batch ratio:  {ratio:.1%}")
            if native.get('apply_time') is not None:
                print(f"    Apply batch:  {native['apply_time']:.3f}s")
            if native.get('verified') is True:
                print(f"    Verified:     {colors.success('✓')}")
            elif native.get('verified') is False:
                print(f"    Verified:     {colors.error('✗')}")
            else:
                print(f"    Verified:     {colors.warning('?')}")
            slowdown = py['total_time'] / native['total_time']
            color = colors.GREEN() if slowdown < 2 else (colors.YELLOW() if slowdown < 5 else colors.RED())
            print(f"    Slowdown:     {color}{slowdown:.1f}x{colors.RESET()}")

    print(f"\n{colors.bold('=' * 80)}")
    print(colors.success("✓ Benchmark complete!"))
    print(colors.bold("=" * 80))


if __name__ == '__main__':
    run_benchmark_suite()
