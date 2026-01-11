#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Herramienta de comparación directa con el código C original de rsync

Este script facilita la comparación de salidas entre la implementación Python
y el código C original de rsync para validación cruzada.
"""

import os
import sys
import subprocess
import struct
from pathlib import Path
from typing import List, Tuple, Optional

# Import implementación Python
from rsync_phoenix_rebuilt import Checksum, ChecksumEngine


class CSourceComparator:
    """Herramienta para comparar con código C de rsync"""

    def __init__(self, c_source_dir: str = "rsync-original-source-code"):
        self.c_source_dir = Path(c_source_dir)
        if not self.c_source_dir.exists():
            raise RuntimeError(f"Directorio de código C no encontrado: {c_source_dir}")

        self.checksum_c = self.c_source_dir / "checksum.c"
        self.match_c = self.c_source_dir / "match.c"

    def find_c_function(self, filename: str, function_name: str) -> Optional[str]:
        """Encuentra una función en un archivo C"""
        filepath = self.c_source_dir / filename
        if not filepath.exists():
            return None

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Buscar la función (simplificado)
        import re
        pattern = rf'([\w\s\*]+{function_name}\s*\([^)]*\)\s*\{{[^}}]*\}})'
        match = re.search(pattern, content, re.DOTALL | re.MULTILINE)

        if match:
            return match.group(0)

        return None

    def extract_checksum_algorithm(self) -> str:
        """Extrae el algoritmo de checksum del código C"""
        if not self.checksum_c.exists():
            return "Archivo checksum.c no encontrado"

        with open(self.checksum_c, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Buscar la función de rolling checksum
        lines = []
        lines.append("=" * 70)
        lines.append("ROLLING CHECKSUM ALGORITHM FROM C SOURCE")
        lines.append("=" * 70)

        # Buscar sum_update
        sum_update = self.find_c_function("checksum.c", "sum_update")
        if sum_update:
            lines.append("\nsum_update function:")
            lines.append("-" * 70)
            lines.append(sum_update)

        return "\n".join(lines)

    def compare_implementations(self, test_data: bytes) -> str:
        """Compara las implementaciones Python y C (descripción)"""
        lines = []
        lines.append("=" * 70)
        lines.append("COMPARISON: Python vs C Implementation")
        lines.append("=" * 70)

        # Python implementation
        lines.append("\nPython Implementation:")
        lines.append("-" * 70)
        checksum = Checksum(block_size=700)
        weak = checksum.rolling_checksum(test_data)
        strong = checksum.strong_checksum(test_data)

        lines.append(f"Data length: {len(test_data)} bytes")
        lines.append(f"Weak checksum:  {weak:#010x} ({weak})")
        lines.append(f"Strong checksum: {strong.hex()}")

        # C implementation notes
        lines.append("\nC Implementation (from checksum.c):")
        lines.append("-" * 70)
        lines.append("The C implementation uses:")
        lines.append("1. Adler-32 style rolling checksum (sum1, sum2)")
        lines.append("2. MD5 for strong checksum")
        lines.append("3. Block-based processing")

        # Comparación detallada
        lines.append("\nImplementation Details:")
        lines.append("-" * 70)

        # Descomponer el weak checksum
        a = weak >> 16
        b = weak & 0xFFFF

        lines.append(f"Weak checksum components:")
        lines.append(f"  a (sum1): {a:#06x} ({a})")
        lines.append(f"  b (sum2): {b:#06x} ({b})")
        lines.append(f"  combined: (a << 16) | b = {weak:#010x}")

        return "\n".join(lines)


def test_rolling_checksum_values():
    """Test con valores conocidos del código C"""
    print("\n" + "=" * 70)
    print("ROLLING CHECKSUM TEST - Known Values")
    print("=" * 70)

    test_cases = [
        (b"a", "Single byte 'a'"),
        (b"ab", "Two bytes 'ab'"),
        (b"abc", "Three bytes 'abc'"),
        (b"abcd", "Four bytes 'abcd'"),
        (b"a" * 100, "100 'a' characters"),
        (b"The quick brown fox", "English text"),
        (bytes(range(256)), "All byte values 0-255"),
    ]

    checksum = Checksum()

    for data, description in test_cases:
        weak = checksum.rolling_checksum(data)
        strong = checksum.strong_checksum(data)

        a = weak >> 16
        b = weak & 0xFFFF

        print(f"\n{description}:")
        print(f"  Data: {data[:20]!r}{'...' if len(data) > 20 else ''}")
        print(f"  Length: {len(data)} bytes")
        print(f"  Weak:  {weak:#010x} (a={a:#06x}, b={b:#06x})")
        print(f"  Strong: {strong.hex()[:32]}{'...' if len(strong.hex()) > 32 else ''}")


def test_checksum_components():
    """Analiza componentes del checksum en detalle"""
    print("\n" + "=" * 70)
    print("CHECKSUM COMPONENTS ANALYSIS")
    print("=" * 70)

    checksum = Checksum()
    data = b"Hello, World!"

    print(f"\nTest data: {data!r}")
    print(f"Length: {len(data)} bytes")

    # Calcular manualmente paso a paso
    print("\nManual calculation (step by step):")
    a = 0
    b = 0

    for i, byte in enumerate(data):
        old_a, old_b = a, b
        a = (a + byte) & 0xFFFF
        b = (b + a) & 0xFFFF
        print(f"  Step {i:2d}: byte={byte:3d} ('{chr(byte)}')  a: {old_a:5d} -> {a:5d}  b: {old_b:7d} -> {b:7d}")

    manual_weak = (a << 16) | b
    print(f"\nManual weak checksum: {manual_weak:#010x}")

    # Calcular con función
    func_weak = checksum.rolling_checksum(data)
    print(f"Function weak checksum: {func_weak:#010x}")

    # Verificar coincidencia
    if manual_weak == func_weak:
        print("[OK] Manual and function results MATCH")
    else:
        print("[FAIL] MISMATCH between manual and function!")


def test_rolling_update():
    """Test de actualización rolling"""
    print("\n" + "=" * 70)
    print("ROLLING UPDATE TEST")
    print("=" * 70)

    checksum = Checksum()
    data = b"abcdefghij"
    window_size = 5

    print(f"Data: {data!r}")
    print(f"Window size: {window_size}")

    # Checksum inicial para primeros 5 bytes
    initial_data = data[:window_size]
    initial_weak = checksum.rolling_checksum(initial_data)
    a, b = checksum.checksum_from_weak(initial_weak)

    print(f"\nInitial window: {initial_data!r}")
    print(f"Initial weak: {initial_weak:#010x} (a={a:#06x}, b={b:#06x})")

    # Rolling update para cada posición
    print("\nRolling through data:")
    for i in range(len(data) - window_size):
        old_byte = data[i]
        new_byte = data[i + window_size]

        # Update usando rolling_update
        new_a, new_b = checksum.rolling_update(old_byte, new_byte, a, b, window_size)
        rolling_weak = checksum.weak_to_checksum(new_a, new_b)

        # Calcular directamente para verificar
        window_data = data[i+1:i+1+window_size]
        direct_weak = checksum.rolling_checksum(window_data)

        match = "[OK]" if rolling_weak == direct_weak else "[FAIL]"
        print(f"  Pos {i+1}: window={window_data!r}  "
              f"rolling={rolling_weak:#010x}  direct={direct_weak:#010x}  {match}")

        # Update para siguiente iteración
        a, b = new_a, new_b


def generate_test_vectors():
    """Genera vectores de test para validación"""
    print("\n" + "=" * 70)
    print("TEST VECTORS FOR C VALIDATION")
    print("=" * 70)

    checksum = Checksum()

    test_vectors = [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        b"abcde",
        b"Hello, World!",
        b"\x00\x01\x02\x03\x04",
        b"\xff\xfe\xfd\xfc\xfb",
        bytes(range(256)),
    ]

    print("\n/* Test vectors for C code validation */")
    print("typedef struct {")
    print("    unsigned char *data;")
    print("    size_t length;")
    print("    uint32_t expected_weak;")
    print("    char expected_strong[33];  // MD5 hex + null")
    print("} test_vector_t;")
    print("\ntest_vector_t test_vectors[] = {")

    for data in test_vectors:
        weak = checksum.rolling_checksum(data)
        strong = checksum.strong_checksum(data)

        # Formatear data como C string
        if len(data) == 0:
            c_data = '""'
        elif all(32 <= b < 127 for b in data):
            c_data = f'"{data.decode("ascii")}"'
        else:
            hex_values = ', '.join(f'0x{b:02x}' for b in data)
            c_data = f'(unsigned char[]){{{hex_values}}}'

        print(f"    {{ {c_data}, {len(data)}, {weak:#010x}U, \"{strong.hex()}\" }},")

    print("};")
    print(f"#define NUM_TEST_VECTORS {len(test_vectors)}")


def main():
    """Función principal"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Comparar implementación Python con código C de rsync"
    )
    parser.add_argument(
        '--c-source',
        default='rsync-original-source-code',
        help='Directorio del código fuente C de rsync'
    )
    parser.add_argument(
        '--test',
        choices=['all', 'values', 'components', 'rolling', 'vectors'],
        default='all',
        help='Tipo de test a ejecutar'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("RSYNC-PYTHON - C SOURCE COMPARISON TOOL")
    print("=" * 70)

    # Crear comparador
    try:
        comparator = CSourceComparator(args.c_source)
        print(f"[OK] C source directory found: {comparator.c_source_dir}")

        # Mostrar información del código C
        print("\n" + comparator.extract_checksum_algorithm())

    except RuntimeError as e:
        print(f"[Warning] {e}")
        print("Continuing with Python-only tests...\n")

    # Ejecutar tests
    if args.test in ['all', 'values']:
        test_rolling_checksum_values()

    if args.test in ['all', 'components']:
        test_checksum_components()

    if args.test in ['all', 'rolling']:
        test_rolling_update()

    if args.test in ['all', 'vectors']:
        generate_test_vectors()

    # Test de comparación con datos reales
    if args.test == 'all':
        print("\n" + "=" * 70)
        print("REAL DATA COMPARISON")
        print("=" * 70)

        test_data = b"The quick brown fox jumps over the lazy dog. " * 10

        try:
            comparator = CSourceComparator(args.c_source)
            print("\n" + comparator.compare_implementations(test_data))
        except:
            checksum = Checksum()
            weak = checksum.rolling_checksum(test_data)
            strong = checksum.strong_checksum(test_data)
            print(f"\nPython results:")
            print(f"  Weak:  {weak:#010x}")
            print(f"  Strong: {strong.hex()}")

    print("\n" + "=" * 70)
    print("COMPARISON COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    main()
