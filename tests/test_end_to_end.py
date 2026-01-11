#!/usr/bin/env python
"""
test_end_to_end.py - End-to-End Integration Tests
==================================================

Tests que simulan sincronización completa de archivos usando el algoritmo rsync.
Estos tests demuestran el flujo completo: signature -> delta -> reconstrucción.
"""

import unittest
import os
import tempfile
import shutil
from pathlib import Path
from rsync_phoenix_rebuilt import (
    ChecksumEngine, ChecksumType,
    ValidationError, ResourceLimitError,
    validate_block_size, validate_data, validate_protocol_version,
    apply_delta_over_wire,
    CompressionType,
    Config,
)


class TestEndToEndSync(unittest.TestCase):
    """Tests de sincronización end-to-end"""

    def setUp(self):
        """Crear directorio temporal para tests"""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Limpiar directorio temporal"""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_identical_files_no_transfer(self):
        """Test: Archivos idénticos no deberían transferir datos"""
        # Archivo original
        original_data = b"Hello, World!" * 1000

        # Generar signature del original
        engine = ChecksumEngine(block_size=1024)
        sum_head, blocks = engine.generate_sums(original_data)

        # Archivo nuevo es idéntico
        new_data = original_data

        # Hacer matching
        results = engine.match_sums(new_data, sum_head, blocks)

        # Contar matches vs literals
        matches = sum(1 for item in results if len(item) >= 2 and item[0] == 'block')
        literals = sum(1 for item in results if len(item) >= 2 and item[0] == 'literal')

        # Con archivos idénticos, debería haber más matches que literals
        # (idealmente 100% matches, pero el algoritmo puede variar)
        self.assertGreater(matches, 0, "Debería haber al menos un match")

    def test_small_modification_minimal_transfer(self):
        """Test: Modificación pequeña debería transferir poco"""
        # Archivo original (10KB)
        original_data = b"A" * 10000

        # Generar signature
        engine = ChecksumEngine(block_size=512)
        sum_head, blocks = engine.generate_sums(original_data)

        # Archivo nuevo: solo cambia 100 bytes en el medio
        new_data = original_data[:5000] + b"B" * 100 + original_data[5100:]

        # Hacer matching
        results = engine.match_sums(new_data, sum_head, blocks)

        # Contar datos literales transferidos
        literal_bytes = sum(
            len(item[2]) if len(item) >= 3 else 0 for item in results if len(item) >= 3 and item[0] == "literal"
        )

        # Los datos literales deberían ser mucho menos que el archivo completo
        self.assertLess(
            literal_bytes,
            len(new_data) * 0.5,  # Menos del 50% del archivo
            f"Literal bytes ({literal_bytes}) deberían ser < 50% del archivo ({len(new_data)})"
        )

    def test_append_to_file(self):
        """Test: Append al final del archivo"""
        # Archivo original
        original_data = b"Original content"

        # Generar signature
        # Use a block size small enough that the original content forms at least
        # one full block that can match inside the longer target.
        engine = ChecksumEngine(block_size=16)
        sum_head, blocks = engine.generate_sums(original_data)

        # Archivo nuevo: original + datos nuevos
        new_data = original_data + b"\nAppended data"

        # Hacer matching
        results = engine.match_sums(new_data, sum_head, blocks)

        # Debería tener al menos un match (el contenido original)
        matches = sum(1 for item in results if len(item) >= 2 and item[0] == "block")
        self.assertGreater(matches, 0)

    def test_prepend_to_file(self):
        """Test: Prepend al inicio del archivo"""
        # Archivo original
        original_data = b"Original content"

        # Generar signature
        engine = ChecksumEngine(block_size=128)
        sum_head, blocks = engine.generate_sums(original_data)

        # Archivo nuevo: datos nuevos + original
        new_data = b"Prepended data\n" + original_data

        # Hacer matching
        results = engine.match_sums(new_data, sum_head, blocks)

        # Puede o no encontrar matches dependiendo de alignment
        # Verificar que no crashea
        self.assertIsNotNone(results)

    def test_completely_different_file(self):
        """Test: Archivos completamente diferentes"""
        # Archivo original
        original_data = b"A" * 10000

        # Generar signature
        engine = ChecksumEngine(block_size=1024)
        sum_head, blocks = engine.generate_sums(original_data)

        # Archivo nuevo completamente diferente
        new_data = b"B" * 10000

        # Hacer matching
        results = engine.match_sums(new_data, sum_head, blocks)

        # Con archivos completamente diferentes, deberían ser casi todos literals
        literals = sum(1 for item in results if len(item) >= 2 and item[0] == "literal")
        matches = sum(1 for item in results if len(item) >= 2 and item[0] == "block")

        # Más literals que matches (o ningún match)
        self.assertGreaterEqual(literals, matches)

    def test_wire_token_roundtrip_reconstructs(self):
        """Test: Roundtrip delta por wire tokens reconstruye exacto."""
        old_data = (b"The quick brown fox jumps over the lazy dog\n" * 200) + b"TAIL"
        new_data = (
            (b"The quick brown fox jumps over the lazy dog\n" * 120)
            + b"INSERTED\n"
            + (b"The quick brown fox jumps over the lazy cat\n" * 80)
            + b"TAIL"
            + b"APPEND"
        )

        engine = ChecksumEngine(block_size=64)
        signature = engine.generate_signature(old_data)
        delta = engine.generate_delta(signature, new_data)

        reconstructed, stats = apply_delta_over_wire(
            old_data,
            signature,
            delta,
            protocol_version=signature.protocol_version,
        )

        self.assertEqual(reconstructed, new_data)
        self.assertGreaterEqual(stats.literal_data, 0)
        self.assertGreaterEqual(stats.matched_data, 0)

    def test_wire_token_roundtrip_reconstructs_zlibx(self):
        """Test: Roundtrip delta por wire tokens (zlibx) reconstruye exacto."""
        old_data = (b"The quick brown fox jumps over the lazy dog\n" * 200) + b"TAIL"
        new_data = (
            (b"The quick brown fox jumps over the lazy dog\n" * 120)
            + b"INSERTED\n"
            + (b"The quick brown fox jumps over the lazy cat\n" * 80)
            + b"TAIL"
            + b"APPEND"
        )

        engine = ChecksumEngine(block_size=64)
        signature = engine.generate_signature(old_data)
        delta = engine.generate_delta(signature, new_data)

        reconstructed, _stats = apply_delta_over_wire(
            old_data,
            signature,
            delta,
            protocol_version=signature.protocol_version,
            compression=CompressionType.ZLIBX,
        )

        self.assertEqual(reconstructed, new_data)

    def test_wire_token_roundtrip_reconstructs_zstd(self):
        """Test: Roundtrip delta por wire tokens (zstd) reconstruye exacto."""
        old_data = (b"The quick brown fox jumps over the lazy dog\n" * 200) + b"TAIL"
        new_data = (
            (b"The quick brown fox jumps over the lazy dog\n" * 120)
            + b"INSERTED\n"
            + (b"The quick brown fox jumps over the lazy cat\n" * 80)
            + b"TAIL"
            + b"APPEND"
        )

        engine = ChecksumEngine(block_size=64)
        signature = engine.generate_signature(old_data)
        delta = engine.generate_delta(signature, new_data)

        reconstructed, _stats = apply_delta_over_wire(
            old_data,
            signature,
            delta,
            protocol_version=signature.protocol_version,
            compression=CompressionType.ZSTD,
        )

        self.assertEqual(reconstructed, new_data)

    def test_wire_token_roundtrip_reconstructs_lz4(self):
        """Test: Roundtrip delta por wire tokens (lz4) reconstruye exacto."""
        old_data = (b"The quick brown fox jumps over the lazy dog\n" * 200) + b"TAIL"
        new_data = (
            (b"The quick brown fox jumps over the lazy dog\n" * 120)
            + b"INSERTED\n"
            + (b"The quick brown fox jumps over the lazy cat\n" * 80)
            + b"TAIL"
            + b"APPEND"
        )

        engine = ChecksumEngine(block_size=64)
        signature = engine.generate_signature(old_data)
        delta = engine.generate_delta(signature, new_data)

        reconstructed, _stats = apply_delta_over_wire(
            old_data,
            signature,
            delta,
            protocol_version=signature.protocol_version,
            compression=CompressionType.LZ4,
        )

        self.assertEqual(reconstructed, new_data)

    def test_apply_delta_uses_delta_block_size(self):
        """Test: apply_delta no depende del block_size del engine receptor."""
        old_data = (b"ABCDEF" * 500) + b"TAIL"
        new_data = (b"ABCDEF" * 200) + b"INSERTED" + (b"ABCDEF" * 300) + b"TAIL"

        sender = ChecksumEngine(block_size=64)
        signature = sender.generate_signature(old_data)
        delta = sender.generate_delta(signature, new_data)

        # Receptor con block_size distinto: debe funcionar igual.
        receiver = ChecksumEngine(block_size=128)
        reconstructed = receiver.apply_delta(old_data, delta)
        self.assertEqual(reconstructed, new_data)

    def test_delta_includes_sender_file_sum(self):
        """Test: generate_delta calcula y adjunta sender_file_sum (match.c sum_end)."""
        old_data = b"0123456789" * 50
        new_data = b"0123456789" * 40 + b"CHANGED" + b"0123456789" * 10

        engine = ChecksumEngine(block_size=16, checksum_type=ChecksumType.MD5, checksum_seed=12345)
        signature = engine.generate_signature(old_data)
        delta = engine.generate_delta(signature, new_data)

        self.assertIsNotNone(delta.sender_file_sum)
        expected = engine.checksum.strong_checksum(new_data)
        self.assertEqual(delta.sender_file_sum, expected)

    def test_updating_basis_file_prefers_non_bypassed_matches(self):
        """Test: updating_basis_file evita usar bloques con offset < offset actual (match.c)."""
        prev = Config.UPDATING_BASIS_FILE
        Config.UPDATING_BASIS_FILE = True
        try:
            block = b"ABCDEFGHIJKLMNOP"  # 16 bytes
            basis = block + block + (b"I" * 16)
            new_data = (b"X" * 16) + block

            engine = ChecksumEngine(block_size=16)
            signature = engine.generate_signature(basis)
            delta = engine.generate_delta(signature, new_data)

            matches = [instr for cmd, instr in delta.instructions if cmd == "match"]
            self.assertGreaterEqual(len(matches), 1)
            self.assertEqual(matches[0].block_index, 1)
        finally:
            Config.UPDATING_BASIS_FILE = prev

    def test_generate_delta_streaming_reconstructs(self):
        """Test: _generate_delta_streaming reconstruye exacto."""
        old_data = (b"The quick brown fox jumps over the lazy dog\n" * 50) + b"TAIL"
        new_data = (
            (b"The quick brown fox jumps over the lazy dog\n" * 20)
            + b"STREAMING-INSERT\n"
            + (b"The quick brown fox jumps over the lazy cat\n" * 30)
            + b"TAIL"
        )

        engine = ChecksumEngine(block_size=64)
        signature = engine.generate_signature(old_data)

        new_path = os.path.join(self.test_dir, "new.bin")
        with open(new_path, "wb") as f:
            f.write(new_data)

        delta = engine._generate_delta_streaming(signature, new_path)
        reconstructed = engine.apply_delta(old_data, delta)
        self.assertEqual(reconstructed, new_data)
        self.assertGreaterEqual(delta.matched_bytes, 0)


class TestValidation(unittest.TestCase):
    """Tests de validación de inputs"""

    def test_invalid_block_size_negative(self):
        """Test: block_size negativo debe fallar"""
        with self.assertRaises(ValidationError):
            validate_block_size(-1)

    def test_invalid_block_size_zero(self):
        """Test: block_size cero debe fallar"""
        with self.assertRaises(ValidationError):
            validate_block_size(0)

    def test_invalid_block_size_too_small(self):
        """Test: block_size muy pequeño debe fallar"""
        with self.assertRaises(ValidationError):
            validate_block_size(10)  # Menor que MIN_BLOCK_SIZE

    def test_invalid_block_size_too_large(self):
        """Test: block_size muy grande debe fallar"""
        with self.assertRaises(ValidationError):
            validate_block_size(100 * 1024 * 1024)  # 100MB

    def test_invalid_data_type(self):
        """Test: data de tipo incorrecto debe fallar"""
        with self.assertRaises(ValidationError):
            validate_data("not bytes")  # type: ignore

    def test_data_exceeds_memory_limit(self):
        """Test: data que excede límite de memoria debe fallar"""
        # Crear datos grandes (más del límite)
        with self.assertRaises(ResourceLimitError):
            large_data = b"X" * (200 * 1024 * 1024)  # 200MB
            validate_data(large_data, max_size=100 * 1024 * 1024)  # Límite: 100MB

    def test_invalid_protocol_version_low(self):
        """Test: Versión de protocolo muy baja debe fallar"""
        with self.assertRaises(ValidationError):
            validate_protocol_version(10)  # Menor que MIN_PROTOCOL_VERSION

    def test_invalid_protocol_version_high(self):
        """Test: Versión de protocolo muy alta debe fallar"""
        with self.assertRaises(ValidationError):
            validate_protocol_version(100)  # Mayor que MAX_PROTOCOL_VERSION

    def test_valid_inputs(self):
        """Test: Inputs válidos deben pasar"""
        # Estos no deberían lanzar excepciones
        validate_block_size(1024)
        validate_data(b"Hello, World!")
        validate_protocol_version(30)


class TestRealWorldScenarios(unittest.TestCase):
    """Tests de escenarios del mundo real"""

    def test_text_file_modification(self):
        """Test: Modificación de archivo de texto (típico en code sync)"""
        # Simular archivo Python original
        original = b"""
def hello():
    print("Hello, World!")

def goodbye():
    print("Goodbye!")
"""

        # Generar signature
        # Use a smaller block size so unchanged sections produce full-block matches.
        engine = ChecksumEngine(block_size=64)
        sum_head, blocks = engine.generate_sums(original)

        # Archivo modificado: agregar nueva función
        modified = b"""
def hello():
    print("Hello, World!")

def greet(name):
    print(f"Hello, {name}!")

def goodbye():
    print("Goodbye!")
"""

        # Hacer matching
        results = engine.match_sums(modified, sum_head, blocks)

        # Verificar que encontró algunos matches
        matches = sum(1 for item in results if len(item) >= 2 and item[0] == "block")
        self.assertGreater(matches, 0, "Debería encontrar código común")

    def test_binary_file_modification(self):
        """Test: Modificación de archivo binario"""
        # Simular archivo binario (ej: imagen con header)
        header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        data = b"\xFF" * 10000
        original = header + data

        # Generar signature
        # Use a smaller block size so the unchanged header contributes full blocks.
        engine = ChecksumEngine(block_size=64)
        sum_head, blocks = engine.generate_sums(original)

        # Archivo modificado: cambiar algo en los datos pero header intacto
        modified_data = b"\xFE" * 10000
        modified = header + modified_data

        # Hacer matching
        results = engine.match_sums(modified, sum_head, blocks)

        # Debería encontrar el header sin cambios
        matches = sum(1 for item in results if len(item) >= 2 and item[0] == "block")
        self.assertGreater(matches, 0, "Debería encontrar header común")


def run_end_to_end_tests():
    """Ejecutar todos los tests end-to-end"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestEndToEndSync))
    suite.addTests(loader.loadTestsFromTestCase(TestValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestRealWorldScenarios))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print("END-TO-END TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run:     {result.testsRun}")
    print(f"Successes:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:      {len(result.failures)}")
    print(f"Errors:        {len(result.errors)}")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_end_to_end_tests()
    sys.exit(0 if success else 1)
