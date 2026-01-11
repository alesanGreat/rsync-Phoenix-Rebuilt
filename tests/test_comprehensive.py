#!/usr/bin/env python
"""
Comprehensive Test Suite for rsync_phoenix_rebuilt.py
==============================================

Tests completos con cobertura extendida:
1. Edge cases (archivos vacíos, muy grandes, datos corruptos)
2. Boundary testing (límites de protocolo, tamaños de bloque)
3. Stress testing (muchos bloques, datos aleatorios)
4. Regression testing (bugs conocidos)
5. Integration testing (múltiples protocolos juntos)
"""

import unittest
import os
import sys
import random
import hashlib
from rsync_phoenix_rebuilt import (
    Checksum,
    ChecksumEngine,
    ChecksumType,
    CompressionType,
    CompressionRegistry,
    ProtocolVersionManager,
    IOBuffer,
    ProtocolIO,
    PROTOCOL_VERSION,
    MIN_PROTOCOL_VERSION,
    MAX_BLOCK_SIZE,
    OLD_MAX_BLOCK_SIZE
)


class TestEdgeCases(unittest.TestCase):
    """Tests de casos extremos y límites"""

    def test_empty_data(self):
        """Test con datos completamente vacíos"""
        engine = ChecksumEngine()
        sum_head, blocks = engine.generate_sums(b'')
        self.assertEqual(len(blocks), 0)
        self.assertIsNotNone(sum_head)

    def test_single_byte(self):
        """Test con un solo byte"""
        engine = ChecksumEngine(block_size=100)
        data = b'X'
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 1)
        # Blocks pueden ser tuples o bytes, verificar que existan
        self.assertIsNotNone(blocks[0])

    def test_exactly_block_size(self):
        """Test con datos exactamente del tamaño de un bloque"""
        block_size = 1024
        engine = ChecksumEngine(block_size=block_size)
        data = b'A' * block_size
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 1)

    def test_one_byte_over_block(self):
        """Test con un byte más que el tamaño del bloque"""
        block_size = 1024
        engine = ChecksumEngine(block_size=block_size)
        data = b'A' * (block_size + 1)
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 2)

    def test_very_large_file(self):
        """Test con archivo muy grande (50MB)"""
        engine = ChecksumEngine(block_size=MAX_BLOCK_SIZE)
        # Generar 50MB de datos con patrón repetitivo
        chunk = b'0123456789' * 1000  # 10KB
        data = chunk * 5000  # 50MB
        sum_head, blocks = engine.generate_sums(data)
        expected_blocks = (len(data) + MAX_BLOCK_SIZE - 1) // MAX_BLOCK_SIZE
        self.assertEqual(len(blocks), expected_blocks)

    def test_all_zero_bytes(self):
        """Test con datos todos en cero"""
        engine = ChecksumEngine()
        data = b'\x00' * 10000
        sum_head, blocks = engine.generate_sums(data)
        self.assertTrue(len(blocks) > 0)

    def test_all_ff_bytes(self):
        """Test con datos todos en 0xFF"""
        engine = ChecksumEngine()
        data = b'\xff' * 10000
        sum_head, blocks = engine.generate_sums(data)
        self.assertTrue(len(blocks) > 0)

    def test_random_data(self):
        """Test con datos completamente aleatorios"""
        engine = ChecksumEngine()
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(50000))
        sum_head, blocks = engine.generate_sums(data)
        self.assertTrue(len(blocks) > 0)


class TestBoundaryConditions(unittest.TestCase):
    """Tests de condiciones de límite"""

    def test_min_protocol_version(self):
        """Test con versión mínima de protocolo (20)"""
        manager = ProtocolVersionManager(desired_protocol=MIN_PROTOCOL_VERSION)
        negotiated = manager.negotiate_protocol(MIN_PROTOCOL_VERSION)
        self.assertEqual(negotiated, MIN_PROTOCOL_VERSION)
        self.assertEqual(manager.get_max_block_size(), OLD_MAX_BLOCK_SIZE)

    def test_max_protocol_version(self):
        """Test con versión máxima de protocolo (32)"""
        manager = ProtocolVersionManager(desired_protocol=PROTOCOL_VERSION)
        negotiated = manager.negotiate_protocol(PROTOCOL_VERSION)
        self.assertEqual(negotiated, PROTOCOL_VERSION)
        self.assertEqual(manager.get_max_block_size(), MAX_BLOCK_SIZE)

    def test_protocol_downgrade(self):
        """Test de downgrade de protocolo"""
        manager = ProtocolVersionManager(desired_protocol=32)
        # Servidor solo soporta protocolo 25
        negotiated = manager.negotiate_protocol(25)
        self.assertEqual(negotiated, 25)

    def test_protocol_upgrade_attempt(self):
        """Test de intento de upgrade (debe usar el menor)"""
        manager = ProtocolVersionManager(desired_protocol=25)
        # Servidor soporta protocolo 32
        negotiated = manager.negotiate_protocol(32)
        self.assertEqual(negotiated, 25)  # Debe usar el nuestro (menor)

    def test_min_block_size(self):
        """Test con tamaño de bloque mínimo razonable"""
        engine = ChecksumEngine(block_size=128)
        data = b'A' * 1000
        sum_head, blocks = engine.generate_sums(data)
        expected_blocks = (1000 + 127) // 128
        self.assertEqual(len(blocks), expected_blocks)

    def test_max_block_size(self):
        """Test con tamaño de bloque máximo"""
        engine = ChecksumEngine(block_size=MAX_BLOCK_SIZE)
        data = b'A' * (MAX_BLOCK_SIZE * 3)
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 3)


class TestCompressionExtensive(unittest.TestCase):
    """Tests extensivos de compresión"""

    def test_highly_compressible_data(self):
        """Test con datos altamente comprimibles"""
        data = b'A' * 10000
        for comp_type in [CompressionType.ZLIB, CompressionType.LZ4, CompressionType.ZSTD]:
            compressed = CompressionRegistry.compress(data, comp_type)
            self.assertLess(len(compressed), len(data))
            decompressed = CompressionRegistry.decompress(compressed, comp_type)
            self.assertEqual(data, decompressed)

    def test_incompressible_data(self):
        """Test con datos incomprimibles (aleatorios)"""
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        for comp_type in [CompressionType.ZLIB, CompressionType.LZ4, CompressionType.ZSTD]:
            compressed = CompressionRegistry.compress(data, comp_type)
            # Datos aleatorios pueden resultar más grandes al comprimirse
            decompressed = CompressionRegistry.decompress(compressed, comp_type)
            self.assertEqual(data, decompressed)

    def test_empty_compression(self):
        """Test de compresión de datos vacíos"""
        data = b''
        for comp_type in [CompressionType.ZLIB, CompressionType.LZ4, CompressionType.ZSTD]:
            compressed = CompressionRegistry.compress(data, comp_type)
            decompressed = CompressionRegistry.decompress(compressed, comp_type)
            self.assertEqual(data, decompressed)

    def test_compression_levels(self):
        """Test de diferentes niveles de compresión"""
        data = b'The quick brown fox jumps over the lazy dog. ' * 100
        for level in [1, 5, 9]:
            compressed = CompressionRegistry.compress(data, CompressionType.ZLIB, level=level)
            decompressed = CompressionRegistry.decompress(compressed, CompressionType.ZLIB)
            self.assertEqual(data, decompressed)


class TestChecksumAlgorithms(unittest.TestCase):
    """Tests extensivos de algoritmos de checksum"""

    def test_all_checksum_types(self):
        """Test de todos los tipos de checksum disponibles"""
        data = b'Testing all checksum algorithms'
        for checksum_type in [ChecksumType.MD5, ChecksumType.SHA1,
                              ChecksumType.XXH64, ChecksumType.XXH3, ChecksumType.XXH128]:
            engine = ChecksumEngine(checksum_type=checksum_type)
            sum_head, blocks = engine.generate_sums(data)
            self.assertTrue(len(blocks) > 0)
            # Verificar que cada bloque existe
            for block in blocks:
                self.assertIsNotNone(block)

    def test_checksum_consistency(self):
        """Test de consistencia de checksums (mismo input = mismo output)"""
        data = b'Consistency test data'
        for _ in range(10):
            engine = ChecksumEngine()
            sum_head1, blocks1 = engine.generate_sums(data)
            sum_head2, blocks2 = engine.generate_sums(data)
            self.assertEqual(len(blocks1), len(blocks2))
            for b1, b2 in zip(blocks1, blocks2):
                self.assertEqual(b1, b2)

    def test_rolling_checksum_properties(self):
        """Test de propiedades matemáticas del rolling checksum"""
        checksum = Checksum()
        data = b'abcdefgh'

        # Calcular checksum completo de la ventana final
        full_weak = checksum.rolling_checksum(data[4:])

        # Calcular con rolling update desde el principio
        window_len = 4
        # Calcular checksum inicial de los primeros 4 bytes
        initial = checksum.rolling_checksum(data[:window_len])
        s1, s2 = checksum.checksum_components(initial)

        # Rolling update para deslizar la ventana
        for i in range(window_len, len(data)):
            s1, s2 = checksum.rolling_update(data[i-window_len], data[i], s1, s2, window_len)

        rolling_weak = checksum.combine_checksum(s1, s2)

        # Deben ser iguales
        self.assertEqual(full_weak, rolling_weak)


class TestProtocolFeatures(unittest.TestCase):
    """Tests de características específicas por protocolo"""

    def test_protocol_20_features(self):
        """Verificar características de protocolo 20"""
        manager = ProtocolVersionManager(desired_protocol=20)
        manager.negotiate_protocol(20)
        self.assertEqual(manager.get_max_block_size(), OLD_MAX_BLOCK_SIZE)
        self.assertEqual(manager.get_default_checksum_type(), ChecksumType.MD4)
        self.assertFalse(manager.supports_varint())
        self.assertFalse(manager.supports_long_names())

    def test_protocol_27_features(self):
        """Verificar características de protocolo 27 (varint)"""
        manager = ProtocolVersionManager(desired_protocol=27)
        manager.negotiate_protocol(27)
        self.assertTrue(manager.supports_varint())
        self.assertFalse(manager.supports_long_names())

    def test_protocol_30_features(self):
        """Verificar características de protocolo 30 (MD5, bloques grandes)"""
        manager = ProtocolVersionManager(desired_protocol=30)
        manager.negotiate_protocol(30)
        self.assertEqual(manager.get_max_block_size(), MAX_BLOCK_SIZE)
        self.assertEqual(manager.get_default_checksum_type(), ChecksumType.MD5)
        self.assertTrue(manager.supports_varint())
        self.assertTrue(manager.supports_inc_recursion())

    def test_protocol_31_features(self):
        """Verificar características de protocolo 31 (xxHash, zstd)"""
        manager = ProtocolVersionManager(desired_protocol=31)
        manager.negotiate_protocol(31)
        self.assertTrue(manager.supports_xxhash())
        self.assertTrue(manager.supports_zstd())
        self.assertTrue(manager.supports_crtimes())


class TestIOBufferExtensive(unittest.TestCase):
    """Tests extensivos del buffer de I/O"""

    def test_buffer_initialization(self):
        """Test de inicialización del buffer"""
        buffer = IOBuffer(bufsize=1024)
        self.assertEqual(buffer.size, 1024)
        self.assertEqual(buffer.pos, 0)
        self.assertEqual(buffer.len, 0)

    def test_buffer_different_sizes(self):
        """Test con diferentes tamaños de buffer"""
        for size in [512, 1024, 4096, 65536]:
            buffer = IOBuffer(bufsize=size)
            self.assertEqual(buffer.size, size)

    def test_buffer_attributes(self):
        """Test de atributos del buffer"""
        buffer = IOBuffer()
        self.assertIsNotNone(buffer.buf)
        self.assertIsInstance(buffer.buf, bytearray)
        self.assertTrue(len(buffer.buf) > 0)


class TestRegressionBugs(unittest.TestCase):
    """Tests de regresión para bugs conocidos"""

    def test_checksum_engine_block_size_bug(self):
        """
        Regression test: ChecksumEngine no pasaba block_size al constructor de Checksum
        Bug reportado: 2026-01-08
        """
        engine = ChecksumEngine(block_size=8192)
        # Este test fallaría antes del fix
        data = b'Test data for block size bug'
        sum_head, blocks = engine.generate_sums(data)
        self.assertTrue(len(blocks) > 0)


class TestStress(unittest.TestCase):
    """Tests de estrés y performance"""

    def test_many_small_blocks(self):
        """Test con muchos bloques pequeños"""
        engine = ChecksumEngine(block_size=16)
        data = b'X' * 10000  # 625 bloques de 16 bytes
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 625)

    def test_few_large_blocks(self):
        """Test con pocos bloques grandes"""
        engine = ChecksumEngine(block_size=MAX_BLOCK_SIZE)
        data = b'Y' * (MAX_BLOCK_SIZE * 5)
        sum_head, blocks = engine.generate_sums(data)
        self.assertEqual(len(blocks), 5)

    def test_repeated_checksum_calculation(self):
        """Test de cálculo repetido de checksums (stress)"""
        engine = ChecksumEngine()
        data = b'Stress test data' * 100
        for _ in range(100):
            sum_head, blocks = engine.generate_sums(data)
            self.assertTrue(len(blocks) > 0)


def run_comprehensive_tests():
    """Ejecutar todos los tests comprehensivos"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Agregar todas las suites de tests
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestBoundaryConditions))
    suite.addTests(loader.loadTestsFromTestCase(TestCompressionExtensive))
    suite.addTests(loader.loadTestsFromTestCase(TestChecksumAlgorithms))
    suite.addTests(loader.loadTestsFromTestCase(TestProtocolFeatures))
    suite.addTests(loader.loadTestsFromTestCase(TestIOBufferExtensive))
    suite.addTests(loader.loadTestsFromTestCase(TestRegressionBugs))
    suite.addTests(loader.loadTestsFromTestCase(TestStress))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Resumen
    print("\n" + "=" * 70)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run:     {result.testsRun}")
    print(f"Successes:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:      {len(result.failures)}")
    print(f"Errors:        {len(result.errors)}")
    print("=" * 70)

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)
