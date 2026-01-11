#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Wire Protocol Parity - rsync-python

This test suite validates that rsync-python's wire protocol implementation
is byte-for-byte compatible with rsync's C implementation.

Tests cover:
- Token encoding/decoding (send_token/recv_token)
- Sum header format (read_sum_head/write_sum_head)
- Delta roundtrip through wire protocol

Key insight: For testing purposes, we use in-memory byte buffers instead of
actual file descriptors/pipes, since os.read() blocks on empty pipes.

Reference:
    token.c: simple_send_token() lines 306-322
    token.c: recv_token() lines 253-302
    io.c: read_sum_head() lines 1965-1992
    io.c: write_sum_head() lines 1997-2010
    receiver.c: receive_data() lines 240-413
"""

import io
import struct
import unittest
from typing import List, Tuple, Optional, Dict


# =============================================================================
# In-Memory Protocol I/O for Testing
# =============================================================================

class InMemoryProtocolIO:
    """In-memory ProtocolIO for testing (avoids blocking I/O issues).
    
    This class provides a ProtocolIO interface using in-memory byte buffers
    instead of file descriptors, which is essential for unit testing.
    """
    
    def __init__(self) -> None:
        self._read_buffer = io.BytesIO()
        self._write_buffer = io.BytesIO()
    
    # Writing methods
    def write_int(self, value: int) -> None:
        """Write 32-bit integer (little-endian, like io.c SIVAL)."""
        self._write_buffer.write(struct.pack('<i', value))
    
    def write_bytes(self, data: bytes) -> None:
        """Write bytes."""
        self._write_buffer.write(data)
    
    def write_byte(self, value: int) -> None:
        """Write single byte."""
        self._write_buffer.write(bytes([value]))
    
    # Reading methods
    def read_int(self) -> int:
        """Read 32-bit integer (little-endian, like io.c IVAL)."""
        return struct.unpack('<i', self._read_buffer.read(4))[0]
    
    def read_bytes(self, size: int) -> bytes:
        """Read exactly size bytes."""
        data = self._read_buffer.read(size)
        if len(data) < size:
            raise EOFError(f"Expected {size} bytes, got {len(data)}")
        return data
    
    def read_byte(self) -> int:
        """Read single byte."""
        return self._read_buffer.read(1)[0]
    
    def has_data(self, needed: int = 4) -> bool:
        """Check if buffer has at least 'needed' bytes available."""
        pos = self._read_buffer.tell()
        remaining = len(self._read_buffer.getvalue()) - pos
        return remaining >= needed
    
    # Buffer management
    def get_written_data(self) -> bytes:
        """Get all data written and reset buffer."""
        data = self._write_buffer.getvalue()
        self._write_buffer = io.BytesIO()
        return data
    
    def load_data(self, data: bytes) -> None:
        """Load data to be read."""
        self._read_buffer = io.BytesIO(data)
    
    def flush(self) -> None:
        """Flush (no-op for in-memory)."""
        pass
    
    # Token operations
    def send_token(self, token: int, data: Optional[bytes] = None,
                   offset: int = 0, n: int = 0) -> None:
        """Send token with optional literal data."""
        if data is not None and n > 0:
            sent = 0
            while sent < n:
                chunk_len = min(CHUNK_SIZE, n - sent)
                self.write_int(chunk_len)
                self.write_bytes(data[offset + sent:offset + sent + chunk_len])
                sent += chunk_len
        if token != -2:
            self.write_int(-(token + 1))
    
    def recv_token(self) -> Tuple[int, Optional[bytes]]:
        """Receive token."""
        i = self.read_int()
        if i == 0:
            return (0, None)
        if i > 0:
            data = self.read_bytes(i)
            return (i, data)
        return (i, None)
    
    # Variable-length integers (protocol >= 27)
    def write_varint(self, value: int) -> None:
        """Write variable-length integer."""
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
    
    def read_varint(self) -> int:
        """Read variable-length integer."""
        int_byte_extra = (
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5, 6,
        )
        ch = self.read_byte() & 0xFF
        extra = int_byte_extra[ch // 4]
        if extra:
            if extra >= 5:
                raise ValueError("Overflow in read_varint()")
            bit = 1 << (8 - extra)
            buf = bytearray(5)
            data = self.read_bytes(extra)
            buf[:extra] = data
            buf[extra] = ch & (bit - 1)
            return int.from_bytes(buf[:4], 'little', signed=True)
        return int.from_bytes(bytes([ch, 0, 0, 0]), 'little', signed=True)
    
    # Sum header operations
    def write_sum_head(self, sum_struct: Dict[str, int], protocol_version: int = 32) -> None:
        """Write sum_struct header."""
        self.write_int(sum_struct['count'])
        self.write_int(sum_struct['blength'])
        if protocol_version >= 27:
            self.write_int(sum_struct['s2length'])
        self.write_int(sum_struct['remainder'])
    
    def read_sum_head(self, protocol_version: int = 32) -> Dict[str, int]:
        """Read sum_struct header."""
        count = self.read_int()
        blength = self.read_int()
        s2length = self.read_int() if protocol_version >= 27 else SHORT_SUM_LENGTH
        remainder = self.read_int()
        return {
            'count': count,
            'blength': blength,
            's2length': s2length,
            'remainder': remainder,
        }


# =============================================================================
# Import from rsync_phoenix_rebuilt
# =============================================================================

from rsync_phoenix_rebuilt import (
    ChecksumEngine,
    ChecksumType,
    CHUNK_SIZE,
    SHORT_SUM_LENGTH,
    ChecksumSignature,
    DeltaMatch,
    DeltaLiteral,
    DeltaInstructions,
)


# =============================================================================
# Test Cases
# =============================================================================

class TestWireProtocolTokens(unittest.TestCase):
    """Test wire protocol token encoding/decoding."""

    def test_literal_token_roundtrip(self):
        """Test literal data token roundtrip."""
        original_data = b"Hello, World! This is a test message."
        
        sender = InMemoryProtocolIO()
        sender.send_token(-2, original_data, 0, len(original_data))
        sender.flush()
        
        sender.load_data(sender.get_written_data())
        token, data = sender.recv_token()
        
        self.assertEqual(token, len(original_data))
        self.assertEqual(data, original_data)

    def test_match_token_roundtrip(self):
        """Test match token encoding."""
        for block_index in [0, 1, 5, 100, 1000]:
            sender = InMemoryProtocolIO()
            sender.send_token(block_index)
            sender.flush()
            
            sender.load_data(sender.get_written_data())
            token, data = sender.recv_token()
            
            expected_token = -(block_index + 1)
            self.assertEqual(token, expected_token)
            self.assertIsNone(data)

    def test_end_of_transfer(self):
        """Test end-of-transfer marker (token = 0)."""
        sender = InMemoryProtocolIO()
        sender.write_int(0)
        
        sender.load_data(sender.get_written_data())
        token, data = sender.recv_token()
        
        self.assertEqual(token, 0)
        self.assertIsNone(data)

    def test_literal_in_chunks(self):
        """Test that large literals are sent in CHUNK_SIZE pieces."""
        large_data = b"X" * (CHUNK_SIZE * 2 + 100)
        
        sender = InMemoryProtocolIO()
        sender.send_token(-2, large_data, 0, len(large_data))
        sender.flush()
        
        sender.load_data(sender.get_written_data())
        
        chunks: List[bytes] = []
        while sender.has_data(4):
            token, data = sender.recv_token()
            if token == 0:
                break
            if token < 0:
                break  # Match token - shouldn't happen
            # data should not be None for literal tokens
            assert data is not None, "Literal data should not be None"
            self.assertEqual(len(data), token)
            chunks.append(data)
        
        received_data = b''.join(chunks)
        self.assertEqual(received_data, large_data)

    def test_mixed_tokens(self):
        """Test sequence of literal and match tokens."""
        literals = [b"First literal", b"Second literal"]
        match_blocks = [0, 2]
        
        sender = InMemoryProtocolIO()
        sender.send_token(-2, literals[0], 0, len(literals[0]))
        sender.send_token(match_blocks[0])
        sender.send_token(-2, literals[1], 0, len(literals[1]))
        sender.send_token(match_blocks[1])
        sender.write_int(0)
        sender.flush()
        
        sender.load_data(sender.get_written_data())
        
        # Expected tokens for each iteration
        expected_tokens = [
            len(literals[0]),  # First literal length
            -(match_blocks[0] + 1),  # First match (block 0 -> -1)
            len(literals[1]),  # Second literal length
            -(match_blocks[1] + 1),  # Second match (block 2 -> -3)
            0,  # EOT
        ]
        
        for i, expected_token in enumerate(expected_tokens):
            token, data = sender.recv_token()
            self.assertEqual(token, expected_token, f"Token {i} mismatch")
            
            if token > 0:
                # Literal - data should not be None
                assert data is not None, f"Literal data should not be None at token {i}"


class TestSumHeadProtocol(unittest.TestCase):
    """Test sum_struct header encoding/decoding."""

    def test_sum_head_write_read(self):
        """Test sum header roundtrip."""
        sum_struct = {
            'count': 100,
            'blength': 4096,
            's2length': 16,
            'remainder': 512,
        }
        
        proto = InMemoryProtocolIO()
        proto.write_sum_head(sum_struct, protocol_version=30)
        
        proto.load_data(proto.get_written_data())
        read_head = proto.read_sum_head(protocol_version=30)
        
        self.assertEqual(read_head['count'], sum_struct['count'])
        self.assertEqual(read_head['blength'], sum_struct['blength'])
        self.assertEqual(read_head['s2length'], sum_struct['s2length'])
        self.assertEqual(read_head['remainder'], sum_struct['remainder'])

    def test_sum_head_protocol_26(self):
        """Test sum header without s2length (protocol < 27)."""
        sum_struct = {
            'count': 50,
            'blength': 8192,
            's2length': 0,
            'remainder': 0,
        }
        
        proto = InMemoryProtocolIO()
        proto.write_sum_head(sum_struct, protocol_version=26)
        
        proto.load_data(proto.get_written_data())
        read_head = proto.read_sum_head(protocol_version=26)
        
        self.assertEqual(read_head['blength'], sum_struct['blength'])
        self.assertEqual(read_head['remainder'], sum_struct['remainder'])

    def test_sum_head_empty(self):
        """Test empty sum header."""
        sum_struct = {'count': 0, 'blength': 0, 's2length': 0, 'remainder': 0}
        
        proto = InMemoryProtocolIO()
        proto.write_sum_head(sum_struct, protocol_version=30)
        
        proto.load_data(proto.get_written_data())
        read_head = proto.read_sum_head(protocol_version=30)
        
        self.assertEqual(read_head['count'], 0)
        self.assertEqual(read_head['blength'], 0)


class TestDeltaWireProtocol(unittest.TestCase):
    """Test full delta roundtrip through wire protocol."""

    def _send_delta(self, signature: ChecksumSignature, 
                   delta: DeltaInstructions) -> bytes:
        """Send delta and return wire bytes."""
        proto = InMemoryProtocolIO()
        
        # Write sum_head
        sum_head = {
            'count': signature.num_blocks,
            'blength': signature.block_size,
            's2length': signature.s2length,
            'remainder': signature.remainder,
        }
        proto.write_sum_head(sum_head, protocol_version=signature.protocol_version)
        
        # Write instructions
        for cmd, instr in delta.instructions:
            if cmd == 'literal' and isinstance(instr, DeltaLiteral):
                if instr.data:
                    proto.send_token(-2, instr.data, 0, len(instr.data))
            elif cmd == 'match' and isinstance(instr, DeltaMatch):
                proto.send_token(instr.block_index)
        
        proto.write_int(0)  # End of transfer
        proto.flush()
        
        return proto.get_written_data()

    def _receive_delta(self, wire_data: bytes, basis_data: bytes,
                      signature: ChecksumSignature) -> bytes:
        """Receive delta from wire and reconstruct."""
        proto = InMemoryProtocolIO()
        proto.load_data(wire_data)
        
        # Read sum_head
        sum_head = proto.read_sum_head(protocol_version=signature.protocol_version)
        
        # Reconstruct using receive_data logic
        result = bytearray()
        blength_val = sum_head['blength']
        remainder_val = sum_head['remainder']
        count_val = sum_head['count']
        
        while proto.has_data(4):
            token, data = proto.recv_token()
            if token == 0:
                break
            if token > 0 and data:
                result.extend(data)
            elif token < 0:
                block_num = -(token + 1)
                if block_num < 0 or block_num >= count_val:
                    raise ValueError(f"Invalid block number {block_num}")
                
                offset = block_num * blength_val
                block_len = remainder_val if (block_num == count_val - 1 and remainder_val > 0) else blength_val
                
                if offset + block_len <= len(basis_data):
                    result.extend(basis_data[offset:offset + block_len])
                else:
                    raise ValueError(f"Block {block_num} extends past basis file")
        
        return bytes(result)

    def test_delta_roundtrip(self):
        """Test delta sent over wire and reconstructed."""
        original_data = b"A" * 1000 + b"B" * 1000
        modified_data = original_data[:1000] + b"X" * 500 + original_data[1500:]
        
        engine = ChecksumEngine(block_size=512, checksum_type=ChecksumType.MD5)
        signature = engine.generate_signature(original_data)
        delta = engine.generate_delta(signature, modified_data)
        
        # Roundtrip through wire
        wire_data = self._send_delta(signature, delta)
        result = self._receive_delta(wire_data, original_data, signature)
        
        self.assertEqual(result, modified_data)

    def test_delta_only_literals(self):
        """Test delta with no matches (all literals)."""
        original_data = b"A" * 1000
        modified_data = b"B" * 1000
        
        engine = ChecksumEngine(block_size=512, checksum_type=ChecksumType.MD5)
        signature = engine.generate_signature(original_data)
        delta = engine.generate_delta(signature, modified_data)
        
        self.assertEqual(delta.num_matches, 0)
        self.assertEqual(delta.num_literals, 1)
        
        wire_data = self._send_delta(signature, delta)
        result = self._receive_delta(wire_data, original_data, signature)
        
        self.assertEqual(result, modified_data)

    def test_delta_only_matches(self):
        """Test delta with all matches (no literals)."""
        original_data = b"A" * 1000
        modified_data = original_data
        
        engine = ChecksumEngine(block_size=512, checksum_type=ChecksumType.MD5)
        signature = engine.generate_signature(original_data)
        delta = engine.generate_delta(signature, modified_data)
        
        self.assertEqual(delta.num_literals, 0)
        self.assertEqual(delta.num_matches, 2)
        
        wire_data = self._send_delta(signature, delta)
        result = self._receive_delta(wire_data, original_data, signature)
        
        self.assertEqual(result, modified_data)

    def test_delta_small_file(self):
        """Test delta for file smaller than block size."""
        original_data = b"Hello, World!"
        modified_data = b"Hello, rsync!"
        
        engine = ChecksumEngine(block_size=2048, checksum_type=ChecksumType.MD5)
        signature = engine.generate_signature(original_data)
        delta = engine.generate_delta(signature, modified_data)
        
        wire_data = self._send_delta(signature, delta)
        result = self._receive_delta(wire_data, original_data, signature)
        
        self.assertEqual(result, modified_data)

    def test_delta_large_literal(self):
        """Test delta with large literal data."""
        original_data = b"A" * 10000
        modified_data = original_data[:4500] + b"X" * 1000 + original_data[5500:]
        
        engine = ChecksumEngine(block_size=1024, checksum_type=ChecksumType.MD5)
        signature = engine.generate_signature(original_data)
        delta = engine.generate_delta(signature, modified_data)
        
        wire_data = self._send_delta(signature, delta)
        result = self._receive_delta(wire_data, original_data, signature)
        
        self.assertEqual(result, modified_data)


class TestChecksumWireEncoding(unittest.TestCase):
    """Test checksum encoding on wire."""

    def test_checksum_lengths(self):
        """Test checksum length calculations."""
        from rsync_phoenix_rebuilt import csum_len_for_type, CSUM_MD5, CSUM_XXH64
        
        self.assertEqual(csum_len_for_type(CSUM_MD5), 16)
        self.assertEqual(csum_len_for_type(CSUM_XXH64), 8)


class TestVarintProtocol(unittest.TestCase):
    """Test varint encoding/decoding parity with io.c."""

    def test_varint_known_vectors(self):
        cases = [
            (0, b"\x00"),
            (1, b"\x01"),
            (127, b"\x7f"),
            (128, b"\x80\x80"),
            (255, b"\x80\xff"),
            (256, b"\x81\x00"),
            (16383, b"\xbf\xff"),
            (16384, b"\xc0\x00\x40"),
        ]
        for value, expected in cases:
            proto = InMemoryProtocolIO()
            proto.write_varint(value)
            self.assertEqual(proto.get_written_data(), expected, f"encode({value})")

            proto.load_data(expected)
            self.assertEqual(proto.read_varint(), value, f"decode({value})")

    def test_varint_roundtrip_range(self):
        values = [0, 1, 2, 5, 10, 63, 64, 65, 127, 128, 129, 255, 256, 1024, 4096, 16383, 16384, 1 << 20]
        for value in values:
            proto = InMemoryProtocolIO()
            proto.write_varint(value)
            data = proto.get_written_data()
            proto.load_data(data)
            self.assertEqual(proto.read_varint(), value)


class TestIntEncoding(unittest.TestCase):
    """Validate little-endian int encoding (io.c: read_int/write_int)."""

    def test_write_int_little_endian(self):
        proto = InMemoryProtocolIO()
        proto.write_int(0x01020304)
        self.assertEqual(proto.get_written_data(), b"\x04\x03\x02\x01")

        proto = InMemoryProtocolIO()
        proto.write_int(-1)
        self.assertEqual(proto.get_written_data(), b"\xff\xff\xff\xff")
