# rsync-Phoenix-Rebuilt

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Protocol](https://img.shields.io/badge/rsync_protocol-20--32-green.svg)](https://rsync.samba.org/)
[![Tests](https://img.shields.io/badge/tests-120%2F120_passing-brightgreen.svg)](./tests/)
[![CI/CD](https://github.com/alesanGreat/rsync-Phoenix-Rebuilt/actions/workflows/ci.yml/badge.svg)](https://github.com/alesanGreat/rsync-Phoenix-Rebuilt/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Pure Python rsync algorithm + protocol building blocks (no rsync binary needed for the core library).**

## 🎯 Why This Exists

**Problem:** You need rsync functionality but:
- ❌ Can't install the rsync binary (restricted environments, embedded systems)
- ❌ Don't have compiler access to build rsync from source
- ❌ Need rsync in Python applications without subprocess calls
- ❌ Want to understand the algorithm through readable code

**Solution:** This pure Python implementation gives you:
- ✅ **No dependencies on rsync binary** - Works anywhere Python runs
- ✅ **Easy integration** - Import as a Python module
- ✅ **Cross-platform** - Windows, Linux, macOS, embedded systems
- ✅ **1:1 algorithm parity** - Compatible with rsync protocol versions 20-32
- ✅ **Educational** - Learn rsync internals with readable Python code

## 🎯 What Makes This Special

- **1:1 C Code Parity**: Every algorithm mirrors the original rsync C implementation with exact line references
- **High Confidence**: 120 passing tests including cross-validation/interop against rsync binary
- **Monolithic Design**: Single ~9200-line Python file - easy to audit, deploy, and integrate
- **Protocol Versions 20–32**: Algorithm support (checksums, compression, delta) + expanding wire-level parity (compat/mplex/flist)
- **Streaming Support**: Process files larger than RAM with constant memory usage
- **Professional CLI**: Beautiful terminal output with colors, progress, and statistics

## 🚀 Quick Start

### Installation

**Method 1: From Source (Recommended for Development)**
```bash
# Clone the repository
git clone https://github.com/alesanGreat/rsync-Phoenix-Rebuilt.git
cd rsync-Phoenix-Rebuilt

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks (optional)
pre-commit install

# Run tests to verify installation
python -m unittest discover
```

**Method 2: PyPI Installation (Coming Soon)**
```bash
pip install rsync-python
```

**Method 3: Minimal Installation**
```bash
# Clone and install core dependencies only
git clone https://github.com/alesanGreat/rsync-Phoenix-Rebuilt.git
cd rsync-Phoenix-Rebuilt
pip install xxhash lz4 zstandard
```

### Basic Usage

```python
from rsync_phoenix_rebuilt import ChecksumEngine

# Create engine
engine = ChecksumEngine(block_size=4096)

# Example data
original = b"Hello, World! " * 1000
modified = original[:500] + b"CHANGED!" + original[508:]

# Generate signature of original file
signature = engine.generate_signature(original)

# Generate delta (what changed)
delta = engine.generate_delta(signature, modified)
print(f"Compression: {delta.compression_ratio:.1%}")  # 99.9%

# Reconstruct modified file from original + delta
reconstructed = engine.apply_delta(original, delta)
assert reconstructed == modified  # ✓
```

### CLI Usage

```bash
# Compare two files and show statistics
python rsync_phoenix_rebuilt.py sync original.txt modified.txt

# Three-step workflow (signature → delta → patch)
python rsync_phoenix_rebuilt.py signature original.bin -o original.sig
python rsync_phoenix_rebuilt.py delta original.sig modified.bin -o changes.delta
python rsync_phoenix_rebuilt.py patch original.bin changes.delta -o result.bin

# Run performance benchmarks
python rsync_phoenix_rebuilt.py benchmark --size 100  # 100MB test file

# Get help
python rsync_phoenix_rebuilt.py --help
python rsync_phoenix_rebuilt.py --examples
```

## 📚 Key Features

### Algorithm Implementation

- **Rolling Checksum** (Adler-32 variant): O(1) update as window slides byte-by-byte
- **Strong Checksums**: MD4, MD5, SHA1, SHA256, xxHash64, xxHash3-64, xxHash3-128
- **Hash Table Matching**: Dynamic sizing with 80% load factor (same as C implementation)
- **Optimizations**: want_i adjacent matching, early flush logic, aligned matching

### Protocol Support

| Protocol | Features | Checksums | Max Block Size |
|----------|----------|-----------|----------------|
| 20-26 | Basic rsync | MD4 | 8 KB |
| 27-29 | Variable-length integers, long filenames | MD4 | 8 KB |
| 30 | Incremental recursion | MD5 (default) | 128 KB |
| 31-32 | xxHash support, zstd compression, creation times | MD5, xxHash, SHA | 128 KB |

### API Design

**Modern API** (Recommended):
```python
signature: ChecksumSignature = engine.generate_signature(data)
delta: DeltaInstructions = engine.generate_delta(signature, new_data)
result: bytes = engine.apply_delta(data, delta)
```

**Legacy API** (Backward compatibility):
```python
sum_head, blocks = engine.generate_sums(data)
matches = engine.match_sums(new_data, sum_head, blocks)
```

### Streaming for Large Files

```python
# Process 10GB file with constant memory usage
signature = engine.generate_signature_from_file("large.iso")
delta = engine.generate_delta_from_files(signature, "modified.iso")
```

## 📊 Performance

Real-world benchmark results (WSL2, tested 2026-01-10):

### Large Text File (1.1 MB with ~90 bytes changed)
| Metric | Value |
|--------|-------|
| **Original file size** | 1,125,000 bytes (1.07 MB) |
| **Signature size** | 24,273 bytes (23.7 KB) |
| **Delta size** | 17,533 bytes (17.1 KB) |
| **Matched data** | 1,124,352 bytes (99.9%) |
| **Literal data** | 648 bytes |
| **Data transferred** | 41,806 bytes (3.72% of original) |
| **Bandwidth saved** | 1,083,194 bytes (96.3% compression) |
| **Signature time** | 0.141s |
| **Delta time** | 0.130s |
| **Patch time** | <0.01s |

### Binary File (100 KB with 50 bytes changed)
| Metric | Value |
|--------|-------|
| **Original file size** | 102,400 bytes (100 KB) |
| **Matched data** | 100,352 bytes (98.0%) |
| **Literal data** | 2,048 bytes |
| **Signature time** | 0.012s |
| **Delta time** | 0.010s |
| **Verification** | ✓ MD5 checksum identical |

### Typical Compression Ratios
- **Small changes** (<1% modified): 96-99% bandwidth savings
- **Medium changes** (1-10% modified): 85-95% bandwidth savings
- **Large changes** (>10% modified): 50-85% bandwidth savings

## 🧪 Testing

This implementation includes comprehensive test suites:

```bash
# Run all unit tests (120 tests)
python -m unittest -q

# Run protocol parity tests (37 checks against C implementation)
python test_protocol_parity.py

# Run cross-validation with rsync binary
python test_cross_validation.py

# Run comprehensive wire protocol tests
python test_wire_protocol_parity.py

# Run end-to-end tests
python test_end_to_end.py
```

**Test Coverage**: 120 tests covering:
- Algorithm correctness (rolling checksum, strong checksums, matching)
- Protocol compliance (wire format, compression, tokens, compat/flist framing)
- Edge cases (empty files, single-byte changes, large files)
- Cross-validation with rsync C binary

## 📖 Documentation

- **Code Documentation**: Inline comments with exact C source references (e.g., `match.c:145-350`)
- **Type Hints**: Full type annotations for IDE autocomplete and static analysis
- **Examples**: Run `python rsync_phoenix_rebuilt.py --test` for interactive examples
- **Technical Details**: See [docs/](./docs/) folder for architecture and implementation notes

## 🛠️ Advanced Usage

### Protocol Negotiation

```python
from rsync_phoenix_rebuilt import ProtocolVersionManager, ChecksumType

# Use specific protocol version
manager = ProtocolVersionManager(desired_protocol=31)
manager.negotiate_protocol(remote_version=30)  # Agrees on v30

engine = ChecksumEngine(
    block_size=131072,  # 128KB
    checksum_type=ChecksumType.XXH64,
    protocol_manager=manager
)
```

### Wire Protocol (Token Stream)

```python
from rsync_phoenix_rebuilt import send_delta_over_wire, apply_delta_over_wire, CompressionType

# Roundtrip through wire protocol with compression
reconstructed, stats = apply_delta_over_wire(
    basis_data=original,
    signature=signature,
    delta=delta,
    protocol_version=31,
    compression=CompressionType.ZSTD,
    compression_level=6
)

print(f"Matches: {stats.matches}, Literals: {stats.literal_data} bytes")
```

### Custom Validation

```python
from rsync_phoenix_rebuilt import validate_block_size, validate_protocol_version, check_memory_limit

# Validate inputs before processing
validate_block_size(4096, protocol_version=31)
validate_protocol_version(31)
check_memory_limit(file_size, operation="signature generation")
```

## 🤝 Contributing

This project maintains strict 1:1 parity with the rsync C implementation. When contributing:

1. Reference exact C source lines in comments
2. Run full test suite: `python -m unittest discover`
3. Verify parity tests: `python tests/test_protocol_parity.py`
4. Follow existing code style (see inline comments)
5. Update documentation as needed

See [CONTRIBUTING.md](./docs/CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/alesanGreat/rsync-Phoenix-Rebuilt.git
cd rsync-Phoenix-Rebuilt

# Install with development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks for code quality
pre-commit install

# Run pre-commit on all files
pre-commit run --all-files
```

### Code Quality Tools

- **Formatting**: `black rsync_phoenix_rebuilt.py`
- **Linting**: `flake8 rsync_phoenix_rebuilt.py --max-line-length=100`
- **Type Checking**: `mypy rsync_phoenix_rebuilt.py --ignore-missing-imports`
- **Import Sorting**: `isort rsync_phoenix_rebuilt.py --profile=black`
- **Security**: `bandit -r rsync_phoenix_rebuilt.py`

### Running Tests

```bash
# All tests
python -m unittest discover

# Specific test suite
python tests/test_comprehensive.py
python tests/test_protocol_parity.py
python tests/test_cross_validation.py

# With coverage
pytest --cov=rsync_phoenix_rebuilt --cov-report=html
```

## 📜 License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Special exception: As with the original rsync, this implementation may be dynamically linked with OpenSSL and xxhash libraries.

## 🙏 Credits

### Original rsync Authors
- **Andrew Tridgell** - Original rsync algorithm (PhD thesis, 1999)
- **Paul Mackerras** - Original rsync implementation
- **Wayne Davison** - rsync maintainer (2003-2024)

### Python Implementation
- **Alejandro Sanchez** (2024-2026) - This faithful Python replica

## 📚 Academic References

1. Tridgell, A. (1999). *Efficient Algorithms for Sorting and Synchronization*. PhD Thesis, Australian National University. [PDF](https://www.samba.org/~tridge/phd_thesis.pdf)

2. Tridgell, A., & Mackerras, P. (1996). *The rsync algorithm*. Technical Report TR-CS-96-05, Australian National University. [Tech Report](https://rsync.samba.org/tech_report/)

3. rsync source code repository: [github.com/WayneD/rsync](https://github.com/WayneD/rsync)

## 🔗 Links

- **Source Code**: [github.com/alesanGreat/rsync-Phoenix-Rebuilt](https://github.com/alesanGreat/rsync-Phoenix-Rebuilt)
- **Original rsync**: [rsync.samba.org](https://rsync.samba.org/)
- **Issue Tracker**: [github.com/alesanGreat/rsync-Phoenix-Rebuilt/issues](https://github.com/alesanGreat/rsync-Phoenix-Rebuilt/issues)

---

<div align="center">

**Made with ❤️ by the community**

If this project helps you, consider giving it a ⭐ on GitHub!

</div>
