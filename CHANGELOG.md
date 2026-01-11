# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Paridad CLI 1:1 (audit-friendly)**:
  - `create_rsync_parser()` expone exactamente los option-strings de `rsync-original-source-code/options.c` (`long_options[]`) + aliases del bloque `help-rsync.h` en `rsync-original-source-code/rsync.1.md`.
  - El texto de ayuda `--help` y `rsync --daemon --help` se valida contra `rsync-original-source-code/rsync.1.md`.
  - Script de verificación: `python verificar_paridad_opciones.py` (debe reportar `PARIDAD 1:1: OK`).
- **Interop real (rsync C → python)**: test que decodifica un file-list real desde `rsync --server --sender` (wire-level) en `tests/test_rsync_sender_flist_interop.py`.
- **exclude.c wire framing**: helpers `send_filter_list_wire()` / `recv_filter_list_wire()` para el preámbulo de filtros requerido por `start_server()` antes del file-list.

### Changed
- `--version`/`--help`: el header de versión se alinea con `rsync-original-source-code/usage.c` (líneas `Copyright` + `Web site`).

### Fixed
- `recv_file_list_wire()`: consume correctamente `XMIT_{USER,GROUP}_NAME_FOLLOWS` para evitar desincronización con rsync real cuando hay inc-recursive/ID maps.

## [3.0.2] - 2026-01-10

### Added
- **README.md Professional**: Comprehensive README with badges, quick start, performance benchmarks, and complete documentation
- **Enhanced Type Safety**:
  - `SumHead` TypedDict for sum_struct headers
  - `SumSizes` TypedDict for sum_sizes_sqroot() return values
  - `ParityTraceEvent` TypedDict for debugging traces
  - `ChecksumAccumulator` Protocol for type-safe checksums
  - Replaced `Dict[str, int]` with proper TypedDicts across codebase
- **Enhanced Validation Functions**:
  - `validate_checksum_seed()`: Validates checksum seed values (0-0xFFFFFFFF range)
  - `validate_signature()`: Validates ChecksumSignature internal consistency
  - Enhanced `validate_data()` with min_size parameter and None checks
  - Enhanced `check_memory_limit()` with negative size validation
- **Improved CLI Error Handling**:
  - Granular error codes (1=general, 2=validation, 3=resource, 4=IO, 5=permission, 6=format, 130=interrupt)
  - File existence validation before operations
  - User-friendly error messages with hints
  - Automatic traceback display in non-quiet mode
  - Proper handling of JSON/pickle format errors
  - KeyboardInterrupt handling with exit code 130
- **Development Infrastructure**:
  - `setup.py`: Full setuptools configuration for PyPI distribution
  - `pyproject.toml`: Modern Python packaging with tool configs
  - `.pre-commit-config.yaml`: Pre-commit hooks (black, flake8, mypy, bandit, isort)
  - `.github/workflows/ci.yml`: Complete CI/CD pipeline with GitHub Actions
  - `.gitignore`: Comprehensive ignore patterns
  - `CONTRIBUTING.md`: Detailed contribution guidelines

### Changed
- **Module Docstring**: Completely rewritten for clarity and conciseness (114 → 67 lines)
  - Clear "Quick Start" section with runnable example
  - Focused "Key Features" with checkmarks
  - Concise algorithm explanation
  - Streamlined references and copyright
- **API Exports**: Added `validate_checksum_seed` and `validate_signature` to `__all__`
- **Type Hints**: Improved type safety with TypedDicts replacing Dict[str, Any] in 6 functions

### Fixed
- CLI now validates file existence before attempting operations
- Better error messages when loading malformed signature/delta files
- Consistent error handling across all CLI commands

### Testing
- All unit tests passing (currently 120)
- All 37 protocol parity checks passing
- Comprehensive test coverage maintained

### Infrastructure
- **GitHub Actions CI/CD**:
  - Test matrix: Python 3.8-3.12 on Ubuntu, macOS, Windows
  - Code quality checks (black, flake8, isort, mypy)
  - Integration tests with rsync binary
  - Performance benchmarks
  - Security scanning with bandit
  - Build and distribution checks
- **Pre-commit Hooks**:
  - Code formatting (black, isort)
  - Linting (flake8 with plugins)
  - Type checking (mypy)
  - Security (bandit)
  - File checks (trailing whitespace, YAML, JSON)
  - Markdown linting

### Documentation
- New README.md with:
  - Badges (Python version, license, protocol, tests)
  - Quick start guide
  - Performance benchmarks table
  - Protocol support matrix
  - API examples (modern and legacy)
  - CLI usage examples
  - Advanced usage (protocol negotiation, wire protocol, validation)
  - Contributing guidelines
  - Academic references

## [3.0.1] - 2026-01-09

### Added
- Protocol wire compatibility (protocol versions 20-32)
- Streaming support for files larger than RAM
- Professional CLI with colors and statistics
- Cross-validation tests with rsync binary

### Changed
- Improved rolling checksum algorithm (1:1 parity with match.c)
- Enhanced API with typed dataclasses

## [3.0.0] - 2026-01-08

### Added
- Initial release of 1:1 Python implementation
- Support for MD4, MD5, SHA1, SHA256, xxHash checksums
- Protocol versions 20-32 support
- Comprehensive test suite

---

## Version Guidelines

### Major Version (X.0.0)
- Breaking API changes
- Protocol compatibility changes
- Major architectural rewrites

### Minor Version (0.X.0)
- New features
- Non-breaking API additions
- Performance improvements

### Patch Version (0.0.X)
- Bug fixes
- Documentation improvements
- Minor enhancements
