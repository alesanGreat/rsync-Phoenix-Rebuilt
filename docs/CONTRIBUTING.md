# Contributing to rsync-python

First off, thank you for considering contributing to rsync-python! 🎉

This project maintains strict 1:1 parity with the original rsync C implementation. All contributions must preserve this core principle while enhancing usability, documentation, or testing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)

## Code of Conduct

This project adheres to a code of conduct that emphasizes:
- **Respectful collaboration**
- **Technical excellence**
- **Constructive feedback**
- **Inclusive environment**

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** describing the issue
- **Reproduction steps** with minimal example
- **Expected vs actual behavior**
- **Environment details** (Python version, OS, rsync version)
- **Error messages** with full stack traces

**Template:**
```markdown
**Bug Description:**
Brief description of the issue

**Reproduction:**
```python
# Minimal code to reproduce
```

**Expected:** What should happen
**Actual:** What actually happens
**Environment:** Python 3.11, Ubuntu 22.04, rsync (>= 3.0 recommended)
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Use case** - Why is this needed?
- **Proposed solution** - How should it work?
- **Alternatives considered** - What other approaches did you think about?
- **Breaking changes** - Will this affect existing users?

**Areas for enhancement:**
- Performance optimizations (must maintain 1:1 parity)
- Better error messages
- Additional validation
- Documentation improvements
- Test coverage expansion

### Contributing Code

Great! Here's how to contribute code:

## Development Setup

### 1. Fork and Clone

```bash
# Fork on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/rsync-python.git
cd rsync-python
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Core dependencies
pip install xxhash lz4 zstandard

# Development dependencies
pip install -e ".[dev]"

# Pre-commit hooks
pip install pre-commit
pre-commit install
```

### 4. Verify Setup

```bash
# Run tests
python -m unittest -q

# Run parity checks
python test_protocol_parity.py
python verificar_paridad_opciones.py

# Verify CLI works
python rsync_phoenix_rebuilt.py --version
```

## Pull Request Process

### 1. Create Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

### 2. Make Changes

Follow these principles:

✅ **DO:**
- Reference C source lines in comments
- Maintain 1:1 algorithm parity
- Add tests for new functionality
- Update documentation
- Run pre-commit hooks
- Follow existing code style

❌ **DON'T:**
- Change core algorithm behavior
- Remove C source references
- Break backward compatibility without discussion
- Skip tests

### 3. Test Thoroughly

```bash
# Run all tests
python -m unittest -q

# Run specific test suite
python test_cross_validation.py

# Run with coverage
pip install pytest pytest-cov
pytest --cov=rsync_phoenix_rebuilt --cov-report=html

# Manual testing
python rsync_phoenix_rebuilt.py --test
```

### 4. Commit with Clear Messages

```bash
# Good commit messages
git commit -m "Add validation for negative block sizes (fixes #123)"
git commit -m "Optimize rolling checksum with memoryview (maintains parity)"
git commit -m "docs: Update README with installation examples"

# Commit message format
<type>: <subject>

<body>

<footer>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

### 5. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:

**PR Title:** Clear, descriptive (50 chars max)

**PR Description Template:**
```markdown
## Changes
- What did you change?
- Why was it needed?

## Testing
- [ ] All unit tests pass
- [ ] Parity tests pass
- [ ] Added new tests (if applicable)
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] C source references added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if user-facing)
- [ ] No breaking changes (or discussed first)

## Related Issues
Fixes #123
Related to #456
```

## Coding Standards

### Style Guide

- **PEP 8** compliance (enforced by `black`)
- **Line length:** 100 characters
- **Type hints:** Required for public API
- **Docstrings:** Google style, required for public functions

### C Source References

Every algorithm implementation MUST reference the C source:

```python
def rolling_checksum(self, data: bytes) -> int:
    """
    Calculate rolling checksum (Adler-32 variant).

    This implements the algorithm from rsync.h (lines 450-470).
    Reference: rsync-original-source-code/rsync.h:450-470

    Args:
        data: Input bytes

    Returns:
        32-bit checksum
    """
    # Implementation matching C code...
```

### Type Safety

- Use `TypedDict` for structured dictionaries
- Avoid `Any` where possible
- Use `Protocol` for duck typing
- Add type hints to all new functions

### Error Handling

- Use custom exception hierarchy
- Provide helpful error messages
- Include context in exceptions
- Validate inputs early

## Testing Requirements

### Minimum Coverage

All PRs must:
- ✅ Pass all existing tests (130+ tests)
- ✅ Maintain or improve coverage
- ✅ Include tests for new features
- ✅ Pass protocol parity checks

### Test Categories

1. **Unit Tests** (`test_*.py`)
   - Test individual functions
   - Cover edge cases
   - Fast execution (<10s total)

2. **Parity Tests** (`test_protocol_parity.py`)
   - Verify 1:1 C compatibility
   - Critical for core changes

3. **Integration Tests** (`test_end_to_end.py`)
   - Test full workflows
   - CLI testing
   - File I/O

4. **Cross-Validation** (`test_cross_validation.py`)
   - Compare with rsync binary
   - Requires rsync installed

### Writing Tests

```python
import unittest
from rsync_phoenix_rebuilt import ChecksumEngine, ValidationError

class TestNewFeature(unittest.TestCase):
    """Test suite for new feature."""

    def setUp(self):
        """Set up test fixtures."""
        self.engine = ChecksumEngine(block_size=4096)

    def test_basic_functionality(self):
        """Test basic use case."""
        # Arrange
        data = b"test data"

        # Act
        result = self.engine.some_method(data)

        # Assert
        self.assertIsNotNone(result)
        self.assertEqual(len(result), expected_length)

    def test_edge_case_empty_data(self):
        """Test with empty data."""
        with self.assertRaises(ValidationError):
            self.engine.some_method(b"")
```

## Documentation

### Code Documentation

- **Module docstring:** Overview, usage examples
- **Class docstrings:** Purpose, attributes, examples
- **Function docstrings:** Args, returns, raises, examples
- **Inline comments:** Explain "why", not "what"

### User Documentation

Update when adding user-facing features:
- `README.md` - Usage examples
- `AGENTS.md` - Implementation details
- `CHANGELOG.md` - Version history

## Questions?

- 📧 **Email:** alesangreat@gmail.com
- 🐛 **Issues:** [GitHub Issues](https://github.com/yourusername/rsync-python/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/rsync-python/discussions)

## License

By contributing, you agree that your contributions will be licensed under the **GPL-3.0-or-later** license, consistent with the original rsync project.

---

**Thank you for contributing to rsync-python!** 🚀

Your efforts help make this project a valuable reference implementation and educational resource for the community.
