#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convenience runner for protocol parity checks.

This repo keeps some parity checks as script-style tests (stdout reports),
which are referenced from multiple docs. Running the file in `tests/` directly
doesn't work reliably because `sys.path[0]` becomes the `tests/` directory.

This wrapper runs the parity functions with the repo root on `sys.path`.
"""

from __future__ import annotations

import sys


def main() -> int:
    from tests.test_protocol_parity import (
        test_protocol_version_parity,
        test_checksum_parity_across_protocols,
    )

    ok1 = bool(test_protocol_version_parity())
    ok2 = bool(test_checksum_parity_across_protocols())
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    raise SystemExit(main())

