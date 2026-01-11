#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convenience runner for the multi-protocol script test.

The canonical implementation lives in `tests/test_multi_protocol.py`.
Running that file directly makes imports brittle (because `sys.path[0]`
becomes `tests/`). This wrapper keeps a stable entry-point from repo root.
"""

from __future__ import annotations


def main() -> int:
    from tests.test_multi_protocol import main as _main

    return int(_main())


if __name__ == "__main__":
    raise SystemExit(main())

