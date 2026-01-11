#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convenience runner for the end-to-end unittest module.

The real tests live in `tests/test_end_to_end.py`.
"""

from __future__ import annotations

import unittest


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_end_to_end")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

