#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convenience runner for the cross-validation unittest module.

Docs reference `python test_cross_validation.py`. The actual tests live in
`tests/test_cross_validation.py`, but running that file directly sets
`sys.path[0]` to `tests/` and can break imports depending on environment.
"""

from __future__ import annotations

import unittest


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_cross_validation")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

