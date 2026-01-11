#!/usr/bin/env bash
set -euo pipefail

# Convenience runner for rsync-python.
# Intended to be called by an agent or a human.

python -m unittest -q
python test_cross_validation.py
python test_protocol_parity.py
python test_multi_protocol.py
python test_comprehensive.py
python test_end_to_end.py
