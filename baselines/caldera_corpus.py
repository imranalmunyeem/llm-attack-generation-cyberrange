"""Compatibility wrapper for the Phase 6 CALDERA baseline.

The full Phase 6 table is produced by `baselines/real_baselines.py`, which
parses CALDERA Stockpile plus Atomic Red Team with shared metrics.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from baselines.real_baselines import main


if __name__ == "__main__":
    raise SystemExit(main())
