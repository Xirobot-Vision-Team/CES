#!/usr/bin/env python3
"""EC311: full signed CAS decision/observer continuity without store I/O."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from cas_decision_history.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
