#!/usr/bin/env python3
"""EC333: unsigned complete EC332 delta handoff; verify path read-only."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from replayable_delta_handoff.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
