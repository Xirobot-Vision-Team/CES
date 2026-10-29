#!/usr/bin/env python3
"""EC336 isolated read-only receiver: pinned old-path ORIGINAL signed replay."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec336_portable_signed_replay.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
