#!/usr/bin/env python3
"""EC347 signed independent local readback challenge and read-only verifier."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from readback_challenge.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
