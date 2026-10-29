#!/usr/bin/env python3
"""EC310: bounded signed observer history verifier, no network or signer."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from observer_history.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
