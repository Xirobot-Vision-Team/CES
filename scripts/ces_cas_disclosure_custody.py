#!/usr/bin/env python3
"""EC346 isolated offline receiver signing candidates and read-only copies audit."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from disclosure_custody.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
