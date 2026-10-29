#!/usr/bin/env python3
"""EC413 read-only genuine original LOTL CA/signer OCSP isolated CLI."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from ec413_lotl_ocsp.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
