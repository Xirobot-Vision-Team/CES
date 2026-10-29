#!/usr/bin/env python3
"""EC402 isolated read-only native PDF/ByteRange/CMS evidence receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from ec402_signed_pdf.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
