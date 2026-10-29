#!/usr/bin/env python3
"""EC403 isolated read-only restricted original XMLDSig evidence receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from ec403_signed_xml.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
