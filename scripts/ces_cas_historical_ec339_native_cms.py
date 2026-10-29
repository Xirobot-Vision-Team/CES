#!/usr/bin/env python3
"""EC400 isolated read-only original native CMS/PKCS#7 receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from ec400_native_cms.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
