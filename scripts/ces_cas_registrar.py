#!/usr/bin/env python3
"""EC319 independent local offline signed receipt registrar; do not run as Host."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec319_offline_transfer_registry.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
