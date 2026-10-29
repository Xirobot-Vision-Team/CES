#!/usr/bin/env python3
"""EC291: owner-approved original EC230 DocsOnly local Git readback (not publish)."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec291_docs_receipt_host.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
