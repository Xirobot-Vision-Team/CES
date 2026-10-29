#!/usr/bin/env python3
"""EC290 exact independent EC230 private report readback operator executable."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from ec290_report_receipt_host.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
