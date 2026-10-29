#!/usr/bin/env python3
"""EC289 fixed, opt-in entry to independently hosted original EC228."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from report_publish_host.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
