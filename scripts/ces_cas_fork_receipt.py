#!/usr/bin/env python3
"""EC324 two-channel offline handoff and local immutable fork receipt CLI."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from ec324_dual_channel_receipt.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
