#!/usr/bin/env python3
"""CES 1.0 unified Action/Mode entry point."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from unified_action_router import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
