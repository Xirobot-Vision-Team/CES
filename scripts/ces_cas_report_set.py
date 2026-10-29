#!/usr/bin/env python3
"""EC331 fixed read-only multi-report original-signature replayer (no CAS)."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from ec331_offline_report_set_crosscheck.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
