#!/usr/bin/env python3
"""EC279 explicitly separate FindingShow.Query host; not EC241/243 Router."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from ec279_finding_query_host.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
