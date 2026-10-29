#!/usr/bin/env python3
"""EC280 QualityShow.Query separate private pinned-batch host (not EC241/243 Router)."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from quality_query_host.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
