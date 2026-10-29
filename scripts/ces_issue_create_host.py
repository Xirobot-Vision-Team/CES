#!/usr/bin/env python3
"""EC287 separately authorized IssueCreate.Create independent host operator."""
from __future__ import annotations
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from issue_create_host.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
