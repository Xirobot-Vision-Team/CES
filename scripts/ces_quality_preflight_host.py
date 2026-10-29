#!/usr/bin/env python3
"""Standalone EC281 fixed QualityRun.Preflight host and offline operator CLI."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'construction'))
from quality_preflight_host.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
